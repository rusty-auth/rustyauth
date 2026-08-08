//! Realm-side Fleet management and one-time pairing boundary.

use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use http::{HeaderMap, header};
use secrecy::{ExposeSecret, SecretString};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use uuid::Uuid;

use crate::{
    config::Environment,
    operator_auth::{OperatorAuthorizer, OperatorCapability},
    proto::rustyauth::management::v1::*,
    store::{RealmFleetGrantRecord, Store, StorePolicyError, now},
};

const PROTOCOL_VERSION: &str = "1";
const DEFAULT_SCOPES: &[&str] = &["realm.read"];
const ALLOWED_SCOPES: &[&str] = &["realm.read", "realm.support"];

pub(crate) struct ManagementRpc {
    store: Store,
    authorizer: OperatorAuthorizer,
    environment: Environment,
    realm_id: String,
    issuer: String,
    rp_id: String,
}

impl ManagementRpc {
    pub(crate) fn new(
        store: Store,
        authorizer: OperatorAuthorizer,
        environment: Environment,
        realm_id: String,
        issuer: String,
        rp_id: String,
    ) -> Self {
        Self {
            store,
            authorizer,
            environment,
            realm_id,
            issuer,
            rp_id,
        }
    }

    async fn grant(
        &self,
        headers: &HeaderMap,
        required_scope: &str,
    ) -> Result<RealmFleetGrantRecord, ConnectError> {
        let credential = bearer(headers)
            .ok_or_else(|| ConnectError::new(ErrorCode::Unauthenticated, "realm grant required"))?;
        let grant = self
            .store
            .realm_fleet_grant_by_credential(credential.expose_secret())
            .await
            .map_err(internal)?
            .ok_or_else(|| ConnectError::new(ErrorCode::Unauthenticated, "realm grant required"))?;
        if grant.realm_id != self.realm_id
            || !grant
                .granted_scopes
                .iter()
                .any(|scope| scope == required_scope)
        {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "realm grant does not allow this operation",
            ));
        }
        Ok(grant)
    }
}

#[allow(refining_impl_trait)]
impl RealmManagementService for ManagementRpc {
    async fn get_discovery(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetDiscoveryRequest>,
    ) -> ServiceResult<RealmDiscovery> {
        Response::ok(RealmDiscovery {
            realm_id: self.realm_id.clone(),
            deployment_version: env!("CARGO_PKG_VERSION").into(),
            management_protocol_version: PROTOCOL_VERSION.into(),
            issuer: self.issuer.clone(),
            rp_id: self.rp_id.clone(),
            rpc_protocols: vec!["connect+protobuf".into(), "grpc+protobuf".into()],
            capabilities: vec![
                ManagementCapability {
                    name: "realm.health".into(),
                    version: 1,
                    ..Default::default()
                },
                ManagementCapability {
                    name: "realm.summary".into(),
                    version: 1,
                    ..Default::default()
                },
            ],
            pairing_supported: true,
            outbound_connector_supported: false,
            ..Default::default()
        })
    }

    async fn get_health(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetHealthRequest>,
    ) -> ServiceResult<RealmHealth> {
        let started = std::time::Instant::now();
        self.store
            .ensure_restore_complete()
            .await
            .map_err(internal)?;
        Response::ok(RealmHealth {
            realm_id: self.realm_id.clone(),
            state: RealmServingState::Healthy.into(),
            datastore_latency_milliseconds: started.elapsed().as_millis().min(u128::from(u64::MAX))
                as u64,
            checked_at: format_timestamp(now())?,
            ..Default::default()
        })
    }

    async fn get_summary(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, GetSummaryRequest>,
    ) -> ServiceResult<RealmSummary> {
        self.grant(ctx.headers(), "realm.read").await?;
        let counts = self.store.realm_summary_counts().await.map_err(internal)?;
        Response::ok(RealmSummary {
            realm_id: self.realm_id.clone(),
            users: counts.users,
            passkeys: counts.passkeys,
            active_sessions: counts.active_sessions,
            service_accounts: counts.service_accounts,
            latest_backup_at: String::new(),
            signing_key_state: "active+staged".into(),
            calculated_at: format_timestamp(now())?,
            ..Default::default()
        })
    }

    async fn create_pairing_code(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreatePairingCodeRequest>,
    ) -> ServiceResult<PairingCode> {
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        required_uuid(request.request_id, "request_id")?;
        let origin = safe_control_plane_origin(request.control_plane_origin, &self.environment)?;
        let requested_scopes = request
            .requested_scopes
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        let scopes = safe_scopes(&requested_scopes)?;
        let (record, code) = self
            .store
            .create_realm_pairing(self.realm_id.clone(), origin, scopes.clone(), actor.user.id)
            .await
            .map_err(internal)?;
        Response::ok(PairingCode {
            id: record.id.to_string(),
            code,
            realm_id: record.realm_id,
            control_plane_origin: record.control_plane_origin,
            requested_scopes: scopes,
            state: PairingState::Pending.into(),
            expires_at: format_timestamp(record.expires_at)?,
            ..Default::default()
        })
    }

    async fn exchange_pairing_code(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ExchangePairingCodeRequest>,
    ) -> ServiceResult<PairingGrant> {
        required_uuid(request.request_id, "request_id")?;
        let code = safe_secret(request.code, 16, 256)?;
        let origin = safe_control_plane_origin(request.control_plane_origin, &self.environment)?;
        let instance_id = safe_identifier(request.control_plane_instance_id, "instance id", 128)?;
        let (grant, credential) = self
            .store
            .exchange_realm_pairing(code.expose_secret(), &origin, instance_id)
            .await
            .map_err(store_error)?;
        Response::ok(PairingGrant {
            connection_id: grant.connection_id.to_string(),
            realm_id: grant.realm_id,
            credential,
            credential_hint: grant.credential_hint,
            granted_scopes: grant.granted_scopes,
            created_at: format_timestamp(grant.created_at)?,
            expires_at: format_timestamp(grant.expires_at)?,
            ..Default::default()
        })
    }

    async fn revoke_fleet_connection(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeFleetConnectionRequest>,
    ) -> ServiceResult<FleetConnectionState> {
        let grant = self.grant(ctx.headers(), "realm.read").await?;
        let connection_id = required_uuid(request.connection_id, "connection_id")?;
        required_uuid(request.request_id, "request_id")?;
        if grant.connection_id != connection_id {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "realm grant is bound to another connection",
            ));
        }
        let revoked = self
            .store
            .revoke_realm_fleet_grant(connection_id)
            .await
            .map_err(store_error)?;
        Response::ok(FleetConnectionState {
            connection_id: revoked.connection_id.to_string(),
            realm_id: revoked.realm_id,
            revoked: true,
            revoked_at: format_optional_timestamp(revoked.revoked_at)?,
            ..Default::default()
        })
    }
}

fn bearer(headers: &HeaderMap) -> Option<SecretString> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|value| value.starts_with("rfg_") && value.len() <= 128)
        .map(|value| SecretString::from(value.to_owned()))
}

fn safe_control_plane_origin(
    value: &str,
    environment: &Environment,
) -> Result<String, ConnectError> {
    let value = Url::parse(value.trim()).map_err(|_| invalid("control plane origin is invalid"))?;
    if value.username() != ""
        || value.password().is_some()
        || value.query().is_some()
        || value.fragment().is_some()
        || !matches!(value.path(), "" | "/")
    {
        return Err(invalid("control plane origin is invalid"));
    }
    let host = value
        .host_str()
        .ok_or_else(|| invalid("control plane origin has no host"))?;
    match value.scheme() {
        "https" => {}
        "http"
            if environment == &Environment::Development
                && matches!(host, "localhost" | "127.0.0.1" | "::1") => {}
        _ => return Err(invalid("control plane origin must use HTTPS")),
    }
    Ok(value.to_string().trim_end_matches('/').to_owned())
}

fn safe_scopes(values: &[String]) -> Result<Vec<String>, ConnectError> {
    let values = if values.is_empty() {
        DEFAULT_SCOPES
            .iter()
            .map(|value| (*value).to_owned())
            .collect()
    } else {
        values.to_vec()
    };
    if values.len() > ALLOWED_SCOPES.len()
        || values
            .iter()
            .any(|value| !ALLOWED_SCOPES.contains(&value.as_str()))
    {
        return Err(invalid("requested Fleet scope is not supported"));
    }
    let mut values = values;
    values.sort_unstable();
    values.dedup();
    Ok(values)
}

fn safe_identifier(
    value: &str,
    _field: &'static str,
    maximum: usize,
) -> Result<String, ConnectError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > maximum
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(invalid("identifier is invalid"));
    }
    Ok(value.to_owned())
}

fn safe_secret(value: &str, minimum: usize, maximum: usize) -> Result<SecretString, ConnectError> {
    let value = value.trim();
    if !(minimum..=maximum).contains(&value.len())
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(invalid("pairing code is invalid"));
    }
    Ok(SecretString::from(value.to_owned()))
}

fn required_uuid(value: &str, _field: &'static str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(value).map_err(|_| invalid("request id is invalid"))
}

fn format_timestamp(value: u64) -> Result<String, ConnectError> {
    let value = i64::try_from(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "stored timestamp is invalid"))?;
    OffsetDateTime::from_unix_timestamp(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "stored timestamp is invalid"))?
        .format(&Rfc3339)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "format timestamp"))
}

fn format_optional_timestamp(value: Option<u64>) -> Result<String, ConnectError> {
    value
        .map(format_timestamp)
        .transpose()
        .map(Option::unwrap_or_default)
}

fn store_error(error: anyhow::Error) -> ConnectError {
    if let Some(policy) = error.downcast_ref::<StorePolicyError>() {
        return match policy {
            StorePolicyError::RealmPairingInvalid => ConnectError::new(
                ErrorCode::FailedPrecondition,
                "pairing code is invalid, expired or already consumed",
            ),
            StorePolicyError::RealmFleetGrantInvalid => {
                ConnectError::new(ErrorCode::NotFound, "realm Fleet connection is missing")
            }
            _ => internal(error),
        };
    }
    internal(error)
}

fn invalid(message: &'static str) -> ConnectError {
    ConnectError::new(ErrorCode::InvalidArgument, message)
}

fn internal(error: impl std::fmt::Display) -> ConnectError {
    tracing::error!(error = %error, "realm management operation failed");
    ConnectError::new(ErrorCode::Internal, "realm management operation failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_bounded_and_deduplicated() {
        assert_eq!(safe_scopes(&[]).unwrap(), vec!["realm.read"]);
        assert_eq!(
            safe_scopes(&["realm.read".into(), "realm.read".into()]).unwrap(),
            vec!["realm.read"]
        );
        assert!(safe_scopes(&["database.direct".into()]).is_err());
    }
}
