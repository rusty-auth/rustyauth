//! Realm-side Fleet management and one-time pairing boundary.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use http::{HeaderMap, header};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use uuid::Uuid;

use crate::{
    backup::BackupStore,
    config::Environment,
    event_rpc::event_to_proto,
    identity_rpc::projection::record_to_proto,
    jwt::JwtIssuer,
    metrics_rpc::MetricsRpc,
    operator_auth::{OperatorAuthorizer, OperatorCapability},
    proto::rustyauth::{
        identity::v1::ListUsersResponse, management::v1::*,
        service_accounts::v1::ListServiceAccountsResponse, webhooks::v1::ListWebhooksResponse,
    },
    rate_limit::{RateLimitClass, RateLimiter},
    service_account_rpc::projection::service_account_to_proto,
    store::{
        RealmFleetGrantRecord, RemoteMutationClaim, ServiceAccountStatusRecord, Store,
        StorePolicyError, WebhookManagementSourceRecord, WebhookStatusRecord, now,
    },
    webhook_rpc::webhook_to_proto,
};

const PROTOCOL_VERSION: &str = "1";
const DEFAULT_SCOPES: &[&str] = &["realm.read", "telemetry.export"];
const ALLOWED_SCOPES: &[&str] = &["realm.read", "realm.support", "telemetry.export"];

pub(crate) struct ManagementRpc {
    store: Store,
    authorizer: OperatorAuthorizer,
    environment: Environment,
    realm_id: String,
    issuer: String,
    rp_id: String,
    rate_limiter: Arc<RateLimiter>,
    executor: RealmCommandExecutor,
}

/// The realm-local command boundary shared by public management RPCs and the
/// private, realm-initiated connector. It deliberately contains no operator
/// authorizer or Fleet transport state: callers must authenticate and scope a
/// realm grant before invoking it, while this layer enforces exact connection
/// binding, bounded reads, mutation expiry and the durable replay ledger.
#[derive(Clone)]
pub(crate) struct RealmCommandExecutor {
    store: Store,
    realm_id: String,
    jwt: JwtIssuer,
    backup: Option<BackupStore>,
}

pub(crate) struct ManagementRpcConfig {
    pub(crate) environment: Environment,
    pub(crate) realm_id: String,
    pub(crate) issuer: String,
    pub(crate) rp_id: String,
    pub(crate) rate_limiter: Arc<RateLimiter>,
    pub(crate) jwt: JwtIssuer,
    pub(crate) backup: Option<BackupStore>,
}

impl ManagementRpc {
    pub(crate) fn new(
        store: Store,
        authorizer: OperatorAuthorizer,
        config: ManagementRpcConfig,
    ) -> Self {
        let executor = RealmCommandExecutor::new(
            store.clone(),
            config.realm_id.clone(),
            config.jwt,
            config.backup,
        );
        Self {
            store,
            authorizer,
            environment: config.environment,
            realm_id: config.realm_id,
            issuer: config.issuer,
            rp_id: config.rp_id,
            rate_limiter: config.rate_limiter,
            executor,
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

    async fn operational_summary(&self) -> Result<RealmSummary, ConnectError> {
        self.executor.operational_summary().await
    }
}

impl RealmCommandExecutor {
    pub(crate) fn new(
        store: Store,
        realm_id: String,
        jwt: JwtIssuer,
        backup: Option<BackupStore>,
    ) -> Self {
        Self {
            store,
            realm_id,
            jwt,
            backup,
        }
    }

    async fn operational_summary(&self) -> Result<RealmSummary, ConnectError> {
        let counts = self.store.realm_summary_counts().await.map_err(internal)?;
        let signing = self.jwt.stored_status().await.map_err(internal)?;
        let latest_backup_at = match &self.backup {
            Some(backup) => backup
                .persisted_status(&self.store)
                .await
                .map_err(internal)?
                .last_success_at
                .map(format_timestamp)
                .transpose()?
                .unwrap_or_default(),
            None => String::new(),
        };
        Ok(RealmSummary {
            realm_id: self.realm_id.clone(),
            users: counts.users,
            passkeys: counts.passkeys,
            active_sessions: counts.active_sessions,
            service_accounts: counts.service_accounts,
            latest_backup_at,
            signing_key_state: format!(
                "active:{};staged:{};retired:{};next_rotation_at:{}",
                signing.active_kid,
                signing.staged_kid.as_deref().unwrap_or("none"),
                signing.retired_kids.len(),
                format_timestamp(signing.next_rotation_at)?,
            ),
            calculated_at: format_timestamp(now())?,
            ..Default::default()
        })
    }

    pub(crate) async fn operational_snapshot(
        &self,
        expected_connection_id: Uuid,
        request: GetOperationalSnapshotRequest,
    ) -> Result<RealmOperationalSnapshot, ConnectError> {
        if required_uuid(&request.connection_id, "connection_id")? != expected_connection_id {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "realm grant is bound to another connection",
            ));
        }
        let user_page_size = bounded_page_size(request.user_page_size, 50, "user_page_size")?;
        let user_after = decode_uuid_page_token(&request.user_page_token, "user_page_token")?;
        let users = self
            .store
            .list_users(user_after, user_page_size)
            .await
            .map_err(internal)?;
        let users = ListUsersResponse {
            users: users
                .users
                .into_iter()
                .map(|user| record_to_proto(user.into()))
                .collect::<Result<_, _>>()?,
            next_page_token: users
                .next_after
                .map(encode_uuid_page_token)
                .unwrap_or_default(),
            ..Default::default()
        };

        let event_page_size = bounded_page_size(request.event_page_size, 100, "event_page_size")?;
        let latest_event_sequence = self.store.latest_event_sequence().await.map_err(internal)?;
        if request.event_after_sequence > latest_event_sequence {
            return Err(invalid(
                "event_after_sequence is ahead of the realm event log",
            ));
        }
        let events = self
            .store
            .events(request.event_after_sequence, event_page_size as u64)
            .await
            .map_err(internal)?
            .into_iter()
            .map(event_to_proto)
            .collect::<Result<_, _>>()?;

        let service_account_page_size = bounded_page_size(
            request.service_account_page_size,
            50,
            "service_account_page_size",
        )?;
        let service_account_after = decode_uuid_page_token(
            &request.service_account_page_token,
            "service_account_page_token",
        )?;
        let mut service_accounts = self.store.service_accounts().await.map_err(internal)?;
        service_accounts.sort_unstable_by_key(|account| account.id);
        service_accounts.retain(|account| service_account_after.is_none_or(|id| account.id > id));
        let service_account_next = (service_accounts.len() > service_account_page_size)
            .then(|| encode_uuid_page_token(service_accounts[service_account_page_size - 1].id));
        service_accounts.truncate(service_account_page_size);
        let service_accounts = ListServiceAccountsResponse {
            service_accounts: service_accounts
                .into_iter()
                .map(service_account_to_proto)
                .collect::<Result<_, _>>()?,
            next_page_token: service_account_next.unwrap_or_default(),
            ..Default::default()
        };

        let webhook_page_size =
            bounded_page_size(request.webhook_page_size, 50, "webhook_page_size")?;
        let webhook_after =
            decode_text_page_token(&request.webhook_page_token, "webhook_page_token")?;
        let mut webhooks = self.store.webhooks().await.map_err(internal)?;
        webhooks.retain(|webhook| webhook_after.as_ref().is_none_or(|id| webhook.id > *id));
        let webhook_next = (webhooks.len() > webhook_page_size)
            .then(|| encode_text_page_token(&webhooks[webhook_page_size - 1].id));
        webhooks.truncate(webhook_page_size);
        let webhooks = ListWebhooksResponse {
            webhooks: webhooks
                .into_iter()
                .map(webhook_to_proto)
                .collect::<Result<_, _>>()?,
            next_page_token: webhook_next.unwrap_or_default(),
            ..Default::default()
        };

        let metrics = MetricsRpc::new(self.store.clone(), self.backup.clone())
            .overview(&request.metrics_starts_at, &request.metrics_ends_at)
            .await?;
        Ok(RealmOperationalSnapshot {
            realm_id: self.realm_id.clone(),
            summary: self.operational_summary().await?.into(),
            users: users.into(),
            events,
            latest_event_sequence,
            service_accounts: service_accounts.into(),
            webhooks: webhooks.into(),
            metrics: metrics.into(),
            source: "live-realm".into(),
            calculated_at: format_timestamp(now())?,
            ..Default::default()
        })
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
                ManagementCapability {
                    name: "realm.operations".into(),
                    version: 1,
                    ..Default::default()
                },
                ManagementCapability {
                    name: "realm.remote-admin".into(),
                    version: 1,
                    ..Default::default()
                },
                ManagementCapability {
                    name: crate::analytics::CAPABILITY_TELEMETRY_ROLLUPS_V1.into(),
                    version: 1,
                    ..Default::default()
                },
            ],
            pairing_supported: true,
            // Once paired, this realm maintains a signed bidirectional
            // connector for telemetry, health, bounded reads and controlled
            // remote administration without requiring a public inbound path.
            outbound_connector_supported: true,
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
        Response::ok(self.operational_summary().await?)
    }

    async fn get_operational_snapshot(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetOperationalSnapshotRequest>,
    ) -> ServiceResult<RealmOperationalSnapshot> {
        let grant = self.grant(ctx.headers(), "realm.read").await?;
        Response::ok(
            self.executor
                .operational_snapshot(grant.connection_id, request.to_owned_message())
                .await?,
        )
    }

    async fn execute_remote_mutation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RemoteMutationRequest>,
    ) -> ServiceResult<RemoteMutationResult> {
        let grant = self.grant(ctx.headers(), "realm.support").await?;
        Response::ok(
            self.executor
                .remote_mutation(grant.connection_id, request.to_owned_message())
                .await?,
        )
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
        if !self
            .rate_limiter
            .check(RateLimitClass::PairingExchange, "realm-pairing-global")
            .await
            .allowed
        {
            return Err(ConnectError::new(
                ErrorCode::ResourceExhausted,
                "pairing exchange rate limit exceeded",
            ));
        }
        required_uuid(request.request_id, "request_id")?;
        let code = safe_secret(request.code, 16, 256)?;
        let origin = safe_control_plane_origin(request.control_plane_origin, &self.environment)?;
        let instance_id = safe_identifier(request.control_plane_instance_id, "instance id", 128)?;
        if request.assignment_epoch == 0 {
            return Err(invalid("assignment_epoch must be positive"));
        }
        let (grant, credential) = self
            .store
            .exchange_realm_pairing(
                code.expose_secret(),
                &origin,
                instance_id,
                request.assignment_epoch,
            )
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
            assignment_epoch: grant.assignment_epoch,
            control_plane_instance_id: grant.control_plane_instance_id,
            ..Default::default()
        })
    }

    async fn rotate_fleet_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RotateFleetCredentialRequest>,
    ) -> ServiceResult<PairingGrant> {
        let grant = self.grant(ctx.headers(), "realm.read").await?;
        Response::ok(
            self.executor
                .rotate_connection_credential(grant.connection_id, request.to_owned_message())
                .await?,
        )
    }

    async fn revoke_fleet_connection(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeFleetConnectionRequest>,
    ) -> ServiceResult<FleetConnectionState> {
        let grant = self.grant(ctx.headers(), "realm.read").await?;
        Response::ok(
            self.executor
                .revoke_connection(grant.connection_id, request.to_owned_message())
                .await?,
        )
    }
}

impl RealmCommandExecutor {
    pub(crate) async fn remote_mutation(
        &self,
        expected_connection_id: Uuid,
        request: RemoteMutationRequest,
    ) -> Result<RemoteMutationResult, ConnectError> {
        let connection_id = required_uuid(&request.connection_id, "connection_id")?;
        if connection_id != expected_connection_id {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "realm grant is bound to another connection",
            ));
        }
        let request_id = required_uuid(&request.request_id, "request_id")?;
        let reason = safe_remote_reason(&request.reason)?;
        let expires_at = remote_mutation_expiry(&request.expires_at)?;
        let operation = request
            .operation
            .as_known()
            .filter(|value| *value != RemoteMutationOperation::Unspecified)
            .ok_or_else(|| invalid("remote mutation operation is required"))?;
        let target_id = safe_remote_target(&request.target_id, "target_id", 1_024)?;
        let secondary_id = safe_optional_remote_target(&request.secondary_id, 1_024)?;
        validate_remote_mutation_shape(operation, &target_id, &secondary_id)?;
        let digest = remote_mutation_digest(
            connection_id,
            operation,
            &target_id,
            &secondary_id,
            request.enabled,
            &reason,
            expires_at,
        );
        match self
            .store
            .claim_remote_mutation(request_id, &digest)
            .await
            .map_err(store_error)?
        {
            RemoteMutationClaim::Completed {
                completed_at,
                succeeded,
                summary,
            } => {
                if !succeeded {
                    return Err(ConnectError::new(
                        ErrorCode::FailedPrecondition,
                        "remote mutation previously failed and requires a new request id",
                    ));
                }
                return Ok(RemoteMutationResult {
                    connection_id: connection_id.to_string(),
                    request_id: request_id.to_string(),
                    operation: operation.into(),
                    applied: false,
                    replayed: true,
                    completed_at: format_timestamp(completed_at)?,
                    summary,
                    ..Default::default()
                });
            }
            RemoteMutationClaim::Claimed => {}
        }

        let outcome = self
            .apply_remote_mutation(operation, &target_id, &secondary_id, request.enabled)
            .await;
        let summary = match outcome {
            Ok(summary) => summary,
            Err(error) => {
                let _ = self
                    .store
                    .complete_remote_mutation(
                        request_id,
                        &digest,
                        false,
                        "remote mutation failed before completion".into(),
                    )
                    .await;
                return Err(store_error(error));
            }
        };
        if let Err(error) = self
            .store
            .append_event_with_data(
                "fleet.remote_mutation.completed",
                Uuid::parse_str(&target_id).ok(),
                serde_json::json!({
                    "connectionId": connection_id,
                    "requestId": request_id,
                    "operation": remote_mutation_name(operation),
                    "targetId": target_id,
                    "secondaryId": secondary_id,
                    "reason": reason,
                }),
            )
            .await
        {
            let _ = self
                .store
                .complete_remote_mutation(
                    request_id,
                    &digest,
                    false,
                    "remote mutation applied but correlated local audit failed".into(),
                )
                .await;
            return Err(internal(error));
        }
        let completed_at = self
            .store
            .complete_remote_mutation(request_id, &digest, true, summary.clone())
            .await
            .map_err(store_error)?;
        Ok(RemoteMutationResult {
            connection_id: connection_id.to_string(),
            request_id: request_id.to_string(),
            operation: operation.into(),
            applied: true,
            replayed: false,
            completed_at: format_timestamp(completed_at)?,
            summary,
            ..Default::default()
        })
    }

    pub(crate) async fn revoke_connection(
        &self,
        expected_connection_id: Uuid,
        request: RevokeFleetConnectionRequest,
    ) -> Result<FleetConnectionState, ConnectError> {
        let connection_id = required_uuid(&request.connection_id, "connection_id")?;
        required_uuid(&request.request_id, "request_id")?;
        safe_remote_reason(&request.reason)?;
        if connection_id != expected_connection_id {
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
        Ok(FleetConnectionState {
            connection_id: revoked.connection_id.to_string(),
            realm_id: revoked.realm_id,
            revoked: true,
            revoked_at: format_optional_timestamp(revoked.revoked_at)?,
            ..Default::default()
        })
    }

    pub(crate) async fn rotate_connection_credential(
        &self,
        expected_connection_id: Uuid,
        request: RotateFleetCredentialRequest,
    ) -> Result<PairingGrant, ConnectError> {
        let connection_id = required_uuid(&request.connection_id, "connection_id")?;
        let request_id = required_uuid(&request.request_id, "request_id")?;
        let reason = safe_remote_reason(&request.reason)?;
        let credential = safe_secret(&request.new_credential, 32, 128)?;
        if !credential.expose_secret().starts_with("rfg_") {
            return Err(invalid("new Fleet credential is invalid"));
        }
        let expected_hint = credential
            .expose_secret()
            .chars()
            .rev()
            .take(6)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();
        if request.new_credential_hint != expected_hint {
            return Err(invalid("new Fleet credential hint is invalid"));
        }
        if connection_id != expected_connection_id {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "realm grant is bound to another connection",
            ));
        }
        self.store
            .append_event_with_data(
                "fleet.credential_rotation.requested",
                None,
                serde_json::json!({
                    "connectionId": connection_id,
                    "requestId": request_id,
                    "reason": reason,
                }),
            )
            .await
            .map_err(internal)?;
        let grant = self
            .store
            .rotate_realm_fleet_grant(
                connection_id,
                request_id,
                credential.expose_secret(),
                &expected_hint,
            )
            .await
            .map_err(store_error)?;
        Ok(PairingGrant {
            connection_id: grant.connection_id.to_string(),
            realm_id: grant.realm_id,
            credential: String::new(),
            credential_hint: grant.credential_hint,
            granted_scopes: grant.granted_scopes,
            created_at: format_timestamp(grant.created_at)?,
            expires_at: format_timestamp(grant.expires_at)?,
            assignment_epoch: grant.assignment_epoch,
            control_plane_instance_id: grant.control_plane_instance_id,
            ..Default::default()
        })
    }

    async fn apply_remote_mutation(
        &self,
        operation: RemoteMutationOperation,
        target_id: &str,
        secondary_id: &str,
        enabled: bool,
    ) -> anyhow::Result<String> {
        match operation {
            RemoteMutationOperation::RevokeUserPasskey => {
                self.store
                    .revoke_passkey(Uuid::parse_str(target_id)?, secondary_id)
                    .await?;
                Ok("user passkey revoked and its sessions invalidated".into())
            }
            RemoteMutationOperation::SetServiceAccountEnabled => {
                let id = Uuid::parse_str(target_id)?;
                let account = self
                    .store
                    .service_account(id)
                    .await?
                    .ok_or(StorePolicyError::ServiceAccountMissing)?;
                self.store
                    .update_service_account(
                        id,
                        account.name,
                        account.description,
                        if enabled {
                            ServiceAccountStatusRecord::Active
                        } else {
                            ServiceAccountStatusRecord::Disabled
                        },
                        account.scopes,
                    )
                    .await?;
                Ok(if enabled {
                    "service account enabled"
                } else {
                    "service account disabled"
                }
                .into())
            }
            RemoteMutationOperation::RevokeServiceAccountCredential => {
                self.store
                    .revoke_service_credential(
                        Uuid::parse_str(target_id)?,
                        Uuid::parse_str(secondary_id)?,
                    )
                    .await?;
                Ok("service-account credential revoked".into())
            }
            RemoteMutationOperation::PauseWebhook => {
                let mut webhook = self
                    .store
                    .webhook(target_id)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("webhook is missing"))?;
                if webhook.management_source == WebhookManagementSourceRecord::Configuration {
                    anyhow::bail!("configuration-managed webhook cannot be changed remotely");
                }
                webhook.status = WebhookStatusRecord::Paused;
                webhook.updated_at = now();
                self.store
                    .put_webhook(&webhook, "webhook.paused.remotely")
                    .await?;
                Ok("webhook paused".into())
            }
            RemoteMutationOperation::DeleteWebhook => {
                let webhook = self
                    .store
                    .webhook(target_id)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("webhook is missing"))?;
                if webhook.management_source == WebhookManagementSourceRecord::Configuration {
                    anyhow::bail!("configuration-managed webhook cannot be deleted remotely");
                }
                self.store.remove_webhook(target_id).await?;
                Ok("webhook deleted".into())
            }
            RemoteMutationOperation::Unspecified => {
                anyhow::bail!("remote mutation operation is required")
            }
        }
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

fn safe_remote_reason(value: &str) -> Result<String, ConnectError> {
    let value = value.trim();
    if !(10..=500).contains(&value.len()) || value.chars().any(char::is_control) {
        return Err(invalid(
            "remote mutation reason must contain 10-500 safe characters",
        ));
    }
    Ok(value.to_owned())
}

fn safe_remote_target(
    value: &str,
    _field: &'static str,
    maximum: usize,
) -> Result<String, ConnectError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > maximum
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(invalid("remote mutation target is invalid"));
    }
    Ok(value.to_owned())
}

fn safe_optional_remote_target(value: &str, maximum: usize) -> Result<String, ConnectError> {
    if value.trim().is_empty() {
        return Ok(String::new());
    }
    safe_remote_target(value, "secondary_id", maximum)
}

fn remote_mutation_expiry(value: &str) -> Result<u64, ConnectError> {
    let value = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| invalid("remote mutation expiry must be an RFC 3339 timestamp"))?;
    let value = u64::try_from(value.unix_timestamp())
        .map_err(|_| invalid("remote mutation expiry is invalid"))?;
    let current = now();
    if value <= current || value > current.saturating_add(5 * 60) {
        return Err(invalid(
            "remote mutation expiry must be in the next five minutes",
        ));
    }
    Ok(value)
}

fn validate_remote_mutation_shape(
    operation: RemoteMutationOperation,
    target_id: &str,
    secondary_id: &str,
) -> Result<(), ConnectError> {
    match operation {
        RemoteMutationOperation::RevokeUserPasskey => {
            required_uuid(target_id, "target_id")?;
            if secondary_id.is_empty() {
                return Err(invalid("passkey credential id is required"));
            }
        }
        RemoteMutationOperation::SetServiceAccountEnabled => {
            required_uuid(target_id, "target_id")?;
            if !secondary_id.is_empty() {
                return Err(invalid("secondary_id is not allowed for this operation"));
            }
        }
        RemoteMutationOperation::RevokeServiceAccountCredential => {
            required_uuid(target_id, "target_id")?;
            required_uuid(secondary_id, "secondary_id")?;
        }
        RemoteMutationOperation::PauseWebhook | RemoteMutationOperation::DeleteWebhook => {
            if target_id.len() > 64
                || !target_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(invalid("webhook target id is invalid"));
            }
            if !secondary_id.is_empty() {
                return Err(invalid("secondary_id is not allowed for this operation"));
            }
        }
        RemoteMutationOperation::Unspecified => {
            return Err(invalid("remote mutation operation is required"));
        }
    }
    Ok(())
}

fn remote_mutation_digest(
    connection_id: Uuid,
    operation: RemoteMutationOperation,
    target_id: &str,
    secondary_id: &str,
    enabled: bool,
    reason: &str,
    expires_at: u64,
) -> String {
    let canonical = serde_json::to_vec(&serde_json::json!({
        "connectionId": connection_id,
        "operation": operation as i32,
        "targetId": target_id,
        "secondaryId": secondary_id,
        "enabled": enabled,
        "reason": reason,
        "expiresAt": expires_at,
    }))
    .expect("remote mutation digest input is serializable");
    hex::encode(Sha256::digest(canonical))
}

const fn remote_mutation_name(operation: RemoteMutationOperation) -> &'static str {
    match operation {
        RemoteMutationOperation::Unspecified => "unspecified",
        RemoteMutationOperation::RevokeUserPasskey => "revoke_user_passkey",
        RemoteMutationOperation::SetServiceAccountEnabled => "set_service_account_enabled",
        RemoteMutationOperation::RevokeServiceAccountCredential => {
            "revoke_service_account_credential"
        }
        RemoteMutationOperation::PauseWebhook => "pause_webhook",
        RemoteMutationOperation::DeleteWebhook => "delete_webhook",
    }
}

fn required_uuid(value: &str, _field: &'static str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(value).map_err(|_| invalid("request id is invalid"))
}

fn bounded_page_size(
    value: u32,
    maximum: usize,
    _field: &'static str,
) -> Result<usize, ConnectError> {
    match value {
        0 => Ok(25),
        value if value as usize <= maximum => Ok(value as usize),
        _ => Err(invalid("page size exceeds the operational snapshot limit")),
    }
}

fn encode_uuid_page_token(value: Uuid) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

fn decode_uuid_page_token(value: &str, _field: &'static str) -> Result<Option<Uuid>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid("page token is invalid"))?;
    Uuid::from_slice(&bytes)
        .map(Some)
        .map_err(|_| invalid("page token is invalid"))
}

fn encode_text_page_token(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

fn decode_text_page_token(
    value: &str,
    _field: &'static str,
) -> Result<Option<String>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 128 {
        return Err(invalid("page token is invalid"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid("page token is invalid"))?;
    let decoded = String::from_utf8(bytes).map_err(|_| invalid("page token is invalid"))?;
    if decoded.is_empty()
        || decoded.len() > 64
        || !decoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid("page token is invalid"));
    }
    Ok(Some(decoded))
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
            StorePolicyError::RemoteMutationIdempotencyConflict => ConnectError::new(
                ErrorCode::AlreadyExists,
                "remote mutation request id is already bound to another operation",
            ),
            StorePolicyError::RemoteMutationPending => ConnectError::new(
                ErrorCode::FailedPrecondition,
                "remote mutation outcome is pending manual reconciliation",
            ),
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
        assert_eq!(
            safe_scopes(&[]).unwrap(),
            vec!["realm.read", "telemetry.export"]
        );
        assert_eq!(
            safe_scopes(&["realm.read".into(), "realm.read".into()]).unwrap(),
            vec!["realm.read"]
        );
        assert!(safe_scopes(&["database.direct".into()]).is_err());
    }

    #[test]
    fn remote_mutations_are_expiring_typed_and_request_bound() {
        let user_id = Uuid::new_v4().to_string();
        assert!(
            validate_remote_mutation_shape(
                RemoteMutationOperation::RevokeUserPasskey,
                &user_id,
                "credential-id",
            )
            .is_ok()
        );
        assert!(
            validate_remote_mutation_shape(
                RemoteMutationOperation::RevokeUserPasskey,
                &user_id,
                "",
            )
            .is_err()
        );
        assert!(
            validate_remote_mutation_shape(
                RemoteMutationOperation::DeleteWebhook,
                "webhook_01",
                "unexpected",
            )
            .is_err()
        );
        assert!(
            remote_mutation_expiry(&format_timestamp(now().saturating_add(60)).unwrap()).is_ok()
        );
        assert!(remote_mutation_expiry(&format_timestamp(now()).unwrap()).is_err());
        assert!(
            remote_mutation_expiry(&format_timestamp(now().saturating_add(600)).unwrap()).is_err()
        );

        let connection_id = Uuid::new_v4();
        let expires_at = now() + 60;
        let first = remote_mutation_digest(
            connection_id,
            RemoteMutationOperation::PauseWebhook,
            "webhook_01",
            "",
            false,
            "Incident containment",
            expires_at,
        );
        let retargeted = remote_mutation_digest(
            connection_id,
            RemoteMutationOperation::DeleteWebhook,
            "webhook_01",
            "",
            false,
            "Incident containment",
            expires_at,
        );
        assert_ne!(first, retargeted);
    }
}

#[cfg(test)]
mod live_tests {
    use std::{env, sync::Arc};

    use super::*;
    use crate::{
        config::{KeyRing, SigningRotationConfig},
        jwt::JwtIssuer,
        proto::rustyauth::management::v1::{
            RealmManagementServiceClient, RealmManagementServiceServer,
        },
        store::{
            EncryptedWebhookSecret, RealmFleetGrantRecord, WebhookManagementSourceRecord,
            WebhookRecord,
        },
    };
    use anyhow::{Context, Result};
    use connectrpc::{
        ConnectRpcService, Protocol,
        client::{ClientConfig, HttpClient},
    };

    #[tokio::test]
    #[ignore = "requires the compose.integration.yaml SableDB service"]
    async fn remote_management_rpc_is_dual_bound_and_restart_safe() -> Result<()> {
        let database_url = env::var("RUSTYAUTH_TEST_SOURCE_SABLEDB_URL")
            .context("RUSTYAUTH_TEST_SOURCE_SABLEDB_URL is missing")?;
        let client = redis::Client::open(database_url)?;
        let redis = redis::aio::ConnectionManager::new(client).await?;
        let mut database = redis.clone();
        redis::cmd("FLUSHDB")
            .arg("ASYNC")
            .query_async::<()>(&mut database)
            .await?;

        let realm_id = "remote-management-qualification";
        let store = Store::new(redis.clone(), realm_id.into());
        let connection_id = Uuid::new_v4();
        let credential = "rfg_remote-management-qualification-secret";
        let credential_digest = URL_SAFE_NO_PAD.encode(Sha256::digest(credential.as_bytes()));
        let grant = RealmFleetGrantRecord {
            connection_id,
            realm_id: realm_id.into(),
            control_plane_origin: "https://fleet.example.com".into(),
            control_plane_instance_id: "qualification-fleet".into(),
            assignment_epoch: 1,
            credential_digest: credential_digest.clone(),
            credential_hint: "secret".into(),
            granted_scopes: vec!["realm.read".into(), "realm.support".into()],
            created_at: now(),
            expires_at: now().saturating_add(3_600),
            revoked_at: None,
        };
        let _: () = redis::pipe()
            .atomic()
            .set(
                format!("auth:fleet-grant:{connection_id}"),
                serde_json::to_string(&grant)?,
            )
            .set(
                format!("auth:fleet-grant-secret:{credential_digest}"),
                connection_id.to_string(),
            )
            .query_async(&mut database)
            .await?;

        let webhook_id = "webhook_remote_qualification";
        store
            .put_webhook(
                &WebhookRecord {
                    id: webhook_id.into(),
                    name: "Qualification webhook".into(),
                    url: "https://hooks.example.com/rustyauth".into(),
                    status: WebhookStatusRecord::Active,
                    event_types: vec!["authentication.completed".into()],
                    secret: EncryptedWebhookSecret {
                        wrapping_key_id: "qualification".into(),
                        nonce: "unused".into(),
                        ciphertext: "unused".into(),
                    },
                    secret_hint: "unused".into(),
                    management_source: WebhookManagementSourceRecord::Dashboard,
                    created_at: now(),
                    updated_at: now(),
                    last_delivery_at: None,
                },
                "webhook.created",
            )
            .await?;

        let master_keys = KeyRing::new("remote-management", [89; 32], Vec::new())?;
        let jwt = JwtIssuer::load_or_create(
            redis.clone(),
            master_keys,
            SigningRotationConfig {
                rotation_seconds: 2_592_000,
                prepublish_seconds: 600,
                overlap_seconds: 600,
                maintenance_seconds: 30,
            },
            store.snapshot_gate(),
            "https://realm.example.com".into(),
            "qualification".into(),
            realm_id.into(),
            300,
        )
        .await?;
        let authorizer = OperatorAuthorizer::new(
            store.clone(),
            "https://realm.example.com".into(),
            1_800,
            true,
            Vec::new(),
        );
        let service =
            ConnectRpcService::new(RealmManagementServiceServer::new(ManagementRpc::new(
                store.clone(),
                authorizer,
                ManagementRpcConfig {
                    environment: Environment::Development,
                    realm_id: realm_id.into(),
                    issuer: "https://realm.example.com".into(),
                    rp_id: "realm.example.com".into(),
                    rate_limiter: Arc::new(RateLimiter::new(1_024)),
                    jwt,
                    backup: None,
                },
            )));
        let app = axum::Router::new().fallback_service(service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let config = ClientConfig::new(endpoint.parse()?)
            .with_protocol(Protocol::Connect)
            .with_default_header(header::AUTHORIZATION, format!("Bearer {credential}"));
        let client = RealmManagementServiceClient::new(HttpClient::plaintext(), config);
        let request_id = Uuid::new_v4();
        let request = RemoteMutationRequest {
            connection_id: connection_id.to_string(),
            request_id: request_id.to_string(),
            reason: "Contain a failing production integration".into(),
            expires_at: format_timestamp(now().saturating_add(60))?,
            operation: RemoteMutationOperation::PauseWebhook.into(),
            target_id: webhook_id.into(),
            ..Default::default()
        };
        let first = client
            .execute_remote_mutation(request.clone())
            .await?
            .into_owned();
        assert!(first.applied);
        assert!(!first.replayed);
        assert_eq!(
            store.webhook(webhook_id).await?.map(|value| value.status),
            Some(WebhookStatusRecord::Paused)
        );

        // A fresh client models a control-plane retry after process state is
        // lost. The durable receipt returns the original outcome without
        // applying or auditing the side effect a second time.
        let replay_client = RealmManagementServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(endpoint.parse()?)
                .with_protocol(Protocol::Connect)
                .with_default_header(header::AUTHORIZATION, format!("Bearer {credential}")),
        );
        let replay = replay_client
            .execute_remote_mutation(request.clone())
            .await?
            .into_owned();
        assert!(!replay.applied);
        assert!(replay.replayed);
        assert_eq!(replay.completed_at, first.completed_at);

        let mut retargeted = request;
        retargeted.operation = RemoteMutationOperation::DeleteWebhook.into();
        assert!(
            replay_client
                .execute_remote_mutation(retargeted)
                .await
                .is_err()
        );
        assert!(store.webhook(webhook_id).await?.is_some());

        server.abort();
        redis::cmd("FLUSHDB")
            .arg("ASYNC")
            .query_async::<()>(&mut database)
            .await?;
        Ok(())
    }
}
