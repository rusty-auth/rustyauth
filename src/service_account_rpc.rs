//! Scoped non-human principals and one-time service credentials.

use std::collections::BTreeSet;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    jwt::JwtIssuer,
    operator_auth::{OperatorAuthorizer, OperatorCapability},
    proto::rustyauth::service_accounts::v1::{
        CreateCredentialRequest, CreateCredentialResponse, CreateServiceAccountRequest,
        ExchangeCredentialRequest, ExchangeCredentialResponse, GetServiceAccountRequest,
        ListServiceAccountsRequest, ListServiceAccountsResponse, RevokeCredentialRequest,
        RevokeCredentialResponse, ServiceAccount as ProtoServiceAccount,
        ServiceAccountCredential as ProtoCredential, ServiceAccountService, ServiceAccountStatus,
        UpdateServiceAccountRequest,
    },
    store::{
        ServiceAccountCredentialRecord, ServiceAccountRecord, ServiceAccountStatusRecord, Store,
        StorePolicyError, now,
    },
};

const DEFAULT_PAGE_SIZE: usize = 25;
const MAX_PAGE_SIZE: usize = 100;
const ALLOWED_SCOPES: &[&str] = &[
    "events.read",
    "identity.read",
    "identity.write",
    "metrics.read",
    "webhooks.manage",
];

pub(crate) struct ServiceAccountRpc {
    store: Store,
    authorizer: OperatorAuthorizer,
    jwt: JwtIssuer,
}

impl ServiceAccountRpc {
    pub(crate) fn new(store: Store, authorizer: OperatorAuthorizer, jwt: JwtIssuer) -> Self {
        Self {
            store,
            authorizer,
            jwt,
        }
    }
}

#[allow(refining_impl_trait)]
impl ServiceAccountService for ServiceAccountRpc {
    async fn list_service_accounts(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListServiceAccountsRequest>,
    ) -> ServiceResult<ListServiceAccountsResponse> {
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Read)
            .await?;
        let after = decode_page_token(request.page_token)?;
        let page_size = page_size(request.page_size)?;
        let status = parse_optional_status(request.status.to_i32())?;
        let query = request.query.trim().to_ascii_lowercase();
        if query.chars().count() > 120 {
            return Err(invalid_argument("query must not exceed 120 characters"));
        }
        let mut accounts = self.store.service_accounts().await.map_err(source_error)?;
        accounts.retain(|account| {
            after.is_none_or(|after| account.id > after)
                && status.is_none_or(|status| account.status == status)
                && (query.is_empty()
                    || account.name.to_ascii_lowercase().contains(&query)
                    || account.description.to_ascii_lowercase().contains(&query))
        });
        let next_page_token =
            (accounts.len() > page_size).then(|| encode_page_token(accounts[page_size - 1].id));
        accounts.truncate(page_size);
        let service_accounts = accounts
            .into_iter()
            .map(service_account_to_proto)
            .collect::<Result<Vec<_>, _>>()?;
        Response::ok(ListServiceAccountsResponse {
            service_accounts,
            next_page_token: next_page_token.unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn get_service_account(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetServiceAccountRequest>,
    ) -> ServiceResult<ProtoServiceAccount> {
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Read)
            .await?;
        let id = parse_id(request.service_account_id, "service_account_id")?;
        let account = self
            .store
            .service_account(id)
            .await
            .map_err(source_error)?
            .ok_or_else(|| ConnectError::new(ErrorCode::NotFound, "service account not found"))?;
        Response::ok(service_account_to_proto(account)?)
    }

    async fn create_service_account(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateServiceAccountRequest>,
    ) -> ServiceResult<ProtoServiceAccount> {
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        let name = safe_text(request.name, "name", 100)?;
        let description = optional_safe_text(request.description, "description", 500)?;
        let scopes = validated_scopes(request.scopes.iter().copied())?;
        let account = self
            .store
            .create_service_account(name, description, scopes, actor.user.id)
            .await
            .map_err(source_error)?;
        Response::ok(service_account_to_proto(account)?)
    }

    async fn update_service_account(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateServiceAccountRequest>,
    ) -> ServiceResult<ProtoServiceAccount> {
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        let id = parse_id(request.service_account_id, "service_account_id")?;
        let name = safe_text(request.name, "name", 100)?;
        let description = optional_safe_text(request.description, "description", 500)?;
        let status = parse_required_status(request.status.to_i32())?;
        let scopes = validated_scopes(request.scopes.iter().copied())?;
        let _reason = safe_text(request.reason, "reason", 240)?;
        let account = self
            .store
            .update_service_account(id, name, description, status, scopes)
            .await
            .map_err(source_error)?;
        Response::ok(service_account_to_proto(account)?)
    }

    async fn create_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateCredentialRequest>,
    ) -> ServiceResult<CreateCredentialResponse> {
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        let id = parse_id(request.service_account_id, "service_account_id")?;
        let name = safe_text(request.name, "name", 100)?;
        let expires_at = parse_expiry(request.expires_at)?;
        let (credential, secret) = self
            .store
            .create_service_credential(id, name, expires_at)
            .await
            .map_err(source_error)?;
        Response::ok(CreateCredentialResponse {
            credential: buffa::MessageField::some(credential_to_proto(credential)?),
            secret,
            ..Default::default()
        })
    }

    async fn revoke_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeCredentialRequest>,
    ) -> ServiceResult<RevokeCredentialResponse> {
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        let account_id = parse_id(request.service_account_id, "service_account_id")?;
        let credential_id = parse_id(request.credential_id, "credential_id")?;
        let _reason = safe_text(request.reason, "reason", 240)?;
        self.store
            .revoke_service_credential(account_id, credential_id)
            .await
            .map_err(source_error)?;
        Response::ok(RevokeCredentialResponse::default())
    }

    async fn exchange_credential(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ExchangeCredentialRequest>,
    ) -> ServiceResult<ExchangeCredentialResponse> {
        let requested_scopes =
            validated_scopes_allow_empty(request.requested_scopes.iter().copied())?;
        let grant = self
            .store
            .exchange_service_credential(request.credential, &requested_scopes)
            .await
            .map_err(source_error)?;
        let issued = self
            .jwt
            .issue_service_account(grant.service_account_id, grant.scopes.clone())
            .map_err(source_error)?;
        let expires_in_seconds = u32::try_from(issued.expires_in)
            .map_err(|_| ConnectError::new(ErrorCode::Internal, "token lifetime is invalid"))?;
        Response::ok(ExchangeCredentialResponse {
            access_token: issued.token,
            token_type: "Bearer".into(),
            expires_in_seconds,
            scopes: grant.scopes,
            ..Default::default()
        })
    }
}

fn validated_scopes<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<Vec<String>, ConnectError> {
    let scopes = validated_scopes_allow_empty(values)?;
    if scopes.is_empty() {
        return Err(invalid_argument("at least one scope is required"));
    }
    Ok(scopes)
}

fn validated_scopes_allow_empty<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<Vec<String>, ConnectError> {
    let mut scopes = BTreeSet::new();
    for value in values {
        if !ALLOWED_SCOPES.contains(&value) {
            return Err(invalid_argument("unsupported service-account scope"));
        }
        scopes.insert(value.to_owned());
    }
    if scopes.len() > ALLOWED_SCOPES.len() {
        return Err(invalid_argument("too many service-account scopes"));
    }
    Ok(scopes.into_iter().collect())
}

fn parse_optional_status(value: i32) -> Result<Option<ServiceAccountStatusRecord>, ConnectError> {
    match value {
        value if value == ServiceAccountStatus::Unspecified as i32 => Ok(None),
        value if value == ServiceAccountStatus::Active as i32 => {
            Ok(Some(ServiceAccountStatusRecord::Active))
        }
        value if value == ServiceAccountStatus::Disabled as i32 => {
            Ok(Some(ServiceAccountStatusRecord::Disabled))
        }
        _ => Err(invalid_argument("invalid service-account status")),
    }
}

fn parse_required_status(value: i32) -> Result<ServiceAccountStatusRecord, ConnectError> {
    parse_optional_status(value)?
        .ok_or_else(|| invalid_argument("service-account status is required"))
}

fn parse_expiry(value: &str) -> Result<Option<u64>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    let expiry = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| invalid_argument("expires_at must be an RFC3339 timestamp"))?;
    let expiry = u64::try_from(expiry.unix_timestamp())
        .map_err(|_| invalid_argument("expires_at must be after the Unix epoch"))?;
    if expiry <= now().saturating_add(60) {
        return Err(invalid_argument(
            "expires_at must be at least one minute in the future",
        ));
    }
    Ok(Some(expiry))
}

fn safe_text(value: &str, field: &'static str, maximum: usize) -> Result<String, ConnectError> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > maximum
        || value.chars().any(crate::store::forbidden_display_character)
    {
        return Err(invalid_argument(format!(
            "{field} must contain 1-{maximum} safe characters"
        )));
    }
    Ok(value.to_owned())
}

fn optional_safe_text(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<String, ConnectError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    safe_text(value, field, maximum)
}

fn parse_id(value: &str, field: &'static str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(value).map_err(|_| invalid_argument(format!("{field} must be a UUID")))
}

fn page_size(value: u32) -> Result<usize, ConnectError> {
    match value {
        0 => Ok(DEFAULT_PAGE_SIZE),
        value if value as usize <= MAX_PAGE_SIZE => Ok(value as usize),
        _ => Err(invalid_argument(format!(
            "page_size must not exceed {MAX_PAGE_SIZE}"
        ))),
    }
}

fn service_account_to_proto(
    account: ServiceAccountRecord,
) -> Result<ProtoServiceAccount, ConnectError> {
    let credentials = account
        .credentials
        .into_iter()
        .map(credential_to_proto)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ProtoServiceAccount {
        id: account.id.to_string(),
        name: account.name,
        description: account.description,
        status: match account.status {
            ServiceAccountStatusRecord::Active => ServiceAccountStatus::Active.into(),
            ServiceAccountStatusRecord::Disabled => ServiceAccountStatus::Disabled.into(),
        },
        scopes: account.scopes,
        credentials,
        created_at: format_timestamp(account.created_at)?,
        created_by: account.created_by.to_string(),
        last_used_at: account
            .last_used_at
            .map(format_timestamp)
            .transpose()?
            .unwrap_or_default(),
        ..Default::default()
    })
}

fn credential_to_proto(
    credential: ServiceAccountCredentialRecord,
) -> Result<ProtoCredential, ConnectError> {
    Ok(ProtoCredential {
        id: credential.id.to_string(),
        name: credential.name,
        secret_hint: credential.secret_hint,
        created_at: format_timestamp(credential.created_at)?,
        expires_at: credential
            .expires_at
            .map(format_timestamp)
            .transpose()?
            .unwrap_or_default(),
        last_used_at: credential
            .last_used_at
            .map(format_timestamp)
            .transpose()?
            .unwrap_or_default(),
        revoked_at: credential
            .revoked_at
            .map(format_timestamp)
            .transpose()?
            .unwrap_or_default(),
        ..Default::default()
    })
}

fn format_timestamp(value: u64) -> Result<String, ConnectError> {
    let value = i64::try_from(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "stored timestamp is invalid"))?;
    OffsetDateTime::from_unix_timestamp(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "stored timestamp is invalid"))?
        .format(&Rfc3339)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "format service-account timestamp"))
}

fn encode_page_token(value: Uuid) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

fn decode_page_token(value: &str) -> Result<Option<Uuid>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid_argument("invalid page_token"))?;
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| invalid_argument("invalid page_token"))?;
    Ok(Some(Uuid::from_bytes(bytes)))
}

fn source_error(error: anyhow::Error) -> ConnectError {
    if let Some(policy) = error.downcast_ref::<StorePolicyError>() {
        return match policy {
            StorePolicyError::ServiceAccountMissing
            | StorePolicyError::ServiceCredentialMissing => {
                ConnectError::new(ErrorCode::NotFound, policy.to_string())
            }
            StorePolicyError::InvalidServiceCredential => {
                ConnectError::new(ErrorCode::Unauthenticated, "service credential is invalid")
            }
            StorePolicyError::ServiceScopeDenied => {
                ConnectError::new(ErrorCode::PermissionDenied, policy.to_string())
            }
            _ => ConnectError::new(ErrorCode::FailedPrecondition, policy.to_string()),
        };
    }
    tracing::error!(error = %error, "service-account RPC failed");
    ConnectError::new(ErrorCode::Internal, "service-account operation failed")
}

fn invalid_argument(message: impl Into<String>) -> ConnectError {
    ConnectError::new(ErrorCode::InvalidArgument, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_allowlisted_sorted_and_unique() {
        assert_eq!(
            validated_scopes(["metrics.read", "identity.read", "metrics.read"].into_iter())
                .unwrap(),
            vec!["identity.read", "metrics.read"]
        );
        assert!(validated_scopes(["root"].into_iter()).is_err());
        assert!(validated_scopes(std::iter::empty()).is_err());
    }

    #[test]
    fn service_account_page_tokens_round_trip() {
        let id = Uuid::new_v4();
        assert_eq!(decode_page_token(&encode_page_token(id)).unwrap(), Some(id));
    }
}
