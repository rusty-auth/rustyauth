//! Connect handlers for service-account CRUD, credential issuance and
//! revocation, and the rate-limited anonymous credential-to-token exchange.

use std::sync::Arc;

use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use uuid::Uuid;

use crate::{
    operator_auth::{OperatorActor, OperatorCapability},
    proto::rustyauth::service_accounts::v1::{
        CreateCredentialRequest, CreateCredentialResponse, CreateServiceAccountRequest,
        ExchangeCredentialRequest, ExchangeCredentialResponse, GetServiceAccountRequest,
        ListServiceAccountsRequest, ListServiceAccountsResponse, RevokeCredentialRequest,
        RevokeCredentialResponse, ServiceAccount as ProtoServiceAccount, ServiceAccountService,
        UpdateServiceAccountRequest,
    },
    rate_limit::{RateLimitClass, RateLimiter},
};

use super::{
    errors::{invalid_argument, source_error},
    pagination::{decode_page_token, encode_page_token, page_size},
    ports::{OperatorGate, ServiceAccountSource, ServiceTokenIssuer},
    projection::{
        credential_to_proto, parse_optional_status, parse_required_status, service_account_to_proto,
    },
    validation::{
        optional_safe_text, parse_expiry, parse_id, safe_text, validated_scopes,
        validated_scopes_allow_empty,
    },
};

pub(crate) struct ServiceAccountRpc<S, A, J> {
    store: S,
    authorizer: A,
    jwt: J,
    exchange_limiter: Arc<RateLimiter>,
}

impl<S, A, J> ServiceAccountRpc<S, A, J> {
    pub(crate) fn new(store: S, authorizer: A, jwt: J, exchange_limiter: Arc<RateLimiter>) -> Self {
        Self {
            store,
            authorizer,
            jwt,
            exchange_limiter,
        }
    }
}

#[allow(refining_impl_trait)]
impl<S: ServiceAccountSource, A: OperatorGate, J: ServiceTokenIssuer> ServiceAccountService
    for ServiceAccountRpc<S, A, J>
{
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
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        let id = parse_id(request.service_account_id, "service_account_id")?;
        let name = safe_text(request.name, "name", 100)?;
        let description = optional_safe_text(request.description, "description", 500)?;
        let status = parse_required_status(request.status.to_i32())?;
        let scopes = validated_scopes(request.scopes.iter().copied())?;
        let reason = safe_text(request.reason, "reason", 240)?;
        let account = self
            .store
            .update_service_account(id, name, description, status, scopes)
            .await
            .map_err(source_error)?;
        record_privileged_mutation(&actor, "service_account.updated", id, None, Some(&reason));
        Response::ok(service_account_to_proto(account)?)
    }

    async fn create_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateCredentialRequest>,
    ) -> ServiceResult<CreateCredentialResponse> {
        let actor = self
            .authorizer
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
        record_privileged_mutation(
            &actor,
            "service_account.credential.created",
            id,
            Some(credential.id),
            None,
        );
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
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        let account_id = parse_id(request.service_account_id, "service_account_id")?;
        let credential_id = parse_id(request.credential_id, "credential_id")?;
        let reason = safe_text(request.reason, "reason", 240)?;
        self.store
            .revoke_service_credential(account_id, credential_id)
            .await
            .map_err(source_error)?;
        record_privileged_mutation(
            &actor,
            "service_account.credential.revoked",
            account_id,
            Some(credential_id),
            Some(&reason),
        );
        Response::ok(RevokeCredentialResponse::default())
    }

    async fn exchange_credential(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ExchangeCredentialRequest>,
    ) -> ServiceResult<ExchangeCredentialResponse> {
        let requested_scopes =
            validated_scopes_allow_empty(request.requested_scopes.iter().copied())?;
        // This is the only unauthenticated RPC, and the store call behind it takes
        // the process-wide mutation lock across a datastore round trip. Metering by
        // credential prefix bounds how much of that lock an anonymous flood can hold
        // without letting one noisy client lock out every other service account.
        let bucket = request.credential.get(..12).unwrap_or(request.credential);
        if !self
            .exchange_limiter
            .check(RateLimitClass::CredentialExchange, bucket)
            .await
            .allowed
        {
            record_exchange_outcome(&self.store, "service_account.token.denied", None).await;
            return Err(ConnectError::new(
                ErrorCode::ResourceExhausted,
                "too many credential exchange attempts",
            ));
        }
        let grant = match self
            .store
            .exchange_service_credential(request.credential, &requested_scopes)
            .await
        {
            Ok(grant) => grant,
            Err(error) => {
                let event_type = if matches!(
                    error.downcast_ref::<crate::store::StorePolicyError>(),
                    Some(crate::store::StorePolicyError::ServiceScopeDenied)
                ) {
                    "service_account.token.denied"
                } else {
                    "service_account.token.failed"
                };
                record_exchange_outcome(&self.store, event_type, None).await;
                return Err(source_error(error));
            }
        };
        let issued = match self
            .jwt
            .issue_service_account(grant.service_account_id, grant.scopes.clone())
        {
            Ok(issued) => issued,
            Err(error) => {
                record_exchange_outcome(
                    &self.store,
                    "service_account.token.failed",
                    Some(grant.service_account_id),
                )
                .await;
                return Err(source_error(error));
            }
        };
        record_exchange_outcome(
            &self.store,
            "service_account.token.issued",
            Some(grant.service_account_id),
        )
        .await;
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

async fn record_exchange_outcome<S: ServiceAccountSource>(
    store: &S,
    event_type: &'static str,
    service_account_id: Option<Uuid>,
) {
    if let Err(error) = store
        .record_token_exchange_outcome(event_type, service_account_id)
        .await
    {
        // Metrics are explicitly fail-open: an unavailable projector or event
        // sink must not change the credential exchange response.
        tracing::warn!(error = %error, event_type, "record service-account exchange failure");
    }
}

/// Attributes a privileged service-account mutation to the operator who made it.
///
/// The store's mutation APIs accept neither an actor nor a reason, so the audit
/// event they append cannot name who acted. This log line is the only record
/// tying a change that grants or withdraws machine access to a human.
fn record_privileged_mutation(
    actor: &OperatorActor,
    action: &'static str,
    service_account_id: Uuid,
    credential_id: Option<Uuid>,
    reason: Option<&str>,
) {
    let credential_id = credential_id.map(|id| id.to_string()).unwrap_or_default();
    tracing::info!(
        actor_id = %actor.user.id,
        actor_role = ?actor.operator.role,
        action,
        service_account_id = %service_account_id,
        credential_id,
        reason = reason.unwrap_or_default(),
        "service-account privileged mutation"
    );
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use anyhow::Result;
    use connectrpc::{
        ConnectRpcService, Protocol,
        client::{ClientConfig, HttpClient},
    };
    use http::HeaderMap;
    use tokio::sync::RwLock;

    use super::*;
    use crate::jwt::IssuedServiceAccountToken;
    use crate::proto::rustyauth::service_accounts::v1::{
        ServiceAccountServiceClient, ServiceAccountServiceServer,
    };
    use crate::rpc::RpcAuth;
    use crate::store::{
        ServiceAccountCredentialRecord, ServiceAccountGrant, ServiceAccountRecord,
        ServiceAccountStatusRecord, StorePolicyError, now,
    };

    const EVENT_TOKEN: &str = "event-rpc-test-token-longer-than-32-characters";
    const IDENTITY_TOKEN: &str = "identity-rpc-test-token-longer-than-32-characters";
    const ACCOUNT_SCOPES: [&str; 2] = ["identity.read", "metrics.read"];

    fn active_account_id() -> Uuid {
        Uuid::from_u128(0x0a11)
    }

    fn disabled_account_id() -> Uuid {
        Uuid::from_u128(0x0d15)
    }

    /// Mirrors the shape the store demands: `rsa_` plus 43 secret characters.
    fn secret(tag: char) -> String {
        format!("rsa_{}", tag.to_string().repeat(43))
    }

    fn credential(
        id: u128,
        expires_at: Option<u64>,
        revoked_at: Option<u64>,
    ) -> ServiceAccountCredentialRecord {
        ServiceAccountCredentialRecord {
            id: Uuid::from_u128(id),
            name: "deploy".into(),
            secret_hint: "aaaaaa".into(),
            created_at: 1_700_000_000,
            expires_at,
            last_used_at: None,
            revoked_at,
        }
    }

    #[derive(Clone)]
    struct MemoryServiceAccountSource {
        accounts: Arc<RwLock<Vec<ServiceAccountRecord>>>,
        secrets: Arc<RwLock<HashMap<String, (Uuid, Uuid)>>>,
    }

    impl ServiceAccountSource for MemoryServiceAccountSource {
        async fn service_account(&self, id: Uuid) -> Result<Option<ServiceAccountRecord>> {
            Ok(self
                .accounts
                .read()
                .await
                .iter()
                .find(|account| account.id == id)
                .cloned())
        }

        async fn service_accounts(&self) -> Result<Vec<ServiceAccountRecord>> {
            Ok(self.accounts.read().await.clone())
        }

        async fn create_service_account(
            &self,
            name: String,
            description: String,
            scopes: Vec<String>,
            created_by: Uuid,
        ) -> Result<ServiceAccountRecord> {
            let account = ServiceAccountRecord {
                id: Uuid::new_v4(),
                name,
                description,
                status: ServiceAccountStatusRecord::Active,
                scopes,
                credentials: Vec::new(),
                created_at: now(),
                created_by,
                last_used_at: None,
            };
            self.accounts.write().await.push(account.clone());
            Ok(account)
        }

        async fn update_service_account(
            &self,
            id: Uuid,
            name: String,
            description: String,
            status: ServiceAccountStatusRecord,
            scopes: Vec<String>,
        ) -> Result<ServiceAccountRecord> {
            let mut accounts = self.accounts.write().await;
            let account = accounts
                .iter_mut()
                .find(|account| account.id == id)
                .ok_or(StorePolicyError::ServiceAccountMissing)?;
            account.name = name;
            account.description = description;
            account.status = status;
            account.scopes = scopes;
            Ok(account.clone())
        }

        async fn create_service_credential(
            &self,
            service_account_id: Uuid,
            name: String,
            expires_at: Option<u64>,
        ) -> Result<(ServiceAccountCredentialRecord, String)> {
            let raw = secret('n');
            let record = ServiceAccountCredentialRecord {
                id: Uuid::new_v4(),
                name,
                secret_hint: "nnnnnn".into(),
                created_at: now(),
                expires_at,
                last_used_at: None,
                revoked_at: None,
            };
            let mut accounts = self.accounts.write().await;
            let account = accounts
                .iter_mut()
                .find(|account| account.id == service_account_id)
                .ok_or(StorePolicyError::ServiceAccountMissing)?;
            account.credentials.push(record.clone());
            self.secrets
                .write()
                .await
                .insert(raw.clone(), (service_account_id, record.id));
            Ok((record, raw))
        }

        async fn revoke_service_credential(
            &self,
            service_account_id: Uuid,
            credential_id: Uuid,
        ) -> Result<ServiceAccountCredentialRecord> {
            let mut accounts = self.accounts.write().await;
            let account = accounts
                .iter_mut()
                .find(|account| account.id == service_account_id)
                .ok_or(StorePolicyError::ServiceAccountMissing)?;
            let credential = account
                .credentials
                .iter_mut()
                .find(|credential| credential.id == credential_id)
                .ok_or(StorePolicyError::ServiceCredentialMissing)?;
            credential.revoked_at.get_or_insert_with(now);
            Ok(credential.clone())
        }

        /// Reproduces the store's denial order exactly so the handler is tested
        /// against the real set of rejection causes rather than a single one.
        async fn exchange_service_credential(
            &self,
            raw: &str,
            requested_scopes: &[String],
        ) -> Result<ServiceAccountGrant> {
            if raw.len() < 40 || raw.len() > 128 || !raw.starts_with("rsa_") {
                return Err(StorePolicyError::InvalidServiceCredential.into());
            }
            let (account_id, credential_id) = *self
                .secrets
                .read()
                .await
                .get(raw)
                .ok_or(StorePolicyError::InvalidServiceCredential)?;
            let mut accounts = self.accounts.write().await;
            let account = accounts
                .iter_mut()
                .find(|account| account.id == account_id)
                .ok_or(StorePolicyError::InvalidServiceCredential)?;
            if account.status != ServiceAccountStatusRecord::Active {
                return Err(StorePolicyError::InvalidServiceCredential.into());
            }
            let current = now();
            let credential = account
                .credentials
                .iter_mut()
                .find(|credential| credential.id == credential_id)
                .filter(|credential| {
                    credential.revoked_at.is_none()
                        && credential.expires_at.is_none_or(|expiry| expiry > current)
                })
                .ok_or(StorePolicyError::InvalidServiceCredential)?;
            if requested_scopes
                .iter()
                .any(|scope| !account.scopes.contains(scope))
            {
                return Err(StorePolicyError::ServiceScopeDenied.into());
            }
            credential.last_used_at = Some(current);
            account.last_used_at = Some(current);
            let scopes = if requested_scopes.is_empty() {
                account.scopes.clone()
            } else {
                requested_scopes.to_vec()
            };
            Ok(ServiceAccountGrant {
                service_account_id: account.id,
                scopes,
            })
        }

        async fn record_token_exchange_outcome(
            &self,
            _event_type: &'static str,
            _service_account_id: Option<Uuid>,
        ) -> Result<()> {
            Ok(())
        }
    }

    /// Encodes the granted scopes into the token so a test can prove the issued
    /// credential carries nothing the caller was not granted.
    struct MemoryTokenIssuer;

    impl ServiceTokenIssuer for MemoryTokenIssuer {
        fn issue_service_account(
            &self,
            service_account_id: Uuid,
            scopes: Vec<String>,
        ) -> Result<IssuedServiceAccountToken> {
            Ok(IssuedServiceAccountToken {
                token: format!("test.{service_account_id}.{}", scopes.join("+")),
                expires_in: 300,
            })
        }
    }

    struct DeniedOperatorGate;

    impl OperatorGate for DeniedOperatorGate {
        async fn authorize(
            &self,
            _headers: &HeaderMap,
            _capability: OperatorCapability,
        ) -> Result<OperatorActor, ConnectError> {
            Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "operator access denied",
            ))
        }
    }

    fn fixture() -> MemoryServiceAccountSource {
        let scopes = ACCOUNT_SCOPES.map(str::to_owned).to_vec();
        let active = ServiceAccountRecord {
            id: active_account_id(),
            name: "deploy-bot".into(),
            description: "ci".into(),
            status: ServiceAccountStatusRecord::Active,
            scopes: scopes.clone(),
            credentials: vec![
                credential(0xa1, None, None),
                credential(0xa2, None, Some(1_700_000_500)),
                credential(0xa3, Some(now().saturating_sub(3_600)), None),
            ],
            created_at: 1_700_000_000,
            created_by: Uuid::from_u128(0x0f00),
            last_used_at: None,
        };
        let disabled = ServiceAccountRecord {
            id: disabled_account_id(),
            name: "retired-bot".into(),
            description: String::new(),
            status: ServiceAccountStatusRecord::Disabled,
            scopes,
            credentials: vec![credential(0xd1, None, None)],
            created_at: 1_700_000_000,
            created_by: Uuid::from_u128(0x0f00),
            last_used_at: None,
        };
        let secrets = HashMap::from([
            (secret('a'), (active_account_id(), Uuid::from_u128(0xa1))),
            (secret('r'), (active_account_id(), Uuid::from_u128(0xa2))),
            (secret('e'), (active_account_id(), Uuid::from_u128(0xa3))),
            (secret('d'), (disabled_account_id(), Uuid::from_u128(0xd1))),
        ]);
        MemoryServiceAccountSource {
            accounts: Arc::new(RwLock::new(vec![active, disabled])),
            secrets: Arc::new(RwLock::new(secrets)),
        }
    }

    async fn spawn_test_service(
        source: MemoryServiceAccountSource,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let dispatcher = ServiceAccountServiceServer::new(ServiceAccountRpc::new(
            source,
            DeniedOperatorGate,
            MemoryTokenIssuer,
            Arc::new(RateLimiter::new(1024)),
        ));
        let service = ConnectRpcService::new(dispatcher).with_interceptor(RpcAuth::new(
            &secrecy::SecretString::from(EVENT_TOKEN),
            &secrecy::SecretString::from(IDENTITY_TOKEN),
        ));
        let app = axum::Router::new().fallback_service(service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind service-account RPC test server");
        let address = listener.local_addr().expect("service-account RPC address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve service-account RPC test server");
        });
        (format!("http://{address}"), server)
    }

    fn client(base_url: &str) -> ServiceAccountServiceClient<HttpClient> {
        let config = ClientConfig::new(base_url.parse().expect("valid service-account RPC URL"))
            .with_protocol(Protocol::Connect)
            .with_default_timeout(std::time::Duration::from_secs(2));
        ServiceAccountServiceClient::new(HttpClient::plaintext(), config)
    }

    fn exchange(credential: String, requested_scopes: &[&str]) -> ExchangeCredentialRequest {
        ExchangeCredentialRequest {
            credential,
            requested_scopes: requested_scopes
                .iter()
                .copied()
                .map(str::to_owned)
                .collect(),
            ..Default::default()
        }
    }

    /// ExchangeCredential is the only unauthenticated RPC. If a caller can tell
    /// "no such credential" from "revoked", "expired", "account disabled" or
    /// "scope not held", the endpoint confirms stolen secrets and enumerates an
    /// account's grant for an anonymous attacker.
    #[tokio::test]
    async fn credential_exchange_denials_are_indistinguishable() {
        let (base_url, server) = spawn_test_service(fixture()).await;
        let client = client(&base_url);
        let cases = [
            ("unknown credential", exchange(secret('u'), &[])),
            ("revoked credential", exchange(secret('r'), &[])),
            ("expired credential", exchange(secret('e'), &[])),
            ("disabled service account", exchange(secret('d'), &[])),
            (
                "secret below the minimum length",
                exchange("rsa_short".into(), &[]),
            ),
            (
                "secret without the credential prefix",
                exchange(secret('a').replacen("rsa_", "xxx_", 1), &[]),
            ),
        ];
        let mut denials = Vec::new();
        for (label, request) in cases {
            let error = client
                .exchange_credential(request)
                .await
                .err()
                .unwrap_or_else(|| panic!("{label} must be rejected"));
            assert_eq!(error.code, ErrorCode::Unauthenticated, "{label}");
            denials.push((label, error.message));
        }
        let expected = &denials[0].1;
        for (label, message) in &denials {
            assert_eq!(message, expected, "{label} must not be distinguishable");
        }

        // Scope denial is deliberately distinguishable. It is only reachable after
        // the secret has already authenticated, so it tells the caller nothing they
        // did not already know, and collapsing it into the authentication failure
        // would leave a correctly-configured integrator debugging blind.
        let scope_denial = client
            .exchange_credential(exchange(secret('a'), &["identity.write"]))
            .await
            .expect_err("an unheld scope must be refused");
        assert_eq!(scope_denial.code, ErrorCode::PermissionDenied);
        assert_ne!(
            scope_denial.message.as_ref(),
            Some(expected.as_ref().expect("denials carry a message")),
        );
        server.abort();
    }

    #[tokio::test]
    async fn credential_exchange_issues_only_the_granted_scopes() {
        let (base_url, server) = spawn_test_service(fixture()).await;
        let client = client(&base_url);
        let account = active_account_id();

        let full = client
            .exchange_credential(exchange(secret('a'), &[]))
            .await
            .expect("a valid credential must be accepted")
            .into_owned();
        assert_eq!(full.token_type, "Bearer");
        assert_eq!(full.expires_in_seconds, 300);
        assert_eq!(full.scopes, ACCOUNT_SCOPES);
        assert_eq!(
            full.access_token,
            format!("test.{account}.identity.read+metrics.read")
        );

        let narrowed = client
            .exchange_credential(exchange(secret('a'), &["metrics.read"]))
            .await
            .expect("narrowing the grant must be accepted")
            .into_owned();
        assert_eq!(narrowed.scopes, ["metrics.read"]);
        assert_eq!(
            narrowed.access_token,
            format!("test.{account}.metrics.read")
        );
        assert!(!narrowed.access_token.contains("identity.read"));
        server.abort();
    }
}
