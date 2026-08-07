//! Composition and authentication for RustyAuth's private RPC services.

use std::sync::Arc;

use connectrpc::interceptor::{StreamRequest, StreamResponse, UnaryRequest, UnaryResponse};
use connectrpc::{
    ConnectError, ConnectRpcService, ErrorCode, Interceptor, Limits, Next, NextStream,
    PayloadStream,
};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    event_rpc::EventRpc,
    identity_rpc::IdentityRpc,
    jwt::JwtIssuer,
    operator_auth::{OperatorAuthorizer, OperatorCapability},
    organization_rpc::OrganizationRpc,
    service_account_rpc::ServiceAccountRpc,
    store::Store,
};

const EVENT_SERVICE_PREFIX: &str = "/rustyauth.events.v1.AuthEventService/";
const IDENTITY_SERVICE_PREFIX: &str = "/rustyauth.identity.v1.IdentityService/";
const ORGANIZATION_SERVICE_PREFIX: &str = "/rustyauth.organization.v1.OrganizationService/";
const SERVICE_ACCOUNT_SERVICE_PREFIX: &str =
    "/rustyauth.service_accounts.v1.ServiceAccountService/";

pub(crate) type RpcService = ConnectRpcService<connectrpc::Router>;

pub(crate) fn service(
    store: Store,
    event_token: &SecretString,
    identity_token: &SecretString,
    rp_origin: &str,
    session_idle_seconds: u64,
    operator_emails: Vec<String>,
    jwt: JwtIssuer,
) -> RpcService {
    let authorizer = OperatorAuthorizer::new(
        store.clone(),
        rp_origin.to_owned(),
        session_idle_seconds,
        operator_emails,
    );
    let router = connectrpc::Router::new()
        .add_service(Arc::new(EventRpc::new(store.clone())))
        .add_service(Arc::new(IdentityRpc::new(store.clone())))
        .add_service(Arc::new(OrganizationRpc::new(
            store.clone(),
            authorizer.clone(),
        )))
        .add_service(Arc::new(ServiceAccountRpc::new(
            store,
            authorizer.clone(),
            jwt,
        )));
    ConnectRpcService::new(router)
        .with_limits(
            Limits::default()
                .max_request_body_size(64 * 1024)
                .max_message_size(256 * 1024),
        )
        .with_interceptor(RpcAuth::with_operator(
            event_token,
            identity_token,
            authorizer,
        ))
}

#[derive(Clone)]
pub(crate) struct RpcAuth {
    event_digest: [u8; 32],
    identity_digest: [u8; 32],
    operator: Option<OperatorAuthorizer>,
}

impl RpcAuth {
    fn with_operator(
        event_token: &SecretString,
        identity_token: &SecretString,
        operator: OperatorAuthorizer,
    ) -> Self {
        Self {
            event_digest: token_digest(event_token.expose_secret()),
            identity_digest: token_digest(identity_token.expose_secret()),
            operator: Some(operator),
        }
    }

    #[cfg(test)]
    pub(crate) fn new(event_token: &SecretString, identity_token: &SecretString) -> Self {
        Self {
            event_digest: token_digest(event_token.expose_secret()),
            identity_digest: token_digest(identity_token.expose_secret()),
            operator: None,
        }
    }

    fn bearer_authorized(&self, path: Option<&str>, headers: &http::HeaderMap) -> bool {
        bearer_authorized(&self.event_digest, &self.identity_digest, path, headers)
    }

    async fn authorize_unary(
        &self,
        path: Option<&str>,
        headers: &http::HeaderMap,
    ) -> Result<(), ConnectError> {
        let Some(path) = path else {
            return Err(unauthenticated());
        };
        if path.starts_with(EVENT_SERVICE_PREFIX) {
            return self
                .bearer_authorized(Some(path), headers)
                .then_some(())
                .ok_or_else(unauthenticated);
        }
        if path.starts_with(IDENTITY_SERVICE_PREFIX) {
            if self.bearer_authorized(Some(path), headers) {
                return Ok(());
            }
            let capability = if path.ends_with("/GetUser") || path.ends_with("/SearchUsers") {
                OperatorCapability::Read
            } else {
                OperatorCapability::Support
            };
            self.operator_authorizer()?
                .authorize(headers, capability)
                .await?;
            return Ok(());
        }
        if path.starts_with(ORGANIZATION_SERVICE_PREFIX) {
            let capability = if path.ends_with("/UpdateOrganization") {
                OperatorCapability::Administer
            } else {
                OperatorCapability::Read
            };
            self.operator_authorizer()?
                .authorize(headers, capability)
                .await?;
            return Ok(());
        }
        if path.starts_with(SERVICE_ACCOUNT_SERVICE_PREFIX) {
            if path.ends_with("/ExchangeCredential") {
                return Ok(());
            }
            let capability =
                if path.ends_with("/ListServiceAccounts") || path.ends_with("/GetServiceAccount") {
                    OperatorCapability::Read
                } else {
                    OperatorCapability::Administer
                };
            self.operator_authorizer()?
                .authorize(headers, capability)
                .await?;
            return Ok(());
        }
        Err(unauthenticated())
    }

    fn operator_authorizer(&self) -> Result<&OperatorAuthorizer, ConnectError> {
        self.operator.as_ref().ok_or_else(unauthenticated)
    }

    fn authorize_streaming(
        &self,
        path: Option<&str>,
        headers: &http::HeaderMap,
    ) -> Result<(), ConnectError> {
        if self.bearer_authorized(path, headers) {
            Ok(())
        } else {
            Err(unauthenticated())
        }
    }
}

fn bearer_authorized(
    event_digest: &[u8; 32],
    identity_digest: &[u8; 32],
    path: Option<&str>,
    headers: &http::HeaderMap,
) -> bool {
    let expected = match path {
        Some(path) if path.starts_with(EVENT_SERVICE_PREFIX) => event_digest,
        Some(path) if path.starts_with(IDENTITY_SERVICE_PREFIX) => identity_digest,
        _ => return false,
    };
    let supplied = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    bool::from(expected.ct_eq(&token_digest(supplied)))
}

#[connectrpc::async_trait]
impl Interceptor for RpcAuth {
    async fn intercept_unary(
        &self,
        request: UnaryRequest,
        next: Next<'_>,
    ) -> Result<UnaryResponse, ConnectError> {
        self.authorize_unary(request.ctx.path(), request.ctx.headers())
            .await?;
        next.run(request).await
    }

    async fn intercept_streaming(
        &self,
        request: StreamRequest,
        inbound: PayloadStream,
        next: NextStream<'_>,
    ) -> Result<StreamResponse, ConnectError> {
        self.authorize_streaming(request.ctx.path(), request.ctx.headers())?;
        next.run(request, inbound).await
    }
}

fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn unauthenticated() -> ConnectError {
    ConnectError::new(ErrorCode::Unauthenticated, "authentication required")
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENT_TOKEN: &str = "event-rpc-test-token-longer-than-32-characters";
    const IDENTITY_TOKEN: &str = "identity-rpc-test-token-longer-than-32-characters";

    #[test]
    fn tokens_are_scoped_to_their_service_and_fail_closed() {
        let event_digest = token_digest(EVENT_TOKEN);
        let identity_digest = token_digest(IDENTITY_TOKEN);
        let mut headers = http::HeaderMap::new();
        assert!(!bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/rustyauth.identity.v1.IdentityService/GetUser"),
            &headers
        ));
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {EVENT_TOKEN}")).unwrap(),
        );
        assert!(bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/rustyauth.events.v1.AuthEventService/Subscribe"),
            &headers
        ));
        assert!(!bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/rustyauth.identity.v1.IdentityService/GetUser"),
            &headers
        ));
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {IDENTITY_TOKEN}")).unwrap(),
        );
        assert!(bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/rustyauth.identity.v1.IdentityService/GetUser"),
            &headers
        ));
        assert!(!bearer_authorized(
            &event_digest,
            &identity_digest,
            None,
            &headers
        ));
        assert!(!bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/unknown.Service/Method"),
            &headers
        ));
    }
}
