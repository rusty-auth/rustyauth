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

use crate::{event_rpc::EventRpc, identity_rpc::IdentityRpc, store::Store};

const EVENT_SERVICE_PREFIX: &str = "/rustyauth.events.v1.AuthEventService/";
const IDENTITY_SERVICE_PREFIX: &str = "/rustyauth.identity.v1.IdentityService/";

pub(crate) type RpcService = ConnectRpcService<connectrpc::Router>;

pub(crate) fn service(
    store: Store,
    event_token: &SecretString,
    identity_token: &SecretString,
) -> RpcService {
    let router = connectrpc::Router::new()
        .add_service(Arc::new(EventRpc::new(store.clone())))
        .add_service(Arc::new(IdentityRpc::new(store)));
    ConnectRpcService::new(router)
        .with_limits(
            Limits::default()
                .max_request_body_size(64 * 1024)
                .max_message_size(256 * 1024),
        )
        .with_interceptor(RpcAuth::new(event_token, identity_token))
}

#[derive(Clone)]
pub(crate) struct RpcAuth {
    event_digest: [u8; 32],
    identity_digest: [u8; 32],
}

impl RpcAuth {
    pub(crate) fn new(event_token: &SecretString, identity_token: &SecretString) -> Self {
        Self {
            event_digest: token_digest(event_token.expose_secret()),
            identity_digest: token_digest(identity_token.expose_secret()),
        }
    }

    fn authorize(&self, path: Option<&str>, headers: &http::HeaderMap) -> Result<(), ConnectError> {
        bearer_authorized(&self.event_digest, &self.identity_digest, path, headers)
            .then_some(())
            .ok_or_else(unauthenticated)
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
        self.authorize(request.ctx.path(), request.ctx.headers())?;
        next.run(request).await
    }

    async fn intercept_streaming(
        &self,
        request: StreamRequest,
        inbound: PayloadStream,
        next: NextStream<'_>,
    ) -> Result<StreamResponse, ConnectError> {
        self.authorize(request.ctx.path(), request.ctx.headers())?;
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
    fn bearer_tokens_are_scoped_to_their_service() {
        let event_digest = token_digest(EVENT_TOKEN);
        let identity_digest = token_digest(IDENTITY_TOKEN);
        let mut headers = http::HeaderMap::new();
        assert!(!bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/rustyauth.identity.v1.IdentityService/GetUser"),
            &headers,
        ));

        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {EVENT_TOKEN}")).unwrap(),
        );
        assert!(bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/rustyauth.events.v1.AuthEventService/Subscribe"),
            &headers,
        ));
        assert!(!bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/rustyauth.identity.v1.IdentityService/GetUser"),
            &headers,
        ));

        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {IDENTITY_TOKEN}")).unwrap(),
        );
        assert!(bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/rustyauth.identity.v1.IdentityService/GetUser"),
            &headers,
        ));
        assert!(!bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/rustyauth.events.v1.AuthEventService/Subscribe"),
            &headers,
        ));
    }
}
