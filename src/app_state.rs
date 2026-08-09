//! Shared application dependencies and runtime policy.
//!
//! `AppState` contains initialized capabilities, not request data. Keeping this
//! composition root explicit makes handler dependencies reviewable and avoids
//! hidden global state in authentication code.

use std::sync::Arc;

use secrecy::SecretString;
use webauthn_rs::Webauthn;

use crate::{
    backup::BackupStore, config::DeploymentRole, jwt::JwtIssuer, rate_limit::RateLimiter,
    store::Store, webhook::WebhookRuntime,
};

#[derive(Clone)]
pub struct AppState {
    pub rate_limiter: Arc<RateLimiter>,
    /// Reverse proxies in front of this service, for resolving the client address.
    pub trusted_proxy_hops: usize,
    pub store: Store,
    pub webauthn: Arc<Webauthn>,
    pub jwt: JwtIssuer,
    pub issuer: String,
    pub deployment_role: DeploymentRole,
    pub rp_origin: String,
    pub bootstrap_token: SecretString,
    pub session_idle_seconds: u64,
    pub session_absolute_seconds: u64,
    pub secure_cookie: bool,
    pub identity_verification_required: bool,
    pub local_agent_handoffs_enabled: bool,
    pub backup: Option<BackupStore>,
    pub webhook_runtime: Option<WebhookRuntime>,
}
