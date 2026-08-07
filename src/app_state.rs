//! Shared application dependencies and runtime policy.
//!
//! `AppState` contains initialized capabilities, not request data. Keeping this
//! composition root explicit makes handler dependencies reviewable and avoids
//! hidden global state in authentication code.

use std::sync::Arc;

use secrecy::SecretString;
use webauthn_rs::Webauthn;

use crate::{backup::BackupStore, jwt::JwtIssuer, store::Store};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) store: Store,
    pub(crate) webauthn: Arc<Webauthn>,
    pub(crate) jwt: JwtIssuer,
    pub(crate) issuer: String,
    pub(crate) rp_origin: String,
    pub(crate) bootstrap_token: SecretString,
    pub(crate) session_idle_seconds: u64,
    pub(crate) session_absolute_seconds: u64,
    pub(crate) secure_cookie: bool,
    pub(crate) identity_verification_required: bool,
    pub(crate) local_agent_handoffs_enabled: bool,
    pub(crate) backup: Option<BackupStore>,
}
