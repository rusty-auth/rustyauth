//! Public HTTP authentication protocol.
//!
//! Handlers validate transport policy and translate domain failures into a
//! deliberately small public error surface. Durable mutations remain in
//! `store`; WebAuthn verification remains in the upstream library boundary.

mod account;
mod agent_handoff;
mod authentication;
mod credentials;
mod discovery;
mod dto;
mod error;
mod events;
mod guard;
mod registration;
mod session;
mod validate;

use axum::{
    Router,
    routing::{get, post},
};

use crate::app_state::AppState;

use self::{
    account::{account, add_identifier, remove_identifier, set_primary_identifier, update_profile},
    agent_handoff::local_agent_handoff,
    authentication::{authentication_options, authentication_verify},
    credentials::{
        add_registration_options, add_registration_verify, credentials, rename_credential,
        revoke_credential,
    },
    discovery::{discovery, jwks},
    events::{email_link, events},
    registration::{registration_options, registration_verify},
    session::{sign_out, token},
};

pub(crate) use self::session::session_cookie_name;

const CEREMONY_SECONDS: u64 = 300;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route(
            "/v1/passkeys/registration/options",
            post(registration_options),
        )
        .route(
            "/v1/passkeys/registration/verify",
            post(registration_verify),
        )
        .route(
            "/v1/passkeys/authentication/options",
            post(authentication_options),
        )
        .route(
            "/v1/passkeys/authentication/verify",
            post(authentication_verify),
        )
        .route("/v1/token", post(token))
        .route("/v1/sign-out", post(sign_out))
        .route("/v1/email-links", post(email_link))
        .route("/v1/account", get(account))
        .route("/v1/account/profile", post(update_profile))
        .route("/v1/account/identifiers", post(add_identifier))
        .route("/v1/account/identifiers/remove", post(remove_identifier))
        .route(
            "/v1/account/identifiers/primary",
            post(set_primary_identifier),
        )
        .route("/v1/local-agent-handoff", get(local_agent_handoff))
        .route("/v1/credentials", get(credentials))
        .route(
            "/v1/passkeys/registration/add/options",
            post(add_registration_options),
        )
        .route(
            "/v1/passkeys/registration/add/verify",
            post(add_registration_verify),
        )
        .route("/v1/credentials/rename", post(rename_credential))
        .route("/v1/credentials/revoke", post(revoke_credential))
        .route("/v1/events", get(events))
}
