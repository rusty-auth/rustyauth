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
mod recovery;
mod registration;
mod session;
mod validate;
mod verification;

use axum::{
    Router,
    routing::{get, post},
};
use serde_json::Value;
use tokio::sync::mpsc;
use uuid::Uuid;

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
    recovery::{recovery_options, recovery_verify, rotate_recovery_codes},
    registration::{registration_options, registration_verify},
    session::{
        device_token, revoke_all_sessions, sign_out, step_up_options, step_up_verify, token,
    },
    verification::{complete_identifier_verification, request_identifier_verification},
};

pub(crate) use self::session::session_cookie_name;

const CEREMONY_SECONDS: u64 = 300;
const AUTH_TELEMETRY_QUEUE_CAPACITY: usize = 8_192;
const AUTH_TELEMETRY_BATCH_SIZE: usize = 256;
const AUTH_TELEMETRY_BATCH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

struct QueuedTelemetryEvent {
    event_type: &'static str,
    subject: Option<Uuid>,
    data: Value,
}

#[derive(Clone)]
pub struct AuthTelemetry {
    sender: mpsc::Sender<QueuedTelemetryEvent>,
}

impl AuthTelemetry {
    pub fn new(store: crate::store::Store) -> Self {
        let (sender, mut receiver) =
            mpsc::channel::<QueuedTelemetryEvent>(AUTH_TELEMETRY_QUEUE_CAPACITY);
        tokio::spawn(async move {
            while let Some(first) = receiver.recv().await {
                let mut queued = Vec::with_capacity(AUTH_TELEMETRY_BATCH_SIZE);
                queued.push(first);
                // The records are explicitly response-path telemetry, not part
                // of the authorization decision. Holding the first event for a
                // bounded 100 ms lets a busy realm commit many observations in
                // one atomic RocksDB write instead of one transaction per token
                // response. This also prevents the fail-open queue from shedding
                // valid observations during a sustained workload.
                tokio::time::sleep(AUTH_TELEMETRY_BATCH_INTERVAL).await;
                while queued.len() < AUTH_TELEMETRY_BATCH_SIZE {
                    match receiver.try_recv() {
                        Ok(event) => queued.push(event),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
                let batch = queued
                    .into_iter()
                    .map(|event| (event.event_type.to_owned(), event.subject, event.data))
                    .collect();
                if let Err(error) = store.append_telemetry_events(batch).await {
                    tracing::warn!(error = %error, "persist authentication telemetry batch");
                }
            }
        });
        Self { sender }
    }

    fn record(&self, event_type: &'static str, subject: Option<Uuid>, data: Value) {
        if let Err(error) = self.sender.try_send(QueuedTelemetryEvent {
            event_type,
            subject,
            data,
        }) {
            tracing::warn!(%error, event_type, "authentication telemetry queue is full");
        }
    }
}

fn record_telemetry_event(
    telemetry: &AuthTelemetry,
    event_type: &'static str,
    subject: Option<Uuid>,
    data: Value,
) {
    telemetry.record(event_type, subject, data);
}

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
        .route("/v1/device-tokens", post(device_token))
        .route("/v1/sign-out", post(sign_out))
        .route("/v1/sessions/revoke-all", post(revoke_all_sessions))
        .route("/v1/passkeys/step-up/options", post(step_up_options))
        .route("/v1/passkeys/step-up/verify", post(step_up_verify))
        .route("/v1/passkeys/recovery/options", post(recovery_options))
        .route("/v1/passkeys/recovery/verify", post(recovery_verify))
        .route("/v1/account/recovery-codes", post(rotate_recovery_codes))
        .route(
            "/v1/account/identifiers/verification/request",
            post(request_identifier_verification),
        )
        .route(
            "/v1/account/identifiers/verification/verify",
            post(complete_identifier_verification),
        )
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
