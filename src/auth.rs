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

use std::collections::BTreeSet;

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
const TOKEN_TELEMETRY_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

enum QueuedTelemetryEvent {
    Event {
        event_type: &'static str,
        subject: Option<Uuid>,
        data: Value,
    },
    UserTokenIssued {
        subject: Uuid,
    },
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
            let mut queued = Vec::with_capacity(AUTH_TELEMETRY_BATCH_SIZE);
            let mut token_count = 0_u64;
            let mut token_subjects = BTreeSet::new();
            let mut event_flush = tokio::time::interval(AUTH_TELEMETRY_BATCH_INTERVAL);
            event_flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut token_flush = tokio::time::interval_at(
                tokio::time::Instant::now() + TOKEN_TELEMETRY_FLUSH_INTERVAL,
                TOKEN_TELEMETRY_FLUSH_INTERVAL,
            );
            token_flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    next = receiver.recv() => {
                        match next {
                            Some(QueuedTelemetryEvent::Event { event_type, subject, data }) => {
                                queued.push((event_type.to_owned(), subject, data));
                                if queued.len() >= AUTH_TELEMETRY_BATCH_SIZE {
                                    persist_auth_telemetry(&store, &mut queued).await;
                                }
                            }
                            Some(QueuedTelemetryEvent::UserTokenIssued { subject }) => {
                                token_count = token_count.saturating_add(1);
                                token_subjects.insert(subject);
                            }
                            None => {
                                persist_auth_telemetry(&store, &mut queued).await;
                                persist_token_telemetry(
                                    &store,
                                    &mut token_count,
                                    &mut token_subjects,
                                ).await;
                                break;
                            }
                        }
                    }
                    _ = event_flush.tick() => {
                        persist_auth_telemetry(&store, &mut queued).await;
                    }
                    _ = token_flush.tick() => {
                        persist_token_telemetry(
                            &store,
                            &mut token_count,
                            &mut token_subjects,
                        ).await;
                    }
                }
            }
        });
        Self { sender }
    }

    fn record(&self, event_type: &'static str, subject: Option<Uuid>, data: Value) {
        if let Err(error) = self.sender.try_send(QueuedTelemetryEvent::Event {
            event_type,
            subject,
            data,
        }) {
            tracing::warn!(%error, event_type, "authentication telemetry queue is full");
        }
    }

    fn record_user_token_issued(&self, subject: Uuid) {
        if let Err(error) = self
            .sender
            .try_send(QueuedTelemetryEvent::UserTokenIssued { subject })
        {
            tracing::warn!(%error, event_type = "token.user.issued", "authentication telemetry queue is full");
        }
    }
}

async fn persist_auth_telemetry(
    store: &crate::store::Store,
    queued: &mut Vec<(String, Option<Uuid>, Value)>,
) {
    if queued.is_empty() {
        return;
    }
    if let Err(error) = store.append_telemetry_events(queued.clone()).await {
        tracing::warn!(error = %error, "persist authentication telemetry batch");
    } else {
        queued.clear();
    }
}

async fn persist_token_telemetry(
    store: &crate::store::Store,
    token_count: &mut u64,
    token_subjects: &mut BTreeSet<Uuid>,
) {
    if *token_count == 0 {
        return;
    }
    let data = serde_json::json!({
        "count": *token_count,
        "subjectIds": token_subjects,
    });
    let batch = vec![("token.user.issued".to_owned(), None, data)];
    if let Err(error) = store.append_telemetry_events(batch).await {
        tracing::warn!(error = %error, "persist aggregated user-token telemetry");
    } else {
        *token_count = 0;
        token_subjects.clear();
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
