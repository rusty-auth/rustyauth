//! Passkey authentication ceremonies for existing accounts.

use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    rate_limit::RateLimitClass,
    store::{AuthenticationCeremony, AuthenticationPurpose, IdentifierValue, SessionOrigin, now},
};

use super::{
    CEREMONY_SECONDS,
    dto::{AuthenticationVerifyInput, IdentifierLookupInput, IdentifierRequest},
    error::ApiError,
    guard::{require_origin, require_rate_limit},
    record_telemetry_event,
    session::token_response,
    validate::lookup_identifier_ref,
};

pub(super) async fn authentication_options(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<IdentifierLookupInput>,
) -> Result<Json<Value>, ApiError> {
    require_origin(&state, &headers)?;
    let identifier = lookup_identifier(input.identifier, input.email, input.phone)?;
    // Address-keyed only, deliberately. Keying this on the identifier would let
    // anyone who knows a victim's address spend that address's budget from
    // anywhere and lock the victim out of signing in — a denial of service handed
    // to an unauthenticated caller. Enumeration is the shape this needs to stop,
    // and enumeration is many identifiers from few addresses, which the address
    // bucket already bounds.
    require_rate_limit(
        &state,
        peer,
        &headers,
        RateLimitClass::IdentifierProbe,
        None,
    )
    .await?;
    let user = state
        .store
        .user_by_identifier(&identifier)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::unauthorized("passkey authentication is unavailable"))?;
    let passkeys = user
        .passkeys
        .iter()
        .map(|stored| stored.passkey.clone())
        .collect::<Vec<_>>();
    let (options, ceremony_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| ApiError::unauthorized("passkey authentication is unavailable"))?;
    let ceremony = AuthenticationCeremony {
        id: Uuid::new_v4(),
        user_id: user.id,
        purpose: AuthenticationPurpose::SignIn,
        initiating_session_id: None,
        expires_at: now().saturating_add(CEREMONY_SECONDS),
        state: ceremony_state,
    };
    state
        .store
        .save_authentication(&ceremony)
        .await
        .map_err(ApiError::internal)?;
    record_telemetry_event(
        &state.auth_telemetry,
        "authentication.options.started",
        Some(user.id),
        json!({ "flow": "passkey" }),
    );
    Ok(Json(
        json!({ "ceremonyId": ceremony.id, "options": options }),
    ))
}

pub(super) async fn authentication_verify(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<AuthenticationVerifyInput>,
) -> Result<Response, ApiError> {
    let started = std::time::Instant::now();
    require_origin(&state, &headers)?;
    require_rate_limit(&state, peer, &headers, RateLimitClass::Ceremony, None).await?;
    let ceremony = match state.store.take_authentication(input.ceremony_id).await {
        Ok(ceremony) => ceremony,
        Err(_) => {
            record_authentication_outcome(
                &state,
                None,
                "authentication.failed",
                "challengeExpired",
                started,
            );
            return Err(ApiError::unauthorized(
                "authentication ceremony is invalid or expired",
            ));
        }
    };
    if ceremony.purpose != AuthenticationPurpose::SignIn || ceremony.initiating_session_id.is_some()
    {
        record_authentication_outcome(
            &state,
            Some(ceremony.user_id),
            "authentication.denied",
            "policyDenied",
            started,
        );
        return Err(ApiError::unauthorized(
            "authentication ceremony is invalid or expired",
        ));
    }
    let result = match state
        .webauthn
        .finish_passkey_authentication(&input.response, &ceremony.state)
    {
        Ok(result) => result,
        Err(_) => {
            record_authentication_outcome(
                &state,
                Some(ceremony.user_id),
                "authentication.failed",
                "invalidCredential",
                started,
            );
            return Err(ApiError::unauthorized("passkey verification failed"));
        }
    };
    if !result.user_verified() {
        record_authentication_outcome(
            &state,
            Some(ceremony.user_id),
            "authentication.denied",
            "policyDenied",
            started,
        );
        return Err(ApiError::unauthorized("passkey did not verify the user"));
    }
    let user = state
        .store
        .apply_authentication(ceremony.user_id, &result)
        .await
        .map_err(|_| ApiError::unauthorized("passkey verification failed"))?;
    let current_credential_id = URL_SAFE_NO_PAD.encode(result.cred_id().as_ref());
    let (session_token, session) = state
        .store
        .create_session(
            &user,
            SessionOrigin::Passkey {
                credential_id: current_credential_id,
            },
            state.session_absolute_seconds,
        )
        .await
        .map_err(ApiError::internal)?;
    record_authentication_outcome(
        &state,
        Some(user.id),
        "authentication.completed",
        "success",
        started,
    );
    token_response(&state, &user, &session, &session_token, StatusCode::OK)
}

fn record_authentication_outcome(
    state: &AppState,
    subject: Option<Uuid>,
    event_type: &'static str,
    outcome_class: &'static str,
    started: std::time::Instant,
) {
    record_telemetry_event(
        &state.auth_telemetry,
        event_type,
        subject,
        json!({
            "flow": "passkey",
            "outcomeClass": outcome_class,
            "latencyMilliseconds": started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        }),
    );
}

fn lookup_identifier(
    identifier: Option<IdentifierRequest>,
    email: Option<String>,
    phone: Option<String>,
) -> Result<IdentifierValue, ApiError> {
    lookup_identifier_ref(identifier.as_ref(), email.as_deref(), phone.as_deref())
}
