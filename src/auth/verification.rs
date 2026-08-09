//! Self-service email and phone verification through explicitly subscribed,
//! signed delivery webhooks.

use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};

use crate::{app_state::AppState, rate_limit::RateLimitClass, store::IdentifierValue};

use super::{
    dto::{CompleteIdentifierVerificationInput, RequestIdentifierVerificationInput},
    error::ApiError,
    guard::{authenticated, require_rate_limit},
};

pub(super) async fn request_identifier_verification(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<RequestIdentifierVerificationInput>,
) -> Result<Json<Value>, ApiError> {
    let (_, _, user) = authenticated(&state, &headers).await?;
    let identifier = IdentifierValue::canonical(input.identifier.kind, &input.identifier.value)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    require_rate_limit(
        &state,
        peer,
        &headers,
        RateLimitClass::Verification,
        Some(&identifier.value),
    )
    .await?;
    let (challenge, raw_code) = state
        .store
        .create_identifier_verification(user.id, identifier.clone())
        .await
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let delivered = match &state.webhook_runtime {
        Some(runtime) => runtime
            .deliver_identifier_verification(
                challenge.id,
                &identifier,
                &raw_code,
                challenge.expires_at,
            )
            .await
            .map_err(ApiError::internal)?,
        None => 0,
    };
    if state.identity_verification_required && delivered == 0 {
        state
            .store
            .delete_identifier_verification(challenge.id)
            .await
            .map_err(ApiError::internal)?;
        return Err(ApiError::unavailable(
            "identifier verification delivery is unavailable",
        ));
    }
    Ok(Json(json!({
        "challengeId": challenge.id,
        "expiresAt": challenge.expires_at,
        "delivered": delivered > 0,
        "developmentCode": (!state.identity_verification_required).then_some(raw_code),
    })))
}

pub(super) async fn complete_identifier_verification(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<CompleteIdentifierVerificationInput>,
) -> Result<StatusCode, ApiError> {
    let (_, _, user) = authenticated(&state, &headers).await?;
    require_rate_limit(&state, peer, &headers, RateLimitClass::Verification, None).await?;
    let identifier = state
        .store
        .consume_identifier_verification(input.challenge_id, user.id, input.code.trim())
        .await
        .map_err(|_| ApiError::unauthorized("verification challenge is invalid or expired"))?;
    state
        .store
        .set_identifier_verification(user.id, &identifier, true)
        .await
        .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}
