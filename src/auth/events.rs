//! Bootstrap-scoped event export and email sign-in link requests.

use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};

use crate::{app_state::AppState, rate_limit::RateLimitClass};

use super::{
    dto::{EmailInput, EventsQuery},
    error::ApiError,
    guard::{require_bootstrap, require_origin, require_rate_limit},
    validate::canonical_email,
};

pub(super) async fn email_link(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<EmailInput>,
) -> Result<StatusCode, ApiError> {
    require_origin(&state, &headers)?;
    let email = canonical_email(&input.email)?;
    // Address-keyed only, for the same reason as authentication: an identifier
    // bucket here would let an attacker stop a specific person receiving a
    // sign-in link.
    require_rate_limit(
        &state,
        peer,
        &headers,
        RateLimitClass::IdentifierProbe,
        None,
    )?;
    let subject = state
        .store
        .user_by_email(&email)
        .await
        .map_err(ApiError::internal)?
        .map(|user| user.id);
    state
        .store
        .append_event("email.sign_in.requested", subject)
        .await
        .map_err(ApiError::internal)?;
    Ok(StatusCode::ACCEPTED)
}

pub(super) async fn events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<EventsQuery>,
) -> Result<Json<Value>, ApiError> {
    require_bootstrap(&state, &headers)?;
    let events = state
        .store
        .events(query.after.unwrap_or(0), 500)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "events": events })))
}
