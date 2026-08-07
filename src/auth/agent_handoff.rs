//! Development-only local agent handoff redemption.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::{app_state::AppState, rate_limit::RateLimitClass};

use super::{
    dto::LocalAgentHandoffQuery, error::ApiError, guard::require_rate_limit,
    session::set_cookie_with_lifetime,
};

pub(super) async fn local_agent_handoff(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<LocalAgentHandoffQuery>,
) -> Result<Response, ApiError> {
    if !state.local_agent_handoffs_enabled {
        return Err(ApiError::unauthorized("local agent handoff is disabled"));
    }
    require_rate_limit(&state, peer, &headers, RateLimitClass::Ceremony, None)?;
    let handoff = state
        .store
        .take_local_agent_handoff(&query.code)
        .await
        .map_err(|_| ApiError::unauthorized("agent handoff is invalid or expired"))?;
    let user = state
        .store
        .user(handoff.user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::unauthorized("agent handoff account no longer exists"))?;
    let (session_token, _) = state
        .store
        .create_session(&user, "agent", None, 3_600)
        .await
        .map_err(ApiError::internal)?;
    let location = HeaderValue::from_str(&handoff.redirect_url)
        .map_err(|_| ApiError::internal("stored handoff redirect is invalid"))?;
    Ok((
        StatusCode::SEE_OTHER,
        [
            (
                header::SET_COOKIE,
                set_cookie_with_lifetime(state.secure_cookie, &session_token, 3_600),
            ),
            (header::LOCATION, location),
        ],
    )
        .into_response())
}
