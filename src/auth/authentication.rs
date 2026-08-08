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
    store::{AuthenticationCeremony, IdentifierValue, SessionOrigin, now},
};

use super::{
    CEREMONY_SECONDS,
    dto::{AuthenticationVerifyInput, IdentifierLookupInput, IdentifierRequest},
    error::ApiError,
    guard::{require_origin, require_rate_limit},
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
    )?;
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
        expires_at: now().saturating_add(CEREMONY_SECONDS),
        state: ceremony_state,
    };
    state
        .store
        .save_authentication(&ceremony)
        .await
        .map_err(ApiError::internal)?;
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
    require_origin(&state, &headers)?;
    require_rate_limit(&state, peer, &headers, RateLimitClass::Ceremony, None)?;
    let ceremony = state
        .store
        .take_authentication(input.ceremony_id)
        .await
        .map_err(|_| ApiError::unauthorized("authentication ceremony is invalid or expired"))?;
    let result = state
        .webauthn
        .finish_passkey_authentication(&input.response, &ceremony.state)
        .map_err(|_| ApiError::unauthorized("passkey verification failed"))?;
    if !result.user_verified() {
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
    token_response(&state, &user, &session, &session_token, StatusCode::OK)
}

fn lookup_identifier(
    identifier: Option<IdentifierRequest>,
    email: Option<String>,
    phone: Option<String>,
) -> Result<IdentifierValue, ApiError> {
    lookup_identifier_ref(identifier.as_ref(), email.as_deref(), phone.as_deref())
}
