//! Session token minting, sign-out and the session cookie contract.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::app_state::AppState;

use super::{
    error::ApiError,
    guard::{authenticated, require_origin},
};

const SESSION_COOKIE: &str = "passkey_auth_session";

pub(super) async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (raw, session, user) = authenticated(&state, &headers).await?;
    token_response(&state, &user, &session, raw, StatusCode::OK)
}

pub(super) async fn sign_out(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_origin(&state, &headers)?;
    if let Some(token) = session_cookie(&headers) {
        state
            .store
            .delete_session(token)
            .await
            .map_err(ApiError::internal)?;
    }
    let cookie = clear_cookie(&state);
    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]).into_response())
}

pub(super) fn token_response(
    state: &AppState,
    user: &crate::store::User,
    session: &crate::store::Session,
    session_token: &str,
    status: StatusCode,
) -> Result<Response, ApiError> {
    let mut body = state.jwt.issue(user, session).map_err(ApiError::internal)?;
    // Local development must not depend on an external email/SMS provider. Existing
    // local users created before this policy changed are treated as verified
    // in responses without mutating production data or weakening production.
    if !state.identity_verification_required {
        body.email_verified = body.email.is_some();
        body.phone_number_verified = body.phone_number.is_some();
    }
    let cookie = set_cookie(state, session_token);
    Ok((status, [(header::SET_COOKIE, cookie)], Json(body)).into_response())
}

pub(super) fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&format!("{SESSION_COOKIE}=")))
}

fn set_cookie(state: &AppState, token: &str) -> HeaderValue {
    set_cookie_with_lifetime(state.secure_cookie, token, state.session_absolute_seconds)
}

pub(super) fn set_cookie_with_lifetime(
    secure: bool,
    token: &str,
    lifetime_seconds: u64,
) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={lifetime_seconds}{secure}"
    ))
    .expect("session cookie contains only validated characters")
}

fn clear_cookie(state: &AppState) -> HeaderValue {
    set_cookie_with_lifetime(state.secure_cookie, "", 0)
}

#[cfg(test)]
mod tests {
    use super::set_cookie_with_lifetime;

    #[test]
    fn session_cookies_are_http_only_same_site_strict_and_secure_in_production() {
        let production = set_cookie_with_lifetime(true, "token-value", 900);
        let production = production.to_str().unwrap();
        assert!(production.starts_with("passkey_auth_session=token-value;"));
        assert!(production.contains("; HttpOnly"));
        // SameSite=Strict is the CSRF control for every cookie-authenticated route.
        assert!(production.contains("; SameSite=Strict"));
        assert!(production.contains("; Path=/"));
        assert!(production.contains("; Max-Age=900"));
        assert!(production.contains("; Secure"));

        // Development serves over plain HTTP on loopback, where Secure would stop
        // the browser storing the cookie at all.
        let development = set_cookie_with_lifetime(false, "token-value", 900);
        assert!(!development.to_str().unwrap().contains("Secure"));
    }
}
