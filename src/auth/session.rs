//! Session token minting, sign-out and the session cookie contract.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    store::{AuthenticationCeremony, AuthenticationPurpose, SessionOrigin, now},
};

use super::{
    CEREMONY_SECONDS,
    dto::StepUpVerifyInput,
    error::ApiError,
    guard::{authenticated, require_origin, require_passkey_session, require_recent_passkey},
    record_telemetry_event,
};

const DEVELOPMENT_SESSION_COOKIE: &str = "passkey_auth_session";
const PRODUCTION_SESSION_COOKIE: &str = "__Host-Http-rustyauth_session";
const DEVICE_SESSION_SECONDS: u64 = 15 * 60;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceTokenResponse {
    token: String,
    expires_at: u64,
}

pub(super) async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (raw, session, user) = authenticated(&state, &headers).await?;
    record_telemetry_event(
        state.store.clone(),
        "token.user.issued",
        Some(user.id),
        json!({}),
    );
    token_response(&state, &user, &session, raw, StatusCode::OK)
}

pub(super) async fn sign_out(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(token) = device_session_bearer(&headers) {
        if headers.contains_key(header::ORIGIN) {
            return Err(ApiError::unauthorized(
                "device sessions are not accepted by browsers",
            ));
        }
        state
            .store
            .delete_session(token)
            .await
            .map_err(ApiError::internal)?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    require_origin(&state, &headers)?;
    if let Some(token) = session_cookie(&headers, state.secure_cookie) {
        state
            .store
            .delete_session(token)
            .await
            .map_err(ApiError::internal)?;
    }
    let cookie = clear_cookie(&state);
    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]).into_response())
}

pub(super) async fn revoke_all_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (_, session, user) = authenticated(&state, &headers).await?;
    require_recent_passkey(&session)?;
    state
        .store
        .revoke_all_sessions(user.id)
        .await
        .map_err(ApiError::internal)?;
    Ok((
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, clear_cookie(&state))],
    )
        .into_response())
}

/// Mints a one-time-returned, short-lived credential for the native console.
///
/// The browser has to prove the operator's passkey immediately before this
/// call. The resulting session stays bound to that credential and to the
/// account session version, so passkey revocation or "revoke all" ends it.
pub(super) async fn device_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (_, session, user) = authenticated(&state, &headers).await?;
    require_recent_passkey(&session)?;
    let credential_id = session
        .current_credential_id
        .ok_or_else(|| ApiError::unauthorized("a credential-bound passkey session is required"))?;
    let lifetime = DEVICE_SESSION_SECONDS.min(state.session_idle_seconds);
    let (token, device_session) = state
        .store
        .create_session(&user, SessionOrigin::Device { credential_id }, lifetime)
        .await
        .map_err(ApiError::internal)?;
    record_telemetry_event(
        state.store.clone(),
        "device_session.issued",
        Some(user.id),
        json!({ "expiresAt": device_session.absolute_expires_at }),
    );
    Ok((
        StatusCode::CREATED,
        [
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (header::PRAGMA, HeaderValue::from_static("no-cache")),
        ],
        Json(DeviceTokenResponse {
            token,
            expires_at: device_session.absolute_expires_at,
        }),
    )
        .into_response())
}

pub(super) async fn step_up_options(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (_, session, user) = authenticated(&state, &headers).await?;
    require_passkey_session(&session)?;
    let passkeys = user
        .passkeys
        .iter()
        .map(|stored| stored.passkey.clone())
        .collect::<Vec<_>>();
    let (options, ceremony_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|error| ApiError::internal(format!("start passkey step-up: {error}")))?;
    let ceremony = AuthenticationCeremony {
        id: Uuid::new_v4(),
        user_id: user.id,
        purpose: AuthenticationPurpose::StepUp,
        initiating_session_id: Some(session.id),
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

pub(super) async fn step_up_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<StepUpVerifyInput>,
) -> Result<StatusCode, ApiError> {
    let (raw, session, user) = authenticated(&state, &headers).await?;
    require_passkey_session(&session)?;
    let ceremony = state
        .store
        .take_authentication(input.ceremony_id)
        .await
        .map_err(|_| ApiError::unauthorized("step-up ceremony is invalid or expired"))?;
    if ceremony.purpose != AuthenticationPurpose::StepUp
        || ceremony.user_id != user.id
        || ceremony.initiating_session_id != Some(session.id)
    {
        return Err(ApiError::unauthorized(
            "step-up ceremony is invalid or expired",
        ));
    }
    let result = state
        .webauthn
        .finish_passkey_authentication(&input.response, &ceremony.state)
        .map_err(|_| ApiError::unauthorized("passkey verification failed"))?;
    if !result.user_verified() {
        return Err(ApiError::unauthorized("passkey did not verify the user"));
    }
    state
        .store
        .apply_authentication(user.id, &result)
        .await
        .map_err(|_| ApiError::unauthorized("passkey verification failed"))?;
    state
        .store
        .mark_session_step_up(
            raw,
            session.id,
            URL_SAFE_NO_PAD.encode(result.cred_id().as_ref()),
        )
        .await
        .map_err(|_| ApiError::unauthorized("session is no longer active"))?;
    Ok(StatusCode::NO_CONTENT)
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

pub(super) fn session_cookie(headers: &HeaderMap, secure: bool) -> Option<&str> {
    let name = session_cookie_name(secure);
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&format!("{name}=")))
}

fn device_session_bearer(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer")
        && token.starts_with("rdt_")
        && token.len() >= 36
        && token.len() <= 256
        && !token.chars().any(char::is_whitespace))
    .then_some(token)
}

pub(crate) const fn session_cookie_name(secure: bool) -> &'static str {
    if secure {
        PRODUCTION_SESSION_COOKIE
    } else {
        DEVELOPMENT_SESSION_COOKIE
    }
}

fn set_cookie(state: &AppState, token: &str) -> HeaderValue {
    set_cookie_with_lifetime(state.secure_cookie, token, state.session_absolute_seconds)
}

pub(super) fn set_cookie_with_lifetime(
    secure: bool,
    token: &str,
    lifetime_seconds: u64,
) -> HeaderValue {
    let name = session_cookie_name(secure);
    let secure_attribute = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{name}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={lifetime_seconds}{secure_attribute}"
    ))
    .expect("session cookie contains only validated characters")
}

fn clear_cookie(state: &AppState) -> HeaderValue {
    set_cookie_with_lifetime(state.secure_cookie, "", 0)
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, header};

    use super::{device_session_bearer, set_cookie_with_lifetime};

    #[test]
    fn session_cookies_are_http_only_same_site_strict_and_secure_in_production() {
        let production = set_cookie_with_lifetime(true, "token-value", 900);
        let production = production.to_str().unwrap();
        assert!(production.starts_with("__Host-Http-rustyauth_session=token-value;"));
        assert!(production.contains("; HttpOnly"));
        // SameSite=Strict is the CSRF control for every cookie-authenticated route.
        assert!(production.contains("; SameSite=Strict"));
        assert!(production.contains("; Path=/"));
        assert!(production.contains("; Max-Age=900"));
        assert!(production.contains("; Secure"));

        // Development serves over plain HTTP on loopback, where Secure would stop
        // the browser storing the cookie at all.
        let development = set_cookie_with_lifetime(false, "token-value", 900);
        let development = development.to_str().unwrap();
        assert!(development.starts_with("passkey_auth_session=token-value;"));
        assert!(!development.contains("Secure"));
    }

    #[test]
    fn device_sign_out_accepts_only_the_native_token_namespace() {
        let token = format!("rdt_{}", "a".repeat(43));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("bearer {token}").parse().unwrap(),
        );
        assert_eq!(device_session_bearer(&headers), Some(token.as_str()));
        headers.insert(
            header::AUTHORIZATION,
            "Bearer service-account-token".parse().unwrap(),
        );
        assert_eq!(device_session_bearer(&headers), None);
    }
}
