//! Public HTTP authentication protocol.
//!
//! Handlers validate transport policy and translate domain failures into a
//! deliberately small public error surface. Durable mutations remain in
//! `store`; WebAuthn verification remains in the upstream library boundary.

mod dto;
mod error;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    store::{AuthenticationCeremony, RegistrationCeremony, StorePolicyError, now},
};

use self::{
    dto::{
        AddRegistrationOptionsInput, AuthenticationVerifyInput, CredentialOutput, EmailInput,
        EventsQuery, LocalAgentHandoffQuery, RegistrationVerifyInput, RenameCredentialInput,
        RevokeCredentialInput,
    },
    error::ApiError,
};

const CEREMONY_SECONDS: u64 = 300;
const SESSION_COOKIE: &str = "passkey_auth_session";

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

async fn discovery(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "issuer": state.issuer,
        "jwks_uri": format!("{}/.well-known/jwks.json", state.issuer),
        "token_endpoint": format!("{}/v1/token", state.issuer),
        "id_token_signing_alg_values_supported": ["ES256"],
        "subject_types_supported": ["public"]
    }))
}

async fn jwks(State(state): State<AppState>) -> Json<Value> {
    Json(state.jwt.jwks())
}

async fn registration_options(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<EmailInput>,
) -> Result<Json<Value>, ApiError> {
    require_origin(&state, &headers)?;
    require_bootstrap(&state, &headers)?;
    let email = canonical_email(&input.email)?;
    if state
        .store
        .user_by_email(&email)
        .await
        .map_err(ApiError::internal)?
        .is_some()
    {
        return Err(ApiError::conflict("email already has an account"));
    }
    let user_id = Uuid::new_v4();
    let (options, ceremony_state) = state
        .webauthn
        .start_passkey_registration(user_id, &email, &email, None)
        .map_err(|error| ApiError::internal(format!("start passkey registration: {error}")))?;
    let ceremony = RegistrationCeremony {
        id: Uuid::new_v4(),
        user_id,
        email,
        label: None,
        expires_at: now() + CEREMONY_SECONDS,
        state: ceremony_state,
    };
    state
        .store
        .save_registration(&ceremony)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(
        json!({ "ceremonyId": ceremony.id, "options": options }),
    ))
}

async fn registration_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RegistrationVerifyInput>,
) -> Result<Response, ApiError> {
    require_origin(&state, &headers)?;
    require_bootstrap(&state, &headers)?;
    let ceremony = state
        .store
        .take_registration(input.ceremony_id)
        .await
        .map_err(|_| ApiError::unauthorized("registration ceremony is invalid or expired"))?;
    let passkey = state
        .webauthn
        .finish_passkey_registration(&input.response, &ceremony.state)
        .map_err(|_| ApiError::unauthorized("passkey verification failed"))?;
    let current_credential_id = URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());
    let user = state
        .store
        .create_user_with_passkey(
            ceremony.user_id,
            ceremony.email,
            passkey,
            !state.email_verification_required,
        )
        .await
        .map_err(|error| match error.downcast_ref::<StorePolicyError>() {
            Some(
                StorePolicyError::EmailAlreadyExists | StorePolicyError::CredentialAlreadyExists,
            ) => ApiError::conflict(error.to_string()),
            _ => ApiError::internal(error),
        })?;
    let (session_token, session) = state
        .store
        .create_session(
            &user,
            "passkey",
            Some(current_credential_id),
            state.session_absolute_seconds,
        )
        .await
        .map_err(ApiError::internal)?;
    token_response(&state, &user, &session, &session_token, StatusCode::CREATED)
}

async fn authentication_options(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<EmailInput>,
) -> Result<Json<Value>, ApiError> {
    require_origin(&state, &headers)?;
    let email = canonical_email(&input.email)?;
    let user = state
        .store
        .user_by_email(&email)
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
        expires_at: now() + CEREMONY_SECONDS,
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

async fn authentication_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<AuthenticationVerifyInput>,
) -> Result<Response, ApiError> {
    require_origin(&state, &headers)?;
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
            "passkey",
            Some(current_credential_id),
            state.session_absolute_seconds,
        )
        .await
        .map_err(ApiError::internal)?;
    token_response(&state, &user, &session, &session_token, StatusCode::OK)
}

async fn token(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let (raw, session, user) = authenticated(&state, &headers).await?;
    token_response(&state, &user, &session, raw, StatusCode::OK)
}

async fn credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (_, session, user) = authenticated(&state, &headers).await?;
    let credentials = user
        .passkeys
        .into_iter()
        .map(|passkey| CredentialOutput {
            current: session.current_credential_id.as_deref() == Some(passkey.id.as_str()),
            id: passkey.id,
            label: passkey.label,
            created_at: timestamp(passkey.created_at),
            last_used_at: passkey.last_used_at.map(timestamp).unwrap_or_default(),
            authenticator: "Passkey",
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({ "credentials": credentials })))
}

async fn local_agent_handoff(
    State(state): State<AppState>,
    Query(query): Query<LocalAgentHandoffQuery>,
) -> Result<Response, ApiError> {
    if !state.local_agent_handoffs_enabled {
        return Err(ApiError::unauthorized("local agent handoff is disabled"));
    }
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
                set_cookie_with_lifetime(&state, &session_token, 3_600),
            ),
            (header::LOCATION, location),
        ],
    )
        .into_response())
}

async fn add_registration_options(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<AddRegistrationOptionsInput>,
) -> Result<Json<Value>, ApiError> {
    let (_, _, user) = authenticated(&state, &headers).await?;
    let label = credential_label(&input.label)?;
    let (options, ceremony_state) = state
        .webauthn
        .start_passkey_registration(user.id, &user.email, &user.email, None)
        .map_err(|error| ApiError::internal(format!("start passkey registration: {error}")))?;
    let ceremony = RegistrationCeremony {
        id: Uuid::new_v4(),
        user_id: user.id,
        email: user.email,
        label: Some(label),
        expires_at: now() + CEREMONY_SECONDS,
        state: ceremony_state,
    };
    state
        .store
        .save_registration(&ceremony)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(
        json!({ "ceremonyId": ceremony.id, "options": options }),
    ))
}

async fn add_registration_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RegistrationVerifyInput>,
) -> Result<StatusCode, ApiError> {
    let (_, _, user) = authenticated(&state, &headers).await?;
    let ceremony = state
        .store
        .take_registration(input.ceremony_id)
        .await
        .map_err(|_| ApiError::unauthorized("registration ceremony is invalid or expired"))?;
    if ceremony.user_id != user.id {
        return Err(ApiError::unauthorized(
            "registration ceremony belongs to another account",
        ));
    }
    let passkey = state
        .webauthn
        .finish_passkey_registration(&input.response, &ceremony.state)
        .map_err(|_| ApiError::unauthorized("passkey verification failed"))?;
    state
        .store
        .add_passkey(
            user.id,
            ceremony.label.unwrap_or_else(|| "Passkey".into()),
            passkey,
        )
        .await
        .map_err(|error| match error.downcast_ref::<StorePolicyError>() {
            Some(StorePolicyError::CredentialAlreadyExists) => {
                ApiError::conflict("passkey is already registered")
            }
            _ => ApiError::internal(error),
        })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn rename_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RenameCredentialInput>,
) -> Result<StatusCode, ApiError> {
    let (_, _, user) = authenticated(&state, &headers).await?;
    let credential_id = credential_id(&input.credential_id)?;
    let label = credential_label(&input.label)?;
    state
        .store
        .rename_passkey(user.id, credential_id, label)
        .await
        .map_err(|error| match error.downcast_ref::<StorePolicyError>() {
            Some(StorePolicyError::CredentialNotLinked) => {
                ApiError::bad_request("passkey is not linked to this account")
            }
            _ => ApiError::internal(error),
        })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RevokeCredentialInput>,
) -> Result<StatusCode, ApiError> {
    let (_, session, user) = authenticated(&state, &headers).await?;
    if now().saturating_sub(session.created_at) > CEREMONY_SECONDS {
        return Err(ApiError::unauthorized(
            "confirm with a passkey before removing a credential",
        ));
    }
    let credential_id = credential_id(&input.credential_id)?;
    state
        .store
        .revoke_passkey(user.id, credential_id)
        .await
        .map_err(|error| match error.downcast_ref::<StorePolicyError>() {
            Some(StorePolicyError::FinalCredential) => {
                ApiError::conflict("the final passkey cannot be removed")
            }
            Some(StorePolicyError::CredentialNotLinked) => {
                ApiError::bad_request("passkey is not linked to this account")
            }
            _ => ApiError::internal(error),
        })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn sign_out(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
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

async fn email_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<EmailInput>,
) -> Result<StatusCode, ApiError> {
    require_origin(&state, &headers)?;
    let email = canonical_email(&input.email)?;
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

async fn events(
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

fn token_response(
    state: &AppState,
    user: &crate::store::User,
    session: &crate::store::Session,
    session_token: &str,
    status: StatusCode,
) -> Result<Response, ApiError> {
    let mut body = state.jwt.issue(user, session).map_err(ApiError::internal)?;
    // Local development must not depend on an external mail provider. Existing
    // local users created before this policy changed are treated as verified
    // in responses without mutating production data or weakening production.
    if !state.email_verification_required {
        body.email_verified = true;
    }
    let cookie = set_cookie(state, session_token);
    Ok((status, [(header::SET_COOKIE, cookie)], Json(body)).into_response())
}

fn require_origin(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let expected = state.rp_origin.trim_end_matches('/');
    let actual = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if actual != Some(expected) {
        return Err(ApiError::unauthorized("request origin is not allowed"));
    }
    Ok(())
}

fn require_bootstrap(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let actual = headers
        .get("x-bootstrap-token")
        .and_then(|value| value.to_str().ok());
    if actual != Some(state.bootstrap_token.expose_secret()) {
        return Err(ApiError::unauthorized("enrolment is not authorized"));
    }
    Ok(())
}

fn canonical_email(value: &str) -> Result<String, ApiError> {
    let email = value.trim().to_ascii_lowercase();
    if email.len() > 320 || !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
        return Err(ApiError::bad_request("valid email required"));
    }
    Ok(email)
}

fn credential_label(value: &str) -> Result<String, ApiError> {
    let label = value.trim();
    if label.is_empty() || label.len() > 80 || label.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "passkey label must be between 1 and 80 characters",
        ));
    }
    Ok(label.to_string())
}

fn credential_id(value: &str) -> Result<&str, ApiError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 1024
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApiError::bad_request("invalid passkey id"));
    }
    Ok(value)
}

fn timestamp(value: u64) -> String {
    OffsetDateTime::from_unix_timestamp(value as i64)
        .ok()
        .and_then(|value| value.format(&Rfc3339).ok())
        .unwrap_or_default()
}

async fn authenticated<'a>(
    state: &AppState,
    headers: &'a HeaderMap,
) -> Result<(&'a str, crate::store::Session, crate::store::User), ApiError> {
    require_origin(state, headers)?;
    let raw =
        session_cookie(headers).ok_or_else(|| ApiError::unauthorized("authentication required"))?;
    let (session, user) = state
        .store
        .session(raw, state.session_idle_seconds)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::unauthorized("authentication required"))?;
    Ok((raw, session, user))
}

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&format!("{SESSION_COOKIE}=")))
}

fn set_cookie(state: &AppState, token: &str) -> HeaderValue {
    set_cookie_with_lifetime(state, token, state.session_absolute_seconds)
}

fn set_cookie_with_lifetime(state: &AppState, token: &str, lifetime_seconds: u64) -> HeaderValue {
    let secure = if state.secure_cookie { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        lifetime_seconds, secure
    ))
    .expect("session cookie contains only validated characters")
}

fn clear_cookie(state: &AppState) -> HeaderValue {
    let secure = if state.secure_cookie { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}"
    ))
    .expect("static cookie header is valid")
}

#[cfg(test)]
mod tests {
    use super::{credential_id, credential_label, timestamp};

    #[test]
    fn credential_labels_are_trimmed_and_bounded() {
        assert_eq!(credential_label("  MacBook  ").unwrap(), "MacBook");
        assert!(credential_label("").is_err());
        assert!(credential_label(&"x".repeat(81)).is_err());
        assert!(credential_label("bad\nlabel").is_err());
    }

    #[test]
    fn credential_ids_accept_only_base64url_characters() {
        assert_eq!(credential_id("abc_-123").unwrap(), "abc_-123");
        assert!(credential_id("").is_err());
        assert!(credential_id("has space").is_err());
        assert!(credential_id("slash/not-base64url").is_err());
    }

    #[test]
    fn credential_dates_are_rfc3339() {
        assert_eq!(timestamp(0), "1970-01-01T00:00:00Z");
    }
}
