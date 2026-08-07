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
    store::{
        AccountProfile, AuthenticationCeremony, IdentifierKind, IdentifierValue,
        RegistrationCeremony, RegistrationPurpose, Session, StorePolicyError, User,
        forbidden_display_character, now,
    },
};

use self::{
    dto::{
        AddRegistrationOptionsInput, AuthenticationVerifyInput, ChangeIdentifierInput,
        CredentialOutput, EmailInput, EventsQuery, IdentifierLookupInput, IdentifierOutput,
        IdentifierRequest, LocalAgentHandoffQuery, RegistrationOptionsInput,
        RegistrationVerifyInput, RenameCredentialInput, RevokeCredentialInput, UpdateProfileInput,
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

async fn discovery(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "issuer": state.issuer,
        "jwks_uri": format!("{}/.well-known/jwks.json", state.issuer),
        "token_endpoint": format!("{}/v1/token", state.issuer),
        "id_token_signing_alg_values_supported": ["ES256"],
        "subject_types_supported": ["public"]
    }))
}

async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(
            header::CACHE_CONTROL,
            "public, max-age=300, must-revalidate",
        )],
        Json(state.jwt.jwks()),
    )
}

async fn registration_options(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RegistrationOptionsInput>,
) -> Result<Json<Value>, ApiError> {
    require_origin(&state, &headers)?;
    require_bootstrap(&state, &headers)?;
    let identifier = registration_identifier(&input)?;
    let profile = account_profile(input.given_name, input.family_name, input.display_name)?;
    if state
        .store
        .user_by_identifier(&identifier)
        .await
        .map_err(ApiError::internal)?
        .is_some()
    {
        return Err(ApiError::conflict("identifier already has an account"));
    }
    let user_id = Uuid::new_v4();
    let display_name = profile_display_name(&profile).unwrap_or_else(|| identifier.value.clone());
    let (options, ceremony_state) = state
        .webauthn
        .start_passkey_registration(user_id, &identifier.value, &display_name, None)
        .map_err(|error| ApiError::internal(format!("start passkey registration: {error}")))?;
    let ceremony = RegistrationCeremony {
        id: Uuid::new_v4(),
        user_id,
        email: if identifier.kind == IdentifierKind::Email {
            identifier.value.clone()
        } else {
            String::new()
        },
        identifier: Some(identifier),
        profile,
        purpose: RegistrationPurpose::Initial,
        initiating_session_id: None,
        label: None,
        expires_at: now().saturating_add(CEREMONY_SECONDS),
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
    if ceremony.purpose != RegistrationPurpose::Initial || ceremony.initiating_session_id.is_some()
    {
        return Err(ApiError::unauthorized(
            "registration ceremony is invalid or expired",
        ));
    }
    let passkey = state
        .webauthn
        .finish_passkey_registration(&input.response, &ceremony.state)
        .map_err(|_| ApiError::unauthorized("passkey verification failed"))?;
    let current_credential_id = URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());
    let identifier = ceremony
        .account_identifier()
        .ok_or_else(|| ApiError::internal("registration identifier is missing"))?;
    let user = state
        .store
        .create_user_with_passkey(
            ceremony.user_id,
            identifier,
            ceremony.profile,
            passkey,
            !state.identity_verification_required,
        )
        .await
        .map_err(|error| match error.downcast_ref::<StorePolicyError>() {
            Some(
                StorePolicyError::IdentifierAlreadyExists
                | StorePolicyError::CredentialAlreadyExists,
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
    Json(input): Json<IdentifierLookupInput>,
) -> Result<Json<Value>, ApiError> {
    require_origin(&state, &headers)?;
    let identifier = lookup_identifier(input.identifier, input.email, input.phone)?;
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

async fn account(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (_, _, user) = authenticated(&state, &headers).await?;
    Ok(Json(account_body(&user)))
}

async fn update_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<UpdateProfileInput>,
) -> Result<Json<Value>, ApiError> {
    let (_, session, user) = authenticated(&state, &headers).await?;
    require_passkey_session(&session)?;
    let profile = account_profile(input.given_name, input.family_name, input.display_name)?;
    let user = state
        .store
        .update_profile(user.id, profile)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(account_body(&user)))
}

async fn add_identifier(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ChangeIdentifierInput>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let (_, session, user) = authenticated(&state, &headers).await?;
    require_recent_passkey(&session)?;
    let identifier = canonical_identifier(input.kind, &input.value)?;
    let user = state
        .store
        .add_identifier(user.id, identifier, !state.identity_verification_required)
        .await
        .map_err(|error| match error.downcast_ref::<StorePolicyError>() {
            Some(StorePolicyError::IdentifierAlreadyExists) => {
                ApiError::conflict("identifier already has an account")
            }
            Some(StorePolicyError::IdentifierLimit) => {
                ApiError::conflict("account has reached the identifier limit")
            }
            _ => ApiError::internal(error),
        })?;
    Ok((StatusCode::CREATED, Json(account_body(&user))))
}

async fn remove_identifier(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ChangeIdentifierInput>,
) -> Result<Json<Value>, ApiError> {
    let (_, session, user) = authenticated(&state, &headers).await?;
    require_recent_passkey(&session)?;
    let identifier = canonical_identifier(input.kind, &input.value)?;
    let user = state
        .store
        .remove_identifier(user.id, &identifier)
        .await
        .map_err(|error| match error.downcast_ref::<StorePolicyError>() {
            Some(StorePolicyError::FinalIdentifier) => {
                ApiError::conflict("the final account identifier cannot be removed")
            }
            Some(StorePolicyError::IdentifierNotLinked) => {
                ApiError::bad_request("identifier is not linked to this account")
            }
            _ => ApiError::internal(error),
        })?;
    Ok(Json(account_body(&user)))
}

async fn set_primary_identifier(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ChangeIdentifierInput>,
) -> Result<Json<Value>, ApiError> {
    let (_, session, user) = authenticated(&state, &headers).await?;
    require_recent_passkey(&session)?;
    let identifier = canonical_identifier(input.kind, &input.value)?;
    let user = state
        .store
        .set_primary_identifier(user.id, &identifier)
        .await
        .map_err(|error| match error.downcast_ref::<StorePolicyError>() {
            Some(StorePolicyError::IdentifierNotLinked) => {
                ApiError::bad_request("identifier is not linked to this account")
            }
            _ => ApiError::internal(error),
        })?;
    Ok(Json(account_body(&user)))
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
    let (_, session, user) = authenticated(&state, &headers).await?;
    require_recent_passkey(&session)?;
    let label = credential_label(&input.label)?;
    let passkey_name = user.passkey_name();
    let passkey_display_name = user.passkey_display_name();
    let (options, ceremony_state) = state
        .webauthn
        .start_passkey_registration(user.id, &passkey_name, &passkey_display_name, None)
        .map_err(|error| ApiError::internal(format!("start passkey registration: {error}")))?;
    let ceremony = RegistrationCeremony {
        id: Uuid::new_v4(),
        user_id: user.id,
        email: user.email,
        identifier: None,
        profile: AccountProfile::default(),
        purpose: RegistrationPurpose::AddCredential,
        initiating_session_id: Some(session.id),
        label: Some(label),
        expires_at: now().saturating_add(CEREMONY_SECONDS),
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
    let (_, session, user) = authenticated(&state, &headers).await?;
    require_recent_passkey(&session)?;
    let ceremony = state
        .store
        .take_registration(input.ceremony_id)
        .await
        .map_err(|_| ApiError::unauthorized("registration ceremony is invalid or expired"))?;
    if ceremony.purpose != RegistrationPurpose::AddCredential
        || ceremony.initiating_session_id != Some(session.id)
        || ceremony.user_id != user.id
    {
        return Err(ApiError::unauthorized(
            "registration ceremony is invalid or expired",
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
    let (_, session, user) = authenticated(&state, &headers).await?;
    require_passkey_session(&session)?;
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
    require_recent_passkey(&session)?;
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

fn registration_identifier(input: &RegistrationOptionsInput) -> Result<IdentifierValue, ApiError> {
    lookup_identifier_ref(
        input.identifier.as_ref(),
        input.email.as_deref(),
        input.phone.as_deref(),
    )
}

fn lookup_identifier(
    identifier: Option<IdentifierRequest>,
    email: Option<String>,
    phone: Option<String>,
) -> Result<IdentifierValue, ApiError> {
    lookup_identifier_ref(identifier.as_ref(), email.as_deref(), phone.as_deref())
}

fn lookup_identifier_ref(
    identifier: Option<&IdentifierRequest>,
    email: Option<&str>,
    phone: Option<&str>,
) -> Result<IdentifierValue, ApiError> {
    let supplied = usize::from(identifier.is_some())
        + usize::from(email.is_some())
        + usize::from(phone.is_some());
    if supplied != 1 {
        return Err(ApiError::bad_request(
            "provide exactly one email or phone identifier",
        ));
    }
    if let Some(identifier) = identifier {
        return canonical_identifier(identifier.kind, &identifier.value);
    }
    if let Some(email) = email {
        return canonical_identifier(IdentifierKind::Email, email);
    }
    canonical_identifier(
        IdentifierKind::Phone,
        phone.expect("one identifier was validated above"),
    )
}

fn canonical_identifier(kind: IdentifierKind, value: &str) -> Result<IdentifierValue, ApiError> {
    IdentifierValue::canonical(kind, value)
        .map_err(|error| ApiError::bad_request(error.to_string()))
}

fn canonical_email(value: &str) -> Result<String, ApiError> {
    Ok(canonical_identifier(IdentifierKind::Email, value)?.value)
}

#[cfg(test)]
#[cfg(test)]
fn canonical_phone(value: &str) -> Result<String, ApiError> {
    Ok(canonical_identifier(IdentifierKind::Phone, value)?.value)
}

fn account_profile(
    given_name: Option<String>,
    family_name: Option<String>,
    display_name: Option<String>,
) -> Result<AccountProfile, ApiError> {
    AccountProfile::canonical(given_name, family_name, display_name)
        .map_err(|error| ApiError::bad_request(error.to_string()))
}

fn profile_display_name(profile: &AccountProfile) -> Option<String> {
    profile.display_name.clone().or_else(|| {
        let name = [
            profile.given_name.as_deref(),
            profile.family_name.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
        (!name.is_empty()).then_some(name)
    })
}

fn require_recent_passkey(session: &Session) -> Result<(), ApiError> {
    require_passkey_session(session)?;
    let current = now();
    if session.created_at > current || current.saturating_sub(session.created_at) > CEREMONY_SECONDS
    {
        return Err(ApiError::unauthorized(
            "confirm with a recent passkey before changing account security",
        ));
    }
    Ok(())
}

fn require_passkey_session(session: &Session) -> Result<(), ApiError> {
    if session.auth_method != "passkey" {
        return Err(ApiError::unauthorized(
            "confirm with a passkey before changing account identity",
        ));
    }
    Ok(())
}

fn account_body(user: &User) -> Value {
    let identifiers = user
        .identifiers
        .iter()
        .map(|identifier| IdentifierOutput {
            kind: identifier.kind,
            value: identifier.value.clone(),
            verified: identifier.verified,
            verified_at: identifier.verified_at.map(timestamp),
            primary: identifier.primary,
            created_at: timestamp(identifier.created_at),
        })
        .collect::<Vec<_>>();
    json!({
        "id": user.id,
        "profile": user.profile,
        "identifiers": identifiers,
        "createdAt": timestamp(user.created_at),
    })
}

fn credential_label(value: &str) -> Result<String, ApiError> {
    let label = value.trim();
    if label.is_empty()
        || label.chars().count() > 80
        || label.chars().any(forbidden_display_character)
    {
        return Err(ApiError::bad_request(
            "passkey label must contain 1–80 characters and no control or formatting characters",
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
    use uuid::Uuid;

    use super::{
        CEREMONY_SECONDS, account_profile, canonical_email, canonical_phone, credential_id,
        credential_label, lookup_identifier_ref, require_passkey_session, require_recent_passkey,
        timestamp,
    };
    use crate::{
        auth::dto::IdentifierRequest,
        store::{IdentifierKind, Session, now},
    };

    #[test]
    fn credential_labels_are_trimmed_and_bounded() {
        assert_eq!(credential_label("  MacBook  ").unwrap(), "MacBook");
        assert!(credential_label("").is_err());
        assert!(credential_label(&"x".repeat(81)).is_err());
        assert!(credential_label("bad\nlabel").is_err());
        assert!(credential_label("safe\u{202e}spoof").is_err());
        assert!(credential_label(&"🔑".repeat(80)).is_ok());
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

    #[test]
    fn phone_numbers_are_normalized_to_e164() {
        assert_eq!(
            canonical_phone(" +44 (7700) 900-123 ").unwrap(),
            "+447700900123"
        );
        assert!(canonical_phone("07700 900123").is_err());
        assert!(canonical_phone("+0123456789").is_err());
        assert!(canonical_phone("+1234567").is_err());
        assert!(canonical_phone("+1234567890123456").is_err());
    }

    #[test]
    fn emails_use_a_strict_ascii_dot_atom_profile() {
        assert_eq!(
            canonical_email(" Ada.Lovelace+alerts@Example.COM ").unwrap(),
            "ada.lovelace+alerts@example.com"
        );
        for invalid in [
            "a@@example.com",
            "a b@example.com",
            "é@example.com",
            ".a@example.com",
            "a..b@example.com",
            "a@-example.com",
            "a@example-.com",
            "a@example..com",
        ] {
            assert!(canonical_email(invalid).is_err(), "accepted {invalid}");
        }
        assert!(canonical_email(&format!("a@{}.test", "x".repeat(64))).is_err());
    }

    #[test]
    fn identifier_input_is_unambiguous_and_backwards_compatible() {
        let email = lookup_identifier_ref(None, Some(" Person@Example.com "), None).unwrap();
        assert_eq!(email.kind, IdentifierKind::Email);
        assert_eq!(email.value, "person@example.com");

        let phone = IdentifierRequest {
            kind: IdentifierKind::Phone,
            value: "+44 7700 900123".into(),
        };
        assert_eq!(
            lookup_identifier_ref(Some(&phone), None, None)
                .unwrap()
                .value,
            "+447700900123"
        );
        assert!(lookup_identifier_ref(None, None, None).is_err());
        assert!(lookup_identifier_ref(Some(&phone), Some("a@b.test"), None).is_err());
    }

    #[test]
    fn basic_profile_names_are_trimmed_and_bounded() {
        let profile = account_profile(
            Some(" Ada ".into()),
            Some(" Lovelace ".into()),
            Some(" ".into()),
        )
        .unwrap();
        assert_eq!(profile.given_name.as_deref(), Some("Ada"));
        assert_eq!(profile.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(profile.display_name, None);
        assert!(account_profile(Some("bad\nname".into()), None, None).is_err());
        assert!(account_profile(Some("bad\u{200b}name".into()), None, None).is_err());
        assert!(account_profile(None, None, Some("bad\u{202e}name".into())).is_err());
        assert!(account_profile(Some("x".repeat(101)), None, None).is_err());
    }

    #[test]
    fn sensitive_account_changes_require_a_recent_passkey_session() {
        let current = now();
        let session = |auth_method: &str, created_at: u64| Session {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            auth_method: auth_method.into(),
            current_credential_id: None,
            session_version: 1,
            created_at,
            last_seen_at: current,
            absolute_expires_at: current + 3_600,
        };
        assert!(require_recent_passkey(&session("passkey", current)).is_ok());
        assert!(require_passkey_session(&session("passkey", current)).is_ok());
        assert!(require_recent_passkey(&session("agent", current)).is_err());
        assert!(require_passkey_session(&session("agent", current)).is_err());
        assert!(require_passkey_session(&session("passkey", current - 301)).is_ok());
        assert!(require_recent_passkey(&session("passkey", current + 1)).is_err());
        assert!(
            require_recent_passkey(&session(
                "passkey",
                current.saturating_sub(CEREMONY_SECONDS + 1),
            ))
            .is_err()
        );
    }
}
