//! Initial registration ceremonies that create a new account and its first
//! passkey.

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
    store::{
        AccountProfile, IdentifierKind, IdentifierValue, RegistrationCeremony, RegistrationPurpose,
        SessionOrigin, StorePolicyError, now,
    },
};

use super::{
    CEREMONY_SECONDS,
    dto::{RegistrationOptionsInput, RegistrationVerifyInput},
    error::ApiError,
    guard::{require_bootstrap, require_origin, require_rate_limit},
    session::token_response,
    validate::{account_profile, lookup_identifier_ref},
};

pub(super) async fn registration_options(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<RegistrationOptionsInput>,
) -> Result<Json<Value>, ApiError> {
    require_origin(&state, &headers)?;
    require_bootstrap(&state, &headers)?;
    let identifier = registration_identifier(&input)?;
    // Identifier-keyed here, unlike the sign-in paths. Exhausting an unregistered
    // identifier's budget denies nobody an existing account, and this endpoint is
    // already behind the enrolment token, so the bucket bounds ceremony farming
    // against one address without becoming a lockout primitive.
    require_rate_limit(
        &state,
        peer,
        &headers,
        RateLimitClass::IdentifierProbe,
        Some(&identifier.value),
    )?;
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

pub(super) async fn registration_verify(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<RegistrationVerifyInput>,
) -> Result<Response, ApiError> {
    require_origin(&state, &headers)?;
    require_bootstrap(&state, &headers)?;
    require_rate_limit(&state, peer, &headers, RateLimitClass::Ceremony, None)?;
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
            SessionOrigin::Passkey {
                credential_id: current_credential_id,
            },
            state.session_absolute_seconds,
        )
        .await
        .map_err(ApiError::internal)?;
    token_response(&state, &user, &session, &session_token, StatusCode::CREATED)
}

fn registration_identifier(input: &RegistrationOptionsInput) -> Result<IdentifierValue, ApiError> {
    lookup_identifier_ref(
        input.identifier.as_ref(),
        input.email.as_deref(),
        input.phone.as_deref(),
    )
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
