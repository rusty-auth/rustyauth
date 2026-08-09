//! Offline recovery-code rotation and passkey re-enrolment.

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
    store::{AccountProfile, RegistrationCeremony, RegistrationPurpose, SessionOrigin, now},
};

use super::{
    CEREMONY_SECONDS,
    credentials::credential_label,
    dto::{RecoveryCodesOutput, RecoveryOptionsInput, RegistrationVerifyInput},
    error::ApiError,
    guard::{authenticated, require_origin, require_rate_limit, require_recent_passkey},
    session::token_response,
    validate::lookup_identifier_ref,
};

pub(super) async fn rotate_recovery_codes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RecoveryCodesOutput>, ApiError> {
    let (_, session, user) = authenticated(&state, &headers).await?;
    require_recent_passkey(&session)?;
    let (_, recovery_codes) = state
        .store
        .rotate_recovery_codes(user.id)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(RecoveryCodesOutput { recovery_codes }))
}

pub(super) async fn recovery_options(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<RecoveryOptionsInput>,
) -> Result<Json<Value>, ApiError> {
    require_origin(&state, &headers)?;
    require_rate_limit(&state, peer, &headers, RateLimitClass::Recovery, None).await?;
    let identifier = lookup_identifier_ref(
        input.identifier.as_ref(),
        input.email.as_deref(),
        input.phone.as_deref(),
    )?;
    let label = credential_label(&input.label)?;
    let user = state
        .store
        .consume_recovery_code(&identifier, input.recovery_code.trim())
        .await
        .map_err(|_| ApiError::unauthorized("account recovery is unavailable"))?;
    let passkey_name = user.passkey_name();
    let passkey_display_name = user.passkey_display_name();
    let (options, ceremony_state) = state
        .webauthn
        .start_passkey_registration(user.id, &passkey_name, &passkey_display_name, None)
        .map_err(|error| ApiError::internal(format!("start recovery registration: {error}")))?;
    let ceremony = RegistrationCeremony {
        id: Uuid::new_v4(),
        user_id: user.id,
        email: String::new(),
        identifier: None,
        profile: AccountProfile::default(),
        purpose: RegistrationPurpose::RecoverAccount,
        initiating_session_id: None,
        invitation_id: None,
        invitation_digest: None,
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

pub(super) async fn recovery_verify(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<RegistrationVerifyInput>,
) -> Result<Response, ApiError> {
    require_origin(&state, &headers)?;
    require_rate_limit(&state, peer, &headers, RateLimitClass::Recovery, None).await?;
    let ceremony = state
        .store
        .take_registration(input.ceremony_id)
        .await
        .map_err(|_| ApiError::unauthorized("recovery ceremony is invalid or expired"))?;
    if ceremony.purpose != RegistrationPurpose::RecoverAccount
        || ceremony.initiating_session_id.is_some()
    {
        return Err(ApiError::unauthorized(
            "recovery ceremony is invalid or expired",
        ));
    }
    let passkey = state
        .webauthn
        .finish_passkey_registration(&input.response, &ceremony.state)
        .map_err(|_| ApiError::unauthorized("passkey verification failed"))?;
    let current_credential_id = URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());
    let user = state
        .store
        .add_recovery_passkey(
            ceremony.user_id,
            ceremony.label.unwrap_or_else(|| "Recovery passkey".into()),
            passkey,
        )
        .await
        .map_err(|_| ApiError::unauthorized("account recovery is unavailable"))?;
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
