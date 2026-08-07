//! Passkey credential management: listing, adding, renaming and revoking.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    store::{
        AccountProfile, RegistrationCeremony, RegistrationPurpose, StorePolicyError,
        forbidden_display_character, now,
    },
};

use super::{
    CEREMONY_SECONDS,
    dto::{
        AddRegistrationOptionsInput, CredentialOutput, RegistrationVerifyInput,
        RenameCredentialInput, RevokeCredentialInput,
    },
    error::ApiError,
    guard::{authenticated, require_passkey_session, require_recent_passkey},
    validate::timestamp,
};

pub(super) async fn credentials(
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

pub(super) async fn add_registration_options(
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

pub(super) async fn add_registration_verify(
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

pub(super) async fn rename_credential(
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

pub(super) async fn revoke_credential(
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

#[cfg(test)]
mod tests {
    use super::{credential_id, credential_label};

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
}
