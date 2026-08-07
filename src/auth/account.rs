//! Account projection, profile updates and identifier management.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};

use crate::{
    app_state::AppState,
    store::{StorePolicyError, User},
};

use super::{
    dto::{ChangeIdentifierInput, IdentifierOutput, UpdateProfileInput},
    error::ApiError,
    guard::{authenticated, require_passkey_session, require_recent_passkey},
    validate::{account_profile, canonical_identifier, timestamp},
};

pub(super) async fn account(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (_, _, user) = authenticated(&state, &headers).await?;
    Ok(Json(account_body(&user)))
}

pub(super) async fn update_profile(
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

pub(super) async fn add_identifier(
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

pub(super) async fn remove_identifier(
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

pub(super) async fn set_primary_identifier(
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
