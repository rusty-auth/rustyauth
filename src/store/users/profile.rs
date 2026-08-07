//! Account profile fields: bounded, spoofing-resistant display text and its
//! validated mutation.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::store::{Store, StorePolicyError};

use super::User;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountProfile {
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error(
    "{field} must contain at most {maximum} characters and no control or formatting characters"
)]
pub struct ProfileValidationError {
    field: &'static str,
    maximum: usize,
}

impl AccountProfile {
    pub(crate) fn canonical(
        given_name: Option<String>,
        family_name: Option<String>,
        display_name: Option<String>,
    ) -> Result<Self, ProfileValidationError> {
        Ok(Self {
            given_name: canonical_profile_value(given_name, "given name", 100)?,
            family_name: canonical_profile_value(family_name, "family name", 100)?,
            display_name: canonical_profile_value(display_name, "display name", 200)?,
        })
    }
}

impl Store {
    pub async fn update_profile(&self, user_id: Uuid, profile: AccountProfile) -> Result<User> {
        validate_account_profile(&profile)?;
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut user = self
            .user(user_id)
            .await?
            .ok_or(StorePolicyError::UserMissing)?;
        user.profile = profile;
        self.persist_user_with_event(
            &user,
            "profile.updated",
            "persist account profile and event",
        )
        .await?;
        Ok(user)
    }
}

fn canonical_profile_value(
    value: Option<String>,
    field: &'static str,
    maximum: usize,
) -> Result<Option<String>, ProfileValidationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > maximum || value.chars().any(forbidden_display_character) {
        return Err(ProfileValidationError { field, maximum });
    }
    Ok(Some(value.to_owned()))
}

fn validate_profile_value(value: Option<&str>, maximum: usize) -> Result<()> {
    if value.is_some_and(|value| {
        value.is_empty()
            || value.trim() != value
            || value.chars().count() > maximum
            || value.chars().any(forbidden_display_character)
    }) {
        bail!("stored user has invalid profile data");
    }
    Ok(())
}

pub(super) fn validate_account_profile(profile: &AccountProfile) -> Result<()> {
    validate_profile_value(profile.given_name.as_deref(), 100)?;
    validate_profile_value(profile.family_name.as_deref(), 100)?;
    validate_profile_value(profile.display_name.as_deref(), 200)
}

pub(crate) fn forbidden_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{200B}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}
