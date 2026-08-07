//! Durable user aggregate: hydration, fail-closed validation and account
//! creation with the first passkey.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::store::{
    MAX_IDENTIFIERS, Store, StorePolicyError, StoredPasskey, credential_id, events::queue_events,
    identifier_key, now, require_canonical_identifier,
};

use super::{
    AccountIdentifier, AccountProfile, IdentifierKind, IdentifierValue,
    profile::{forbidden_display_character, validate_account_profile},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: Uuid,
    // Retained on disk for compatibility with pre-identifier users and older
    // integrations. New code treats `identifiers` as the source of truth.
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub profile: AccountProfile,
    #[serde(default)]
    pub identifiers: Vec<AccountIdentifier>,
    pub session_version: u64,
    pub created_at: u64,
    pub passkeys: Vec<StoredPasskey>,
}

impl User {
    pub(crate) fn normalize_and_validate(&mut self) -> Result<()> {
        if self.identifiers.is_empty() && !self.email.is_empty() {
            self.identifiers.push(AccountIdentifier {
                kind: IdentifierKind::Email,
                value: self.email.clone(),
                verified: self.email_verified,
                verified_at: None,
                primary: true,
                created_at: self.created_at,
            });
        }
        if self.identifiers.is_empty() {
            bail!("stored user has no account identifiers");
        }
        if self.identifiers.len() > MAX_IDENTIFIERS {
            bail!("stored user exceeds the account identifier limit");
        }

        let mut seen = BTreeSet::new();
        let mut primary_count = 0_usize;
        for identifier in &mut self.identifiers {
            if identifier.value.is_empty()
                || identifier.value.len() > 320
                || identifier.value.chars().any(forbidden_display_character)
                || !seen.insert(format!("{}:{}", identifier.kind.as_str(), identifier.value))
            {
                bail!("stored user has an invalid or duplicate account identifier");
            }
            if identifier.verified_at.is_some() && !identifier.verified {
                bail!("stored user has inconsistent identifier verification state");
            }
            if identifier.kind == IdentifierKind::Phone {
                let canonical = IdentifierValue::canonical(identifier.kind, &identifier.value)
                    .map_err(|_| anyhow::anyhow!("stored user has an invalid phone identifier"))?;
                if canonical.value != identifier.value {
                    bail!("stored user has a non-canonical phone identifier");
                }
            }
            primary_count += usize::from(identifier.primary);
        }
        if primary_count != 1 {
            bail!("stored user must have exactly one primary account identifier");
        }

        validate_account_profile(&self.profile)?;
        self.sync_legacy_email();
        Ok(())
    }

    pub(super) fn sync_legacy_email(&mut self) {
        let email = self
            .identifiers
            .iter()
            .filter(|identifier| identifier.kind == IdentifierKind::Email)
            .min_by_key(|identifier| (!identifier.primary, identifier.created_at));
        match email {
            Some(identifier) => {
                self.email = identifier.value.clone();
                self.email_verified = identifier.verified;
            }
            None => {
                self.email.clear();
                self.email_verified = false;
            }
        }
    }

    pub fn primary_identifier(&self) -> Option<&AccountIdentifier> {
        self.identifiers
            .iter()
            .find(|identifier| identifier.primary)
            .or_else(|| self.identifiers.first())
    }

    pub fn primary_email(&self) -> Option<&AccountIdentifier> {
        self.identifiers
            .iter()
            .filter(|identifier| identifier.kind == IdentifierKind::Email)
            .min_by_key(|identifier| (!identifier.primary, identifier.created_at))
    }

    pub fn primary_phone(&self) -> Option<&AccountIdentifier> {
        self.identifiers
            .iter()
            .filter(|identifier| identifier.kind == IdentifierKind::Phone)
            .min_by_key(|identifier| (!identifier.primary, identifier.created_at))
    }

    pub fn passkey_name(&self) -> String {
        self.primary_identifier()
            .map(|identifier| identifier.value.clone())
            .unwrap_or_else(|| self.id.to_string())
    }

    pub fn passkey_display_name(&self) -> String {
        if let Some(display_name) = &self.profile.display_name {
            return display_name.clone();
        }
        let full_name = [
            self.profile.given_name.as_deref(),
            self.profile.family_name.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
        if full_name.is_empty() {
            self.passkey_name()
        } else {
            full_name
        }
    }
}

impl Store {
    pub async fn user_by_email(&self, email: &str) -> Result<Option<User>> {
        self.user_by_identifier(&IdentifierValue {
            kind: IdentifierKind::Email,
            value: email.to_owned(),
        })
        .await
    }

    pub async fn user_by_identifier(&self, identifier: &IdentifierValue) -> Result<Option<User>> {
        let mut id = self.get::<String>(&identifier_key(identifier)).await?;
        if id.is_none() && identifier.kind == IdentifierKind::Email {
            id = self
                .get::<String>(&format!("auth:email:{}", identifier.value))
                .await?;
        }
        let Some(id) = id else {
            return Ok(None);
        };
        self.user(Uuid::parse_str(&id).context("stored user id is invalid")?)
            .await
    }

    pub async fn user(&self, id: Uuid) -> Result<Option<User>> {
        let Some(mut user) = self.get_json::<User>(&format!("auth:user:{id}")).await? else {
            return Ok(None);
        };
        user.normalize_and_validate()?;
        Ok(Some(user))
    }

    pub async fn user_by_credential_id(&self, credential_id: &str) -> Result<Option<User>> {
        let Some(id) = self
            .get::<String>(&format!("auth:credential:{credential_id}"))
            .await?
        else {
            return Ok(None);
        };
        self.user(Uuid::parse_str(&id).context("stored credential user id is invalid")?)
            .await
    }

    pub async fn create_user_with_passkey(
        &self,
        user_id: Uuid,
        identifier: IdentifierValue,
        profile: AccountProfile,
        passkey: Passkey,
        identifier_verified: bool,
    ) -> Result<User> {
        require_canonical_identifier(&identifier)?;
        validate_account_profile(&profile)?;
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        if self.user_by_identifier(&identifier).await?.is_some() {
            return Err(StorePolicyError::IdentifierAlreadyExists.into());
        }
        let id = credential_id(&passkey);
        if self
            .get::<String>(&format!("auth:credential:{id}"))
            .await?
            .is_some()
        {
            return Err(StorePolicyError::CredentialAlreadyExists.into());
        }
        let credential: webauthn_rs::prelude::Credential = passkey.clone().into();
        let created_at = now();
        let user = User {
            id: user_id,
            email: if identifier.kind == IdentifierKind::Email {
                identifier.value.clone()
            } else {
                String::new()
            },
            email_verified: identifier.kind == IdentifierKind::Email && identifier_verified,
            profile,
            identifiers: vec![AccountIdentifier {
                kind: identifier.kind,
                value: identifier.value.clone(),
                verified: identifier_verified,
                verified_at: identifier_verified.then_some(created_at),
                primary: true,
                created_at,
            }],
            session_version: 1,
            created_at,
            passkeys: vec![StoredPasskey {
                id: id.clone(),
                label: "Primary passkey".into(),
                counter: credential.counter,
                created_at: now(),
                last_used_at: None,
                passkey,
            }],
        };
        let mut event_inputs = vec![("identity.created".to_owned(), Some(user_id))];
        if !identifier_verified {
            event_inputs.push((
                format!("{}.verification.requested", identifier.kind.as_str()),
                Some(user_id),
            ));
        }
        let events = self.pending_events(event_inputs).await?;
        let mut connection = self.redis.clone();
        let serialized = serde_json::to_string(&user)?;
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(format!("auth:user:{user_id}"), serialized)
            .set(identifier_key(&identifier), user_id.to_string())
            .set(format!("auth:credential:{id}"), user_id.to_string());
        if identifier.kind == IdentifierKind::Email {
            pipeline.set(
                format!("auth:email:{}", identifier.value),
                user_id.to_string(),
            );
        }
        queue_events(&mut pipeline, &events)?;
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("persist user, passkey, and identity events")?;
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_email_users_are_hydrated_without_changing_their_account_id() {
        let id = Uuid::new_v4();
        let mut user = User {
            id,
            email: "person@example.com".into(),
            email_verified: true,
            profile: AccountProfile::default(),
            identifiers: Vec::new(),
            session_version: 1,
            created_at: 100,
            passkeys: Vec::new(),
        };
        user.normalize_and_validate().unwrap();
        assert_eq!(user.id, id);
        assert_eq!(user.identifiers.len(), 1);
        assert_eq!(user.identifiers[0].kind, IdentifierKind::Email);
        assert_eq!(user.identifiers[0].value, "person@example.com");
        assert!(user.identifiers[0].primary);
        assert!(user.identifiers[0].verified);
        assert_eq!(user.identifiers[0].verified_at, None);
    }

    #[test]
    fn phone_only_users_have_a_stable_passkey_label_and_no_legacy_email() {
        let mut user = User {
            id: Uuid::new_v4(),
            email: String::new(),
            email_verified: false,
            profile: AccountProfile {
                given_name: Some("Ada".into()),
                family_name: Some("Lovelace".into()),
                display_name: None,
            },
            identifiers: vec![AccountIdentifier {
                kind: IdentifierKind::Phone,
                value: "+447700900123".into(),
                verified: true,
                verified_at: Some(100),
                primary: true,
                created_at: 100,
            }],
            session_version: 1,
            created_at: 100,
            passkeys: Vec::new(),
        };
        user.normalize_and_validate().unwrap();
        assert_eq!(user.passkey_name(), "+447700900123");
        assert_eq!(user.passkey_display_name(), "Ada Lovelace");
        assert!(user.email.is_empty());
    }

    #[test]
    fn stored_accounts_fail_closed_on_primary_and_duplicate_identifier_corruption() {
        let identifier = AccountIdentifier {
            kind: IdentifierKind::Email,
            value: "person@example.com".into(),
            verified: true,
            verified_at: Some(100),
            primary: true,
            created_at: 100,
        };
        let user = |identifiers: Vec<AccountIdentifier>| User {
            id: Uuid::new_v4(),
            email: "person@example.com".into(),
            email_verified: true,
            profile: AccountProfile::default(),
            identifiers,
            session_version: 1,
            created_at: 100,
            passkeys: Vec::new(),
        };

        let mut no_primary = identifier.clone();
        no_primary.primary = false;
        assert!(user(vec![no_primary]).normalize_and_validate().is_err());

        let mut duplicate = identifier.clone();
        duplicate.primary = false;
        assert!(
            user(vec![identifier.clone(), duplicate])
                .normalize_and_validate()
                .is_err()
        );

        let mut second_primary = AccountIdentifier {
            kind: IdentifierKind::Phone,
            value: "+447700900123".into(),
            ..identifier.clone()
        };
        second_primary.primary = true;
        assert!(
            user(vec![identifier, second_primary])
                .normalize_and_validate()
                .is_err()
        );
    }

    #[test]
    fn stored_accounts_reject_missing_identity_and_dangerous_profile_text() {
        let mut missing = User {
            id: Uuid::new_v4(),
            email: String::new(),
            email_verified: false,
            profile: AccountProfile::default(),
            identifiers: Vec::new(),
            session_version: 1,
            created_at: 100,
            passkeys: Vec::new(),
        };
        assert!(missing.normalize_and_validate().is_err());

        missing.email = "person@example.com".into();
        missing.profile.display_name = Some("safe\u{2066}spoof\u{2069}".into());
        assert!(missing.normalize_and_validate().is_err());
    }

    #[test]
    fn stored_accounts_reject_inconsistent_verification_and_noncanonical_phones() {
        let account = |identifier: AccountIdentifier| User {
            id: Uuid::new_v4(),
            email: String::new(),
            email_verified: false,
            profile: AccountProfile::default(),
            identifiers: vec![identifier],
            session_version: 1,
            created_at: 100,
            passkeys: Vec::new(),
        };
        let mut inconsistent = AccountIdentifier {
            kind: IdentifierKind::Phone,
            value: "+447700900123".into(),
            verified: false,
            verified_at: Some(100),
            primary: true,
            created_at: 100,
        };
        assert!(
            account(inconsistent.clone())
                .normalize_and_validate()
                .is_err()
        );

        inconsistent.verified_at = None;
        inconsistent.value = "+44 7700 900123".into();
        assert!(account(inconsistent).normalize_and_validate().is_err());
    }
}
