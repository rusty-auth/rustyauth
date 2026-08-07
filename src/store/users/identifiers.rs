//! Account contact identifiers: canonical email and phone validation, and the
//! linkage mutations that keep lookup keys consistent with the user record.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::store::{
    MAX_IDENTIFIERS, Store, StorePolicyError, events::queue_events, identifier_key, now,
    require_canonical_identifier,
};

use super::User;

#[derive(Debug, thiserror::Error)]
pub enum IdentifierValidationError {
    #[error("valid email required")]
    Email,
    #[error("phone number must use international E.164 format")]
    Phone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentifierKind {
    Email,
    Phone,
}

impl IdentifierKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentifierValue {
    pub kind: IdentifierKind,
    pub value: String,
}

impl IdentifierValue {
    pub fn canonical(kind: IdentifierKind, value: &str) -> Result<Self, IdentifierValidationError> {
        let value = match kind {
            IdentifierKind::Email => canonical_email_value(value)?,
            IdentifierKind::Phone => canonical_phone_value(value)?,
        };
        Ok(Self { kind, value })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountIdentifier {
    pub kind: IdentifierKind,
    pub value: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub verified_at: Option<u64>,
    #[serde(default)]
    pub primary: bool,
    pub created_at: u64,
}

impl Store {
    pub async fn add_identifier(
        &self,
        user_id: Uuid,
        identifier: IdentifierValue,
        verified: bool,
    ) -> Result<User> {
        require_canonical_identifier(&identifier)?;
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        if self.user_by_identifier(&identifier).await?.is_some() {
            return Err(StorePolicyError::IdentifierAlreadyExists.into());
        }
        let mut user = self
            .user(user_id)
            .await?
            .ok_or(StorePolicyError::UserMissing)?;
        if user.identifiers.len() >= MAX_IDENTIFIERS {
            return Err(StorePolicyError::IdentifierLimit.into());
        }
        user.identifiers.push(AccountIdentifier {
            kind: identifier.kind,
            value: identifier.value.clone(),
            verified,
            verified_at: verified.then_some(now()),
            primary: false,
            created_at: now(),
        });
        user.sync_legacy_email();

        let mut event_inputs = vec![("identifier.added".to_owned(), Some(user_id))];
        if !verified {
            event_inputs.push((
                format!("{}.verification.requested", identifier.kind.as_str()),
                Some(user_id),
            ));
        }
        let events = self.pending_events(event_inputs).await?;

        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(
                format!("auth:user:{user_id}"),
                serde_json::to_string(&user)?,
            )
            .set(identifier_key(&identifier), user_id.to_string());
        if identifier.kind == IdentifierKind::Email {
            pipeline.set(
                format!("auth:email:{}", identifier.value),
                user_id.to_string(),
            );
        }
        queue_events(&mut pipeline, &events)?;
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("persist account identifier and events")?;
        Ok(user)
    }

    pub async fn remove_identifier(
        &self,
        user_id: Uuid,
        identifier: &IdentifierValue,
    ) -> Result<User> {
        require_canonical_identifier(identifier)?;
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut user = self
            .user(user_id)
            .await?
            .ok_or(StorePolicyError::UserMissing)?;
        if user.identifiers.len() <= 1 {
            return Err(StorePolicyError::FinalIdentifier.into());
        }
        let position = user
            .identifiers
            .iter()
            .position(|stored| stored.kind == identifier.kind && stored.value == identifier.value)
            .ok_or(StorePolicyError::IdentifierNotLinked)?;
        let removed_primary = user.identifiers[position].primary;
        user.identifiers
            .retain(|stored| stored.kind != identifier.kind || stored.value != identifier.value);
        if removed_primary {
            user.identifiers[0].primary = true;
        }
        user.sync_legacy_email();

        let events = self
            .pending_events(vec![("identifier.removed".to_owned(), Some(user_id))])
            .await?;

        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(
                format!("auth:user:{user_id}"),
                serde_json::to_string(&user)?,
            )
            .del(identifier_key(identifier));
        if identifier.kind == IdentifierKind::Email {
            pipeline.del(format!("auth:email:{}", identifier.value));
        }
        queue_events(&mut pipeline, &events)?;
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("remove account identifier and persist event")?;
        Ok(user)
    }

    pub async fn set_primary_identifier(
        &self,
        user_id: Uuid,
        identifier: &IdentifierValue,
    ) -> Result<User> {
        require_canonical_identifier(identifier)?;
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut user = self
            .user(user_id)
            .await?
            .ok_or(StorePolicyError::UserMissing)?;
        if !user
            .identifiers
            .iter()
            .any(|stored| stored.kind == identifier.kind && stored.value == identifier.value)
        {
            return Err(StorePolicyError::IdentifierNotLinked.into());
        }
        for stored in &mut user.identifiers {
            stored.primary = stored.kind == identifier.kind && stored.value == identifier.value;
        }
        user.sync_legacy_email();
        self.persist_user_with_event(
            &user,
            "identifier.primary_changed",
            "persist primary account identifier and event",
        )
        .await?;
        Ok(user)
    }

    pub async fn set_identifier_verification(
        &self,
        user_id: Uuid,
        identifier: &IdentifierValue,
        verified: bool,
    ) -> Result<User> {
        require_canonical_identifier(identifier)?;
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut user = self
            .user(user_id)
            .await?
            .ok_or(StorePolicyError::UserMissing)?;
        let stored = user
            .identifiers
            .iter_mut()
            .find(|stored| stored.kind == identifier.kind && stored.value == identifier.value)
            .ok_or(StorePolicyError::IdentifierNotLinked)?;
        stored.verified = verified;
        stored.verified_at = verified.then_some(now());
        user.sync_legacy_email();
        self.persist_user_with_event(
            &user,
            if verified {
                "identifier.verified"
            } else {
                "identifier.unverified"
            },
            "persist account identifier verification and event",
        )
        .await?;
        Ok(user)
    }
}

fn canonical_email_value(value: &str) -> Result<String, IdentifierValidationError> {
    let email = value.trim().to_ascii_lowercase();
    if email.is_empty() || email.len() > 320 || !email.is_ascii() {
        return Err(IdentifierValidationError::Email);
    }
    let Some((local, domain)) = email.split_once('@') else {
        return Err(IdentifierValidationError::Email);
    };
    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.len() > 253
        || domain.contains('@')
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                )
        })
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        return Err(IdentifierValidationError::Email);
    }
    Ok(email)
}

fn canonical_phone_value(value: &str) -> Result<String, IdentifierValidationError> {
    let value = value.trim();
    if value.len() > 64 || !value.starts_with('+') {
        return Err(IdentifierValidationError::Phone);
    }
    let mut digits = String::with_capacity(value.len());
    for character in value[1..].chars() {
        if character.is_ascii_digit() {
            digits.push(character);
        } else if !(character.is_ascii_whitespace() || matches!(character, '-' | '(' | ')' | '.')) {
            return Err(IdentifierValidationError::Phone);
        }
    }
    if !(8..=15).contains(&digits.len()) || digits.starts_with('0') {
        return Err(IdentifierValidationError::Phone);
    }
    Ok(format!("+{digits}"))
}
