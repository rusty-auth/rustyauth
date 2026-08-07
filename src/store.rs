//! SableDB persistence boundary.
//!
//! All durable key construction and serialization is centralized here. Public
//! HTTP handlers do not issue database commands directly. Compound mutations
//! use atomic pipelines and are serialized within the single supported writer.

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, Passkey, PasskeyAuthentication, PasskeyRegistration,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum StorePolicyError {
    #[error("identifier already has an account")]
    IdentifierAlreadyExists,
    #[error("account has reached the identifier limit")]
    IdentifierLimit,
    #[error("identifier is not linked to this user")]
    IdentifierNotLinked,
    #[error("the final identifier cannot be removed")]
    FinalIdentifier,
    #[error("passkey is already registered")]
    CredentialAlreadyExists,
    #[error("user is missing")]
    UserMissing,
    #[error("passkey is not linked to this user")]
    CredentialNotLinked,
    #[error("the final passkey cannot be removed")]
    FinalCredential,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum IdentifierValidationError {
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
    pub(crate) fn canonical(
        kind: IdentifierKind,
        value: &str,
    ) -> Result<Self, IdentifierValidationError> {
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
pub(crate) struct ProfileValidationError {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredPasskey {
    pub id: String,
    pub label: String,
    pub counter: u32,
    pub created_at: u64,
    #[serde(default)]
    pub last_used_at: Option<u64>,
    pub passkey: Passkey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationCeremony {
    pub id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    #[serde(default)]
    pub label: Option<String>,
    pub expires_at: u64,
    pub state: PasskeyRegistration,
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

    fn sync_legacy_email(&mut self) {
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationCeremony {
    pub id: Uuid,
    pub user_id: Uuid,
    pub expires_at: u64,
    pub state: PasskeyAuthentication,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub auth_method: String,
    #[serde(default)]
    pub current_credential_id: Option<String>,
    pub session_version: u64,
    pub created_at: u64,
    pub last_seen_at: u64,
    pub absolute_expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthEvent {
    pub sequence: u64,
    pub id: Uuid,
    pub tenant_id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub subject: Option<Uuid>,
    pub occurred_at: u64,
    #[serde(default = "empty_event_data")]
    pub data: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum EventLogIntegrityError {
    #[error("auth event log is missing sequence {0}")]
    MissingSequence(u64),
    #[error("auth event log record {sequence} is malformed")]
    MalformedRecord { sequence: u64 },
    #[error("auth event log record {expected} contains sequence {actual}")]
    UnexpectedSequence { expected: u64, actual: u64 },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserSearch {
    pub user_id: Option<Uuid>,
    pub identifier: Option<IdentifierValue>,
    pub passkey_credential_id: Option<String>,
    pub passkey_label: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct UserSearchPage {
    pub users: Vec<User>,
    pub next_after: Option<Uuid>,
}

impl UserSearch {
    pub fn is_empty(&self) -> bool {
        self.user_id.is_none()
            && self.identifier.is_none()
            && self.passkey_credential_id.is_none()
            && self.passkey_label.is_none()
            && self.given_name.is_none()
            && self.family_name.is_none()
            && self.display_name.is_none()
    }

    fn matches(&self, user: &User) -> bool {
        self.user_id.is_none_or(|value| user.id == value)
            && self.identifier.as_ref().is_none_or(|value| {
                user.identifiers
                    .iter()
                    .any(|stored| stored.kind == value.kind && stored.value == value.value)
            })
            && self
                .passkey_credential_id
                .as_ref()
                .is_none_or(|value| user.passkeys.iter().any(|stored| stored.id == *value))
            && self
                .passkey_label
                .as_ref()
                .is_none_or(|value| user.passkeys.iter().any(|stored| stored.label == *value))
            && self
                .given_name
                .as_ref()
                .is_none_or(|value| user.profile.given_name.as_ref() == Some(value))
            && self
                .family_name
                .as_ref()
                .is_none_or(|value| user.profile.family_name.as_ref() == Some(value))
            && self
                .display_name
                .as_ref()
                .is_none_or(|value| user.profile.display_name.as_ref() == Some(value))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalAgentHandoff {
    pub user_id: Uuid,
    pub redirect_url: String,
    pub expires_at: u64,
}

const MAX_IDENTIFIERS: usize = 20;
const MAX_USER_SCAN: usize = 1_000_000;

#[derive(Clone)]
pub struct Store {
    redis: redis::aio::ConnectionManager,
    mutation: Arc<Mutex<()>>,
    tenant_id: String,
}

impl Store {
    pub fn new(redis: redis::aio::ConnectionManager, tenant_id: String) -> Self {
        Self {
            redis,
            mutation: Arc::new(Mutex::new(())),
            tenant_id,
        }
    }

    pub fn connection(&self) -> redis::aio::ConnectionManager {
        self.redis.clone()
    }

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

    pub async fn search_users(
        &self,
        search: &UserSearch,
        after: Option<Uuid>,
        page_size: usize,
    ) -> Result<UserSearchPage> {
        if search.is_empty() {
            bail!("at least one user search criterion is required");
        }
        if page_size == 0 || page_size > 100 {
            bail!("user search page size must be between 1 and 100");
        }

        let direct_lookup = search.user_id.is_some()
            || search.identifier.is_some()
            || search.passkey_credential_id.is_some();
        let direct = if let Some(user_id) = search.user_id {
            self.user(user_id).await?
        } else if let Some(identifier) = &search.identifier {
            self.user_by_identifier(identifier).await?
        } else if let Some(credential_id) = &search.passkey_credential_id {
            self.user_by_credential_id(credential_id).await?
        } else {
            None
        };

        if direct_lookup {
            let users = direct
                .filter(|user| after.is_none_or(|cursor| user.id > cursor))
                .filter(|user| search.matches(user))
                .into_iter()
                .collect();
            return Ok(UserSearchPage {
                users,
                next_after: None,
            });
        }

        let mut users = Vec::with_capacity(page_size.saturating_add(1));
        for id in self.user_ids().await? {
            if after.is_some_and(|cursor| id <= cursor) {
                continue;
            }
            let user = self
                .user(id)
                .await?
                .context("user disappeared during identity search")?;
            if search.matches(&user) {
                users.push(user);
                if users.len() > page_size {
                    break;
                }
            }
        }
        let next_after = (users.len() > page_size).then(|| users[page_size - 1].id);
        users.truncate(page_size);
        Ok(UserSearchPage { users, next_after })
    }

    pub async fn save_registration(&self, ceremony: &RegistrationCeremony) -> Result<()> {
        self.set_json_ex(
            &format!("auth:registration:{}", ceremony.id),
            ceremony,
            ceremony.expires_at.saturating_sub(now()).max(1),
        )
        .await
    }

    pub async fn take_registration(&self, id: Uuid) -> Result<RegistrationCeremony> {
        let ceremony: RegistrationCeremony = self
            .take_json(&format!("auth:registration:{id}"))
            .await?
            .context("registration ceremony is missing or already used")?;
        if ceremony.expires_at <= now() {
            bail!("registration ceremony has expired");
        }
        Ok(ceremony)
    }

    pub async fn save_authentication(&self, ceremony: &AuthenticationCeremony) -> Result<()> {
        self.set_json_ex(
            &format!("auth:authentication:{}", ceremony.id),
            ceremony,
            ceremony.expires_at.saturating_sub(now()).max(1),
        )
        .await
    }

    pub async fn take_authentication(&self, id: Uuid) -> Result<AuthenticationCeremony> {
        let ceremony: AuthenticationCeremony = self
            .take_json(&format!("auth:authentication:{id}"))
            .await?
            .context("authentication ceremony is missing or already used")?;
        if ceremony.expires_at <= now() {
            bail!("authentication ceremony has expired");
        }
        Ok(ceremony)
    }

    pub async fn create_user_with_passkey(
        &self,
        user_id: Uuid,
        email: String,
        passkey: Passkey,
        email_verified: bool,
    ) -> Result<User> {
        let identifier = IdentifierValue::canonical(IdentifierKind::Email, &email)?;
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
            email: identifier.value.clone(),
            email_verified,
            profile: AccountProfile::default(),
            identifiers: vec![AccountIdentifier {
                kind: IdentifierKind::Email,
                value: identifier.value.clone(),
                verified: email_verified,
                verified_at: email_verified.then_some(created_at),
                primary: true,
                created_at,
            }],
            session_version: 1,
            created_at,
            passkeys: vec![StoredPasskey {
                id: id.clone(),
                label: "Primary passkey".into(),
                counter: credential.counter,
                created_at,
                last_used_at: None,
                passkey,
            }],
        };
        let mut event_inputs = vec![(
            "identity.created",
            Some(user_id),
            json!({ "email": identifier.value }),
        )];
        if !email_verified {
            event_inputs.push((
                "email.verification.requested",
                Some(user_id),
                json!({ "email": identifier.value }),
            ));
        }
        let events = self.next_events(event_inputs).await?;
        let mut connection = self.redis.clone();
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(
                format!("auth:user:{user_id}"),
                serde_json::to_string(&user)?,
            )
            .set(identifier_key(&identifier), user_id.to_string())
            .set(
                format!("auth:email:{}", identifier.value),
                user_id.to_string(),
            )
            .set(format!("auth:credential:{id}"), user_id.to_string());
        queue_events(&mut pipeline, &events)?;
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("persist user, passkey, and identity events")?;
        Ok(user)
    }

    pub async fn add_identifier(
        &self,
        user_id: Uuid,
        identifier: IdentifierValue,
        verified: bool,
    ) -> Result<User> {
        require_canonical_identifier(&identifier)?;
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
        user.identifiers.remove(position);
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

    pub async fn update_profile(&self, user_id: Uuid, profile: AccountProfile) -> Result<User> {
        validate_account_profile(&profile)?;
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

    pub async fn apply_authentication(
        &self,
        user_id: Uuid,
        result: &AuthenticationResult,
    ) -> Result<User> {
        let _guard = self.mutation.lock().await;
        let mut user = self
            .user(user_id)
            .await?
            .ok_or(StorePolicyError::UserMissing)?;
        let id = URL_SAFE_NO_PAD.encode(result.cred_id().as_ref());
        let stored = user
            .passkeys
            .iter_mut()
            .find(|passkey| passkey.id == id)
            .ok_or(StorePolicyError::CredentialNotLinked)?;
        let next = result.counter();
        if next > 0 && stored.counter > 0 && next <= stored.counter {
            bail!("passkey counter did not advance; possible cloned credential");
        }
        stored
            .passkey
            .update_credential(result)
            .context("passkey result does not match stored credential")?;
        stored.counter = next.max(stored.counter);
        stored.last_used_at = Some(now());
        self.set_json(&format!("auth:user:{user_id}"), &user)
            .await?;
        Ok(user)
    }

    pub async fn add_passkey(
        &self,
        user_id: Uuid,
        label: String,
        passkey: Passkey,
    ) -> Result<User> {
        let _guard = self.mutation.lock().await;
        let mut user = self
            .user(user_id)
            .await?
            .ok_or(StorePolicyError::UserMissing)?;
        let id = credential_id(&passkey);
        if self
            .get::<String>(&format!("auth:credential:{id}"))
            .await?
            .is_some()
        {
            return Err(StorePolicyError::CredentialAlreadyExists.into());
        }
        let credential: webauthn_rs::prelude::Credential = passkey.clone().into();
        user.passkeys.push(StoredPasskey {
            id: id.clone(),
            label,
            counter: credential.counter,
            created_at: now(),
            last_used_at: None,
            passkey,
        });
        let event = self
            .next_event(
                "credential.created",
                Some(user_id),
                json!({ "credentialId": id }),
            )
            .await?;
        let mut connection = self.redis.clone();
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(
                format!("auth:user:{user_id}"),
                serde_json::to_string(&user)?,
            )
            .set(format!("auth:credential:{id}"), user_id.to_string());
        queue_events(&mut pipeline, &[event])?;
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("persist additional passkey and event")?;
        Ok(user)
    }

    pub async fn rename_passkey(
        &self,
        user_id: Uuid,
        credential_id: &str,
        label: String,
    ) -> Result<User> {
        let _guard = self.mutation.lock().await;
        let mut user = self
            .user(user_id)
            .await?
            .ok_or(StorePolicyError::UserMissing)?;
        let passkey = user
            .passkeys
            .iter_mut()
            .find(|passkey| passkey.id == credential_id)
            .ok_or(StorePolicyError::CredentialNotLinked)?;
        passkey.label = label;
        let event = self
            .next_event(
                "credential.renamed",
                Some(user_id),
                json!({ "credentialId": credential_id }),
            )
            .await?;
        let mut connection = self.redis.clone();
        let mut pipeline = redis::pipe();
        pipeline.atomic().set(
            format!("auth:user:{user_id}"),
            serde_json::to_string(&user)?,
        );
        queue_events(&mut pipeline, &[event])?;
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("rename passkey and persist event")?;
        Ok(user)
    }

    pub async fn revoke_passkey(&self, user_id: Uuid, credential_id: &str) -> Result<User> {
        let _guard = self.mutation.lock().await;
        let mut user = self
            .user(user_id)
            .await?
            .ok_or(StorePolicyError::UserMissing)?;
        if user.passkeys.len() <= 1 {
            return Err(StorePolicyError::FinalCredential.into());
        }
        let position = user
            .passkeys
            .iter()
            .position(|passkey| passkey.id == credential_id)
            .ok_or(StorePolicyError::CredentialNotLinked)?;
        user.passkeys.remove(position);
        let event = self
            .next_event(
                "credential.revoked",
                Some(user_id),
                json!({ "credentialId": credential_id }),
            )
            .await?;
        let mut connection = self.redis.clone();
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(
                format!("auth:user:{user_id}"),
                serde_json::to_string(&user)?,
            )
            .del(format!("auth:credential:{credential_id}"));
        queue_events(&mut pipeline, &[event])?;
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("revoke passkey and persist event")?;
        Ok(user)
    }

    pub async fn create_session(
        &self,
        user: &User,
        auth_method: &str,
        current_credential_id: Option<String>,
        absolute_seconds: u64,
    ) -> Result<(String, Session)> {
        let _guard = self.mutation.lock().await;
        let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let current = now();
        let session = Session {
            id: Uuid::new_v4(),
            user_id: user.id,
            auth_method: auth_method.into(),
            current_credential_id: current_credential_id.clone(),
            session_version: user.session_version,
            created_at: current,
            last_seen_at: current,
            absolute_expires_at: current + absolute_seconds,
        };
        let event = self
            .next_event(
                "session.created",
                Some(user.id),
                json!({
                    "authMethod": auth_method,
                    "credentialId": current_credential_id,
                }),
            )
            .await?;
        let mut connection = self.redis.clone();
        let mut pipeline = redis::pipe();
        pipeline.atomic().set_ex(
            session_key(&token),
            serde_json::to_string(&session)?,
            absolute_seconds,
        );
        queue_events(&mut pipeline, &[event])?;
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("persist session and event")?;
        Ok((token, session))
    }

    pub async fn session(&self, token: &str, idle_seconds: u64) -> Result<Option<(Session, User)>> {
        if token.len() < 32 || token.len() > 256 {
            return Ok(None);
        }
        let key = session_key(token);
        let Some(mut session) = self.get_json::<Session>(&key).await? else {
            return Ok(None);
        };
        let current = now();
        if session.absolute_expires_at <= current || session.last_seen_at + idle_seconds <= current
        {
            self.delete(&key).await?;
            return Ok(None);
        }
        let Some(user) = self.user(session.user_id).await? else {
            self.delete(&key).await?;
            return Ok(None);
        };
        if user.session_version != session.session_version {
            self.delete(&key).await?;
            return Ok(None);
        }
        session.last_seen_at = current;
        self.set_json_ex(&key, &session, session.absolute_expires_at - current)
            .await?;
        Ok(Some((session, user)))
    }

    pub async fn delete_session(&self, token: &str) -> Result<()> {
        self.delete(&session_key(token)).await
    }

    pub async fn create_local_agent_handoff(
        &self,
        email: &str,
        redirect_url: String,
        lifetime_seconds: u64,
    ) -> Result<String> {
        let _guard = self.mutation.lock().await;
        let user = self
            .user_by_email(email)
            .await?
            .context("account does not exist")?;
        let code = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let handoff = LocalAgentHandoff {
            user_id: user.id,
            redirect_url,
            expires_at: now() + lifetime_seconds,
        };
        let event = self
            .next_event("agent.handoff.created", Some(user.id), json!({}))
            .await?;
        let mut connection = self.redis.clone();
        let mut pipeline = redis::pipe();
        pipeline.atomic().set_ex(
            handoff_key(&code),
            serde_json::to_string(&handoff)?,
            lifetime_seconds,
        );
        queue_events(&mut pipeline, &[event])?;
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("persist local agent handoff and event")?;
        Ok(code)
    }

    pub async fn take_local_agent_handoff(&self, code: &str) -> Result<LocalAgentHandoff> {
        if code.len() < 32 || code.len() > 256 {
            bail!("agent handoff code is invalid");
        }
        let handoff: LocalAgentHandoff = self
            .take_json(&handoff_key(code))
            .await?
            .context("agent handoff is missing or already used")?;
        if handoff.expires_at <= now() {
            bail!("agent handoff has expired");
        }
        Ok(handoff)
    }

    pub async fn append_event(
        &self,
        event_type: &str,
        subject: Option<Uuid>,
        data: Value,
    ) -> Result<AuthEvent> {
        let _guard = self.mutation.lock().await;
        let event = self.next_event(event_type, subject, data).await?;
        let mut connection = self.redis.clone();
        let mut pipeline = redis::pipe();
        pipeline.atomic();
        queue_events(&mut pipeline, std::slice::from_ref(&event))?;
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("persist auth event")?;
        Ok(event)
    }

    pub async fn events(&self, after: u64, limit: u64) -> Result<Vec<AuthEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let latest = self.latest_event_sequence().await?;
        let end = latest.min(after.saturating_add(limit));
        if end <= after {
            return Ok(Vec::new());
        }
        let keys = (after + 1..=end)
            .map(|sequence| format!("auth:event:{sequence}"))
            .collect::<Vec<_>>();
        let mut connection = self.redis.clone();
        let values: Vec<Option<String>> = redis::cmd("MGET")
            .arg(&keys)
            .query_async(&mut connection)
            .await
            .context("read auth event batch")?;
        let mut result = Vec::with_capacity(values.len());
        for (index, value) in values.into_iter().enumerate() {
            let expected = after + index as u64 + 1;
            let value = value.ok_or(EventLogIntegrityError::MissingSequence(expected))?;
            let event = serde_json::from_str::<AuthEvent>(&value)
                .map_err(|_| EventLogIntegrityError::MalformedRecord { sequence: expected })?;
            if event.sequence != expected {
                return Err(EventLogIntegrityError::UnexpectedSequence {
                    expected,
                    actual: event.sequence,
                }
                .into());
            }
            result.push(event);
        }
        Ok(result)
    }

    pub async fn latest_event_sequence(&self) -> Result<u64> {
        Ok(self.get::<u64>("auth:event-sequence").await?.unwrap_or(0))
    }

    async fn next_event(
        &self,
        event_type: &str,
        subject: Option<Uuid>,
        data: Value,
    ) -> Result<AuthEvent> {
        let mut events = self.next_events(vec![(event_type, subject, data)]).await?;
        Ok(events.pop().expect("one event input produces one event"))
    }

    async fn next_events(
        &self,
        inputs: Vec<(&str, Option<Uuid>, Value)>,
    ) -> Result<Vec<AuthEvent>> {
        if inputs.iter().any(|(_, _, data)| !data.is_object()) {
            bail!("auth event data must be a JSON object");
        }
        let first = self
            .latest_event_sequence()
            .await?
            .checked_add(1)
            .context("auth event sequence exhausted")?;
        inputs
            .into_iter()
            .enumerate()
            .map(|(index, (event_type, subject, data))| {
                let sequence = first
                    .checked_add(index as u64)
                    .context("auth event sequence exhausted")?;
                Ok(AuthEvent {
                    sequence,
                    id: Uuid::new_v4(),
                    tenant_id: self.tenant_id.clone(),
                    event_type: event_type.into(),
                    subject,
                    occurred_at: now(),
                    data,
                })
            })
            .collect()
    }

    async fn pending_events(&self, inputs: Vec<(String, Option<Uuid>)>) -> Result<Vec<AuthEvent>> {
        let inputs = inputs
            .iter()
            .map(|(event_type, subject)| (event_type.as_str(), *subject, json!({})))
            .collect();
        self.next_events(inputs).await
    }

    async fn user_ids(&self) -> Result<Vec<Uuid>> {
        let mut cursor = 0_u64;
        let mut ids = BTreeSet::new();
        loop {
            let mut connection = self.redis.clone();
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("auth:user:*")
                .arg("COUNT")
                .arg(500_u16)
                .query_async(&mut connection)
                .await
                .context("scan RustyAuth users")?;
            for key in batch {
                let id = key
                    .strip_prefix("auth:user:")
                    .context("user scan returned an invalid key")?;
                ids.insert(Uuid::parse_str(id).context("stored user key has an invalid id")?);
            }
            if ids.len() > MAX_USER_SCAN {
                bail!("RustyAuth user namespace exceeds the one-million-user safety limit");
            }
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        Ok(ids.into_iter().collect())
    }

    async fn get<T: redis::FromRedisValue>(&self, key: &str) -> Result<Option<T>> {
        let mut connection = self.redis.clone();
        connection.get(key).await.context("read SableDB value")
    }

    async fn get_json<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let Some(value) = self.get::<String>(key).await? else {
            return Ok(None);
        };
        Ok(Some(
            serde_json::from_str(&value).context("decode stored JSON")?,
        ))
    }

    async fn take_json<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let mut connection = self.redis.clone();
        let value: Option<String> = redis::cmd("GETDEL")
            .arg(key)
            .query_async(&mut connection)
            .await?;
        value
            .map(|value| serde_json::from_str(&value).context("decode one-time stored JSON"))
            .transpose()
    }

    async fn set_json<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let mut connection = self.redis.clone();
        let _: () = connection.set(key, serde_json::to_string(value)?).await?;
        Ok(())
    }

    async fn persist_user_with_event(
        &self,
        user: &User,
        event_type: &str,
        context: &'static str,
    ) -> Result<()> {
        let events = self
            .pending_events(vec![(event_type.to_owned(), Some(user.id))])
            .await?;
        let mut pipeline = redis::pipe();
        pipeline.atomic().set(
            format!("auth:user:{}", user.id),
            serde_json::to_string(user)?,
        );
        queue_events(&mut pipeline, &events)?;
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context(context)?;
        Ok(())
    }

    async fn set_json_ex<T: Serialize>(&self, key: &str, value: &T, seconds: u64) -> Result<()> {
        let mut connection = self.redis.clone();
        let _: () = connection
            .set_ex(key, serde_json::to_string(value)?, seconds)
            .await?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut connection = self.redis.clone();
        let _: usize = connection.del(key).await?;
        Ok(())
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
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

fn validate_account_profile(profile: &AccountProfile) -> Result<()> {
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

fn require_canonical_identifier(identifier: &IdentifierValue) -> Result<()> {
    let canonical = IdentifierValue::canonical(identifier.kind, &identifier.value)?;
    if canonical != *identifier {
        bail!("account identifier is not canonical");
    }
    Ok(())
}

fn credential_id(passkey: &Passkey) -> String {
    URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref())
}

fn empty_event_data() -> Value {
    json!({})
}

fn queue_events(pipeline: &mut redis::Pipeline, events: &[AuthEvent]) -> Result<()> {
    for event in events {
        pipeline.set(
            format!("auth:event:{}", event.sequence),
            serde_json::to_string(event)?,
        );
    }
    if let Some(event) = events.last() {
        pipeline.set("auth:event-sequence", event.sequence);
    }
    Ok(())
}

fn identifier_key(identifier: &IdentifierValue) -> String {
    format!(
        "auth:identifier:{}:{}",
        identifier.kind.as_str(),
        identifier.value
    )
}

fn session_key(token: &str) -> String {
    format!("auth:session:{:x}", Sha256::digest(token.as_bytes()))
}

fn handoff_key(code: &str) -> String {
    format!("auth:agent-handoff:{:x}", Sha256::digest(code.as_bytes()))
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    fn account(identifier: AccountIdentifier) -> User {
        User {
            id: Uuid::new_v4(),
            email: String::new(),
            email_verified: false,
            profile: AccountProfile::default(),
            identifiers: vec![identifier],
            session_version: 1,
            created_at: 100,
            passkeys: Vec::new(),
        }
    }

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
        assert!(user.identifiers[0].primary);
        assert!(user.identifiers[0].verified);
    }

    #[test]
    fn email_phone_and_profile_values_are_canonicalized() {
        assert_eq!(
            IdentifierValue::canonical(IdentifierKind::Email, " Person@Example.COM ")
                .unwrap()
                .value,
            "person@example.com"
        );
        assert_eq!(
            IdentifierValue::canonical(IdentifierKind::Phone, "+44 (7700) 900-123")
                .unwrap()
                .value,
            "+447700900123"
        );
        assert_eq!(
            AccountProfile::canonical(
                Some(" Ada ".into()),
                Some(" Lovelace ".into()),
                Some(" Countess ".into()),
            )
            .unwrap()
            .display_name
            .as_deref(),
            Some("Countess")
        );
    }

    #[test]
    fn corrupt_identifier_and_profile_state_fails_closed() {
        let mut identifier = AccountIdentifier {
            kind: IdentifierKind::Phone,
            value: "+447700900123".into(),
            verified: false,
            verified_at: Some(100),
            primary: true,
            created_at: 100,
        };
        assert!(
            account(identifier.clone())
                .normalize_and_validate()
                .is_err()
        );

        identifier.verified_at = None;
        identifier.value = "+44 7700 900123".into();
        assert!(account(identifier).normalize_and_validate().is_err());

        let mut user = account(AccountIdentifier {
            kind: IdentifierKind::Email,
            value: "person@example.com".into(),
            verified: true,
            verified_at: Some(100),
            primary: true,
            created_at: 100,
        });
        user.profile.display_name = Some("safe\u{2066}spoof\u{2069}".into());
        assert!(user.normalize_and_validate().is_err());
    }
}
