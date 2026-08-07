//! SableDB persistence boundary.
//!
//! All durable key construction and serialization is centralized here. Public
//! HTTP handlers do not issue database commands directly. Compound mutations
//! use atomic pipelines and are serialized within the single supported writer.

use std::{
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
    #[error("email already has an account")]
    EmailAlreadyExists,
    #[error("passkey is already registered")]
    CredentialAlreadyExists,
    #[error("user is missing")]
    UserMissing,
    #[error("passkey is not linked to this user")]
    CredentialNotLinked,
    #[error("the final passkey cannot be removed")]
    FinalCredential,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalAgentHandoff {
    pub user_id: Uuid,
    pub redirect_url: String,
    pub expires_at: u64,
}

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
        let Some(id) = self.get::<String>(&format!("auth:email:{email}")).await? else {
            return Ok(None);
        };
        self.user(Uuid::parse_str(&id).context("stored user id is invalid")?)
            .await
    }

    pub async fn user(&self, id: Uuid) -> Result<Option<User>> {
        self.get_json(&format!("auth:user:{id}")).await
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
        let _guard = self.mutation.lock().await;
        if self.user_by_email(&email).await?.is_some() {
            return Err(StorePolicyError::EmailAlreadyExists.into());
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
        let user = User {
            id: user_id,
            email: email.clone(),
            email_verified,
            session_version: 1,
            created_at: now(),
            passkeys: vec![StoredPasskey {
                id: id.clone(),
                label: "Primary passkey".into(),
                counter: credential.counter,
                created_at: now(),
                last_used_at: None,
                passkey,
            }],
        };
        let mut event_inputs = vec![("identity.created", Some(user_id), json!({ "email": email }))];
        if !email_verified {
            event_inputs.push((
                "email.verification.requested",
                Some(user_id),
                json!({ "email": email }),
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
            .set(format!("auth:email:{email}"), user_id.to_string())
            .set(format!("auth:credential:{id}"), user_id.to_string());
        queue_events(&mut pipeline, &events)?;
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("persist user, passkey, and events")?;
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

fn session_key(token: &str) -> String {
    format!("auth:session:{:x}", Sha256::digest(token.as_bytes()))
}

fn handoff_key(code: &str) -> String {
    format!("auth:agent-handoff:{:x}", Sha256::digest(code.as_bytes()))
}
