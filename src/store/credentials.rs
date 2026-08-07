//! Passkey credential records and their lifecycle mutations.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{AuthenticationResult, Passkey};

use super::{Store, StorePolicyError, User, credential_id, events::queue_events, now};

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

impl Store {
    pub async fn apply_authentication(
        &self,
        user_id: Uuid,
        result: &AuthenticationResult,
    ) -> Result<User> {
        let _snapshot = self.snapshot_gate.read().await;
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
        if counter_regressed(stored.counter, next) {
            bail!("passkey counter did not advance; possible cloned credential");
        }
        stored
            .passkey
            .update_credential(result)
            .context("passkey result does not match stored credential")?;
        stored.counter = next.max(stored.counter);
        stored.last_used_at = Some(now());
        self.persist_user(&user, "persist passkey authentication state")
            .await?;
        Ok(user)
    }

    pub async fn add_passkey(
        &self,
        user_id: Uuid,
        label: String,
        passkey: Passkey,
    ) -> Result<User> {
        let _snapshot = self.snapshot_gate.read().await;
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
        let events = self
            .pending_events(vec![("credential.created".to_owned(), Some(user_id))])
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
        queue_events(&mut pipeline, &events)?;
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
        let _snapshot = self.snapshot_gate.read().await;
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
        self.persist_user_with_event(
            &user,
            "credential.renamed",
            "persist passkey label and event",
        )
        .await?;
        Ok(user)
    }

    pub async fn revoke_passkey(&self, user_id: Uuid, credential_id: &str) -> Result<User> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut user = self
            .user(user_id)
            .await?
            .ok_or(StorePolicyError::UserMissing)?;
        if user.passkeys.len() <= 1 {
            return Err(StorePolicyError::FinalCredential.into());
        }
        if !user
            .passkeys
            .iter()
            .any(|passkey| passkey.id == credential_id)
        {
            return Err(StorePolicyError::CredentialNotLinked.into());
        }
        user.passkeys.retain(|passkey| passkey.id != credential_id);
        let events = self
            .pending_events(vec![("credential.revoked".to_owned(), Some(user_id))])
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
        queue_events(&mut pipeline, &events)?;
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("revoke passkey and persist event")?;
        Ok(user)
    }
}

/// Reports a passkey sign counter that failed to advance, which is WebAuthn's
/// signal that the credential has been cloned.
///
/// A zero on either side is not evidence of anything: authenticators that
/// implement no counter report zero on every assertion, WebAuthn permits them,
/// and rejecting them would lock out every synced passkey. The control therefore
/// only detects clones of authenticators that do count, and cannot be tightened
/// without breaking the rest.
fn counter_regressed(stored: u32, next: u32) -> bool {
    next > 0 && stored > 0 && next <= stored
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sign_counter_that_does_not_advance_is_treated_as_a_clone() {
        assert!(counter_regressed(10, 10));
        assert!(counter_regressed(10, 9));
        assert!(counter_regressed(1, 1));
        assert!(counter_regressed(u32::MAX, u32::MAX));
        assert!(!counter_regressed(10, 11));
        assert!(!counter_regressed(1, u32::MAX));
    }

    #[test]
    fn counterless_authenticators_are_not_treated_as_clones() {
        assert!(!counter_regressed(0, 0));
        assert!(!counter_regressed(0, 1));
        assert!(!counter_regressed(0, u32::MAX));
        assert!(!counter_regressed(10, 0));
        assert!(!counter_regressed(u32::MAX, 0));
    }
}
