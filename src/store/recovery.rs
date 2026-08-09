//! Offline account-recovery codes and recovery passkey enrolment.
//!
//! Codes carry 160 bits of randomness, are returned once, and are persisted only
//! as domain-separated SHA-256 digests inside the account aggregate. Consuming a
//! code is serialized with account mutations. Completing recovery adds a new
//! passkey, revokes every older session, and invalidates every remaining code.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use super::{
    IdentifierValue, RecoveryCodeRecord, Store, StorePolicyError, StoredPasskey, User,
    credential_id, events::queue_events, now,
};

const RECOVERY_CODE_COUNT: usize = 10;
const RECOVERY_CODE_PREFIX: &str = "rrc_";
const RECOVERY_DIGEST_DOMAIN: &[u8] = b"rustyauth.account-recovery.v1\0";

impl Store {
    pub async fn rotate_recovery_codes(&self, user_id: Uuid) -> Result<(User, Vec<String>)> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut user = self
            .user(user_id)
            .await?
            .ok_or(StorePolicyError::UserMissing)?;
        let created_at = now();
        let raw_codes = (0..RECOVERY_CODE_COUNT)
            .map(|_| {
                format!(
                    "{RECOVERY_CODE_PREFIX}{}",
                    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 20]>())
                )
            })
            .collect::<Vec<_>>();
        user.recovery_codes = raw_codes
            .iter()
            .map(|code| RecoveryCodeRecord {
                digest: recovery_digest(code),
                created_at,
            })
            .collect();
        self.persist_user_with_event(
            &user,
            "account.recovery_codes.rotated",
            "persist replacement recovery codes",
        )
        .await?;
        Ok((user, raw_codes))
    }

    pub async fn consume_recovery_code(
        &self,
        identifier: &IdentifierValue,
        raw_code: &str,
    ) -> Result<User> {
        validate_recovery_code(raw_code)?;
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut user = self
            .user_by_identifier(identifier)
            .await?
            .ok_or(StorePolicyError::UserMissing)?;
        let candidate = recovery_digest(raw_code);
        let Some(index) = user
            .recovery_codes
            .iter()
            .position(|record| bool::from(record.digest.as_bytes().ct_eq(candidate.as_bytes())))
        else {
            bail!("recovery code is invalid or already used");
        };
        user.recovery_codes.remove(index);
        self.persist_user_with_event(
            &user,
            "account.recovery.started",
            "consume one-time account recovery code",
        )
        .await?;
        Ok(user)
    }

    pub async fn add_recovery_passkey(
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
        user.session_version = user.session_version.saturating_add(1);
        user.recovery_codes.clear();
        let events = self
            .pending_events(vec![
                ("account.recovery.completed".to_owned(), Some(user_id)),
                ("credential.created".to_owned(), Some(user_id)),
                ("session.revoked_all".to_owned(), Some(user_id)),
            ])
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
            .context("complete account recovery and revoke older sessions")?;
        Ok(user)
    }
}

fn validate_recovery_code(raw_code: &str) -> Result<()> {
    if raw_code.len() != 31
        || !raw_code.starts_with(RECOVERY_CODE_PREFIX)
        || !raw_code[RECOVERY_CODE_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("recovery code is invalid or already used");
    }
    Ok(())
}

fn recovery_digest(raw_code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_DIGEST_DOMAIN);
    hasher.update(raw_code.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_codes_have_a_strict_high_entropy_shape() {
        let code = format!(
            "{RECOVERY_CODE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode([7_u8; 20])
        );
        assert_eq!(code.len(), 31);
        assert!(validate_recovery_code(&code).is_ok());
        assert!(validate_recovery_code("rrc_short").is_err());
        assert!(validate_recovery_code(&format!("{}!", &code[..30])).is_err());
    }

    #[test]
    fn recovery_code_digests_are_stable_domain_separated_and_non_secret() {
        let code = "rrc_BwcHBwcHBwcHBwcHBwcHBwcHBwc";
        let digest = recovery_digest(code);
        assert_eq!(digest.len(), 64);
        assert_ne!(digest, hex::encode(Sha256::digest(code.as_bytes())));
        assert_eq!(digest, recovery_digest(code));
        assert_ne!(digest, recovery_digest("rrc_CAcICAgICAgICAgICAgICAgICAg"));
    }
}
