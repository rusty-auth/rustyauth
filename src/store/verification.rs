//! One-time email and phone verification challenges.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::{IdentifierValue, Store, StorePolicyError, now};

const VERIFICATION_SECONDS: u64 = 900;
const VERIFICATION_DOMAIN: &[u8] = b"rustyauth.identifier-verification.v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentifierVerificationChallenge {
    pub id: Uuid,
    pub user_id: Uuid,
    pub identifier: IdentifierValue,
    pub code_digest: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl Store {
    pub async fn create_identifier_verification(
        &self,
        user_id: Uuid,
        identifier: IdentifierValue,
    ) -> Result<(IdentifierVerificationChallenge, String)> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let user = self
            .user(user_id)
            .await?
            .ok_or(StorePolicyError::UserMissing)?;
        let account_identifier = user
            .identifiers
            .iter()
            .find(|candidate| {
                candidate.kind == identifier.kind && candidate.value == identifier.value
            })
            .ok_or(StorePolicyError::IdentifierNotLinked)?;
        if account_identifier.verified {
            bail!("identifier is already verified");
        }
        let raw_code = format!("rvc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>()));
        let created_at = now();
        let challenge = IdentifierVerificationChallenge {
            id: Uuid::new_v4(),
            user_id,
            identifier,
            code_digest: verification_digest(&raw_code),
            created_at,
            expires_at: created_at.saturating_add(VERIFICATION_SECONDS),
        };
        self.set_json_ex(
            &verification_key(challenge.id),
            &challenge,
            VERIFICATION_SECONDS,
        )
        .await?;
        self.append_event_locked("identifier.verification.requested", Some(user_id))
            .await?;
        Ok((challenge, raw_code))
    }

    pub async fn consume_identifier_verification(
        &self,
        challenge_id: Uuid,
        user_id: Uuid,
        raw_code: &str,
    ) -> Result<IdentifierValue> {
        validate_verification_code(raw_code)?;
        let _snapshot = self.snapshot_gate.read().await;
        let challenge = self
            .take_json::<IdentifierVerificationChallenge>(&verification_key(challenge_id))
            .await?
            .context("verification challenge is missing or already used")?;
        if challenge.user_id != user_id || challenge.expires_at <= now() {
            bail!("verification challenge is invalid or expired");
        }
        let candidate = verification_digest(raw_code);
        if !bool::from(challenge.code_digest.as_bytes().ct_eq(candidate.as_bytes())) {
            bail!("verification challenge is invalid or expired");
        }
        Ok(challenge.identifier)
    }

    pub async fn delete_identifier_verification(&self, challenge_id: Uuid) -> Result<()> {
        self.delete(&verification_key(challenge_id)).await
    }
}

fn verification_key(id: Uuid) -> String {
    format!("auth:identifier-verification:{id}")
}

fn validate_verification_code(raw_code: &str) -> Result<()> {
    if raw_code.len() != 26
        || !raw_code.starts_with("rvc_")
        || !raw_code[4..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("verification challenge is invalid or expired");
    }
    Ok(())
}

fn verification_digest(raw_code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(VERIFICATION_DOMAIN);
    hasher.update(raw_code.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_codes_are_strict_and_domain_separated() {
        let code = format!("rvc_{}", URL_SAFE_NO_PAD.encode([9_u8; 16]));
        assert_eq!(code.len(), 26);
        assert!(validate_verification_code(&code).is_ok());
        assert!(validate_verification_code("rvc_short").is_err());
        assert_ne!(
            verification_digest(&code),
            hex::encode(Sha256::digest(code.as_bytes()))
        );
    }
}
