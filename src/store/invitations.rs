//! Operator-issued, one-time production enrolment invitations.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::{IdentifierValue, Store, now, require_canonical_identifier};

const INVITATION_PREFIX: &str = "auth:invitation:";
const INVITATION_CODE_PREFIX: &str = "auth:invitation-code:";
const INVITATION_DOMAIN: &[u8] = b"rustyauth.account-invitation.v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInvitationRecord {
    pub id: Uuid,
    pub identifier: IdentifierValue,
    pub code_digest: String,
    pub created_by: Uuid,
    pub created_at: u64,
    pub expires_at: u64,
    pub consumed_at: Option<u64>,
    pub revoked_at: Option<u64>,
}

impl Store {
    pub async fn create_account_invitation(
        &self,
        identifier: IdentifierValue,
        created_by: Uuid,
        lifetime_seconds: u64,
    ) -> Result<(AccountInvitationRecord, String)> {
        require_canonical_identifier(&identifier)?;
        if !(300..=604_800).contains(&lifetime_seconds) {
            bail!("invitation lifetime must be between five minutes and seven days");
        }
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        if self.user_by_identifier(&identifier).await?.is_some() {
            bail!("identifier already has an account");
        }
        let raw_code = format!(
            "rinv_{}",
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
        );
        let digest = invitation_digest(&raw_code);
        let created_at = now();
        let record = AccountInvitationRecord {
            id: Uuid::new_v4(),
            identifier,
            code_digest: digest.clone(),
            created_by,
            created_at,
            expires_at: created_at.saturating_add(lifetime_seconds),
            consumed_at: None,
            revoked_at: None,
        };
        let mut connection = self.redis.clone();
        let _: () = redis::pipe()
            .atomic()
            .set(invitation_key(record.id), serde_json::to_string(&record)?)
            .set(invitation_code_key(&digest), record.id.to_string())
            .query_async(&mut connection)
            .await
            .context("persist account invitation")?;
        self.append_event_locked("account.invitation.created", None)
            .await?;
        Ok((record, raw_code))
    }

    pub async fn account_invitations(&self) -> Result<Vec<AccountInvitationRecord>> {
        let ids = self
            .record_ids(INVITATION_PREFIX, "scan account invitations")
            .await?;
        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(record) = self.account_invitation(id).await? {
                records.push(record);
            }
        }
        records.sort_unstable_by_key(|record| (record.created_at, record.id));
        Ok(records)
    }

    pub async fn account_invitation(&self, id: Uuid) -> Result<Option<AccountInvitationRecord>> {
        self.get_json(&invitation_key(id)).await
    }

    /// Validates a code without consuming it so a WebAuthn ceremony can be
    /// started. The returned digest is safe to persist with the short-lived,
    /// server-side ceremony and is rechecked atomically at completion.
    pub async fn validate_account_invitation(
        &self,
        identifier: &IdentifierValue,
        raw_code: &str,
    ) -> Result<(Uuid, String)> {
        require_canonical_identifier(identifier)?;
        validate_invitation_code(raw_code)?;
        let digest = invitation_digest(raw_code);
        let id = self
            .get::<String>(&invitation_code_key(&digest))
            .await?
            .context("invitation is invalid or already used")?;
        let id = Uuid::parse_str(&id).context("stored invitation id is invalid")?;
        let record = self
            .account_invitation(id)
            .await?
            .context("invitation is invalid or already used")?;
        validate_invitation_record(&record, identifier, &digest)?;
        Ok((id, digest))
    }

    pub async fn consume_account_invitation(
        &self,
        identifier: &IdentifierValue,
        raw_code: &str,
    ) -> Result<AccountInvitationRecord> {
        require_canonical_identifier(identifier)?;
        validate_invitation_code(raw_code)?;
        let digest = invitation_digest(raw_code);
        let id = self
            .get::<String>(&invitation_code_key(&digest))
            .await?
            .context("invitation is invalid or already used")?;
        let id = Uuid::parse_str(&id).context("stored invitation id is invalid")?;
        self.consume_account_invitation_claim(identifier, id, &digest)
            .await
    }

    /// Atomically consumes the invitation claim captured by a short-lived
    /// registration ceremony. A second ceremony racing with the first loses.
    pub async fn consume_account_invitation_claim(
        &self,
        identifier: &IdentifierValue,
        id: Uuid,
        digest: &str,
    ) -> Result<AccountInvitationRecord> {
        require_canonical_identifier(identifier)?;
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("invitation is invalid or already used");
        }
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let indexed_id = self
            .get::<String>(&invitation_code_key(digest))
            .await?
            .context("invitation is invalid or already used")?;
        let indexed_id = Uuid::parse_str(&indexed_id).context("stored invitation id is invalid")?;
        if indexed_id != id {
            bail!("invitation is invalid or already used");
        }
        let mut record = self
            .account_invitation(id)
            .await?
            .context("invitation is invalid or already used")?;
        validate_invitation_record(&record, identifier, digest)?;
        record.consumed_at = Some(now());
        let mut connection = self.redis.clone();
        let _: () = redis::pipe()
            .atomic()
            .set(invitation_key(id), serde_json::to_string(&record)?)
            .del(invitation_code_key(digest))
            .query_async(&mut connection)
            .await
            .context("consume account invitation")?;
        self.append_event_locked("account.invitation.consumed", None)
            .await?;
        Ok(record)
    }

    pub async fn revoke_account_invitation(&self, id: Uuid) -> Result<AccountInvitationRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut record = self
            .account_invitation(id)
            .await?
            .context("invitation is missing")?;
        if record.consumed_at.is_some() {
            bail!("consumed invitations cannot be revoked");
        }
        record.revoked_at.get_or_insert_with(now);
        let mut connection = self.redis.clone();
        let _: () = redis::pipe()
            .atomic()
            .set(invitation_key(id), serde_json::to_string(&record)?)
            .del(invitation_code_key(&record.code_digest))
            .query_async(&mut connection)
            .await
            .context("revoke account invitation")?;
        self.append_event_locked("account.invitation.revoked", None)
            .await?;
        Ok(record)
    }
}

pub(super) fn invitation_key(id: Uuid) -> String {
    format!("{INVITATION_PREFIX}{id}")
}

pub(super) fn invitation_code_key(digest: &str) -> String {
    format!("{INVITATION_CODE_PREFIX}{digest}")
}

fn validate_invitation_code(raw_code: &str) -> Result<()> {
    if raw_code.len() != 48
        || !raw_code.starts_with("rinv_")
        || !raw_code[5..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("invitation is invalid or already used");
    }
    Ok(())
}

fn invitation_digest(raw_code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(INVITATION_DOMAIN);
    hasher.update(raw_code.as_bytes());
    hex::encode(hasher.finalize())
}

pub(super) fn validate_invitation_record(
    record: &AccountInvitationRecord,
    identifier: &IdentifierValue,
    digest: &str,
) -> Result<()> {
    if record.identifier != *identifier
        || record.expires_at <= now()
        || record.consumed_at.is_some()
        || record.revoked_at.is_some()
        || !bool::from(record.code_digest.as_bytes().ct_eq(digest.as_bytes()))
    {
        bail!("invitation is invalid or already used");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_codes_have_a_strict_high_entropy_shape() {
        let code = format!("rinv_{}", URL_SAFE_NO_PAD.encode([5_u8; 32]));
        assert_eq!(code.len(), 48);
        assert!(validate_invitation_code(&code).is_ok());
        assert!(validate_invitation_code("rinv_short").is_err());
        assert_ne!(
            invitation_digest(&code),
            hex::encode(Sha256::digest(code.as_bytes()))
        );
    }
}
