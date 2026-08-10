//! Realm-side Fleet pairing and credential custody.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{MeasuredConnection, Store, StorePolicyError, now};

const PAIRING_PREFIX: &str = "auth:fleet-pairing:";
const GRANT_PREFIX: &str = "auth:fleet-grant:";
const GRANT_SECRET_PREFIX: &str = "auth:fleet-grant-secret:";
const GRANT_ROTATION_PREFIX: &str = "auth:fleet-grant-rotation:";
const PAIRING_SECONDS: u64 = 600;
const GRANT_SECONDS: u64 = 31_536_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RealmPairingRecord {
    pub id: Uuid,
    pub realm_id: String,
    pub control_plane_origin: String,
    pub requested_scopes: Vec<String>,
    pub created_by: Uuid,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RealmFleetGrantRecord {
    pub connection_id: Uuid,
    pub realm_id: String,
    pub control_plane_origin: String,
    pub control_plane_instance_id: String,
    #[serde(default = "initial_assignment_epoch")]
    pub assignment_epoch: u64,
    pub credential_digest: String,
    pub credential_hint: String,
    pub granted_scopes: Vec<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RealmFleetGrantRotationRecord {
    connection_id: Uuid,
    credential_digest: String,
    completed_at: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RealmSummaryCounts {
    pub users: u64,
    pub passkeys: u64,
    pub active_sessions: u64,
    pub service_accounts: u64,
}

impl Store {
    pub async fn create_realm_pairing(
        &self,
        realm_id: String,
        control_plane_origin: String,
        requested_scopes: Vec<String>,
        created_by: Uuid,
    ) -> Result<(RealmPairingRecord, String)> {
        let _snapshot = self.snapshot_gate.read().await;
        let timestamp = now();
        let record = RealmPairingRecord {
            id: Uuid::new_v4(),
            realm_id,
            control_plane_origin,
            requested_scopes,
            created_by,
            created_at: timestamp,
            expires_at: timestamp.saturating_add(PAIRING_SECONDS),
        };
        let mut random = [0_u8; 32];
        rand::rng().fill_bytes(&mut random);
        let code = format!("rpair_{}", URL_SAFE_NO_PAD.encode(random));
        let key = pairing_key(&code);
        let mut connection = self.redis.clone();
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg(serde_json::to_string(&record)?)
            .arg("EX")
            .arg(PAIRING_SECONDS)
            .query_async(&mut connection)
            .await
            .context("persist one-time realm pairing code")?;
        Ok((record, code))
    }

    pub async fn exchange_realm_pairing(
        &self,
        code: &str,
        control_plane_origin: &str,
        control_plane_instance_id: String,
        assignment_epoch: u64,
    ) -> Result<(RealmFleetGrantRecord, String)> {
        if assignment_epoch == 0 {
            anyhow::bail!("Fleet assignment epoch must be positive");
        }
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let pairing = self
            .take_json::<RealmPairingRecord>(&pairing_key(code))
            .await?
            .filter(|record| {
                record.expires_at > now() && record.control_plane_origin == control_plane_origin
            })
            .ok_or(StorePolicyError::RealmPairingInvalid)?;
        let mut random = [0_u8; 32];
        rand::rng().fill_bytes(&mut random);
        let credential = format!("rfg_{}", URL_SAFE_NO_PAD.encode(random));
        let digest = credential_digest(&credential);
        let timestamp = now();
        let grant = RealmFleetGrantRecord {
            connection_id: Uuid::new_v4(),
            realm_id: pairing.realm_id,
            control_plane_origin: pairing.control_plane_origin,
            control_plane_instance_id,
            assignment_epoch,
            credential_digest: digest.clone(),
            credential_hint: credential
                .chars()
                .rev()
                .take(6)
                .collect::<String>()
                .chars()
                .rev()
                .collect(),
            granted_scopes: pairing.requested_scopes,
            created_at: timestamp,
            expires_at: timestamp.saturating_add(GRANT_SECONDS),
            revoked_at: None,
        };
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(
                grant_key(grant.connection_id),
                serde_json::to_string(&grant)?,
            )
            .ignore()
            .set(grant_secret_key(&digest), grant.connection_id.to_string())
            .ignore();
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("persist realm Fleet grant")?;
        Ok((grant, credential))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn consume_outbound_realm_pairing(
        &self,
        code: &str,
        control_plane_origin: &str,
        control_plane_instance_id: String,
        assignment_epoch: u64,
        connection_id: Uuid,
        credential: &str,
        granted_scopes: &[String],
    ) -> Result<RealmFleetGrantRecord> {
        if assignment_epoch == 0
            || !credential.starts_with("rfg_")
            || !(32..=128).contains(&credential.len())
        {
            anyhow::bail!("outbound Fleet grant is invalid");
        }
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let pairing = self
            .take_json::<RealmPairingRecord>(&pairing_key(code))
            .await?
            .filter(|record| {
                record.expires_at > now()
                    && record.control_plane_origin == control_plane_origin
                    && record.requested_scopes == granted_scopes
            })
            .ok_or(StorePolicyError::RealmPairingInvalid)?;
        let timestamp = now();
        let digest = credential_digest(credential);
        let grant = RealmFleetGrantRecord {
            connection_id,
            realm_id: pairing.realm_id,
            control_plane_origin: pairing.control_plane_origin,
            control_plane_instance_id,
            assignment_epoch,
            credential_digest: digest.clone(),
            credential_hint: credential
                .chars()
                .rev()
                .take(6)
                .collect::<String>()
                .chars()
                .rev()
                .collect(),
            granted_scopes: granted_scopes.to_vec(),
            created_at: timestamp,
            expires_at: timestamp.saturating_add(GRANT_SECONDS),
            revoked_at: None,
        };
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(
                grant_key(grant.connection_id),
                serde_json::to_string(&grant)?,
            )
            .ignore()
            .set(grant_secret_key(&digest), grant.connection_id.to_string())
            .ignore();
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("persist outbound realm Fleet grant")?;
        Ok(grant)
    }

    pub async fn realm_fleet_grant_by_credential(
        &self,
        credential: &str,
    ) -> Result<Option<RealmFleetGrantRecord>> {
        let digest = credential_digest(credential);
        let Some(id) = self.get::<String>(&grant_secret_key(&digest)).await? else {
            return Ok(None);
        };
        let id = Uuid::parse_str(&id).context("stored realm Fleet grant locator has invalid id")?;
        Ok(self
            .get_json::<RealmFleetGrantRecord>(&grant_key(id))
            .await?
            .filter(|grant| {
                grant.revoked_at.is_none()
                    && grant.expires_at > now()
                    && grant.credential_digest == digest
            }))
    }

    /// Active grants that permit realm-initiated aggregate export. The realm
    /// retains only the one-way connector proof material, never the Fleet-held
    /// management credential returned during pairing.
    pub async fn realm_telemetry_export_grants(&self) -> Result<Vec<RealmFleetGrantRecord>> {
        let mut grants = Vec::new();
        for id in self
            .record_ids(GRANT_PREFIX, "scan realm Fleet grants")
            .await?
        {
            if let Some(grant) = self
                .get_json::<RealmFleetGrantRecord>(&grant_key(id))
                .await?
                .filter(|grant| {
                    grant.revoked_at.is_none()
                        && grant.expires_at > now()
                        && grant
                            .granted_scopes
                            .iter()
                            .any(|scope| scope == "telemetry.export")
                })
            {
                grants.push(grant);
            }
        }
        grants.sort_unstable_by_key(|grant| std::cmp::Reverse(grant.created_at));
        Ok(grants)
    }

    pub async fn revoke_realm_fleet_grant(
        &self,
        connection_id: Uuid,
    ) -> Result<RealmFleetGrantRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut grant = self
            .get_json::<RealmFleetGrantRecord>(&grant_key(connection_id))
            .await?
            .ok_or(StorePolicyError::RealmFleetGrantInvalid)?;
        if grant.revoked_at.is_none() {
            grant.revoked_at = Some(now());
        }
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(grant_key(connection_id), serde_json::to_string(&grant)?)
            .ignore()
            .del(grant_secret_key(&grant.credential_digest))
            .ignore();
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("revoke realm Fleet grant")?;
        Ok(grant)
    }

    pub async fn rotate_realm_fleet_grant(
        &self,
        connection_id: Uuid,
        request_id: Uuid,
        credential: &str,
        credential_hint: &str,
    ) -> Result<RealmFleetGrantRecord> {
        if !credential.starts_with("rfg_")
            || !(32..=128).contains(&credential.len())
            || credential_hint.len() > 32
        {
            anyhow::bail!("new Fleet grant credential is invalid");
        }
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let digest = credential_digest(credential);
        let rotation_key = format!("{GRANT_ROTATION_PREFIX}{request_id}");
        if let Some(completed) = self
            .get_json::<RealmFleetGrantRotationRecord>(&rotation_key)
            .await?
        {
            if completed.connection_id != connection_id || completed.credential_digest != digest {
                anyhow::bail!("Fleet credential rotation request was replayed with different data");
            }
            return self
                .get_json::<RealmFleetGrantRecord>(&grant_key(connection_id))
                .await?
                .filter(|grant| grant.revoked_at.is_none() && grant.credential_digest == digest)
                .ok_or_else(|| StorePolicyError::RealmFleetGrantInvalid.into());
        }
        let mut grant = self
            .get_json::<RealmFleetGrantRecord>(&grant_key(connection_id))
            .await?
            .filter(|grant| grant.revoked_at.is_none() && grant.expires_at > now())
            .ok_or(StorePolicyError::RealmFleetGrantInvalid)?;
        let old_digest = grant.credential_digest.clone();
        let timestamp = now();
        grant.credential_digest = digest.clone();
        grant.credential_hint = credential_hint.to_owned();
        grant.created_at = timestamp;
        grant.expires_at = timestamp.saturating_add(GRANT_SECONDS);
        let completed = RealmFleetGrantRotationRecord {
            connection_id,
            credential_digest: digest.clone(),
            completed_at: timestamp,
        };
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(
                grant_key(grant.connection_id),
                serde_json::to_string(&grant)?,
            )
            .ignore()
            .del(grant_secret_key(&old_digest))
            .ignore()
            .set(grant_secret_key(&digest), grant.connection_id.to_string())
            .ignore()
            .set(&rotation_key, serde_json::to_string(&completed)?)
            .arg("EX")
            .arg(86_400)
            .ignore();
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("rotate realm Fleet grant")?;
        Ok(grant)
    }

    pub async fn realm_summary_counts(&self) -> Result<RealmSummaryCounts> {
        let user_ids = self
            .record_ids("auth:user:", "scan users for realm summary")
            .await?;
        let mut counts = RealmSummaryCounts {
            users: user_ids.len() as u64,
            ..RealmSummaryCounts::default()
        };
        for id in user_ids {
            if let Some(user) = self
                .get_json::<super::User>(&format!("auth:user:{id}"))
                .await?
            {
                counts.passkeys = counts.passkeys.saturating_add(user.passkeys.len() as u64);
            }
        }
        counts.active_sessions = count_keys(&self.redis, "auth:session:*").await?;
        counts.service_accounts = self.service_accounts().await?.len() as u64;
        Ok(counts)
    }
}

const fn initial_assignment_epoch() -> u64 {
    1
}

async fn count_keys(redis: &MeasuredConnection, pattern: &str) -> Result<u64> {
    let mut cursor = 0_u64;
    let mut count = 0_u64;
    loop {
        let mut connection = redis.clone();
        let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(500_u16)
            .query_async(&mut connection)
            .await
            .context("scan realm summary records")?;
        count = count.saturating_add(keys.len() as u64);
        cursor = next;
        if cursor == 0 {
            return Ok(count);
        }
    }
}

fn pairing_key(code: &str) -> String {
    format!("{PAIRING_PREFIX}{}", credential_digest(code))
}

fn grant_key(id: Uuid) -> String {
    format!("{GRANT_PREFIX}{id}")
}

fn grant_secret_key(digest: &str) -> String {
    format!("{GRANT_SECRET_PREFIX}{digest}")
}

fn credential_digest(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_pairing_and_grant_credentials_never_appear_in_keys() {
        let code = "rpair_top-secret";
        let key = pairing_key(code);
        assert!(!key.contains("top-secret"));
        assert!(!grant_secret_key(&credential_digest(code)).contains("top-secret"));
    }
}
