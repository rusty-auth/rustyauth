//! Staged signing-key rotation: maintenance transitions, the cross-process
//! rotation lock and operator-facing status.

use anyhow::{Context, Result, bail};
use redis::AsyncCommands;
use serde::Serialize;
use tokio::sync::watch;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    config::{KeyRing, SigningRotationConfig},
    store::now,
};

use super::{
    JwtIssuer,
    key_material::{StoredSigningKey, generate, open_private_key, seal_private_key},
    keyset::{
        KEYSET_KEY, RetiredPublicKey, StagedSigningKey, StoredKeySet, read_keyset, validate_keyset,
    },
    runtime::runtime_keyset,
};

const MAINTENANCE_LOCK_KEY: &str = "auth:jwt:maintenance-lock";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningKeyStatus {
    pub active_kid: String,
    pub staged_kid: Option<String>,
    pub staged_activates_at: Option<u64>,
    pub retired_kids: Vec<String>,
    pub next_rotation_at: u64,
}

impl JwtIssuer {
    pub async fn stored_status(&self) -> Result<SigningKeyStatus> {
        let keyset = read_keyset(self.inner.redis.clone()).await?;
        Ok(status_for(&keyset, &self.inner.rotation))
    }

    pub async fn force_rotate(&self, activate_immediately: bool) -> Result<SigningKeyStatus> {
        self.maintain_at(now(), true, activate_immediately).await?;
        self.stored_status().await
    }

    pub async fn run_maintenance(self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            self.inner.rotation.maintenance_seconds,
        ));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(error) = self.maintain_at(now(), false, false).await {
                        error!(error = %error, "signing-key maintenance failed");
                    }
                }
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }

    pub(super) async fn maintain_at(
        &self,
        current: u64,
        force_stage: bool,
        activate_immediately: bool,
    ) -> Result<()> {
        let _maintenance = self.inner.maintenance.lock().await;
        let _snapshot = self.inner.snapshot_gate.read().await;
        let Some(lock_token) = acquire_maintenance_lock(self.inner.redis.clone()).await? else {
            let keyset = read_keyset(self.inner.redis.clone()).await?;
            let runtime = runtime_keyset(&keyset, &self.inner.master_keys, current)?;
            *self
                .inner
                .runtime
                .write()
                .map_err(|_| anyhow::anyhow!("JWT runtime lock is poisoned"))? = runtime;
            if force_stage {
                bail!("another process is rotating signing keys; retry in a few seconds");
            }
            return Ok(());
        };
        let result = self
            .maintain_while_locked(current, force_stage, activate_immediately)
            .await;
        release_maintenance_lock(self.inner.redis.clone(), &lock_token).await;
        result
    }

    async fn maintain_while_locked(
        &self,
        current: u64,
        force_stage: bool,
        activate_immediately: bool,
    ) -> Result<()> {
        let mut keyset = read_keyset(self.inner.redis.clone()).await?;
        let before = keyset.clone();
        maintain_keyset(
            &mut keyset,
            &self.inner.master_keys,
            &self.inner.rotation,
            current,
            force_stage,
            activate_immediately,
        )?;
        validate_keyset(&keyset, &self.inner.master_keys)?;
        if keyset != before {
            let mut redis = self.inner.redis.clone();
            let serialized = serde_json::to_string(&keyset)?;
            let _: () = redis.set(KEYSET_KEY, serialized).await?;
            log_transitions(&before, &keyset);
        }
        let runtime = runtime_keyset(&keyset, &self.inner.master_keys, current)?;
        *self
            .inner
            .runtime
            .write()
            .map_err(|_| anyhow::anyhow!("JWT runtime lock is poisoned"))? = runtime;
        Ok(())
    }
}

async fn acquire_maintenance_lock(
    mut redis: redis::aio::ConnectionManager,
) -> Result<Option<String>> {
    let token = Uuid::new_v4().to_string();
    let response: Option<String> = redis::cmd("SET")
        .arg(MAINTENANCE_LOCK_KEY)
        .arg(&token)
        .arg("NX")
        .arg("EX")
        .arg(60_u8)
        .query_async(&mut redis)
        .await
        .context("acquire signing-key maintenance lock")?;
    Ok(response.map(|_| token))
}

/// Releases the signing-key maintenance lock only if this holder still owns it.
///
/// A read-then-delete release deletes whichever lock exists when the delete
/// lands: if this lease had already expired, that lock belongs to the process
/// now rotating, and two processes then stage and activate signing keys at
/// once. SableDB does not implement `EVAL`, so the comparison and the delete
/// are held together by its single-command `DELIFEQ` rather than by a Lua
/// script.
/// Compare-and-delete for datastores that implement `EVAL` instead of `DELIFEQ`.
const COMPARE_AND_DELETE: &str = r#"if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end"#;

fn release_maintenance_lock_command(token: &str) -> redis::Cmd {
    let mut command = redis::cmd("DELIFEQ");
    command.arg(MAINTENANCE_LOCK_KEY).arg(token);
    command
}

async fn release_maintenance_lock(mut redis: redis::aio::ConnectionManager, token: &str) {
    let released = match release_maintenance_lock_command(token)
        .query_async::<i64>(&mut redis)
        .await
    {
        Ok(count) => Ok(count),
        // SABLEDB_URL also accepts a plain Valkey or Redis endpoint, which has no
        // DELIFEQ. The scripted form is the same compare-and-delete; without it a
        // held lock would block rotation until its TTL lapsed.
        Err(_) => {
            let mut command = redis::cmd("EVAL");
            command
                .arg(COMPARE_AND_DELETE)
                .arg(1_u8)
                .arg(MAINTENANCE_LOCK_KEY)
                .arg(token);
            command.query_async::<i64>(&mut redis).await
        }
    };
    match released {
        Ok(1) => {}
        Ok(_) => warn!(
            "signing-key maintenance lock had already expired at release; another process may own it"
        ),
        Err(error) => warn!(error = %error, "release signing-key maintenance lock"),
    }
}

fn maintain_keyset(
    keyset: &mut StoredKeySet,
    master_keys: &KeyRing,
    rotation: &SigningRotationConfig,
    current: u64,
    force_stage: bool,
    activate_immediately: bool,
) -> Result<()> {
    keyset.retired.retain(|key| key.publish_until > current);
    rewrap_if_needed(&mut keyset.active, master_keys)?;
    if let Some(staged) = &mut keyset.staged {
        rewrap_if_needed(&mut staged.key, master_keys)?;
    }

    // Recovery rotation must create fresh material at recovery time, even when the
    // restored snapshot happened to contain a prepublished key.
    if activate_immediately {
        keyset.staged = Some(StagedSigningKey {
            key: generate(master_keys, current)?,
            activate_at: current,
        });
        activate_staged(keyset, rotation, current)?;
        return Ok(());
    }

    if keyset
        .staged
        .as_ref()
        .is_some_and(|staged| staged.activate_at <= current)
    {
        activate_staged(keyset, rotation, current)?;
    }

    if keyset.staged.is_none()
        && (force_stage
            || current
                >= keyset
                    .active
                    .created_at
                    .saturating_add(rotation.rotation_seconds))
    {
        keyset.staged = Some(StagedSigningKey {
            key: generate(master_keys, current)?,
            activate_at: current.saturating_add(rotation.prepublish_seconds),
        });
    }
    Ok(())
}

fn activate_staged(
    keyset: &mut StoredKeySet,
    rotation: &SigningRotationConfig,
    current: u64,
) -> Result<()> {
    let staged = keyset.staged.take().context("staged key is missing")?;
    let previous = std::mem::replace(&mut keyset.active, staged.key);
    keyset.retired.retain(|key| key.kid != previous.kid);
    keyset.retired.push(RetiredPublicKey {
        kid: previous.kid,
        public_jwk: previous.public_jwk,
        publish_until: current.saturating_add(rotation.overlap_seconds),
    });
    Ok(())
}

fn rewrap_if_needed(record: &mut StoredSigningKey, master_keys: &KeyRing) -> Result<()> {
    if record.encrypted_private_key.wrapping_key_id == master_keys.active().0 {
        return Ok(());
    }
    let private_der = open_private_key(master_keys, record)?;
    record.encrypted_private_key =
        seal_private_key(master_keys, &record.kid, private_der.as_slice())?;
    Ok(())
}

fn status_for(keyset: &StoredKeySet, rotation: &SigningRotationConfig) -> SigningKeyStatus {
    SigningKeyStatus {
        active_kid: keyset.active.kid.clone(),
        staged_kid: keyset.staged.as_ref().map(|value| value.key.kid.clone()),
        staged_activates_at: keyset.staged.as_ref().map(|value| value.activate_at),
        retired_kids: keyset
            .retired
            .iter()
            .map(|value| value.kid.clone())
            .collect(),
        next_rotation_at: keyset
            .active
            .created_at
            .saturating_add(rotation.rotation_seconds),
    }
}

fn log_transitions(before: &StoredKeySet, after: &StoredKeySet) {
    if let (None, Some(staged)) = (&before.staged, &after.staged) {
        info!(kid = %staged.key.kid, activate_at = staged.activate_at, "signing key staged");
    }
    if before.active.kid != after.active.kid {
        info!(old_kid = %before.active.kid, new_kid = %after.active.kid, "signing key activated");
    }
    if before.active.encrypted_private_key.wrapping_key_id
        != after.active.encrypted_private_key.wrapping_key_id
    {
        info!(kid = %after.active.kid, wrapping_key_id = %after.active.encrypted_private_key.wrapping_key_id, "signing key rewrapped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, encode, jwk::Jwk};
    use serde_json::{Value, json};

    use super::super::{keyset::KEYSET_VERSION, runtime::RuntimeKeySet};

    fn rotation() -> SigningRotationConfig {
        SigningRotationConfig {
            rotation_seconds: 100,
            prepublish_seconds: 10,
            overlap_seconds: 20,
            maintenance_seconds: 5,
        }
    }

    #[test]
    fn rotation_prepublicizes_then_retires_the_previous_key() {
        let keys = KeyRing::new("master", [1; 32], Vec::new()).unwrap();
        let active = generate(&keys, 1_000).unwrap();
        let old_kid = active.kid.clone();
        let mut keyset = StoredKeySet {
            version: KEYSET_VERSION,
            active,
            staged: None,
            retired: Vec::new(),
        };

        maintain_keyset(&mut keyset, &keys, &rotation(), 1_100, false, false).unwrap();
        let staged_kid = keyset.staged.as_ref().unwrap().key.kid.clone();
        assert_eq!(keyset.active.kid, old_kid);
        assert_eq!(keyset.staged.as_ref().unwrap().activate_at, 1_110);
        assert_eq!(
            runtime_keyset(&keyset, &keys, 1_100).unwrap().jwks["keys"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        maintain_keyset(&mut keyset, &keys, &rotation(), 1_110, false, false).unwrap();
        assert_eq!(keyset.active.kid, staged_kid);
        assert_eq!(keyset.retired[0].kid, old_kid);
        assert_eq!(keyset.retired[0].publish_until, 1_130);

        maintain_keyset(&mut keyset, &keys, &rotation(), 1_130, false, false).unwrap();
        assert!(keyset.retired.is_empty());
    }

    #[test]
    fn wrapping_key_rollover_reencrypts_without_changing_the_signing_key() {
        let old = KeyRing::new("master", [2; 32], Vec::new()).unwrap();
        let active = generate(&old, 1_000).unwrap();
        let kid = active.kid.clone();
        let new = KeyRing::new("master", [3; 32], vec![[2; 32]]).unwrap();
        let mut keyset = StoredKeySet {
            version: KEYSET_VERSION,
            active,
            staged: None,
            retired: Vec::new(),
        };
        maintain_keyset(&mut keyset, &new, &rotation(), 1_001, false, false).unwrap();
        assert_eq!(keyset.active.kid, kid);
        assert_eq!(
            keyset.active.encrypted_private_key.wrapping_key_id,
            new.active().0
        );
        validate_keyset(&keyset, &new).unwrap();
    }

    #[test]
    fn recovery_rotation_replaces_even_a_restored_staged_key() {
        let keys = KeyRing::new("master", [15; 32], Vec::new()).unwrap();
        let active = generate(&keys, 1_000).unwrap();
        let old_kid = active.kid.clone();
        let staged = generate(&keys, 1_001).unwrap();
        let restored_staged_kid = staged.kid.clone();
        let mut keyset = StoredKeySet {
            version: KEYSET_VERSION,
            active,
            staged: Some(StagedSigningKey {
                key: staged,
                activate_at: 1_500,
            }),
            retired: Vec::new(),
        };

        maintain_keyset(&mut keyset, &keys, &rotation(), 1_002, true, true).unwrap();
        assert_ne!(keyset.active.kid, old_kid);
        assert_ne!(keyset.active.kid, restored_staged_kid);
        assert!(keyset.staged.is_none());
        assert_eq!(keyset.retired[0].kid, old_kid);
    }

    #[test]
    fn old_and_new_tokens_verify_during_the_retirement_overlap() {
        let keys = KeyRing::new("master", [5; 32], Vec::new()).unwrap();
        let active = generate(&keys, 1_000).unwrap();
        let old_kid = active.kid.clone();
        let mut keyset = StoredKeySet {
            version: KEYSET_VERSION,
            active,
            staged: None,
            retired: Vec::new(),
        };
        let old_runtime = runtime_keyset(&keyset, &keys, 1_000).unwrap();
        let old_token = test_token(&old_runtime);

        maintain_keyset(&mut keyset, &keys, &rotation(), 1_100, false, false).unwrap();
        maintain_keyset(&mut keyset, &keys, &rotation(), 1_110, false, false).unwrap();
        let new_runtime = runtime_keyset(&keyset, &keys, 1_110).unwrap();
        let new_token = test_token(&new_runtime);
        let jwks = new_runtime.jwks["keys"].as_array().unwrap();
        assert!(verify_with_kid(&old_token, &old_kid, jwks));
        assert!(verify_with_kid(&new_token, &new_runtime.active_kid, jwks));

        maintain_keyset(&mut keyset, &keys, &rotation(), 1_130, false, false).unwrap();
        let after_overlap = runtime_keyset(&keyset, &keys, 1_130).unwrap();
        assert!(
            !after_overlap.jwks["keys"]
                .as_array()
                .unwrap()
                .iter()
                .any(|jwk| jwk["kid"] == old_kid)
        );
    }

    #[test]
    fn a_maintenance_lock_release_is_one_atomic_compare_and_delete() {
        let packed = release_maintenance_lock_command("lock-token").get_packed_command();
        let rendered = String::from_utf8_lossy(&packed).into_owned();
        assert!(rendered.starts_with("*3\r\n"), "{rendered}");
        assert!(rendered.contains("DELIFEQ"), "{rendered}");
        assert!(rendered.contains(MAINTENANCE_LOCK_KEY), "{rendered}");
        assert!(rendered.contains("lock-token"), "{rendered}");
    }

    fn test_token(runtime: &RuntimeKeySet) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(runtime.active_kid.clone());
        encode(
            &header,
            &json!({ "sub": "test", "exp": 4_000_000_000_u64 }),
            &runtime.encoding,
        )
        .unwrap()
    }

    fn verify_with_kid(token: &str, kid: &str, jwks: &[Value]) -> bool {
        let Some(value) = jwks.iter().find(|jwk| jwk["kid"] == kid) else {
            return false;
        };
        let jwk: Jwk = serde_json::from_value(value.clone()).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        decode::<Value>(token, &DecodingKey::from_jwk(&jwk).unwrap(), &validation).is_ok()
    }
}
