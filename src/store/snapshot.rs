//! Logical snapshot export/restore and the backup lease.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    BACKUP_LEASE_KEY, MAX_SNAPSHOT_KEYS, MAX_SNAPSHOT_VALUE_BYTES, OPERATOR_PREFIX,
    OPERATOR_SEEN_PREFIX, ORGANIZATION_KEY, RESTORE_SENTINEL, SERVICE_ACCOUNT_PREFIX,
    SERVICE_CREDENTIAL_PREFIX, Store, User, now,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreRecord {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl Store {
    pub async fn export_records(&self) -> Result<(u64, Vec<StoreRecord>)> {
        let _snapshot = self.snapshot_gate.write().await;
        let captured_at = now();
        let keys = self.auth_keys().await?;
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            match snapshot_key_policy(&key)? {
                SnapshotKeyPolicy::Exclude => continue,
                SnapshotKeyPolicy::Include => {}
            }
            let mut connection = self.redis.clone();
            let (value, ttl): (Option<String>, i64) = redis::pipe()
                .cmd("GET")
                .arg(&key)
                .cmd("TTL")
                .arg(&key)
                .query_async(&mut connection)
                .await
                .with_context(|| format!("read snapshot record {key}"))?;
            let Some(value) = value else {
                continue;
            };
            if value.len() > MAX_SNAPSHOT_VALUE_BYTES {
                bail!("snapshot record {key} exceeds the 8 MiB safety limit");
            }
            let expires_at = match ttl {
                -1 => None,
                value if value >= 0 => Some(captured_at.saturating_add(value as u64)),
                -2 => continue,
                value => bail!("SableDB returned invalid TTL {value} for {key}"),
            };
            records.push(StoreRecord {
                key,
                value,
                expires_at,
            });
        }
        records.sort_unstable_by(|left, right| left.key.cmp(&right.key));
        Ok((captured_at, records))
    }

    pub async fn restore_records(
        &self,
        records: &[StoreRecord],
        preserve_sessions: bool,
    ) -> Result<usize> {
        let _snapshot = self.snapshot_gate.write().await;
        if !self.auth_keys().await?.is_empty() {
            bail!("restore destination is not empty; use a new SableDB volume");
        }
        if records.len() > MAX_SNAPSHOT_KEYS
            || records.windows(2).any(|pair| pair[0].key >= pair[1].key)
        {
            bail!("restore records must be uniquely sorted within the key safety limit");
        }
        for record in records {
            if snapshot_key_policy(&record.key)? != SnapshotKeyPolicy::Include {
                bail!("restore contains an excluded transient key {}", record.key);
            }
            if record.value.len() > MAX_SNAPSHOT_VALUE_BYTES {
                bail!(
                    "restore record {} exceeds the 8 MiB safety limit",
                    record.key
                );
            }
        }
        let mut connection = self.redis.clone();
        let _: () = connection
            .set(RESTORE_SENTINEL, now().to_string())
            .await
            .context("mark restore in progress")?;

        let current = now();
        let mut restored = 0_usize;
        for chunk in records.chunks(250) {
            let mut pipeline = redis::pipe();
            pipeline.atomic();
            let mut queued = 0_usize;
            for record in chunk {
                if record.key.starts_with("auth:session:") && !preserve_sessions {
                    continue;
                }
                if record
                    .expires_at
                    .is_some_and(|expires_at| expires_at <= current)
                {
                    continue;
                }
                let mut value = record.value.clone();
                if record.key.starts_with("auth:user:") {
                    let mut user: User = serde_json::from_str(&value)
                        .with_context(|| format!("decode restored user {}", record.key))?;
                    user.normalize_and_validate()
                        .with_context(|| format!("validate restored user record {}", record.key))?;
                    if !preserve_sessions {
                        user.session_version = user.session_version.saturating_add(1);
                    }
                    value = serde_json::to_string(&user)?;
                }
                pipeline.cmd("SET").arg(&record.key).arg(value);
                if let Some(expires_at) = record.expires_at {
                    pipeline
                        .arg("EX")
                        .arg(expires_at.saturating_sub(current).max(1));
                }
                pipeline.ignore();
                queued += 1;
            }
            if queued > 0 {
                let _: () = pipeline
                    .query_async(&mut connection)
                    .await
                    .context("write restored records")?;
                restored += queued;
            }
        }
        Ok(restored)
    }

    pub async fn complete_restore(&self) -> Result<()> {
        let mut connection = self.redis.clone();
        let _: usize = connection
            .del(RESTORE_SENTINEL)
            .await
            .context("complete restore")?;
        Ok(())
    }

    pub async fn ensure_restore_complete(&self) -> Result<()> {
        let exists: bool = self.get::<String>(RESTORE_SENTINEL).await?.is_some();
        if exists {
            bail!(
                "an incomplete restore marker is present; discard this SableDB volume and restore into a new one"
            );
        }
        Ok(())
    }

    pub async fn acquire_backup_lease(&self) -> Result<Option<String>> {
        let token = Uuid::new_v4().to_string();
        let mut connection = self.redis.clone();
        let response: Option<String> = redis::cmd("SET")
            .arg(BACKUP_LEASE_KEY)
            .arg(&token)
            .arg("NX")
            .arg("EX")
            .arg(3_600_u16)
            .query_async(&mut connection)
            .await
            .context("acquire backup lease")?;
        Ok(response.map(|_| token))
    }

    pub async fn release_backup_lease(&self, token: &str) {
        let mut connection = self.redis.clone();
        let released = match release_backup_lease_command(token)
            .query_async::<i64>(&mut connection)
            .await
        {
            Ok(count) => Ok(count),
            // SABLEDB_URL also accepts a plain Valkey or Redis endpoint, which has
            // no DELIFEQ. Falling back to the equivalent Lua keeps the release
            // atomic there; without it the lease would sit for its full hour and
            // every backup in that window would be refused as already running.
            Err(error) if is_unknown_command(&error) => {
                compare_and_delete_command(BACKUP_LEASE_KEY, token)
                    .query_async::<i64>(&mut connection)
                    .await
            }
            Err(error) => Err(error),
        };
        match released {
            Ok(1) => {}
            Ok(_) => tracing::warn!(
                "backup lease had already expired at release; another backup may own it"
            ),
            Err(error) => tracing::error!(error = %error, "release backup lease"),
        }
    }

    async fn auth_keys(&self) -> Result<Vec<String>> {
        let mut cursor = 0_u64;
        let mut keys = BTreeSet::new();
        loop {
            let mut connection = self.redis.clone();
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("auth:*")
                .arg("COUNT")
                .arg(500_u16)
                .query_async(&mut connection)
                .await
                .context("scan RustyAuth records")?;
            keys.extend(batch);
            if keys.len() > MAX_SNAPSHOT_KEYS {
                bail!("RustyAuth namespace exceeds the one-million-key safety limit");
            }
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        Ok(keys.into_iter().collect())
    }
}

/// Releases the backup lease only if this holder still owns it.
///
/// A read-then-delete release deletes whichever lease exists when the delete
/// lands: if this lease had already expired, that is the lease the next backup
/// run now holds, and two backups then write the same destination. SableDB does
/// not implement `EVAL`, so the comparison and the delete are held together by
/// its single-command `DELIFEQ`. A plain Valkey or Redis endpoint has no
/// `DELIFEQ`, so the caller falls back to [`COMPARE_AND_DELETE`], which is the
/// same operation expressed as a script.
/// Compare-and-delete for datastores that implement `EVAL` instead of `DELIFEQ`.
const COMPARE_AND_DELETE: &str = r#"if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end"#;

fn compare_and_delete_command(key: &str, token: &str) -> redis::Cmd {
    let mut command = redis::cmd("EVAL");
    command
        .arg(COMPARE_AND_DELETE)
        .arg(1_u8)
        .arg(key)
        .arg(token);
    command
}

fn release_backup_lease_command(token: &str) -> redis::Cmd {
    let mut command = redis::cmd("DELIFEQ");
    command.arg(BACKUP_LEASE_KEY).arg(token);
    command
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotKeyPolicy {
    Include,
    Exclude,
}

fn snapshot_key_policy(key: &str) -> Result<SnapshotKeyPolicy> {
    if matches!(
        key,
        "auth:event-sequence" | "auth:jwt:keyset:v1" | ORGANIZATION_KEY
    ) || [
        "auth:user:",
        "auth:email:",
        "auth:identifier:",
        "auth:credential:",
        "auth:session:",
        "auth:event:",
        OPERATOR_PREFIX,
        SERVICE_ACCOUNT_PREFIX,
        SERVICE_CREDENTIAL_PREFIX,
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix))
    {
        return Ok(SnapshotKeyPolicy::Include);
    }
    if matches!(key, "auth:jwt:active" | "auth:jwt:maintenance-lock")
        || key == RESTORE_SENTINEL
        || [
            "auth:registration:",
            "auth:authentication:",
            "auth:agent-handoff:",
            "auth:backup:",
            OPERATOR_SEEN_PREFIX,
        ]
        .iter()
        .any(|prefix| key.starts_with(prefix))
    {
        return Ok(SnapshotKeyPolicy::Exclude);
    }
    bail!("unknown RustyAuth key family in snapshot: {key}")
}

/// Whether a datastore error means "this command does not exist here".
///
/// Only an unknown-command error justifies retrying with the scripted form. A
/// timeout or a dropped connection means the command may well have run, and
/// retrying it against a datastore that has no EVAL just produces a second
/// failure that hides the first.
fn is_unknown_command(error: &redis::RedisError) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("unknown command") || text.contains("unsupported command")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_policy_is_explicit_and_excludes_replayable_state() {
        assert_eq!(
            snapshot_key_policy("auth:user:123").unwrap(),
            SnapshotKeyPolicy::Include
        );
        assert_eq!(
            snapshot_key_policy("auth:session:abc").unwrap(),
            SnapshotKeyPolicy::Include
        );
        assert_eq!(
            snapshot_key_policy("auth:identifier:phone:+447700900123").unwrap(),
            SnapshotKeyPolicy::Include
        );
        assert_eq!(
            snapshot_key_policy("auth:registration:123").unwrap(),
            SnapshotKeyPolicy::Exclude
        );
        assert!(snapshot_key_policy("auth:future-state:123").is_err());
    }

    #[test]
    fn a_backup_lease_release_is_one_atomic_compare_and_delete() {
        let packed = release_backup_lease_command("lease-token").get_packed_command();
        let rendered = String::from_utf8_lossy(&packed).into_owned();
        assert!(rendered.starts_with("*3\r\n"), "{rendered}");
        assert!(rendered.contains("DELIFEQ"), "{rendered}");
        assert!(rendered.contains(BACKUP_LEASE_KEY), "{rendered}");
        assert!(rendered.contains("lease-token"), "{rendered}");
    }
}
