//! Scheduled backup worker: single-flight lease acquisition, run status
//! bookkeeping and the shutdown-aware interval loop.

use std::{panic::AssertUnwindSafe, time::Duration};

use anyhow::{Context, Result};
use futures::FutureExt;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::error;

use crate::{
    config::{BackupStorageProfile, KeyRing},
    store::{Store, now},
};

use super::{BackupReceipt, BackupStore};

const BACKUP_STATUS_KEY: &str = "auth:backup:status";

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BackupStatus {
    pub running: bool,
    pub last_attempt_at: Option<u64>,
    pub last_success_at: Option<u64>,
    pub last_object_key: Option<String>,
    pub consecutive_failures: u64,
    pub rpo_seconds: u64,
    pub retention_days: u64,
    pub storage_profile: String,
    pub profile_transition_pending: bool,
    pub overdue: bool,
    pub alerting: bool,
}

impl BackupStore {
    pub async fn status(&self) -> BackupStatus {
        let mut status = self.status.read().await.clone();
        self.evaluate_health(&mut status);
        status
    }

    /// Loads the last scheduler result from SableDB so one-shot `doctor` and
    /// `backup status` commands report the serving process rather than a fresh
    /// in-memory status object. This operational record is intentionally excluded
    /// from the backup itself.
    pub async fn persisted_status(&self, store: &Store) -> Result<BackupStatus> {
        let mut connection = store.connection();
        let value: Option<String> = connection
            .get(BACKUP_STATUS_KEY)
            .await
            .context("read persisted backup status")?;
        let mut status: BackupStatus = value
            .map(|value| serde_json::from_str(&value).context("decode persisted backup status"))
            .transpose()?
            .unwrap_or_default();
        status.profile_transition_pending =
            storage_profile_transition_pending(&status.storage_profile, self.storage_profile);
        if status.profile_transition_pending {
            // A failure under one provider contract says nothing about the new
            // contract. Keep the transition visible, but let the candidate start
            // so its immediate scheduler tick can establish the first recovery
            // point under the selected profile.
            status.running = false;
            status.last_attempt_at = None;
            status.last_success_at = None;
            status.last_object_key = None;
            status.consecutive_failures = 0;
        }
        status.rpo_seconds = self.rpo_seconds;
        status.retention_days = self.retention_days;
        status.storage_profile = self.storage_profile.as_str().to_owned();
        self.evaluate_health(&mut status);
        Ok(status)
    }

    pub async fn create(
        &self,
        store: &Store,
        tenant_id: &str,
        master_keys: &KeyRing,
    ) -> Result<BackupReceipt> {
        let _operation = self.operation.lock().await;
        self.hydrate_status(store).await;
        let lease = store
            .acquire_backup_lease()
            .await?
            .context("another backup is already running")?;
        {
            let mut status = self.status.write().await;
            status.running = true;
            status.last_attempt_at = Some(now());
            status.rpo_seconds = self.rpo_seconds;
            status.retention_days = self.retention_days;
            status.storage_profile = self.storage_profile.as_str().to_owned();
            status.profile_transition_pending = false;
            self.evaluate_health(&mut status);
            self.persist_status(store, &status).await;
        }
        // The lease is a SableDB key with a one-hour TTL, not an RAII guard, and the
        // release below is the only thing that returns it. Under `panic = "unwind"`
        // a panic in here would unwind straight past it, leaving every backup for
        // the next hour refused with "another backup is already running" and the
        // status stuck at `running: true` with no crash to signal it.
        let result = AssertUnwindSafe(self.create_inner(store, tenant_id, master_keys))
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("backup task panicked")));
        store.release_backup_lease(&lease).await;
        let mut status = self.status.write().await;
        status.running = false;
        match &result {
            Ok(receipt) => {
                status.last_success_at = Some(now());
                status.last_object_key = Some(receipt.object_key.clone());
                status.consecutive_failures = 0;
            }
            Err(_) => {
                status.consecutive_failures = status.consecutive_failures.saturating_add(1);
            }
        }
        self.evaluate_health(&mut status);
        self.persist_status(store, &status).await;
        if status.alerting {
            error!(
                backup_health_alert = true,
                consecutive_failures = status.consecutive_failures,
                last_success_at = ?status.last_success_at,
                rpo_seconds = status.rpo_seconds,
                overdue = status.overdue,
                "backup recovery-point objective is at risk"
            );
        }
        result
    }

    async fn hydrate_status(&self, store: &Store) {
        if self.status.read().await.last_attempt_at.is_some() {
            return;
        }
        match self.persisted_status(store).await {
            Ok(status) => *self.status.write().await = status,
            Err(error) => error!(error = %error, "load persisted backup status"),
        }
    }

    async fn persist_status(&self, store: &Store, status: &BackupStatus) {
        let encoded = match serde_json::to_string(status) {
            Ok(value) => value,
            Err(error) => {
                error!(error = %error, "encode backup status");
                return;
            }
        };
        let mut connection = store.connection();
        if let Err(error) = connection.set::<_, _, ()>(BACKUP_STATUS_KEY, encoded).await {
            error!(error = %error, "persist backup status");
        }
    }

    fn evaluate_health(&self, status: &mut BackupStatus) {
        status.rpo_seconds = self.rpo_seconds;
        status.retention_days = self.retention_days;
        status.storage_profile = self.storage_profile.as_str().to_owned();
        status.overdue = status.last_attempt_at.is_some()
            && status
                .last_success_at
                .is_none_or(|success| now().saturating_sub(success) > self.rpo_seconds);
        status.alerting =
            status.overdue || status.consecutive_failures >= self.alert_after_failures;
    }

    pub async fn run_scheduler(
        self,
        store: Store,
        tenant_id: String,
        master_keys: KeyRing,
        mut shutdown: watch::Receiver<bool>,
    ) {
        // Railway and the supported rollout path create a verified recovery
        // point before replacing the serving process. A fresh Tokio interval
        // ticks immediately, which previously made the replacement take a
        // second full backup seconds later. Besides wasting storage and I/O,
        // that duplicate scan could dominate SableDB long enough to breach
        // authentication latency gates. Resume the persisted schedule from the
        // last successful backup; only a missing or overdue recovery point runs
        // immediately.
        self.hydrate_status(&store).await;
        let initial_delay = {
            let status = self.status.read().await;
            scheduler_initial_delay_seconds(&status, now(), self.interval_seconds)
        };
        let period = Duration::from_secs(self.interval_seconds);
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(initial_delay),
            period,
        );
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(error) = self.create(&store, &tenant_id, &master_keys).await {
                        error!(error = %error, "scheduled encrypted backup failed");
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
}

fn scheduler_initial_delay_seconds(
    status: &BackupStatus,
    current_time: u64,
    interval_seconds: u64,
) -> u64 {
    let Some(last_success_at) = status.last_success_at else {
        return 0;
    };
    let elapsed = current_time.saturating_sub(last_success_at);
    interval_seconds.saturating_sub(elapsed.min(interval_seconds))
}

fn storage_profile_transition_pending(
    stored_profile: &str,
    current_profile: BackupStorageProfile,
) -> bool {
    let current_profile = current_profile.as_str();
    match stored_profile {
        // Status written before profiles existed represented the immutable
        // contract. Preserve its failures unless this deployment explicitly
        // moves to portable storage.
        "" => current_profile == "portable",
        stored_profile => stored_profile != current_profile,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_resumes_after_a_recent_success_instead_of_backing_up_twice() {
        let status = BackupStatus {
            last_success_at: Some(1_000),
            ..BackupStatus::default()
        };
        assert_eq!(
            scheduler_initial_delay_seconds(&status, 1_007, 21_600),
            21_593
        );
        assert_eq!(scheduler_initial_delay_seconds(&status, 22_600, 21_600), 0);
    }

    #[test]
    fn scheduler_runs_immediately_without_a_persisted_success() {
        assert_eq!(
            scheduler_initial_delay_seconds(&BackupStatus::default(), 1_000, 21_600),
            0
        );
    }

    #[test]
    fn storage_profile_transitions_are_explicit_without_erasing_legacy_strict_failures() {
        assert!(!storage_profile_transition_pending(
            "",
            BackupStorageProfile::Immutable
        ));
        assert!(storage_profile_transition_pending(
            "",
            BackupStorageProfile::Portable
        ));
        assert!(storage_profile_transition_pending(
            "portable",
            BackupStorageProfile::Immutable
        ));
        assert!(!storage_profile_transition_pending(
            "portable",
            BackupStorageProfile::Portable
        ));
    }
}
