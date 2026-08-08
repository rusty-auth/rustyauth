//! Scheduled backup worker: single-flight lease acquisition, run status
//! bookkeeping and the shutdown-aware interval loop.

use std::panic::AssertUnwindSafe;

use anyhow::{Context, Result};
use futures::FutureExt;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::error;

use crate::{
    config::KeyRing,
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
        status.rpo_seconds = self.rpo_seconds;
        status.retention_days = self.retention_days;
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
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(self.interval_seconds));
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
