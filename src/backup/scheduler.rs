//! Scheduled backup worker: single-flight lease acquisition, run status
//! bookkeeping and the shutdown-aware interval loop.

use std::panic::AssertUnwindSafe;

use anyhow::{Context, Result};
use futures::FutureExt;
use serde::Serialize;
use tokio::sync::watch;
use tracing::error;

use crate::{
    config::KeyRing,
    store::{Store, now},
};

use super::{BackupReceipt, BackupStore};

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupStatus {
    pub running: bool,
    pub last_attempt_at: Option<u64>,
    pub last_success_at: Option<u64>,
    pub last_object_key: Option<String>,
    pub consecutive_failures: u64,
}

impl BackupStore {
    pub async fn status(&self) -> BackupStatus {
        self.status.read().await.clone()
    }

    pub async fn create(
        &self,
        store: &Store,
        tenant_id: &str,
        master_keys: &KeyRing,
    ) -> Result<BackupReceipt> {
        let _operation = self.operation.lock().await;
        let lease = store
            .acquire_backup_lease()
            .await?
            .context("another backup is already running")?;
        {
            let mut status = self.status.write().await;
            status.running = true;
            status.last_attempt_at = Some(now());
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
        result
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
