//! Fleet Analytics policy, quota, quarantine, and redacted audit authority.
//!
//! These records live in SableDB because GreptimeDB must never become an
//! authorization, expected-coverage, or ingestion-policy boundary.

use anyhow::{Context, Result, bail};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use uuid::Uuid;

use crate::proto::rustyauth::analytics::v1::MetricBucketArchiveManifest;

use super::{FleetConnectionRecord, Store, StorePolicyError, now};

const POLICY_PREFIX: &str = "fleet:analytics-policy:";
const POLICY_IDEMPOTENCY_PREFIX: &str = "fleet:analytics-policy-idempotency:";
const QUOTA_PREFIX: &str = "fleet:analytics-quota:";
const QUOTA_BATCH_PREFIX: &str = "fleet:analytics-quota-batch:";
const QUARANTINE_PREFIX: &str = "fleet:analytics-quarantine:";
const INGESTION_AUDIT_PREFIX: &str = "fleet:analytics-ingestion-audit:";
const OPERATOR_AUDIT_PREFIX: &str = "fleet:analytics-operator-audit:";
const MAINTENANCE_AUDIT_PREFIX: &str = "fleet:analytics-maintenance-audit:";
const MANIFEST_PREFIX: &str = "fleet:analytics-manifest:";
const AUDIT_RETENTION_SECONDS: u64 = 90 * 86_400;
const QUARANTINE_RETENTION_SECONDS: u64 = 90 * 86_400;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FleetAnalyticsResidencyRecord {
    RollupsOnly,
    CustomerOwnedArchive,
    CentralLandingArchive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetAnalyticsPolicyRecord {
    pub organization_id: Uuid,
    pub enabled: bool,
    pub canonical_retention_days: u32,
    pub residency: FleetAnalyticsResidencyRecord,
    pub max_buckets_per_minute_per_realm: u32,
    pub updated_at: u64,
    pub updated_by: Option<Uuid>,
}

impl FleetAnalyticsPolicyRecord {
    fn default_disabled(organization_id: Uuid) -> Self {
        Self {
            organization_id,
            enabled: false,
            canonical_retention_days: 35,
            residency: FleetAnalyticsResidencyRecord::RollupsOnly,
            max_buckets_per_minute_per_realm: 288,
            updated_at: 0,
            updated_by: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetAnalyticsIngestionAuditRecord {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub connection_id: Uuid,
    pub batch_id: Uuid,
    pub outcome: String,
    pub reason: String,
    pub bucket_count: u32,
    pub occurred_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetAnalyticsQuarantineRecord {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub connection_id: Uuid,
    pub realm_id: String,
    pub assignment_epoch: u64,
    pub bucket_start_unix_milliseconds: i64,
    pub revision: u64,
    pub payload_sha256: String,
    pub reason: String,
    pub quarantined_at: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FleetAnalyticsManifestStateRecord {
    Pending,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetAnalyticsManifestRecord {
    pub manifest_id: Uuid,
    pub organization_id: Uuid,
    pub connection_id: Uuid,
    pub realm_id: String,
    pub assignment_epoch: u64,
    pub content_sha256: String,
    pub object_key_sha256: String,
    pub row_count: u64,
    pub state: FleetAnalyticsManifestStateRecord,
    pub accepted_rows: u64,
    pub started_at: u64,
    pub completed_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FleetAnalyticsMaintenanceActionRecord {
    EnforceRetention,
    PurgeConnection,
    PurgeOrganization,
    RepairMaterializations,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FleetAnalyticsMaintenanceOutcomeRecord {
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetAnalyticsMaintenanceAuditRecord {
    pub request_id: Uuid,
    pub organization_id: Uuid,
    pub connection_id: Option<Uuid>,
    pub operator_id: Uuid,
    pub action: FleetAnalyticsMaintenanceActionRecord,
    pub outcome: FleetAnalyticsMaintenanceOutcomeRecord,
    pub reason: String,
    pub occurred_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyIdempotencyRecord {
    organization_id: Uuid,
    policy: FleetAnalyticsPolicyRecord,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperatorAuditRecord<'a> {
    id: Uuid,
    request_id: Uuid,
    organization_id: Uuid,
    operator_id: Uuid,
    action: &'a str,
    reason: &'a str,
    occurred_at: u64,
}

impl Store {
    pub async fn record_fleet_analytics_maintenance(
        &self,
        record: FleetAnalyticsMaintenanceAuditRecord,
    ) -> Result<()> {
        if record.reason.is_empty()
            || record.reason.len() > 500
            || record.reason.chars().any(char::is_control)
        {
            bail!("Fleet analytics maintenance reason is invalid");
        }
        let key = format!(
            "{MAINTENANCE_AUDIT_PREFIX}{:020}:{}",
            record.occurred_at, record.request_id
        );
        let mut database = self.redis.clone();
        let _: () = database
            .set_ex(
                key,
                serde_json::to_string(&record)?,
                AUDIT_RETENTION_SECONDS,
            )
            .await
            .context("persist redacted Fleet analytics maintenance audit")?;
        Ok(())
    }

    pub async fn register_fleet_analytics_manifest(
        &self,
        connection: &FleetConnectionRecord,
        manifest: &MetricBucketArchiveManifest,
    ) -> Result<FleetAnalyticsManifestRecord> {
        let manifest_id =
            Uuid::parse_str(&manifest.manifest_id).context("parse Fleet analytics manifest id")?;
        let key = format!("{MANIFEST_PREFIX}{manifest_id}");
        let record = FleetAnalyticsManifestRecord {
            manifest_id,
            organization_id: connection.organization_id,
            connection_id: connection.id,
            realm_id: connection.realm_id.clone(),
            assignment_epoch: connection.assignment_epoch,
            content_sha256: hex::encode(&manifest.content_sha256),
            object_key_sha256: hex::encode(sha2::Sha256::digest(manifest.object_key.as_bytes())),
            row_count: manifest.row_count,
            state: FleetAnalyticsManifestStateRecord::Pending,
            accepted_rows: 0,
            started_at: now(),
            completed_at: None,
        };
        let mut database = self.redis.clone();
        let claimed: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(serde_json::to_string(&record)?)
            .arg("NX")
            .query_async(&mut database)
            .await
            .context("register Fleet analytics manifest")?;
        if claimed.is_some() {
            return Ok(record);
        }
        let existing = self
            .get_json::<FleetAnalyticsManifestRecord>(&key)
            .await?
            .context("registered Fleet analytics manifest disappeared")?;
        if existing.organization_id != record.organization_id
            || existing.connection_id != record.connection_id
            || existing.realm_id != record.realm_id
            || existing.assignment_epoch != record.assignment_epoch
            || existing.content_sha256 != record.content_sha256
            || existing.object_key_sha256 != record.object_key_sha256
            || existing.row_count != record.row_count
        {
            return Err(StorePolicyError::FleetAnalyticsIdempotencyConflict.into());
        }
        Ok(existing)
    }

    pub async fn complete_fleet_analytics_manifest(
        &self,
        manifest_id: Uuid,
        content_sha256: &[u8],
        accepted_rows: u64,
    ) -> Result<FleetAnalyticsManifestRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let key = format!("{MANIFEST_PREFIX}{manifest_id}");
        let mut record = self
            .get_json::<FleetAnalyticsManifestRecord>(&key)
            .await?
            .context("Fleet analytics manifest is not registered")?;
        if record.content_sha256 != hex::encode(content_sha256) {
            return Err(StorePolicyError::FleetAnalyticsIdempotencyConflict.into());
        }
        if record.state == FleetAnalyticsManifestStateRecord::Complete {
            if record.accepted_rows != accepted_rows {
                return Err(StorePolicyError::FleetAnalyticsIdempotencyConflict.into());
            }
            return Ok(record);
        }
        record.state = FleetAnalyticsManifestStateRecord::Complete;
        record.accepted_rows = accepted_rows;
        record.completed_at = Some(now());
        let mut database = self.redis.clone();
        let _: () = database
            .set(key, serde_json::to_string(&record)?)
            .await
            .context("complete Fleet analytics manifest")?;
        Ok(record)
    }

    pub async fn fleet_analytics_policy(
        &self,
        organization_id: Uuid,
    ) -> Result<FleetAnalyticsPolicyRecord> {
        Ok(self
            .get_json(&policy_key(organization_id))
            .await?
            .unwrap_or_else(|| FleetAnalyticsPolicyRecord::default_disabled(organization_id)))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_fleet_analytics_policy(
        &self,
        organization_id: Uuid,
        enabled: bool,
        canonical_retention_days: u32,
        residency: FleetAnalyticsResidencyRecord,
        max_buckets_per_minute_per_realm: u32,
        request_id: Uuid,
        operator_id: Uuid,
        reason: String,
    ) -> Result<FleetAnalyticsPolicyRecord> {
        if !(1..=35).contains(&canonical_retention_days) {
            bail!("canonical analytics retention must be between 1 and 35 days");
        }
        if !(16..=2_880).contains(&max_buckets_per_minute_per_realm) {
            bail!("analytics realm quota must be between 16 and 2880 buckets per minute");
        }
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        if self.fleet_organization(organization_id).await?.is_none() {
            return Err(StorePolicyError::FleetResourceMissing.into());
        }
        let idempotency_key = policy_idempotency_key(request_id);
        if let Some(existing) = self
            .get_json::<PolicyIdempotencyRecord>(&idempotency_key)
            .await?
        {
            if existing.organization_id != organization_id {
                return Err(StorePolicyError::FleetAnalyticsIdempotencyConflict.into());
            }
            return Ok(existing.policy);
        }
        let timestamp = now();
        let policy = FleetAnalyticsPolicyRecord {
            organization_id,
            enabled,
            canonical_retention_days,
            residency,
            max_buckets_per_minute_per_realm,
            updated_at: timestamp,
            updated_by: Some(operator_id),
        };
        let idempotency = PolicyIdempotencyRecord {
            organization_id,
            policy: policy.clone(),
        };
        let audit = OperatorAuditRecord {
            id: Uuid::new_v4(),
            request_id,
            organization_id,
            operator_id,
            action: "analytics.policy.update",
            reason: &reason,
            occurred_at: timestamp,
        };
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(policy_key(organization_id), serde_json::to_string(&policy)?)
            .ignore()
            .set(idempotency_key, serde_json::to_string(&idempotency)?)
            .ignore()
            .set(
                format!("{OPERATOR_AUDIT_PREFIX}{timestamp:020}:{}", audit.id),
                serde_json::to_string(&audit)?,
            )
            .ignore();
        let mut database = self.redis.clone();
        pipeline
            .query_async::<()>(&mut database)
            .await
            .context("persist Fleet analytics policy and audit")?;
        Ok(policy)
    }

    /// Durable, per-realm minute quota. False means the entire batch must be
    /// retained by the realm and retried after the window rolls over.
    pub async fn consume_fleet_analytics_quota(
        &self,
        connection_id: Uuid,
        batch_id: Uuid,
        bucket_count: usize,
        limit: u32,
    ) -> Result<bool> {
        let minute = now() / 60;
        let counter_key = format!("{QUOTA_PREFIX}{connection_id}:{minute:020}");
        let batch_key = format!("{QUOTA_BATCH_PREFIX}{connection_id}:{batch_id}");
        let mut database = self.redis.clone();
        let claimed: Option<String> = redis::cmd("SET")
            .arg(&batch_key)
            .arg("pending")
            .arg("NX")
            .arg("EX")
            .arg(120_u16)
            .query_async(&mut database)
            .await
            .context("claim Fleet analytics quota batch")?;
        if claimed.is_none() {
            let prior: Option<String> = database
                .get(&batch_key)
                .await
                .context("read Fleet analytics quota batch")?;
            return Ok(prior.as_deref() == Some("allowed"));
        }

        // SableDB deliberately has no Lua scripting surface. A short-lived
        // batch marker makes retries idempotent without EVAL/EVALSHA. A crash
        // between claiming and recording the counter leaves the marker pending,
        // so retries fail closed for at most two minutes instead of bypassing
        // or double-consuming the realm budget.
        let increment = u64::try_from(bucket_count).unwrap_or(u64::MAX);
        let used: u64 = database
            .incr(&counter_key, increment)
            .await
            .context("consume Fleet analytics realm quota")?;
        if used == increment {
            let _: bool = database
                .expire(&counter_key, 120)
                .await
                .context("expire Fleet analytics realm quota")?;
        }
        let allowed = used <= u64::from(limit);
        let _: () = database
            .set_ex(
                &batch_key,
                if allowed { "allowed" } else { "rejected" },
                120,
            )
            .await
            .context("complete Fleet analytics quota batch")?;
        Ok(allowed)
    }

    pub async fn record_fleet_analytics_ingestion(
        &self,
        record: FleetAnalyticsIngestionAuditRecord,
    ) -> Result<()> {
        let key = format!(
            "{INGESTION_AUDIT_PREFIX}{:020}:{}",
            record.occurred_at, record.id
        );
        let mut database = self.redis.clone();
        let _: () = database
            .set_ex(
                key,
                serde_json::to_string(&record)?,
                AUDIT_RETENTION_SECONDS,
            )
            .await
            .context("persist redacted Fleet analytics ingestion audit")?;
        Ok(())
    }

    pub async fn quarantine_fleet_analytics_bucket(
        &self,
        record: FleetAnalyticsQuarantineRecord,
    ) -> Result<()> {
        let mut database = self.redis.clone();
        let _: () = database
            .set_ex(
                format!("{QUARANTINE_PREFIX}{}", record.id),
                serde_json::to_string(&record)?,
                QUARANTINE_RETENTION_SECONDS,
            )
            .await
            .context("persist Fleet analytics quarantine metadata")?;
        Ok(())
    }
}

fn policy_key(organization_id: Uuid) -> String {
    format!("{POLICY_PREFIX}{organization_id}")
}

fn policy_idempotency_key(request_id: Uuid) -> String {
    format!("{POLICY_IDEMPOTENCY_PREFIX}{request_id}")
}
