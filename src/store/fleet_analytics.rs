//! Fleet-side durable acceptance ledger for realm telemetry snapshots.
//!
//! The connector acknowledges a revision only after this ledger commits. It
//! keeps the trusted hierarchy beside the validated, identity-free bucket so a
//! later GreptimeDB writer never trusts hierarchy labels supplied by a realm.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use buffa::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::proto::rustyauth::analytics::v1::{
    BucketAcknowledgementStatus, BucketRejectionReason, TelemetryBatchAcknowledgement,
    TelemetryBucket, TelemetryBucketAcknowledgement, TelemetryBucketBatch, TelemetryBucketKey,
};

use super::{
    FleetAnalyticsIngestionAuditRecord, FleetAnalyticsQuarantineRecord, FleetConnectionRecord,
    Store, now,
};

const FLEET_TELEMETRY_PREFIX: &str = "fleet:analytics-bucket:";
const MAX_FLEET_ANALYTICS_QUERY_RECORDS: usize = 100_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetTelemetryBucketRecord {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub environment_id: Uuid,
    pub connection_id: Uuid,
    pub realm_id: String,
    pub assignment_epoch: u64,
    pub bucket_start_unix_milliseconds: i64,
    pub bucket_width_seconds: u32,
    pub metric_schema_version: i32,
    pub revision: u64,
    pub first_event_sequence: u64,
    pub last_event_sequence: u64,
    pub batch_id: Uuid,
    pub payload_base64url: String,
    pub accepted_at: u64,
}

/// The exact durable records covered by a telemetry acknowledgement. This is
/// used by the Fleet connector to make the secondary analytical write before
/// returning the acknowledgement to the realm. A retry after either store
/// restarts is safe because accepted revisions are immutable/idempotent.
pub struct AcceptedFleetTelemetryBatch {
    pub acknowledgement: TelemetryBatchAcknowledgement,
    pub records: Vec<FleetTelemetryBucketRecord>,
}

impl FleetTelemetryBucketRecord {
    pub(crate) fn from_bucket(
        connection: &FleetConnectionRecord,
        batch_id: Uuid,
        bucket: &TelemetryBucket,
    ) -> Self {
        Self {
            organization_id: connection.organization_id,
            project_id: connection.project_id,
            environment_id: connection.environment_id,
            connection_id: connection.id,
            realm_id: bucket.realm_id.clone(),
            assignment_epoch: bucket.assignment_epoch,
            bucket_start_unix_milliseconds: bucket.bucket_start_unix_milliseconds,
            bucket_width_seconds: bucket.bucket_width_seconds,
            metric_schema_version: bucket.metric_schema_version.to_i32(),
            revision: bucket.revision,
            first_event_sequence: bucket.first_event_sequence,
            last_event_sequence: bucket.last_event_sequence,
            batch_id,
            payload_base64url: URL_SAFE_NO_PAD.encode(bucket.encode_to_vec()),
            accepted_at: now(),
        }
    }

    pub fn bucket(&self) -> Result<TelemetryBucket> {
        let bytes = self.payload()?;
        TelemetryBucket::decode_from_slice(&bytes).context("decode accepted Fleet telemetry bucket")
    }

    pub(crate) fn payload(&self) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(&self.payload_base64url)
            .context("decode accepted Fleet telemetry payload")
    }
}

impl Store {
    /// Atomically accepts all non-rejected revisions and returns one result for
    /// every input bucket. The caller must validate the batch contract first.
    pub async fn accept_fleet_telemetry_batch(
        &self,
        connection: &FleetConnectionRecord,
        batch: &TelemetryBucketBatch,
    ) -> Result<TelemetryBatchAcknowledgement> {
        Ok(self
            .accept_fleet_telemetry_batch_with_records(connection, batch)
            .await?
            .acknowledgement)
    }

    /// Commits the authoritative SableDB acceptance ledger and returns the
    /// precise records that may be mirrored to the analytical store. The
    /// acknowledgement must not be sent until that mirror succeeds.
    pub async fn accept_fleet_telemetry_batch_with_records(
        &self,
        connection: &FleetConnectionRecord,
        batch: &TelemetryBucketBatch,
    ) -> Result<AcceptedFleetTelemetryBatch> {
        self.accept_fleet_telemetry_batch_internal(connection, batch, true)
            .await
    }

    /// Archive backfill is bounded by a signed manifest and the archive row
    /// limit, not the live per-minute connector quota. It still uses the same
    /// revision, sequence, assignment, retention, audit, and mirror contract.
    pub async fn accept_fleet_archive_batch_with_records(
        &self,
        connection: &FleetConnectionRecord,
        batch: &TelemetryBucketBatch,
    ) -> Result<AcceptedFleetTelemetryBatch> {
        self.accept_fleet_telemetry_batch_internal(connection, batch, false)
            .await
    }

    async fn accept_fleet_telemetry_batch_internal(
        &self,
        connection: &FleetConnectionRecord,
        batch: &TelemetryBucketBatch,
        enforce_live_quota: bool,
    ) -> Result<AcceptedFleetTelemetryBatch> {
        let batch_id = Uuid::parse_str(&batch.batch_id).context("parse telemetry batch id")?;
        let policy = self
            .fleet_analytics_policy(connection.organization_id)
            .await?;
        if !policy.enabled {
            let acknowledgement = rejection_acknowledgement(
                batch,
                BucketAcknowledgementStatus::Rejected,
                BucketRejectionReason::PolicyDisabled,
            );
            self.record_fleet_analytics_ingestion(FleetAnalyticsIngestionAuditRecord {
                id: Uuid::new_v4(),
                organization_id: connection.organization_id,
                connection_id: connection.id,
                batch_id,
                outcome: "rejected".into(),
                reason: "policy-disabled".into(),
                bucket_count: u32::try_from(batch.buckets.len()).unwrap_or(u32::MAX),
                occurred_at: now(),
            })
            .await?;
            return Ok(AcceptedFleetTelemetryBatch {
                acknowledgement,
                records: Vec::new(),
            });
        }
        if enforce_live_quota
            && !self
                .consume_fleet_analytics_quota(
                    connection.id,
                    batch_id,
                    batch.buckets.len(),
                    policy.max_buckets_per_minute_per_realm,
                )
                .await?
        {
            let acknowledgement = rejection_acknowledgement(
                batch,
                BucketAcknowledgementStatus::Rejected,
                BucketRejectionReason::ResourceLimit,
            );
            self.record_fleet_analytics_ingestion(FleetAnalyticsIngestionAuditRecord {
                id: Uuid::new_v4(),
                organization_id: connection.organization_id,
                connection_id: connection.id,
                batch_id,
                outcome: "rejected".into(),
                reason: "realm-minute-quota".into(),
                bucket_count: u32::try_from(batch.buckets.len()).unwrap_or(u32::MAX),
                occurred_at: now(),
            })
            .await?;
            return Ok(AcceptedFleetTelemetryBatch {
                acknowledgement,
                records: Vec::new(),
            });
        }

        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut acknowledgements = Vec::with_capacity(batch.buckets.len());
        let mut accepted = Vec::new();
        let mut mirrored = Vec::with_capacity(batch.buckets.len());
        let current_milliseconds = i64::try_from(now())
            .unwrap_or(i64::MAX / 1_000)
            .saturating_mul(1_000);
        let oldest_milliseconds = current_milliseconds.saturating_sub(
            i64::from(policy.canonical_retention_days)
                .saturating_mul(86_400)
                .saturating_mul(1_000),
        );
        let mut quarantine_count = 0_u32;
        let mut retention_rejection_count = 0_u32;

        for bucket in &batch.buckets {
            let key = fleet_telemetry_key(bucket);
            let incoming = FleetTelemetryBucketRecord::from_bucket(connection, batch_id, bucket);
            let existing = self.get_json::<FleetTelemetryBucketRecord>(&key).await?;
            let (status, reason) = if bucket.bucket_start_unix_milliseconds
                > current_milliseconds.saturating_add(10 * 60 * 1_000)
            {
                quarantine_count = quarantine_count.saturating_add(1);
                self.quarantine_fleet_analytics_bucket(FleetAnalyticsQuarantineRecord {
                    id: Uuid::new_v4(),
                    organization_id: connection.organization_id,
                    connection_id: connection.id,
                    realm_id: bucket.realm_id.clone(),
                    assignment_epoch: bucket.assignment_epoch,
                    bucket_start_unix_milliseconds: bucket.bucket_start_unix_milliseconds,
                    revision: bucket.revision,
                    payload_sha256: hex::encode(Sha256::digest(bucket.encode_to_vec())),
                    reason: "clock-skew".into(),
                    quarantined_at: now(),
                })
                .await?;
                (
                    BucketAcknowledgementStatus::Quarantined,
                    BucketRejectionReason::ClockSkew,
                )
            } else if bucket
                .bucket_start_unix_milliseconds
                .saturating_add(i64::from(bucket.bucket_width_seconds) * 1_000)
                < oldest_milliseconds
            {
                retention_rejection_count = retention_rejection_count.saturating_add(1);
                (
                    BucketAcknowledgementStatus::Rejected,
                    BucketRejectionReason::ResourceLimit,
                )
            } else {
                acceptance_decision(existing.as_ref(), &incoming)
            };
            if status == BucketAcknowledgementStatus::Accepted {
                mirrored.push(incoming.clone());
                accepted.push((key, incoming));
            } else if status == BucketAcknowledgementStatus::AlreadyAccepted
                && let Some(existing) = existing
            {
                mirrored.push(existing);
            }
            acknowledgements.push(TelemetryBucketAcknowledgement {
                key: TelemetryBucketKey {
                    realm_id: bucket.realm_id.clone(),
                    assignment_epoch: bucket.assignment_epoch,
                    bucket_start_unix_milliseconds: bucket.bucket_start_unix_milliseconds,
                    bucket_width_seconds: bucket.bucket_width_seconds,
                    metric_schema_version: bucket.metric_schema_version,
                    ..Default::default()
                }
                .into(),
                revision: bucket.revision,
                status: status.into(),
                rejection_reason: reason.into(),
                ..Default::default()
            });
        }

        if !accepted.is_empty() {
            let mut pipeline = redis::pipe();
            pipeline.atomic();
            for (key, record) in accepted {
                pipeline.set(key, serde_json::to_string(&record)?).ignore();
            }
            let mut database = self.redis.clone();
            let _: () = pipeline
                .query_async(&mut database)
                .await
                .context("commit Fleet telemetry acceptance ledger")?;
        }

        let (outcome, reason) = if quarantine_count > 0 {
            ("quarantined", "clock-skew")
        } else if retention_rejection_count > 0 {
            ("rejected", "outside-retention")
        } else if mirrored.is_empty() {
            ("rejected", "revision-or-sequence")
        } else {
            ("accepted", "contract-valid")
        };
        self.record_fleet_analytics_ingestion(FleetAnalyticsIngestionAuditRecord {
            id: Uuid::new_v4(),
            organization_id: connection.organization_id,
            connection_id: connection.id,
            batch_id,
            outcome: outcome.into(),
            reason: reason.into(),
            bucket_count: u32::try_from(batch.buckets.len()).unwrap_or(u32::MAX),
            occurred_at: now(),
        })
        .await?;

        Ok(AcceptedFleetTelemetryBatch {
            acknowledgement: TelemetryBatchAcknowledgement {
                batch_id: batch.batch_id.clone(),
                buckets: acknowledgements,
                ..Default::default()
            },
            records: mirrored,
        })
    }

    pub async fn fleet_telemetry_bucket(
        &self,
        realm_id: &str,
        assignment_epoch: u64,
        bucket_start_unix_milliseconds: i64,
    ) -> Result<Option<FleetTelemetryBucketRecord>> {
        self.get_json(&format!(
            "{FLEET_TELEMETRY_PREFIX}{realm_id}:{assignment_epoch:020}:{bucket_start_unix_milliseconds:020}"
        ))
        .await
    }

    /// Reads a bounded, trusted hierarchy slice from the Fleet acceptance
    /// ledger. Caller-supplied realm labels never participate in hierarchy
    /// authorization: organization/project/environment IDs were stamped from
    /// the authenticated connection when each record was accepted.
    #[allow(clippy::too_many_arguments)]
    pub async fn fleet_telemetry_buckets(
        &self,
        organization_id: Option<Uuid>,
        project_id: Option<Uuid>,
        environment_id: Option<Uuid>,
        connection_id: Option<Uuid>,
        realm_id: Option<&str>,
        starts_at_unix_milliseconds: i64,
        ends_at_unix_milliseconds: i64,
    ) -> Result<Vec<FleetTelemetryBucketRecord>> {
        let mut cursor = 0_u64;
        let mut keys = BTreeSet::new();
        loop {
            let mut database = self.redis.clone();
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{FLEET_TELEMETRY_PREFIX}*"))
                .arg("COUNT")
                .arg(1_000_u16)
                .query_async(&mut database)
                .await
                .context("scan Fleet telemetry ledger")?;
            keys.extend(batch);
            if keys.len() > MAX_FLEET_ANALYTICS_QUERY_RECORDS {
                bail!("Fleet analytics ledger exceeds the bounded V1 query limit");
            }
            if next == 0 {
                break;
            }
            cursor = next;
        }
        let mut records = Vec::new();
        for key in keys {
            let Some(record) = self.get_json::<FleetTelemetryBucketRecord>(&key).await? else {
                continue;
            };
            if organization_id.is_none_or(|id| record.organization_id == id)
                && project_id.is_none_or(|id| record.project_id == id)
                && environment_id.is_none_or(|id| record.environment_id == id)
                && connection_id.is_none_or(|id| record.connection_id == id)
                && realm_id.is_none_or(|id| record.realm_id == id)
                && record.bucket_start_unix_milliseconds >= starts_at_unix_milliseconds
                && record.bucket_start_unix_milliseconds < ends_at_unix_milliseconds
            {
                records.push(record);
            }
        }
        records.sort_unstable_by_key(|record| {
            (
                record.bucket_start_unix_milliseconds,
                record.connection_id,
                record.assignment_epoch,
            )
        });
        Ok(records)
    }
}

fn rejection_acknowledgement(
    batch: &TelemetryBucketBatch,
    status: BucketAcknowledgementStatus,
    reason: BucketRejectionReason,
) -> TelemetryBatchAcknowledgement {
    TelemetryBatchAcknowledgement {
        batch_id: batch.batch_id.clone(),
        buckets: batch
            .buckets
            .iter()
            .map(|bucket| TelemetryBucketAcknowledgement {
                key: TelemetryBucketKey {
                    realm_id: bucket.realm_id.clone(),
                    assignment_epoch: bucket.assignment_epoch,
                    bucket_start_unix_milliseconds: bucket.bucket_start_unix_milliseconds,
                    bucket_width_seconds: bucket.bucket_width_seconds,
                    metric_schema_version: bucket.metric_schema_version,
                    ..Default::default()
                }
                .into(),
                revision: bucket.revision,
                status: status.into(),
                rejection_reason: reason.into(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

fn fleet_telemetry_key(bucket: &TelemetryBucket) -> String {
    format!(
        "{FLEET_TELEMETRY_PREFIX}{}:{:020}:{:020}",
        bucket.realm_id, bucket.assignment_epoch, bucket.bucket_start_unix_milliseconds
    )
}

fn acceptance_decision(
    existing: Option<&FleetTelemetryBucketRecord>,
    incoming: &FleetTelemetryBucketRecord,
) -> (BucketAcknowledgementStatus, BucketRejectionReason) {
    let Some(existing) = existing else {
        return (
            BucketAcknowledgementStatus::Accepted,
            BucketRejectionReason::Unspecified,
        );
    };
    if incoming.revision < existing.revision {
        return (
            BucketAcknowledgementStatus::Rejected,
            BucketRejectionReason::StaleRevision,
        );
    }
    if incoming.revision == existing.revision {
        return if incoming.payload_base64url == existing.payload_base64url {
            (
                BucketAcknowledgementStatus::AlreadyAccepted,
                BucketRejectionReason::Unspecified,
            )
        } else {
            (
                BucketAcknowledgementStatus::Quarantined,
                BucketRejectionReason::InvalidContract,
            )
        };
    }
    if incoming.last_event_sequence < existing.last_event_sequence {
        return (
            BucketAcknowledgementStatus::Rejected,
            BucketRejectionReason::SequenceRegression,
        );
    }
    (
        BucketAcknowledgementStatus::Accepted,
        BucketRejectionReason::Unspecified,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(revision: u64, sequence: u64, payload: &str) -> FleetTelemetryBucketRecord {
        FleetTelemetryBucketRecord {
            organization_id: Uuid::nil(),
            project_id: Uuid::nil(),
            environment_id: Uuid::nil(),
            connection_id: Uuid::nil(),
            realm_id: "realm".into(),
            assignment_epoch: 1,
            bucket_start_unix_milliseconds: 300_000,
            bucket_width_seconds: 300,
            metric_schema_version: crate::proto::rustyauth::analytics::v1::MetricSchemaVersion::V1
                as i32,
            revision,
            first_event_sequence: 1,
            last_event_sequence: sequence,
            batch_id: Uuid::nil(),
            payload_base64url: payload.into(),
            accepted_at: 1,
        }
    }

    #[test]
    fn revisions_are_idempotent_and_sequence_fenced() {
        let current = record(2, 20, "same");
        assert_eq!(
            acceptance_decision(Some(&current), &record(2, 20, "same")).0,
            BucketAcknowledgementStatus::AlreadyAccepted
        );
        assert_eq!(
            acceptance_decision(Some(&current), &record(1, 20, "old")).1,
            BucketRejectionReason::StaleRevision
        );
        assert_eq!(
            acceptance_decision(Some(&current), &record(3, 19, "new")).1,
            BucketRejectionReason::SequenceRegression
        );
        assert_eq!(
            acceptance_decision(Some(&current), &record(3, 21, "new")).0,
            BucketAcknowledgementStatus::Accepted
        );
    }
}
