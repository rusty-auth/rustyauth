//! Versioned, bounded Fleet Analytics contracts.
//!
//! This module owns semantic validation and deterministic aggregate arithmetic.
//! It deliberately has no connector, SableDB, Parquet, or GreptimeDB dependency:
//! those are adapters around this durable product contract.

use std::collections::BTreeSet;

use buffa::{DecodeOptions, Enumeration, Message};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::proto::rustyauth::analytics::v1::{
    AnalyticsServingState, AuthenticationFailureCount, AuthenticationFlow, AuthenticationFlowCount,
    AuthenticationMetrics, BucketAcknowledgementStatus, BucketRejectionReason, FailureClass,
    HistogramProfile, LatencyHistogram, MetricBucketArchiveManifest, MetricFamily,
    MetricSchemaVersion, ParquetCompression, PlatformMetrics, RealmHealthMetrics,
    RegistrationMetrics, ReportingCoverage, ServiceAccountMetrics, SessionTokenMetrics,
    TelemetryBatchAcknowledgement, TelemetryBucket, TelemetryBucketBatch, TelemetryBucketKey,
    WebhookMetrics,
};

pub const TRANSPORT_SCHEMA_VERSION_V1: u32 = 1;
pub const MANIFEST_SCHEMA_VERSION_V1: u32 = 1;
pub const BUCKET_WIDTH_SECONDS_V1: u32 = 300;
pub const BUCKET_WIDTH_MILLISECONDS_V1: i64 = 300_000;
pub const MAX_BUCKETS_PER_BATCH: usize = 288;
pub const MAX_BATCH_WIRE_BYTES: usize = 256 * 1024;
pub const MAX_COUNTER_PER_BUCKET: u64 = 1_000_000_000;
pub const MAX_ARCHIVE_ROWS: u64 = 1_000_000;
pub const MAX_ARCHIVE_BYTES: u64 = 5 * 1024 * 1024 * 1024;
pub const CAPABILITY_TELEMETRY_ROLLUPS_V1: &str = "telemetry.rollups.v1";
pub const CAPABILITY_TELEMETRY_ARCHIVE_MANIFEST_V1: &str = "telemetry.archive-manifest.v1";
pub const ARCHIVE_MANIFEST_SIGNATURE_DOMAIN_V1: &[u8] =
    b"rustyauth.analytics.metric-bucket-manifest.v1\0";

pub const INTERACTIVE_LATENCY_BOUNDS_MILLISECONDS_V1: &[u64] =
    &[5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000];
pub const DELIVERY_LATENCY_BOUNDS_MILLISECONDS_V1: &[u64] = &[
    10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000,
];

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AnalyticsContractError {
    #[error("{field}: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("decode analytics contract: {0}")]
    Decode(String),
    #[error("analytics aggregate overflow")]
    AggregateOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationRollup {
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub denials: u64,
    pub success_rate_numerator: u64,
    pub success_rate_denominator: u64,
    pub active_account_observations: u64,
    pub latency_profile: i32,
    pub latency_count: u64,
    pub latency_sum_milliseconds: u64,
    pub latency_cumulative_counts: Vec<u64>,
    pub latency_p95_upper_bound_milliseconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyHistogramParquetV1 {
    pub profile: i32,
    pub count: u64,
    pub sum_milliseconds: u64,
    pub cumulative_counts: Vec<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthenticationFlowParquetV1 {
    pub flow: i32,
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub denials: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthenticationFailureParquetV1 {
    pub failure_class: i32,
    pub count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthenticationParquetV1 {
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub denials: u64,
    pub active_account_observations: u64,
    pub latency: LatencyHistogramParquetV1,
    pub flows: Vec<AuthenticationFlowParquetV1>,
    pub failure_classes: Vec<AuthenticationFailureParquetV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistrationParquetV1 {
    pub options_started: u64,
    pub ceremonies_opened: u64,
    pub responses_returned: u64,
    pub registrations_completed: u64,
    pub challenges_expired: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionTokenParquetV1 {
    pub sessions_created: u64,
    pub sessions_revoked: u64,
    pub user_tokens_issued: u64,
    pub service_tokens_issued: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceAccountParquetV1 {
    pub calls: u64,
    pub successes: u64,
    pub failures: u64,
    pub denials: u64,
    pub credential_rotations: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WebhookParquetV1 {
    pub deliveries: u64,
    pub successes: u64,
    pub failures: u64,
    pub backlog: u64,
    pub latency: LatencyHistogramParquetV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PlatformParquetV1 {
    pub api_requests: u64,
    pub api_errors: u64,
    pub api_latency: LatencyHistogramParquetV1,
    pub sabledb_operations: u64,
    pub sabledb_errors: u64,
    pub sabledb_latency: LatencyHistogramParquetV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RealmHealthParquetV1 {
    pub serving_state: i32,
    pub backup_age_seconds: u64,
    pub signing_key_age_seconds: u64,
    pub connector_lag_seconds: u64,
}

/// Canonical logical row consumed by the V1 Parquet adapter. Physical writer
/// metadata is deliberately excluded from compatibility; field IDs and types
/// are pinned by the published schema document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetricBucketParquetRowV1 {
    pub realm_id: String,
    pub assignment_epoch: u64,
    pub bucket_start_unix_milliseconds: i64,
    pub bucket_width_seconds: u32,
    pub revision: u64,
    pub first_event_sequence: u64,
    pub last_event_sequence: u64,
    pub metric_schema_version: i32,
    pub closed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<AuthenticationParquetV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration: Option<RegistrationParquetV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sessions_and_tokens: Option<SessionTokenParquetV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_accounts: Option<ServiceAccountParquetV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhooks: Option<WebhookParquetV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<PlatformParquetV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_health: Option<RealmHealthParquetV1>,
}

/// Decode an untrusted V1 batch with strict size, recursion, and unknown-field
/// limits before applying the semantic checks below.
pub fn decode_and_validate_batch(
    bytes: &[u8],
) -> Result<TelemetryBucketBatch, AnalyticsContractError> {
    let batch = DecodeOptions::new()
        .with_recursion_limit(32)
        .with_max_message_size(MAX_BATCH_WIRE_BYTES)
        .with_unknown_field_limit(0)
        .decode_from_slice(bytes)
        .map_err(|error| AnalyticsContractError::Decode(error.to_string()))?;
    validate_batch(&batch)?;
    Ok(batch)
}

pub fn validate_batch(batch: &TelemetryBucketBatch) -> Result<(), AnalyticsContractError> {
    reject_unknown_fields(
        &batch.__buffa_unknown_fields,
        "telemetry_bucket_batch.unknown_fields",
    )?;
    require(
        batch.transport_schema_version == TRANSPORT_SCHEMA_VERSION_V1,
        "telemetry_bucket_batch.transport_schema_version",
        "unsupported transport schema",
    )?;
    validate_uuid(&batch.batch_id, "telemetry_bucket_batch.batch_id")?;
    validate_realm_id(&batch.realm_id, "telemetry_bucket_batch.realm_id")?;
    require(
        !batch.buckets.is_empty(),
        "telemetry_bucket_batch.buckets",
        "batch must contain at least one bucket",
    )?;
    require(
        batch.buckets.len() <= MAX_BUCKETS_PER_BATCH,
        "telemetry_bucket_batch.buckets",
        "batch exceeds the V1 bucket limit",
    )?;
    require(
        batch.encode_to_vec().len() <= MAX_BATCH_WIRE_BYTES,
        "telemetry_bucket_batch",
        "encoded batch exceeds the V1 wire limit",
    )?;

    let mut keys = BTreeSet::new();
    for bucket in &batch.buckets {
        require(
            bucket.realm_id == batch.realm_id,
            "telemetry_bucket.realm_id",
            "bucket realm does not match authenticated batch realm",
        )?;
        validate_bucket(bucket)?;
        require(
            keys.insert((
                bucket.assignment_epoch,
                bucket.bucket_start_unix_milliseconds,
                bucket.bucket_width_seconds,
                bucket.metric_schema_version.to_i32(),
            )),
            "telemetry_bucket_batch.buckets",
            "batch contains more than one snapshot for the same bucket key",
        )?;
    }
    Ok(())
}

pub fn validate_bucket(bucket: &TelemetryBucket) -> Result<(), AnalyticsContractError> {
    reject_unknown_fields(
        &bucket.__buffa_unknown_fields,
        "telemetry_bucket.unknown_fields",
    )?;
    validate_realm_id(&bucket.realm_id, "telemetry_bucket.realm_id")?;
    require(
        bucket.assignment_epoch > 0,
        "telemetry_bucket.assignment_epoch",
        "assignment epoch must be positive",
    )?;
    validate_bucket_start(
        bucket.bucket_start_unix_milliseconds,
        "telemetry_bucket.bucket_start_unix_milliseconds",
    )?;
    require(
        bucket.bucket_width_seconds == BUCKET_WIDTH_SECONDS_V1,
        "telemetry_bucket.bucket_width_seconds",
        "V1 buckets are exactly five minutes",
    )?;
    require(
        bucket.revision > 0,
        "telemetry_bucket.revision",
        "revision must be positive",
    )?;
    validate_sequence_range(
        bucket.first_event_sequence,
        bucket.last_event_sequence,
        "telemetry_bucket.event_sequence",
    )?;
    require(
        bucket.metric_schema_version.as_known() == Some(MetricSchemaVersion::V1),
        "telemetry_bucket.metric_schema_version",
        "unsupported metric schema",
    )?;
    require(
        bucket.closed,
        "telemetry_bucket.closed",
        "V1 transports finalized buckets only",
    )?;

    let family_count = [
        bucket.authentication.is_set(),
        bucket.registration.is_set(),
        bucket.sessions_and_tokens.is_set(),
        bucket.service_accounts.is_set(),
        bucket.webhooks.is_set(),
        bucket.platform.is_set(),
        bucket.realm_health.is_set(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    require(
        family_count > 0,
        "telemetry_bucket",
        "bucket must contain at least one metric family",
    )?;

    if let Some(metrics) = bucket.authentication.as_option() {
        validate_authentication(metrics)?;
    }
    if let Some(metrics) = bucket.registration.as_option() {
        reject_unknown_fields(
            &metrics.__buffa_unknown_fields,
            "registration_metrics.unknown_fields",
        )?;
        validate_counters(&[
            (
                "registration_metrics.options_started",
                metrics.options_started,
            ),
            (
                "registration_metrics.ceremonies_opened",
                metrics.ceremonies_opened,
            ),
            (
                "registration_metrics.responses_returned",
                metrics.responses_returned,
            ),
            (
                "registration_metrics.registrations_completed",
                metrics.registrations_completed,
            ),
            (
                "registration_metrics.challenges_expired",
                metrics.challenges_expired,
            ),
        ])?;
        require(
            metrics.options_started >= metrics.ceremonies_opened
                && metrics.ceremonies_opened >= metrics.responses_returned
                && metrics.responses_returned >= metrics.registrations_completed,
            "registration_metrics",
            "funnel stages must be monotonically non-increasing",
        )?;
    }
    if let Some(metrics) = bucket.sessions_and_tokens.as_option() {
        reject_unknown_fields(
            &metrics.__buffa_unknown_fields,
            "session_token_metrics.unknown_fields",
        )?;
        validate_counters(&[
            (
                "session_token_metrics.sessions_created",
                metrics.sessions_created,
            ),
            (
                "session_token_metrics.sessions_revoked",
                metrics.sessions_revoked,
            ),
            (
                "session_token_metrics.user_tokens_issued",
                metrics.user_tokens_issued,
            ),
            (
                "session_token_metrics.service_tokens_issued",
                metrics.service_tokens_issued,
            ),
        ])?;
    }
    if let Some(metrics) = bucket.service_accounts.as_option() {
        reject_unknown_fields(
            &metrics.__buffa_unknown_fields,
            "service_account_metrics.unknown_fields",
        )?;
        validate_counters(&[
            ("service_account_metrics.calls", metrics.calls),
            ("service_account_metrics.successes", metrics.successes),
            ("service_account_metrics.failures", metrics.failures),
            ("service_account_metrics.denials", metrics.denials),
            (
                "service_account_metrics.credential_rotations",
                metrics.credential_rotations,
            ),
        ])?;
        require_sum(
            metrics.calls,
            &[metrics.successes, metrics.failures, metrics.denials],
            "service_account_metrics.calls",
        )?;
    }
    if let Some(metrics) = bucket.webhooks.as_option() {
        reject_unknown_fields(
            &metrics.__buffa_unknown_fields,
            "webhook_metrics.unknown_fields",
        )?;
        validate_counters(&[
            ("webhook_metrics.deliveries", metrics.deliveries),
            ("webhook_metrics.successes", metrics.successes),
            ("webhook_metrics.failures", metrics.failures),
            ("webhook_metrics.backlog", metrics.backlog),
        ])?;
        require_sum(
            metrics.deliveries,
            &[metrics.successes, metrics.failures],
            "webhook_metrics.deliveries",
        )?;
        validate_histogram(
            metrics.latency.as_option(),
            HistogramProfile::DeliveryMillisecondsV1,
            metrics.deliveries,
            "webhook_metrics.latency",
        )?;
    }
    if let Some(metrics) = bucket.platform.as_option() {
        reject_unknown_fields(
            &metrics.__buffa_unknown_fields,
            "platform_metrics.unknown_fields",
        )?;
        validate_counters(&[
            ("platform_metrics.api_requests", metrics.api_requests),
            ("platform_metrics.api_errors", metrics.api_errors),
            (
                "platform_metrics.sabledb_operations",
                metrics.sabledb_operations,
            ),
            ("platform_metrics.sabledb_errors", metrics.sabledb_errors),
        ])?;
        require(
            metrics.api_errors <= metrics.api_requests,
            "platform_metrics.api_errors",
            "errors cannot exceed requests",
        )?;
        require(
            metrics.sabledb_errors <= metrics.sabledb_operations,
            "platform_metrics.sabledb_errors",
            "errors cannot exceed operations",
        )?;
        validate_histogram(
            metrics.api_latency.as_option(),
            HistogramProfile::InteractiveMillisecondsV1,
            metrics.api_requests,
            "platform_metrics.api_latency",
        )?;
        validate_histogram(
            metrics.sabledb_latency.as_option(),
            HistogramProfile::InteractiveMillisecondsV1,
            metrics.sabledb_operations,
            "platform_metrics.sabledb_latency",
        )?;
    }
    if let Some(metrics) = bucket.realm_health.as_option() {
        reject_unknown_fields(
            &metrics.__buffa_unknown_fields,
            "realm_health_metrics.unknown_fields",
        )?;
        require(
            matches!(
                metrics.serving_state.as_known(),
                Some(
                    AnalyticsServingState::Healthy
                        | AnalyticsServingState::Degraded
                        | AnalyticsServingState::Unavailable
                )
            ),
            "realm_health_metrics.serving_state",
            "serving state must be known and specified",
        )?;
        validate_counters(&[
            (
                "realm_health_metrics.backup_age_seconds",
                metrics.backup_age_seconds,
            ),
            (
                "realm_health_metrics.signing_key_age_seconds",
                metrics.signing_key_age_seconds,
            ),
            (
                "realm_health_metrics.connector_lag_seconds",
                metrics.connector_lag_seconds,
            ),
        ])?;
    }
    Ok(())
}

pub fn validate_acknowledgement(
    acknowledgement: &TelemetryBatchAcknowledgement,
) -> Result<(), AnalyticsContractError> {
    reject_unknown_fields(
        &acknowledgement.__buffa_unknown_fields,
        "telemetry_batch_acknowledgement.unknown_fields",
    )?;
    validate_uuid(
        &acknowledgement.batch_id,
        "telemetry_batch_acknowledgement.batch_id",
    )?;
    require(
        !acknowledgement.buckets.is_empty()
            && acknowledgement.buckets.len() <= MAX_BUCKETS_PER_BATCH,
        "telemetry_batch_acknowledgement.buckets",
        "acknowledgement bucket count is outside V1 bounds",
    )?;
    let mut keys = BTreeSet::new();
    for acknowledgement in &acknowledgement.buckets {
        reject_unknown_fields(
            &acknowledgement.__buffa_unknown_fields,
            "telemetry_bucket_acknowledgement.unknown_fields",
        )?;
        let key = acknowledgement.key.as_option().ok_or_else(|| {
            invalid(
                "telemetry_bucket_acknowledgement.key",
                "bucket key is required",
            )
        })?;
        validate_bucket_key(key)?;
        require(
            acknowledgement.revision > 0,
            "telemetry_bucket_acknowledgement.revision",
            "revision must be positive",
        )?;
        let status = acknowledgement.status.as_known().ok_or_else(|| {
            invalid(
                "telemetry_bucket_acknowledgement.status",
                "acknowledgement status must be known",
            )
        })?;
        require(
            status != BucketAcknowledgementStatus::Unspecified,
            "telemetry_bucket_acknowledgement.status",
            "acknowledgement status must be specified",
        )?;
        let rejection = acknowledgement.rejection_reason.as_known().ok_or_else(|| {
            invalid(
                "telemetry_bucket_acknowledgement.rejection_reason",
                "rejection reason must be known",
            )
        })?;
        match status {
            BucketAcknowledgementStatus::Accepted
            | BucketAcknowledgementStatus::AlreadyAccepted => require(
                rejection == BucketRejectionReason::Unspecified,
                "telemetry_bucket_acknowledgement.rejection_reason",
                "accepted buckets cannot carry a rejection reason",
            )?,
            BucketAcknowledgementStatus::Rejected | BucketAcknowledgementStatus::Quarantined => {
                require(
                    rejection != BucketRejectionReason::Unspecified,
                    "telemetry_bucket_acknowledgement.rejection_reason",
                    "rejected buckets require a bounded rejection reason",
                )?
            }
            BucketAcknowledgementStatus::Unspecified => unreachable!(),
        }
        require(
            keys.insert((
                key.realm_id.clone(),
                key.assignment_epoch,
                key.bucket_start_unix_milliseconds,
                key.metric_schema_version.to_i32(),
            )),
            "telemetry_batch_acknowledgement.buckets",
            "acknowledgement contains more than one result for the same bucket key",
        )?;
    }
    Ok(())
}

pub fn validate_coverage(coverage: &ReportingCoverage) -> Result<(), AnalyticsContractError> {
    reject_unknown_fields(
        &coverage.__buffa_unknown_fields,
        "reporting_coverage.unknown_fields",
    )?;
    require(
        matches!(
            coverage.metric_family.as_known(),
            Some(
                MetricFamily::Authentication
                    | MetricFamily::Registration
                    | MetricFamily::SessionsAndTokens
                    | MetricFamily::ServiceAccounts
                    | MetricFamily::Webhooks
                    | MetricFamily::Platform
                    | MetricFamily::RealmHealth
            )
        ),
        "reporting_coverage.metric_family",
        "metric family must be known and specified",
    )?;
    let expected = coverage
        .reporting_realms
        .checked_add(coverage.stale_realms)
        .ok_or(AnalyticsContractError::AggregateOverflow)?;
    require(
        coverage.expected_realms == expected,
        "reporting_coverage.expected_realms",
        "expected realms must equal reporting plus stale realms",
    )?;
    let total = expected
        .checked_add(coverage.disabled_realms)
        .and_then(|value| value.checked_add(coverage.unsupported_realms))
        .ok_or(AnalyticsContractError::AggregateOverflow)?;
    require(
        coverage.total_realms == total,
        "reporting_coverage.total_realms",
        "total realms must include expected, disabled, and unsupported realms",
    )?;
    require(
        coverage.partial == (coverage.reporting_realms < coverage.expected_realms),
        "reporting_coverage.partial",
        "partial must reflect reporting coverage",
    )?;
    if coverage.last_complete_window_start_unix_milliseconds != 0 {
        validate_bucket_start(
            coverage.last_complete_window_start_unix_milliseconds,
            "reporting_coverage.last_complete_window_start_unix_milliseconds",
        )?;
    }
    Ok(())
}

fn validate_archive_manifest_core(
    manifest: &MetricBucketArchiveManifest,
) -> Result<(), AnalyticsContractError> {
    reject_unknown_fields(
        &manifest.__buffa_unknown_fields,
        "metric_bucket_archive_manifest.unknown_fields",
    )?;
    require(
        manifest.manifest_schema_version == MANIFEST_SCHEMA_VERSION_V1,
        "metric_bucket_archive_manifest.manifest_schema_version",
        "unsupported manifest schema",
    )?;
    require(
        manifest.metric_schema_version.as_known() == Some(MetricSchemaVersion::V1),
        "metric_bucket_archive_manifest.metric_schema_version",
        "unsupported metric schema",
    )?;
    validate_uuid(
        &manifest.manifest_id,
        "metric_bucket_archive_manifest.manifest_id",
    )?;
    validate_realm_id(
        &manifest.realm_id,
        "metric_bucket_archive_manifest.realm_id",
    )?;
    require(
        manifest.assignment_epoch > 0,
        "metric_bucket_archive_manifest.assignment_epoch",
        "assignment epoch must be positive",
    )?;
    validate_object_key(&manifest.object_key)?;
    require(
        manifest.content_sha256.len() == 32,
        "metric_bucket_archive_manifest.content_sha256",
        "SHA-256 digest must contain exactly 32 bytes",
    )?;
    require(
        (1..=MAX_ARCHIVE_BYTES).contains(&manifest.byte_length),
        "metric_bucket_archive_manifest.byte_length",
        "archive byte length is outside V1 bounds",
    )?;
    require(
        (1..=MAX_ARCHIVE_ROWS).contains(&manifest.row_count),
        "metric_bucket_archive_manifest.row_count",
        "archive row count is outside V1 bounds",
    )?;
    validate_bucket_start(
        manifest.minimum_bucket_start_unix_milliseconds,
        "metric_bucket_archive_manifest.minimum_bucket_start_unix_milliseconds",
    )?;
    validate_bucket_start(
        manifest.maximum_bucket_start_unix_milliseconds,
        "metric_bucket_archive_manifest.maximum_bucket_start_unix_milliseconds",
    )?;
    require(
        manifest.minimum_bucket_start_unix_milliseconds
            <= manifest.maximum_bucket_start_unix_milliseconds,
        "metric_bucket_archive_manifest.maximum_bucket_start_unix_milliseconds",
        "maximum bucket start precedes minimum bucket start",
    )?;
    validate_sequence_range(
        manifest.first_event_sequence,
        manifest.last_event_sequence,
        "metric_bucket_archive_manifest.event_sequence",
    )?;
    require(
        manifest.compression.as_known() == Some(ParquetCompression::Zstd),
        "metric_bucket_archive_manifest.compression",
        "V1 archives require Zstandard compression",
    )?;
    require(
        manifest.created_at_unix_milliseconds > 0,
        "metric_bucket_archive_manifest.created_at_unix_milliseconds",
        "creation time must be positive",
    )?;
    validate_signing_key_id(&manifest.signing_key_id)?;
    Ok(())
}

pub fn validate_archive_manifest(
    manifest: &MetricBucketArchiveManifest,
) -> Result<(), AnalyticsContractError> {
    validate_archive_manifest_core(manifest)?;
    require(
        manifest.signature.len() == 64,
        "metric_bucket_archive_manifest.signature",
        "P-256 signature must contain exactly 64 raw bytes",
    )?;
    Ok(())
}

/// Return the deterministic bytes covered by a V1 archive-manifest signature.
/// The committed signature field is validated, then omitted from the encoded
/// message and prefixed with a versioned domain separator.
pub fn archive_manifest_signing_payload(
    manifest: &MetricBucketArchiveManifest,
) -> Result<Vec<u8>, AnalyticsContractError> {
    validate_archive_manifest_core(manifest)?;
    require(
        manifest.signature.is_empty() || manifest.signature.len() == 64,
        "metric_bucket_archive_manifest.signature",
        "signature must be empty before signing or contain exactly 64 raw bytes",
    )?;
    let mut unsigned = manifest.clone();
    unsigned.signature.clear();
    let encoded = unsigned.encode_to_vec();
    let mut payload =
        Vec::with_capacity(ARCHIVE_MANIFEST_SIGNATURE_DOMAIN_V1.len() + encoded.len());
    payload.extend_from_slice(ARCHIVE_MANIFEST_SIGNATURE_DOMAIN_V1);
    payload.extend_from_slice(&encoded);
    Ok(payload)
}

pub fn canonical_parquet_row_v1(
    bucket: &TelemetryBucket,
) -> Result<MetricBucketParquetRowV1, AnalyticsContractError> {
    validate_bucket(bucket)?;
    Ok(MetricBucketParquetRowV1 {
        realm_id: bucket.realm_id.clone(),
        assignment_epoch: bucket.assignment_epoch,
        bucket_start_unix_milliseconds: bucket.bucket_start_unix_milliseconds,
        bucket_width_seconds: bucket.bucket_width_seconds,
        revision: bucket.revision,
        first_event_sequence: bucket.first_event_sequence,
        last_event_sequence: bucket.last_event_sequence,
        metric_schema_version: bucket.metric_schema_version.to_i32(),
        closed: bucket.closed,
        authentication: bucket
            .authentication
            .as_option()
            .map(|metrics| AuthenticationParquetV1 {
                attempts: metrics.attempts,
                successes: metrics.successes,
                failures: metrics.failures,
                denials: metrics.denials,
                active_account_observations: metrics.active_account_observations,
                latency: parquet_histogram(&metrics.latency),
                flows: metrics
                    .flows
                    .iter()
                    .map(|flow| AuthenticationFlowParquetV1 {
                        flow: flow.flow.to_i32(),
                        attempts: flow.attempts,
                        successes: flow.successes,
                        failures: flow.failures,
                        denials: flow.denials,
                    })
                    .collect(),
                failure_classes: metrics
                    .failure_classes
                    .iter()
                    .map(|failure| AuthenticationFailureParquetV1 {
                        failure_class: failure.failure_class.to_i32(),
                        count: failure.count,
                    })
                    .collect(),
            }),
        registration: bucket
            .registration
            .as_option()
            .map(|metrics| RegistrationParquetV1 {
                options_started: metrics.options_started,
                ceremonies_opened: metrics.ceremonies_opened,
                responses_returned: metrics.responses_returned,
                registrations_completed: metrics.registrations_completed,
                challenges_expired: metrics.challenges_expired,
            }),
        sessions_and_tokens: bucket.sessions_and_tokens.as_option().map(|metrics| {
            SessionTokenParquetV1 {
                sessions_created: metrics.sessions_created,
                sessions_revoked: metrics.sessions_revoked,
                user_tokens_issued: metrics.user_tokens_issued,
                service_tokens_issued: metrics.service_tokens_issued,
            }
        }),
        service_accounts: bucket.service_accounts.as_option().map(|metrics| {
            ServiceAccountParquetV1 {
                calls: metrics.calls,
                successes: metrics.successes,
                failures: metrics.failures,
                denials: metrics.denials,
                credential_rotations: metrics.credential_rotations,
            }
        }),
        webhooks: bucket.webhooks.as_option().map(|metrics| WebhookParquetV1 {
            deliveries: metrics.deliveries,
            successes: metrics.successes,
            failures: metrics.failures,
            backlog: metrics.backlog,
            latency: parquet_histogram(&metrics.latency),
        }),
        platform: bucket
            .platform
            .as_option()
            .map(|metrics| PlatformParquetV1 {
                api_requests: metrics.api_requests,
                api_errors: metrics.api_errors,
                api_latency: parquet_histogram(&metrics.api_latency),
                sabledb_operations: metrics.sabledb_operations,
                sabledb_errors: metrics.sabledb_errors,
                sabledb_latency: parquet_histogram(&metrics.sabledb_latency),
            }),
        realm_health: bucket
            .realm_health
            .as_option()
            .map(|metrics| RealmHealthParquetV1 {
                serving_state: metrics.serving_state.to_i32(),
                backup_age_seconds: metrics.backup_age_seconds,
                signing_key_age_seconds: metrics.signing_key_age_seconds,
                connector_lag_seconds: metrics.connector_lag_seconds,
            }),
    })
}

pub fn telemetry_bucket_from_parquet_row_v1(
    row: MetricBucketParquetRowV1,
) -> Result<TelemetryBucket, AnalyticsContractError> {
    let histogram = |value: LatencyHistogramParquetV1| LatencyHistogram {
        profile: HistogramProfile::from_i32(value.profile)
            .unwrap_or(HistogramProfile::Unspecified)
            .into(),
        count: value.count,
        sum_milliseconds: value.sum_milliseconds,
        cumulative_counts: value.cumulative_counts,
        ..Default::default()
    };
    let bucket = TelemetryBucket {
        realm_id: row.realm_id,
        assignment_epoch: row.assignment_epoch,
        bucket_start_unix_milliseconds: row.bucket_start_unix_milliseconds,
        bucket_width_seconds: row.bucket_width_seconds,
        revision: row.revision,
        first_event_sequence: row.first_event_sequence,
        last_event_sequence: row.last_event_sequence,
        metric_schema_version: MetricSchemaVersion::from_i32(row.metric_schema_version)
            .unwrap_or(MetricSchemaVersion::Unspecified)
            .into(),
        closed: row.closed,
        authentication: row
            .authentication
            .map(|metrics| AuthenticationMetrics {
                attempts: metrics.attempts,
                successes: metrics.successes,
                failures: metrics.failures,
                denials: metrics.denials,
                active_account_observations: metrics.active_account_observations,
                latency: histogram(metrics.latency).into(),
                flows: metrics
                    .flows
                    .into_iter()
                    .map(|flow| AuthenticationFlowCount {
                        flow: AuthenticationFlow::from_i32(flow.flow)
                            .unwrap_or(AuthenticationFlow::Unspecified)
                            .into(),
                        attempts: flow.attempts,
                        successes: flow.successes,
                        failures: flow.failures,
                        denials: flow.denials,
                        ..Default::default()
                    })
                    .collect(),
                failure_classes: metrics
                    .failure_classes
                    .into_iter()
                    .map(|failure| AuthenticationFailureCount {
                        failure_class: FailureClass::from_i32(failure.failure_class)
                            .unwrap_or(FailureClass::Unspecified)
                            .into(),
                        count: failure.count,
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            })
            .into(),
        registration: row
            .registration
            .map(|metrics| RegistrationMetrics {
                options_started: metrics.options_started,
                ceremonies_opened: metrics.ceremonies_opened,
                responses_returned: metrics.responses_returned,
                registrations_completed: metrics.registrations_completed,
                challenges_expired: metrics.challenges_expired,
                ..Default::default()
            })
            .into(),
        sessions_and_tokens: row
            .sessions_and_tokens
            .map(|metrics| SessionTokenMetrics {
                sessions_created: metrics.sessions_created,
                sessions_revoked: metrics.sessions_revoked,
                user_tokens_issued: metrics.user_tokens_issued,
                service_tokens_issued: metrics.service_tokens_issued,
                ..Default::default()
            })
            .into(),
        service_accounts: row
            .service_accounts
            .map(|metrics| ServiceAccountMetrics {
                calls: metrics.calls,
                successes: metrics.successes,
                failures: metrics.failures,
                denials: metrics.denials,
                credential_rotations: metrics.credential_rotations,
                ..Default::default()
            })
            .into(),
        webhooks: row
            .webhooks
            .map(|metrics| WebhookMetrics {
                deliveries: metrics.deliveries,
                successes: metrics.successes,
                failures: metrics.failures,
                backlog: metrics.backlog,
                latency: histogram(metrics.latency).into(),
                ..Default::default()
            })
            .into(),
        platform: row
            .platform
            .map(|metrics| PlatformMetrics {
                api_requests: metrics.api_requests,
                api_errors: metrics.api_errors,
                api_latency: histogram(metrics.api_latency).into(),
                sabledb_operations: metrics.sabledb_operations,
                sabledb_errors: metrics.sabledb_errors,
                sabledb_latency: histogram(metrics.sabledb_latency).into(),
                ..Default::default()
            })
            .into(),
        realm_health: row
            .realm_health
            .map(|metrics| RealmHealthMetrics {
                serving_state: AnalyticsServingState::from_i32(metrics.serving_state)
                    .unwrap_or(AnalyticsServingState::Unspecified)
                    .into(),
                backup_age_seconds: metrics.backup_age_seconds,
                signing_key_age_seconds: metrics.signing_key_age_seconds,
                connector_lag_seconds: metrics.connector_lag_seconds,
                ..Default::default()
            })
            .into(),
        ..Default::default()
    };
    validate_bucket(&bucket)?;
    Ok(bucket)
}

/// Aggregate authentication facts directly from canonical realm buckets.
/// Rates remain numerator/denominator pairs and percentiles are calculated only
/// after merging cumulative histograms.
pub fn aggregate_authentication<'a>(
    buckets: impl IntoIterator<Item = &'a TelemetryBucket>,
) -> Result<AuthenticationRollup, AnalyticsContractError> {
    let mut attempts = 0u64;
    let mut successes = 0u64;
    let mut failures = 0u64;
    let mut denials = 0u64;
    let mut active_account_observations = 0u64;
    let mut latency_profile = None;
    let mut latency_count = 0u64;
    let mut latency_sum_milliseconds = 0u64;
    let mut latency_cumulative_counts = Vec::new();

    for bucket in buckets {
        validate_bucket(bucket)?;
        let Some(authentication) = bucket.authentication.as_option() else {
            continue;
        };
        attempts = checked_add(attempts, authentication.attempts)?;
        successes = checked_add(successes, authentication.successes)?;
        failures = checked_add(failures, authentication.failures)?;
        denials = checked_add(denials, authentication.denials)?;
        active_account_observations = checked_add(
            active_account_observations,
            authentication.active_account_observations,
        )?;

        let histogram = authentication
            .latency
            .as_option()
            .expect("validated histogram");
        let profile = histogram.profile.as_known().expect("validated profile");
        if let Some(existing) = latency_profile {
            require(
                existing == profile,
                "authentication_rollup.latency_profile",
                "cannot merge different histogram profiles",
            )?;
        } else {
            latency_profile = Some(profile);
            latency_cumulative_counts.resize(histogram.cumulative_counts.len(), 0);
        }
        latency_count = checked_add(latency_count, histogram.count)?;
        latency_sum_milliseconds =
            checked_add(latency_sum_milliseconds, histogram.sum_milliseconds)?;
        for (aggregate, value) in latency_cumulative_counts
            .iter_mut()
            .zip(&histogram.cumulative_counts)
        {
            *aggregate = checked_add(*aggregate, *value)?;
        }
    }

    let latency_profile = latency_profile.unwrap_or(HistogramProfile::InteractiveMillisecondsV1);
    let latency_p95_upper_bound_milliseconds =
        histogram_quantile_upper_bound(latency_profile, &latency_cumulative_counts, 95, 100);
    Ok(AuthenticationRollup {
        attempts,
        successes,
        failures,
        denials,
        success_rate_numerator: successes,
        success_rate_denominator: attempts,
        active_account_observations,
        latency_profile: latency_profile as i32,
        latency_count,
        latency_sum_milliseconds,
        latency_cumulative_counts,
        latency_p95_upper_bound_milliseconds,
    })
}

pub fn histogram_upper_bounds_milliseconds(profile: HistogramProfile) -> Option<&'static [u64]> {
    match profile {
        HistogramProfile::InteractiveMillisecondsV1 => {
            Some(INTERACTIVE_LATENCY_BOUNDS_MILLISECONDS_V1)
        }
        HistogramProfile::DeliveryMillisecondsV1 => Some(DELIVERY_LATENCY_BOUNDS_MILLISECONDS_V1),
        HistogramProfile::Unspecified => None,
    }
}

fn validate_authentication(metrics: &AuthenticationMetrics) -> Result<(), AnalyticsContractError> {
    reject_unknown_fields(
        &metrics.__buffa_unknown_fields,
        "authentication_metrics.unknown_fields",
    )?;
    validate_counters(&[
        ("authentication_metrics.attempts", metrics.attempts),
        ("authentication_metrics.successes", metrics.successes),
        ("authentication_metrics.failures", metrics.failures),
        ("authentication_metrics.denials", metrics.denials),
        (
            "authentication_metrics.active_account_observations",
            metrics.active_account_observations,
        ),
    ])?;
    require_sum(
        metrics.attempts,
        &[metrics.successes, metrics.failures, metrics.denials],
        "authentication_metrics.attempts",
    )?;
    validate_histogram(
        metrics.latency.as_option(),
        HistogramProfile::InteractiveMillisecondsV1,
        metrics.attempts,
        "authentication_metrics.latency",
    )?;

    let mut flow_kinds = BTreeSet::new();
    let mut flow_totals = [0u64; 4];
    for flow in &metrics.flows {
        reject_unknown_fields(
            &flow.__buffa_unknown_fields,
            "authentication_flow_count.unknown_fields",
        )?;
        let kind = flow.flow.as_known().ok_or_else(|| {
            invalid(
                "authentication_flow_count.flow",
                "authentication flow must be known",
            )
        })?;
        require(
            kind != crate::proto::rustyauth::analytics::v1::AuthenticationFlow::Unspecified,
            "authentication_flow_count.flow",
            "authentication flow must be specified",
        )?;
        require(
            flow_kinds.insert(kind as i32),
            "authentication_metrics.flows",
            "authentication flow appears more than once",
        )?;
        validate_counters(&[
            ("authentication_flow_count.attempts", flow.attempts),
            ("authentication_flow_count.successes", flow.successes),
            ("authentication_flow_count.failures", flow.failures),
            ("authentication_flow_count.denials", flow.denials),
        ])?;
        require_sum(
            flow.attempts,
            &[flow.successes, flow.failures, flow.denials],
            "authentication_flow_count.attempts",
        )?;
        for (total, value) in
            flow_totals
                .iter_mut()
                .zip([flow.attempts, flow.successes, flow.failures, flow.denials])
        {
            *total = checked_add(*total, value)?;
        }
    }
    require(
        flow_totals
            == [
                metrics.attempts,
                metrics.successes,
                metrics.failures,
                metrics.denials,
            ],
        "authentication_metrics.flows",
        "flow breakdown must exactly match authentication totals",
    )?;

    let mut failure_classes = BTreeSet::new();
    let mut failure_total = 0u64;
    for failure in &metrics.failure_classes {
        reject_unknown_fields(
            &failure.__buffa_unknown_fields,
            "authentication_failure_count.unknown_fields",
        )?;
        let failure_class = failure.failure_class.as_known().ok_or_else(|| {
            invalid(
                "authentication_failure_count.failure_class",
                "failure class must be known",
            )
        })?;
        require(
            failure_class != FailureClass::Unspecified,
            "authentication_failure_count.failure_class",
            "failure class must be specified",
        )?;
        require(
            failure_classes.insert(failure_class as i32),
            "authentication_metrics.failure_classes",
            "failure class appears more than once",
        )?;
        validate_counter("authentication_failure_count.count", failure.count)?;
        failure_total = checked_add(failure_total, failure.count)?;
    }
    let rejected = checked_add(metrics.failures, metrics.denials)?;
    require(
        failure_total == rejected,
        "authentication_metrics.failure_classes",
        "failure breakdown must exactly match failures plus denials",
    )?;
    Ok(())
}

fn parquet_histogram(
    histogram: &buffa::MessageField<LatencyHistogram>,
) -> LatencyHistogramParquetV1 {
    let histogram = histogram.as_option().expect("validated histogram");
    LatencyHistogramParquetV1 {
        profile: histogram.profile.to_i32(),
        count: histogram.count,
        sum_milliseconds: histogram.sum_milliseconds,
        cumulative_counts: histogram.cumulative_counts.clone(),
    }
}

fn validate_histogram(
    histogram: Option<&LatencyHistogram>,
    expected_profile: HistogramProfile,
    expected_count: u64,
    field: &'static str,
) -> Result<(), AnalyticsContractError> {
    let histogram = histogram.ok_or_else(|| invalid(field, "histogram is required"))?;
    reject_unknown_fields(&histogram.__buffa_unknown_fields, field)?;
    require(
        histogram.profile.as_known() == Some(expected_profile),
        field,
        "histogram profile is unknown or invalid for this metric family",
    )?;
    validate_counter(field, histogram.count)?;
    require(
        histogram.count == expected_count,
        field,
        "histogram count must equal the metric event count",
    )?;
    let boundaries = histogram_upper_bounds_milliseconds(expected_profile)
        .expect("a validated profile has boundaries");
    require(
        histogram.cumulative_counts.len() == boundaries.len() + 1,
        field,
        "histogram must contain every fixed boundary and the +Inf count",
    )?;
    let mut previous = 0;
    for count in &histogram.cumulative_counts {
        validate_counter(field, *count)?;
        require(
            *count >= previous && *count <= histogram.count,
            field,
            "cumulative histogram counts must be monotonic and bounded by count",
        )?;
        previous = *count;
    }
    require(
        previous == histogram.count,
        field,
        "the +Inf cumulative count must equal count",
    )?;
    let maximum_sum = u128::from(histogram.count) * u128::from(24 * 60 * 60 * 1_000u64);
    require(
        u128::from(histogram.sum_milliseconds) <= maximum_sum,
        field,
        "histogram sum exceeds the V1 per-event bound",
    )?;
    Ok(())
}

fn validate_bucket_key(key: &TelemetryBucketKey) -> Result<(), AnalyticsContractError> {
    reject_unknown_fields(
        &key.__buffa_unknown_fields,
        "telemetry_bucket_key.unknown_fields",
    )?;
    validate_realm_id(&key.realm_id, "telemetry_bucket_key.realm_id")?;
    require(
        key.assignment_epoch > 0,
        "telemetry_bucket_key.assignment_epoch",
        "assignment epoch must be positive",
    )?;
    validate_bucket_start(
        key.bucket_start_unix_milliseconds,
        "telemetry_bucket_key.bucket_start_unix_milliseconds",
    )?;
    require(
        key.bucket_width_seconds == BUCKET_WIDTH_SECONDS_V1,
        "telemetry_bucket_key.bucket_width_seconds",
        "V1 buckets are exactly five minutes",
    )?;
    require(
        key.metric_schema_version.as_known() == Some(MetricSchemaVersion::V1),
        "telemetry_bucket_key.metric_schema_version",
        "unsupported metric schema",
    )
}

fn validate_uuid(value: &str, field: &'static str) -> Result<(), AnalyticsContractError> {
    let parsed = Uuid::parse_str(value).map_err(|_| invalid(field, "must be a canonical UUID"))?;
    require(
        parsed.to_string() == value,
        field,
        "must be a lowercase canonical UUID",
    )
}

fn validate_realm_id(value: &str, field: &'static str) -> Result<(), AnalyticsContractError> {
    require(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        field,
        "must be a 1-64 character stable realm identifier",
    )
}

fn validate_bucket_start(value: i64, field: &'static str) -> Result<(), AnalyticsContractError> {
    require(
        value >= 0 && value % BUCKET_WIDTH_MILLISECONDS_V1 == 0,
        field,
        "must be a non-negative UTC-aligned five-minute instant",
    )
}

fn validate_sequence_range(
    first: u64,
    last: u64,
    field: &'static str,
) -> Result<(), AnalyticsContractError> {
    require(
        (first == 0 && last == 0) || (first > 0 && last >= first),
        field,
        "sequences must both be zero or form an ordered positive range",
    )
}

fn validate_object_key(value: &str) -> Result<(), AnalyticsContractError> {
    let valid_segments = !value.is_empty()
        && value.len() <= 1_024
        && !value.starts_with('/')
        && !value.contains("\\")
        && !value.contains('?')
        && !value.contains('#')
        && !value.contains("://")
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..");
    require(
        valid_segments,
        "metric_bucket_archive_manifest.object_key",
        "must be a credential-free relative object key",
    )
}

fn validate_signing_key_id(value: &str) -> Result<(), AnalyticsContractError> {
    require(
        (1..=128).contains(&value.len())
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            }),
        "metric_bucket_archive_manifest.signing_key_id",
        "contains characters outside the bounded key-id alphabet",
    )
}

fn validate_counters(values: &[(&'static str, u64)]) -> Result<(), AnalyticsContractError> {
    for &(field, value) in values {
        validate_counter(field, value)?;
    }
    Ok(())
}

fn validate_counter(field: &'static str, value: u64) -> Result<(), AnalyticsContractError> {
    require(
        value <= MAX_COUNTER_PER_BUCKET,
        field,
        "value exceeds the V1 per-bucket bound",
    )
}

fn require_sum(
    total: u64,
    parts: &[u64],
    field: &'static str,
) -> Result<(), AnalyticsContractError> {
    let sum = parts.iter().try_fold(0u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or(AnalyticsContractError::AggregateOverflow)
    })?;
    require(
        total == sum,
        field,
        "total does not equal its bounded outcomes",
    )
}

fn histogram_quantile_upper_bound(
    profile: HistogramProfile,
    cumulative_counts: &[u64],
    numerator: u64,
    denominator: u64,
) -> Option<u64> {
    let count = *cumulative_counts.last()?;
    if count == 0 || denominator == 0 || numerator == 0 || numerator > denominator {
        return None;
    }
    let rank = count
        .saturating_mul(numerator)
        .saturating_add(denominator - 1)
        / denominator;
    let index = cumulative_counts
        .iter()
        .position(|cumulative| *cumulative >= rank)?;
    histogram_upper_bounds_milliseconds(profile)?
        .get(index)
        .copied()
}

fn checked_add(left: u64, right: u64) -> Result<u64, AnalyticsContractError> {
    left.checked_add(right)
        .ok_or(AnalyticsContractError::AggregateOverflow)
}

fn reject_unknown_fields(
    fields: &buffa::UnknownFields,
    field: &'static str,
) -> Result<(), AnalyticsContractError> {
    require(
        fields.is_empty(),
        field,
        "unknown V1 fields require a newer metric schema version",
    )
}

fn require(
    condition: bool,
    field: &'static str,
    reason: &'static str,
) -> Result<(), AnalyticsContractError> {
    condition
        .then_some(())
        .ok_or_else(|| invalid(field, reason))
}

fn invalid(field: &'static str, reason: &'static str) -> AnalyticsContractError {
    AnalyticsContractError::Invalid { field, reason }
}

#[cfg(test)]
mod tests {
    use buffa::{Message, MessageField};

    use super::*;
    use crate::proto::rustyauth::analytics::v1::{
        AnalyticsServingState, AuthenticationFailureCount, AuthenticationFlow,
        AuthenticationFlowCount, AuthenticationMetrics, LatencyHistogram,
        MetricBucketArchiveManifest, PlatformMetrics, RealmHealthMetrics, RegistrationMetrics,
        ServiceAccountMetrics, SessionTokenMetrics, TelemetryBucketAcknowledgement, WebhookMetrics,
    };

    const REALM_ID: &str = "11111111-1111-4111-8111-111111111111";
    const SECOND_REALM_ID: &str = "22222222-2222-4222-8222-222222222222";
    const BATCH_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const MANIFEST_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const BUCKET_START: i64 = 1_800_000_000_000;

    fn interactive_histogram(count: u64, sum: u64, cumulative_counts: &[u64]) -> LatencyHistogram {
        LatencyHistogram {
            profile: HistogramProfile::InteractiveMillisecondsV1.into(),
            count,
            sum_milliseconds: sum,
            cumulative_counts: cumulative_counts.to_vec(),
            ..Default::default()
        }
    }

    fn delivery_histogram(count: u64, sum: u64, cumulative_counts: &[u64]) -> LatencyHistogram {
        LatencyHistogram {
            profile: HistogramProfile::DeliveryMillisecondsV1.into(),
            count,
            sum_milliseconds: sum,
            cumulative_counts: cumulative_counts.to_vec(),
            ..Default::default()
        }
    }

    fn sample_authentication() -> AuthenticationMetrics {
        AuthenticationMetrics {
            attempts: 10,
            successes: 8,
            failures: 1,
            denials: 1,
            latency: MessageField::some(interactive_histogram(
                10,
                1_200,
                &[0, 0, 1, 2, 4, 7, 9, 10, 10, 10, 10, 10],
            )),
            flows: vec![
                AuthenticationFlowCount {
                    flow: AuthenticationFlow::Passkey.into(),
                    attempts: 8,
                    successes: 7,
                    failures: 1,
                    denials: 0,
                    ..Default::default()
                },
                AuthenticationFlowCount {
                    flow: AuthenticationFlow::EmailLink.into(),
                    attempts: 2,
                    successes: 1,
                    failures: 0,
                    denials: 1,
                    ..Default::default()
                },
            ],
            failure_classes: vec![
                AuthenticationFailureCount {
                    failure_class: FailureClass::InvalidCredential.into(),
                    count: 1,
                    ..Default::default()
                },
                AuthenticationFailureCount {
                    failure_class: FailureClass::PolicyDenied.into(),
                    count: 1,
                    ..Default::default()
                },
            ],
            active_account_observations: 7,
            ..Default::default()
        }
    }

    fn second_authentication() -> AuthenticationMetrics {
        AuthenticationMetrics {
            attempts: 30,
            successes: 21,
            failures: 6,
            denials: 3,
            latency: MessageField::some(interactive_histogram(
                30,
                6_000,
                &[0, 1, 3, 6, 10, 18, 25, 28, 30, 30, 30, 30],
            )),
            flows: vec![
                AuthenticationFlowCount {
                    flow: AuthenticationFlow::Passkey.into(),
                    attempts: 24,
                    successes: 18,
                    failures: 4,
                    denials: 2,
                    ..Default::default()
                },
                AuthenticationFlowCount {
                    flow: AuthenticationFlow::EmailLink.into(),
                    attempts: 5,
                    successes: 3,
                    failures: 1,
                    denials: 1,
                    ..Default::default()
                },
                AuthenticationFlowCount {
                    flow: AuthenticationFlow::Recovery.into(),
                    attempts: 1,
                    successes: 0,
                    failures: 1,
                    denials: 0,
                    ..Default::default()
                },
            ],
            failure_classes: vec![
                AuthenticationFailureCount {
                    failure_class: FailureClass::InvalidCredential.into(),
                    count: 5,
                    ..Default::default()
                },
                AuthenticationFailureCount {
                    failure_class: FailureClass::ChallengeExpired.into(),
                    count: 1,
                    ..Default::default()
                },
                AuthenticationFailureCount {
                    failure_class: FailureClass::PolicyDenied.into(),
                    count: 2,
                    ..Default::default()
                },
                AuthenticationFailureCount {
                    failure_class: FailureClass::RateLimited.into(),
                    count: 1,
                    ..Default::default()
                },
            ],
            active_account_observations: 20,
            ..Default::default()
        }
    }

    fn sample_bucket() -> TelemetryBucket {
        TelemetryBucket {
            realm_id: REALM_ID.into(),
            assignment_epoch: 7,
            bucket_start_unix_milliseconds: BUCKET_START,
            bucket_width_seconds: BUCKET_WIDTH_SECONDS_V1,
            revision: 2,
            first_event_sequence: 101,
            last_event_sequence: 112,
            metric_schema_version: MetricSchemaVersion::V1.into(),
            closed: true,
            authentication: MessageField::some(sample_authentication()),
            registration: MessageField::some(RegistrationMetrics {
                options_started: 5,
                ceremonies_opened: 4,
                responses_returned: 3,
                registrations_completed: 2,
                challenges_expired: 1,
                ..Default::default()
            }),
            sessions_and_tokens: MessageField::some(SessionTokenMetrics {
                sessions_created: 8,
                sessions_revoked: 1,
                user_tokens_issued: 9,
                service_tokens_issued: 3,
                ..Default::default()
            }),
            service_accounts: MessageField::some(ServiceAccountMetrics {
                calls: 6,
                successes: 4,
                failures: 1,
                denials: 1,
                credential_rotations: 1,
                ..Default::default()
            }),
            webhooks: MessageField::some(WebhookMetrics {
                deliveries: 4,
                successes: 3,
                failures: 1,
                latency: MessageField::some(delivery_histogram(
                    4,
                    2_000,
                    &[0, 0, 0, 1, 1, 2, 3, 4, 4, 4, 4, 4],
                )),
                backlog: 2,
                ..Default::default()
            }),
            platform: MessageField::some(PlatformMetrics {
                api_requests: 20,
                api_errors: 2,
                api_latency: MessageField::some(interactive_histogram(
                    20,
                    2_500,
                    &[0, 1, 3, 6, 10, 15, 18, 20, 20, 20, 20, 20],
                )),
                sabledb_operations: 30,
                sabledb_errors: 1,
                sabledb_latency: MessageField::some(interactive_histogram(
                    30,
                    1_500,
                    &[1, 4, 10, 18, 25, 29, 30, 30, 30, 30, 30, 30],
                )),
                ..Default::default()
            }),
            realm_health: MessageField::some(RealmHealthMetrics {
                serving_state: AnalyticsServingState::Healthy.into(),
                backup_age_seconds: 3_600,
                signing_key_age_seconds: 86_400,
                connector_lag_seconds: 30,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn sample_batch() -> TelemetryBucketBatch {
        TelemetryBucketBatch {
            transport_schema_version: TRANSPORT_SCHEMA_VERSION_V1,
            batch_id: BATCH_ID.into(),
            realm_id: REALM_ID.into(),
            buckets: vec![sample_bucket()],
            ..Default::default()
        }
    }

    fn sample_manifest() -> MetricBucketArchiveManifest {
        MetricBucketArchiveManifest {
            manifest_schema_version: MANIFEST_SCHEMA_VERSION_V1,
            metric_schema_version: MetricSchemaVersion::V1.into(),
            manifest_id: MANIFEST_ID.into(),
            realm_id: REALM_ID.into(),
            assignment_epoch: 7,
            object_key: "rustyauth-telemetry/v1/realm=11111111-1111-4111-8111-111111111111/year=2027/month=01/day=15/hour=08/metric-buckets-000000101-000000112.parquet".into(),
            content_sha256: (0u8..32).collect(),
            byte_length: 8_192,
            row_count: 1,
            minimum_bucket_start_unix_milliseconds: BUCKET_START,
            maximum_bucket_start_unix_milliseconds: BUCKET_START,
            first_event_sequence: 101,
            last_event_sequence: 112,
            compression: ParquetCompression::Zstd.into(),
            created_at_unix_milliseconds: BUCKET_START + BUCKET_WIDTH_MILLISECONDS_V1,
            signing_key_id: "analytics-manifest:p256:v1".into(),
            signature: (0u8..64).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn v1_batch_and_wire_fixture_are_stable() {
        let batch = sample_batch();
        validate_batch(&batch).unwrap();
        let encoded = batch.encode_to_vec();
        let expected = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/packages/protocol/fixtures/analytics/v1/telemetry-bucket-v1.hex"
        ))
        .trim();
        assert_eq!(hex::encode(&encoded), expected);
        assert_eq!(decode_and_validate_batch(&encoded).unwrap(), batch);
    }

    #[test]
    fn incompatible_and_high_cardinality_inputs_fail_closed() {
        let mut batch = sample_batch();
        batch.buckets[0].metric_schema_version = 99.into();
        assert!(validate_batch(&batch).is_err());

        let mut batch = sample_batch();
        let duplicate = batch.buckets[0].authentication.flows[0].clone();
        batch.buckets[0]
            .authentication
            .modify(|metrics| metrics.flows.push(duplicate));
        assert!(validate_batch(&batch).is_err());

        let mut batch = sample_batch();
        batch.buckets = vec![sample_bucket(); MAX_BUCKETS_PER_BATCH + 1];
        assert!(validate_batch(&batch).is_err());

        let mut encoded = sample_batch().encode_to_vec();
        // Unknown field 99 with a varint value. V1 rejects it at decode rather
        // than silently accepting a changed contract under the old version.
        encoded.extend_from_slice(&[0x98, 0x06, 0x01]);
        assert!(decode_and_validate_batch(&encoded).is_err());
    }

    #[test]
    fn aggregation_uses_ratio_of_sums_and_merged_histograms() {
        let first = sample_bucket();
        let mut second = sample_bucket();
        second.realm_id = SECOND_REALM_ID.into();
        second.authentication = MessageField::some(second_authentication());
        let rollup = aggregate_authentication([&first, &second]).unwrap();
        let actual = serde_json::to_value(rollup).unwrap();
        let expected: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/packages/protocol/fixtures/analytics/v1/authentication-rollup-v1.json"
        )))
        .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn acknowledgement_and_coverage_invariants_are_bounded() {
        let acknowledgement = TelemetryBatchAcknowledgement {
            batch_id: BATCH_ID.into(),
            buckets: vec![TelemetryBucketAcknowledgement {
                key: MessageField::some(TelemetryBucketKey {
                    realm_id: REALM_ID.into(),
                    assignment_epoch: 7,
                    bucket_start_unix_milliseconds: BUCKET_START,
                    bucket_width_seconds: BUCKET_WIDTH_SECONDS_V1,
                    metric_schema_version: MetricSchemaVersion::V1.into(),
                    ..Default::default()
                }),
                revision: 2,
                status: BucketAcknowledgementStatus::Accepted.into(),
                rejection_reason: BucketRejectionReason::Unspecified.into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        validate_acknowledgement(&acknowledgement).unwrap();

        let coverage = ReportingCoverage {
            metric_family: MetricFamily::Authentication.into(),
            total_realms: 10,
            expected_realms: 7,
            reporting_realms: 5,
            stale_realms: 2,
            disabled_realms: 1,
            unsupported_realms: 2,
            last_complete_window_start_unix_milliseconds: BUCKET_START,
            partial: true,
            ..Default::default()
        };
        validate_coverage(&coverage).unwrap();

        let mut dishonest = coverage;
        dishonest.partial = false;
        assert!(validate_coverage(&dishonest).is_err());
    }

    #[test]
    fn archive_manifest_protojson_fixture_is_compatible() {
        let expected = sample_manifest();
        validate_archive_manifest(&expected).unwrap();
        let fixture: MetricBucketArchiveManifest = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/packages/protocol/fixtures/analytics/v1/archive-manifest-v1.json"
        )))
        .unwrap();
        assert_eq!(fixture, expected);
        assert_eq!(
            serde_json::to_value(&fixture).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        assert_eq!(
            hex::encode(archive_manifest_signing_payload(&expected).unwrap()),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/packages/protocol/fixtures/analytics/v1/archive-manifest-v1.signing.hex"
            ))
            .trim()
        );
        let mut unsigned = expected;
        unsigned.signature.clear();
        assert_eq!(
            archive_manifest_signing_payload(&unsigned).unwrap(),
            archive_manifest_signing_payload(&fixture).unwrap()
        );
    }

    #[test]
    fn parquet_schema_has_stable_unique_fields() {
        let schema: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/packages/protocol/schemas/analytics/v1/metric-bucket-v1.parquet.schema.json"
        )))
        .unwrap();
        assert_eq!(schema["schemaName"], "rustyauth-metric-bucket-v1");
        assert_eq!(schema["schemaVersion"], 1);
        assert_eq!(schema["compression"], "ZSTD");
        let fields = schema["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 72);
        let ids = fields
            .iter()
            .map(|field| field["id"].as_u64().unwrap())
            .collect::<BTreeSet<_>>();
        let paths = fields
            .iter()
            .map(|field| field["path"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), fields.len());
        assert_eq!(paths.len(), fields.len());
        assert_eq!(
            ids.iter().copied().collect::<Vec<_>>(),
            (1..=72).collect::<Vec<_>>()
        );
    }

    #[test]
    fn canonical_parquet_row_fixture_is_stable() {
        let actual =
            serde_json::to_value(canonical_parquet_row_v1(&sample_bucket()).unwrap()).unwrap();
        let expected: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/packages/protocol/fixtures/analytics/v1/metric-bucket-v1.parquet-row.json"
        )))
        .unwrap();
        assert_eq!(actual, expected);
    }
}
