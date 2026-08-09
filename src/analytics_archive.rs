//! Exact V1 Parquet interchange for approved Fleet Analytics archives.
//!
//! Files are schema-pinned Arrow/Parquet 2.6 data with Zstandard compression.
//! The public helpers are intentionally byte-oriented so object-store access,
//! manifest verification, and residency policy remain separate boundaries.

use std::{collections::HashMap, io::Cursor, sync::Arc};

use anyhow::{Context, Result, bail};
use arrow_array::RecordBatch;
use arrow_json::{LineDelimitedWriter, ReaderBuilder};
use arrow_schema::{DataType, Field, Fields, Schema, TimeUnit};
use bytes::Bytes;
use futures::StreamExt;
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use parquet::{
    arrow::{
        PARQUET_FIELD_ID_META_KEY, arrow_reader::ParquetRecordBatchReaderBuilder,
        arrow_writer::ArrowWriter,
    },
    basic::{Compression, ZstdLevel},
    file::properties::{WriterProperties, WriterVersion},
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

use crate::{
    analytics::{
        MANIFEST_SCHEMA_VERSION_V1, MAX_ARCHIVE_BYTES, MAX_ARCHIVE_ROWS, MetricBucketParquetRowV1,
        TRANSPORT_SCHEMA_VERSION_V1, archive_manifest_signing_payload, canonical_parquet_row_v1,
        telemetry_bucket_from_parquet_row_v1, validate_archive_manifest, validate_batch,
        validate_bucket,
    },
    analytics_store::GreptimeAnalyticsStore,
    proto::rustyauth::analytics::v1::{
        BucketAcknowledgementStatus, MetricBucketArchiveManifest, MetricSchemaVersion,
        ParquetCompression, TelemetryBucket, TelemetryBucketBatch,
    },
    store::{
        FleetAnalyticsManifestRecord, FleetAnalyticsManifestStateRecord,
        FleetAnalyticsResidencyRecord, FleetConnectionRecord, Store,
    },
};

const MAX_PARQUET_BATCH_ROWS: usize = 8_192;
const MAX_PRESIGNED_LIFETIME_SECONDS: i64 = 15 * 60;

pub struct MetricBucketArchiveArtifact {
    pub manifest: MetricBucketArchiveManifest,
    pub parquet_bytes: Vec<u8>,
}

pub fn build_metric_bucket_archive_v1(
    buckets: &[TelemetryBucket],
    object_key: String,
    signing_key_id: String,
    signing_key: &SigningKey,
) -> Result<MetricBucketArchiveArtifact> {
    let first = buckets.first().context("archive contains no buckets")?;
    if buckets.iter().any(|bucket| {
        bucket.realm_id != first.realm_id || bucket.assignment_epoch != first.assignment_epoch
    }) {
        bail!("one Parquet archive may contain only one realm assignment epoch");
    }
    let parquet_bytes = encode_metric_bucket_parquet_v1(buckets)?;
    let minimum_bucket_start_unix_milliseconds = buckets
        .iter()
        .map(|bucket| bucket.bucket_start_unix_milliseconds)
        .min()
        .context("archive contains no buckets")?;
    let maximum_bucket_start_unix_milliseconds = buckets
        .iter()
        .map(|bucket| bucket.bucket_start_unix_milliseconds)
        .max()
        .context("archive contains no buckets")?;
    let first_event_sequence = buckets
        .iter()
        .filter_map(|bucket| {
            (bucket.first_event_sequence > 0).then_some(bucket.first_event_sequence)
        })
        .min()
        .unwrap_or_default();
    let last_event_sequence = buckets
        .iter()
        .map(|bucket| bucket.last_event_sequence)
        .max()
        .unwrap_or_default();
    let mut manifest = MetricBucketArchiveManifest {
        manifest_schema_version: MANIFEST_SCHEMA_VERSION_V1,
        metric_schema_version: MetricSchemaVersion::V1.into(),
        manifest_id: uuid::Uuid::new_v4().to_string(),
        realm_id: first.realm_id.clone(),
        assignment_epoch: first.assignment_epoch,
        object_key,
        content_sha256: Sha256::digest(&parquet_bytes).to_vec(),
        byte_length: u64::try_from(parquet_bytes.len()).context("archive is too large")?,
        row_count: u64::try_from(buckets.len()).context("archive has too many rows")?,
        minimum_bucket_start_unix_milliseconds,
        maximum_bucket_start_unix_milliseconds,
        first_event_sequence,
        last_event_sequence,
        compression: ParquetCompression::Zstd.into(),
        created_at_unix_milliseconds: OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .checked_div(1_000_000)
            .and_then(|value| i64::try_from(value).ok())
            .context("current time is outside the manifest range")?,
        signing_key_id,
        ..Default::default()
    };
    sign_archive_manifest_v1(&mut manifest, signing_key)?;
    Ok(MetricBucketArchiveArtifact {
        manifest,
        parquet_bytes,
    })
}

pub fn sign_archive_manifest_v1(
    manifest: &mut MetricBucketArchiveManifest,
    key: &SigningKey,
) -> Result<()> {
    manifest.signature.clear();
    let payload = archive_manifest_signing_payload(manifest)?;
    let signature: Signature = key.sign(&payload);
    manifest.signature = signature.to_bytes().to_vec();
    validate_archive_manifest(manifest)?;
    Ok(())
}

pub fn verify_archive_manifest_v1(
    manifest: &MetricBucketArchiveManifest,
    key: &VerifyingKey,
) -> Result<()> {
    validate_archive_manifest(manifest)?;
    let signature =
        Signature::from_slice(&manifest.signature).context("decode manifest signature")?;
    let payload = archive_manifest_signing_payload(manifest)?;
    key.verify(&payload, &signature)
        .context("verify archive manifest signature")
}

pub fn verify_archive_object_v1(
    manifest: &MetricBucketArchiveManifest,
    bytes: &[u8],
) -> Result<()> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != manifest.byte_length {
        bail!("archive object byte length does not match its manifest");
    }
    if Sha256::digest(bytes).to_vec() != manifest.content_sha256 {
        bail!("archive object digest does not match its manifest");
    }
    let rows = decode_metric_bucket_parquet_v1(bytes)?;
    if u64::try_from(rows.len()).unwrap_or(u64::MAX) != manifest.row_count {
        bail!("archive object row count does not match its manifest");
    }
    Ok(())
}

/// Imports an approved archive through a short-lived, object-specific URL.
/// The URL is held as a secret, never redirected, and must resolve to the exact
/// manifest object beneath the configured bucket origin. Infrastructure egress
/// policy remains responsible for DNS-rebinding defense.
#[allow(clippy::too_many_arguments)]
pub async fn import_metric_bucket_archive_from_presigned_v1(
    store: &Store,
    analytics: &GreptimeAnalyticsStore,
    connection: &FleetConnectionRecord,
    manifest: &MetricBucketArchiveManifest,
    verifying_key: &VerifyingKey,
    approved_bucket_origin: &Url,
    presigned_url: &SecretString,
) -> Result<FleetAnalyticsManifestRecord> {
    let bytes =
        download_presigned_archive_v1(manifest, approved_bucket_origin, presigned_url).await?;
    import_metric_bucket_archive_v1(
        store,
        analytics,
        connection,
        manifest,
        verifying_key,
        &bytes,
    )
    .await
}

async fn download_presigned_archive_v1(
    manifest: &MetricBucketArchiveManifest,
    approved_bucket_origin: &Url,
    presigned_url: &SecretString,
) -> Result<Vec<u8>> {
    validate_archive_manifest(manifest)?;
    let url = validate_presigned_archive_url(
        manifest,
        approved_bucket_origin,
        presigned_url.expose_secret(),
        OffsetDateTime::now_utc(),
    )?;
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!(
            "rustyauth-analytics-import/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()?;
    let response = client
        .get(url)
        .send()
        .await
        .context("fetch approved archive")?;
    if response.status() != reqwest::StatusCode::OK {
        bail!("approved archive fetch was rejected");
    }
    let advertised = response
        .content_length()
        .context("approved archive omitted Content-Length")?;
    if advertised != manifest.byte_length || advertised > MAX_ARCHIVE_BYTES {
        bail!("approved archive Content-Length does not match its manifest");
    }
    let capacity = usize::try_from(advertised).context("approved archive is too large")?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read approved archive")?;
        if bytes.len().saturating_add(chunk.len()) > capacity {
            bail!("approved archive exceeded its advertised bound");
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != capacity {
        bail!("approved archive was truncated");
    }
    Ok(bytes)
}

fn validate_presigned_archive_url(
    manifest: &MetricBucketArchiveManifest,
    approved_bucket_origin: &Url,
    value: &str,
    now: OffsetDateTime,
) -> Result<Url> {
    if approved_bucket_origin.cannot_be_a_base()
        || approved_bucket_origin.username() != ""
        || approved_bucket_origin.password().is_some()
        || approved_bucket_origin.query().is_some()
        || approved_bucket_origin.fragment().is_some()
        || !approved_bucket_origin.path().ends_with('/')
    {
        bail!("approved archive bucket origin is invalid");
    }
    let secure = approved_bucket_origin.scheme() == "https";
    let local_test = cfg!(test)
        && approved_bucket_origin.scheme() == "http"
        && approved_bucket_origin.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
    if !secure && !local_test {
        bail!("approved archive bucket origin must use HTTPS");
    }
    let expected = approved_bucket_origin
        .join(&manifest.object_key)
        .context("compose approved archive object URL")?;
    let url = Url::parse(value).context("parse approved archive URL")?;
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
        bail!("approved archive URL contains forbidden authority material");
    }
    if url.scheme() != expected.scheme()
        || url.host_str() != expected.host_str()
        || url.port_or_known_default() != expected.port_or_known_default()
        || url.path() != expected.path()
    {
        bail!("approved archive URL is outside its configured object binding");
    }
    validate_presigned_expiry(&url, now)?;
    Ok(url)
}

fn validate_presigned_expiry(url: &Url, now: OffsetDateTime) -> Result<()> {
    let pairs = url.query_pairs().collect::<HashMap<_, _>>();
    for key in [
        "X-Amz-Expires",
        "X-Goog-Expires",
        "x-amz-expires",
        "x-goog-expires",
    ] {
        if let Some(value) = pairs.get(key) {
            let seconds: i64 = value.parse().context("parse archive URL expiry")?;
            if !(1..=MAX_PRESIGNED_LIFETIME_SECONDS).contains(&seconds) {
                bail!("approved archive URL lifetime exceeds the configured bound");
            }
            return Ok(());
        }
    }
    if let Some(value) = pairs.get("se") {
        let expires_at = OffsetDateTime::parse(value, &Rfc3339)
            .context("parse approved archive URL absolute expiry")?;
        let remaining = (expires_at - now).whole_seconds();
        if !(1..=MAX_PRESIGNED_LIFETIME_SECONDS).contains(&remaining) {
            bail!("approved archive URL absolute expiry is outside the configured bound");
        }
        return Ok(());
    }
    bail!("approved archive URL does not declare a bounded expiry")
}

pub async fn import_metric_bucket_archive_v1(
    store: &Store,
    analytics: &GreptimeAnalyticsStore,
    connection: &FleetConnectionRecord,
    manifest: &MetricBucketArchiveManifest,
    verifying_key: &VerifyingKey,
    parquet_bytes: &[u8],
) -> Result<FleetAnalyticsManifestRecord> {
    verify_archive_manifest_v1(manifest, verifying_key)?;
    verify_archive_object_v1(manifest, parquet_bytes)?;
    if manifest.realm_id != connection.realm_id
        || manifest.assignment_epoch != connection.assignment_epoch
    {
        bail!("archive manifest does not match the authenticated realm assignment");
    }
    let policy = store
        .fleet_analytics_policy(connection.organization_id)
        .await?;
    if !policy.enabled {
        bail!("organization analytics policy is disabled");
    }
    if policy.residency == FleetAnalyticsResidencyRecord::RollupsOnly {
        bail!("organization analytics policy does not permit archive processing");
    }

    let rows = decode_metric_bucket_parquet_v1(parquet_bytes)?;
    let buckets = rows
        .into_iter()
        .map(telemetry_bucket_from_parquet_row_v1)
        .collect::<Result<Vec<_>, _>>()?;
    validate_manifest_rows(manifest, &buckets)?;
    let registered = store
        .register_fleet_analytics_manifest(connection, manifest)
        .await?;
    if registered.state == FleetAnalyticsManifestStateRecord::Complete {
        return Ok(registered);
    }

    for chunk in buckets.chunks(crate::analytics::MAX_BUCKETS_PER_BATCH) {
        let batch = TelemetryBucketBatch {
            transport_schema_version: TRANSPORT_SCHEMA_VERSION_V1,
            batch_id: uuid::Uuid::new_v4().to_string(),
            realm_id: connection.realm_id.clone(),
            buckets: chunk.to_vec(),
            ..Default::default()
        };
        validate_batch(&batch)?;
        let accepted = store
            .accept_fleet_archive_batch_with_records(connection, &batch)
            .await?;
        if accepted
            .acknowledgement
            .buckets
            .iter()
            .any(|acknowledgement| {
                !matches!(
                    acknowledgement.status.as_known(),
                    Some(BucketAcknowledgementStatus::Accepted)
                        | Some(BucketAcknowledgementStatus::AlreadyAccepted)
                )
            })
        {
            bail!("archive row was rejected or quarantined by the canonical acceptance ledger");
        }
        analytics.upsert(&accepted.records).await?;
    }
    store
        .complete_fleet_analytics_manifest(
            uuid::Uuid::parse_str(&manifest.manifest_id)?,
            &manifest.content_sha256,
            manifest.row_count,
        )
        .await
}

fn validate_manifest_rows(
    manifest: &MetricBucketArchiveManifest,
    buckets: &[TelemetryBucket],
) -> Result<()> {
    if buckets.iter().any(|bucket| {
        bucket.realm_id != manifest.realm_id || bucket.assignment_epoch != manifest.assignment_epoch
    }) {
        bail!("archive row does not match its manifest realm assignment");
    }
    let minimum = buckets
        .iter()
        .map(|bucket| bucket.bucket_start_unix_milliseconds)
        .min()
        .context("archive contains no rows")?;
    let maximum = buckets
        .iter()
        .map(|bucket| bucket.bucket_start_unix_milliseconds)
        .max()
        .context("archive contains no rows")?;
    let first_sequence = buckets
        .iter()
        .filter_map(|bucket| {
            (bucket.first_event_sequence > 0).then_some(bucket.first_event_sequence)
        })
        .min()
        .unwrap_or_default();
    let last_sequence = buckets
        .iter()
        .map(|bucket| bucket.last_event_sequence)
        .max()
        .unwrap_or_default();
    if minimum != manifest.minimum_bucket_start_unix_milliseconds
        || maximum != manifest.maximum_bucket_start_unix_milliseconds
        || first_sequence != manifest.first_event_sequence
        || last_sequence != manifest.last_event_sequence
    {
        bail!("archive row bounds do not match its manifest");
    }
    Ok(())
}

pub fn encode_metric_bucket_parquet_v1(buckets: &[TelemetryBucket]) -> Result<Vec<u8>> {
    if buckets.is_empty() || u64::try_from(buckets.len()).unwrap_or(u64::MAX) > MAX_ARCHIVE_ROWS {
        bail!("Parquet archive row count is outside V1 bounds");
    }
    let schema = metric_bucket_arrow_schema_v1();
    let mut json = Vec::new();
    for bucket in buckets {
        validate_bucket(bucket).context("validate Parquet telemetry bucket")?;
        let row = canonical_parquet_row_v1(bucket).context("build canonical Parquet row")?;
        let mut value = serde_json::to_value(row)?;
        encode_timestamp(&mut value)?;
        serde_json::to_writer(&mut json, &value)?;
        json.push(b'\n');
    }
    let reader = ReaderBuilder::new(schema.clone())
        .with_batch_size(MAX_PARQUET_BATCH_ROWS)
        .build(Cursor::new(json))?;
    let properties = WriterProperties::builder()
        .set_writer_version(WriterVersion::PARQUET_2_0)
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
        .set_max_row_group_row_count(Some(MAX_PARQUET_BATCH_ROWS))
        .build();
    let mut writer = ArrowWriter::try_new(Vec::new(), schema, Some(properties))?;
    for batch in reader {
        writer.write(&batch?)?;
    }
    let bytes = writer.into_inner()?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ARCHIVE_BYTES {
        bail!("Parquet archive exceeds the V1 byte limit");
    }
    Ok(bytes)
}

pub fn decode_metric_bucket_parquet_v1(bytes: &[u8]) -> Result<Vec<MetricBucketParquetRowV1>> {
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ARCHIVE_BYTES {
        bail!("Parquet archive byte length is outside V1 bounds");
    }
    if !bytes.starts_with(b"PAR1") || !bytes.ends_with(b"PAR1") {
        bail!("Parquet archive magic is invalid");
    }
    let expected = metric_bucket_arrow_schema_v1();
    let builder = ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(bytes))?;
    if builder.schema().fields() != expected.fields() {
        bail!("Parquet archive schema does not match rustyauth-metric-bucket-v1");
    }
    let reader = builder.with_batch_size(MAX_PARQUET_BATCH_ROWS).build()?;
    let mut rows = Vec::new();
    for batch in reader {
        let batch = batch?;
        if rows.len().saturating_add(batch.num_rows())
            > usize::try_from(MAX_ARCHIVE_ROWS).unwrap_or(usize::MAX)
        {
            bail!("Parquet archive exceeds the V1 row limit");
        }
        rows.extend(decode_batch(&batch)?);
    }
    if rows.is_empty() {
        bail!("Parquet archive contains no rows");
    }
    Ok(rows)
}

fn decode_batch(batch: &RecordBatch) -> Result<Vec<MetricBucketParquetRowV1>> {
    let mut json = Vec::new();
    let mut writer = LineDelimitedWriter::new(&mut json);
    writer.write(batch)?;
    writer.finish()?;
    drop(writer);
    let mut rows = Vec::new();
    for line in json
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let mut value: Value = serde_json::from_slice(line)?;
        decode_timestamp(&mut value)?;
        rows.push(serde_json::from_value(value)?);
    }
    Ok(rows)
}

fn encode_timestamp(value: &mut Value) -> Result<()> {
    let milliseconds = value
        .get("bucket_start_unix_milliseconds")
        .and_then(Value::as_i64)
        .context("canonical Parquet row omitted bucket timestamp")?;
    let timestamp =
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(milliseconds) * 1_000_000)?
            .format(&Rfc3339)?;
    value["bucket_start_unix_milliseconds"] = Value::String(timestamp);
    Ok(())
}

fn decode_timestamp(value: &mut Value) -> Result<()> {
    let timestamp = value
        .get("bucket_start_unix_milliseconds")
        .and_then(Value::as_str)
        .context("Parquet JSON row omitted bucket timestamp")?;
    let milliseconds = OffsetDateTime::parse(timestamp, &Rfc3339)?
        .unix_timestamp_nanos()
        .checked_div(1_000_000)
        .and_then(|value| i64::try_from(value).ok())
        .context("Parquet bucket timestamp is outside the supported range")?;
    value["bucket_start_unix_milliseconds"] = Value::from(milliseconds);
    Ok(())
}

pub fn metric_bucket_arrow_schema_v1() -> Arc<Schema> {
    let u64_field = |name, id| field(name, id, DataType::UInt64, false);
    let i32_field = |name, id| field(name, id, DataType::Int32, false);
    let histogram = |prefix: &str, profile_id, count_id, sum_id, cumulative_id| {
        Field::new(
            prefix,
            DataType::Struct(Fields::from(vec![
                Arc::new(i32_field("profile", profile_id)),
                Arc::new(u64_field("count", count_id)),
                Arc::new(u64_field("sum_milliseconds", sum_id)),
                Arc::new(list_field(
                    "cumulative_counts",
                    cumulative_id,
                    DataType::UInt64,
                    false,
                )),
            ])),
            false,
        )
    };
    let authentication = field(
        "authentication",
        10,
        DataType::Struct(Fields::from(vec![
            Arc::new(u64_field("attempts", 11)),
            Arc::new(u64_field("successes", 12)),
            Arc::new(u64_field("failures", 13)),
            Arc::new(u64_field("denials", 14)),
            Arc::new(u64_field("active_account_observations", 15)),
            Arc::new(histogram("latency", 16, 17, 18, 19)),
            Arc::new(struct_list_field(
                "flows",
                20,
                vec![
                    i32_field("flow", 21),
                    u64_field("attempts", 22),
                    u64_field("successes", 23),
                    u64_field("failures", 24),
                    u64_field("denials", 25),
                ],
            )),
            Arc::new(struct_list_field(
                "failure_classes",
                26,
                vec![i32_field("failure_class", 27), u64_field("count", 28)],
            )),
        ])),
        true,
    );
    let registration = optional_struct(
        "registration",
        29,
        vec![
            u64_field("options_started", 30),
            u64_field("ceremonies_opened", 31),
            u64_field("responses_returned", 32),
            u64_field("registrations_completed", 33),
            u64_field("challenges_expired", 34),
        ],
    );
    let sessions = optional_struct(
        "sessions_and_tokens",
        35,
        vec![
            u64_field("sessions_created", 36),
            u64_field("sessions_revoked", 37),
            u64_field("user_tokens_issued", 38),
            u64_field("service_tokens_issued", 39),
        ],
    );
    let service_accounts = optional_struct(
        "service_accounts",
        40,
        vec![
            u64_field("calls", 41),
            u64_field("successes", 42),
            u64_field("failures", 43),
            u64_field("denials", 44),
            u64_field("credential_rotations", 45),
        ],
    );
    let webhooks = field(
        "webhooks",
        46,
        DataType::Struct(Fields::from(vec![
            Arc::new(u64_field("deliveries", 47)),
            Arc::new(u64_field("successes", 48)),
            Arc::new(u64_field("failures", 49)),
            Arc::new(u64_field("backlog", 50)),
            Arc::new(histogram("latency", 51, 52, 53, 54)),
        ])),
        true,
    );
    let platform = field(
        "platform",
        55,
        DataType::Struct(Fields::from(vec![
            Arc::new(u64_field("api_requests", 56)),
            Arc::new(u64_field("api_errors", 57)),
            Arc::new(histogram("api_latency", 58, 59, 60, 61)),
            Arc::new(u64_field("sabledb_operations", 62)),
            Arc::new(u64_field("sabledb_errors", 63)),
            Arc::new(histogram("sabledb_latency", 64, 65, 66, 67)),
        ])),
        true,
    );
    let realm_health = optional_struct(
        "realm_health",
        68,
        vec![
            i32_field("serving_state", 69),
            u64_field("backup_age_seconds", 70),
            u64_field("signing_key_age_seconds", 71),
            u64_field("connector_lag_seconds", 72),
        ],
    );
    Arc::new(Schema::new(vec![
        field("realm_id", 1, DataType::Utf8, false),
        u64_field("assignment_epoch", 2),
        field(
            "bucket_start_unix_milliseconds",
            3,
            DataType::Timestamp(TimeUnit::Millisecond, Some("+00:00".into())),
            false,
        ),
        field("bucket_width_seconds", 4, DataType::UInt32, false),
        u64_field("revision", 5),
        u64_field("first_event_sequence", 6),
        u64_field("last_event_sequence", 7),
        i32_field("metric_schema_version", 8),
        field("closed", 9, DataType::Boolean, false),
        authentication,
        registration,
        sessions,
        service_accounts,
        webhooks,
        platform,
        realm_health,
    ]))
}

fn field(name: &str, id: i32, data_type: DataType, nullable: bool) -> Field {
    Field::new(name, data_type, nullable).with_metadata(HashMap::from([(
        PARQUET_FIELD_ID_META_KEY.into(),
        id.to_string(),
    )]))
}

fn optional_struct(name: &str, id: i32, fields: Vec<Field>) -> Field {
    field(
        name,
        id,
        DataType::Struct(Fields::from(
            fields.into_iter().map(Arc::new).collect::<Vec<_>>(),
        )),
        true,
    )
}

fn list_field(name: &str, id: i32, data_type: DataType, nullable: bool) -> Field {
    field(
        name,
        id,
        DataType::List(Arc::new(Field::new("element", data_type, nullable))),
        false,
    )
}

fn struct_list_field(name: &str, id: i32, fields: Vec<Field>) -> Field {
    list_field(
        name,
        id,
        DataType::Struct(Fields::from(
            fields.into_iter().map(Arc::new).collect::<Vec<_>>(),
        )),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::AnalyticsConfig,
        proto::rustyauth::analytics::v1::{MetricSchemaVersion, SessionTokenMetrics},
        store::{
            EncryptedFleetCredential, FleetConnectionModeRecord, FleetConnectionStateRecord, now,
        },
    };
    use secrecy::SecretString;
    use url::Url;

    #[test]
    fn parquet_v1_is_real_zstd_parquet_and_round_trips_the_canonical_row() -> Result<()> {
        let bucket = TelemetryBucket {
            realm_id: "archive-realm".into(),
            assignment_epoch: 1,
            bucket_start_unix_milliseconds: 1_800_000_000_000,
            bucket_width_seconds: 300,
            revision: 1,
            first_event_sequence: 1,
            last_event_sequence: 1,
            metric_schema_version: MetricSchemaVersion::V1.into(),
            closed: true,
            sessions_and_tokens: SessionTokenMetrics {
                sessions_created: 1,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        let expected = canonical_parquet_row_v1(&bucket)?;
        let signing_key = SigningKey::from_slice(&[7; 32])?;
        let artifact = build_metric_bucket_archive_v1(
            std::slice::from_ref(&bucket),
            "rustyauth-telemetry/v1/archive-realm/2027/01/15/buckets.parquet".into(),
            "archive-test-p256-v1".into(),
            &signing_key,
        )?;
        verify_archive_manifest_v1(&artifact.manifest, signing_key.verifying_key())?;
        verify_archive_object_v1(&artifact.manifest, &artifact.parquet_bytes)?;
        let bytes = artifact.parquet_bytes;
        assert!(bytes.starts_with(b"PAR1") && bytes.ends_with(b"PAR1"));
        let rows = decode_metric_bucket_parquet_v1(&bytes)?;
        assert_eq!(rows, vec![expected]);
        assert_eq!(
            crate::analytics::telemetry_bucket_from_parquet_row_v1(
                rows.into_iter().next().unwrap()
            )?,
            bucket
        );
        Ok(())
    }

    #[test]
    fn parquet_v1_rejects_truncation_and_schema_substitution() {
        assert!(decode_metric_bucket_parquet_v1(b"PAR1PAR1").is_err());
    }

    #[test]
    fn presigned_archive_urls_are_exact_short_lived_object_bindings() -> Result<()> {
        let bucket = TelemetryBucket {
            realm_id: "archive-realm".into(),
            assignment_epoch: 1,
            bucket_start_unix_milliseconds: 1_800_000_000_000,
            bucket_width_seconds: 300,
            revision: 1,
            metric_schema_version: MetricSchemaVersion::V1.into(),
            closed: true,
            sessions_and_tokens: SessionTokenMetrics::default().into(),
            ..Default::default()
        };
        let key = SigningKey::from_slice(&[9; 32])?;
        let artifact = build_metric_bucket_archive_v1(
            &[bucket],
            "realm/archive.parquet".into(),
            "test-key".into(),
            &key,
        )?;
        let origin = Url::parse("http://127.0.0.1:9000/approved-bucket/")?;
        let mut valid = origin.join(&artifact.manifest.object_key)?;
        valid.set_query(Some("X-Amz-Expires=900&X-Amz-Signature=redacted"));
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        assert!(
            validate_presigned_archive_url(&artifact.manifest, &origin, valid.as_str(), now)
                .is_ok()
        );

        let mut long_lived = valid.clone();
        long_lived.set_query(Some("X-Amz-Expires=901&X-Amz-Signature=redacted"));
        assert!(
            validate_presigned_archive_url(&artifact.manifest, &origin, long_lived.as_str(), now)
                .is_err()
        );
        let mut substituted = origin.join("realm/other.parquet")?;
        substituted.set_query(valid.query());
        assert!(
            validate_presigned_archive_url(&artifact.manifest, &origin, substituted.as_str(), now)
                .is_err()
        );
        assert!(
            validate_presigned_archive_url(
                &artifact.manifest,
                &origin,
                "http://169.254.169.254/approved-bucket/realm/archive.parquet?X-Amz-Expires=60",
                now
            )
            .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires the pinned SableDB and GreptimeDB integration services"]
    async fn signed_archive_import_is_idempotent_and_product_queryable() -> Result<()> {
        let sable_url = match std::env::var("RUSTYAUTH_TEST_SOURCE_SABLEDB_URL") {
            Ok(value) => value,
            Err(_) => return Ok(()),
        };
        let greptime_url = match std::env::var("RUSTYAUTH_TEST_GREPTIME_URL") {
            Ok(value) => value,
            Err(_) => return Ok(()),
        };
        let client = redis::Client::open(sable_url)?;
        let redis = redis::aio::ConnectionManager::new(client).await?;
        let mut database = redis.clone();
        redis::cmd("FLUSHDB")
            .arg("ASYNC")
            .query_async::<()>(&mut database)
            .await?;
        let store = Store::new(redis, "archive-import-test".into());
        let owner_id = uuid::Uuid::new_v4();
        let organization = store
            .create_fleet_organization(
                "archive-import".into(),
                "Archive import".into(),
                uuid::Uuid::new_v4(),
                owner_id,
                "archive import qualification".into(),
            )
            .await?;
        store
            .update_fleet_analytics_policy(
                organization.id,
                true,
                35,
                FleetAnalyticsResidencyRecord::CustomerOwnedArchive,
                288,
                uuid::Uuid::new_v4(),
                owner_id,
                "enable archive import qualification".into(),
            )
            .await?;
        let connection = FleetConnectionRecord {
            id: uuid::Uuid::new_v4(),
            organization_id: organization.id,
            project_id: uuid::Uuid::new_v4(),
            environment_id: uuid::Uuid::new_v4(),
            realm_id: "archive-import-realm".into(),
            assignment_epoch: 1,
            display_name: "Archive import realm".into(),
            mode: FleetConnectionModeRecord::OutboundConnector,
            management_endpoint: "http://127.0.0.1:1".into(),
            credential: EncryptedFleetCredential {
                wrapping_key_id: "test".into(),
                nonce: String::new(),
                ciphertext: String::new(),
            },
            credential_hint: String::new(),
            staged_credential: None,
            staged_credential_hint: None,
            credential_rotation_request_id: None,
            deployment_version: env!("CARGO_PKG_VERSION").into(),
            protocol_version: "1".into(),
            capabilities: vec![("telemetry.rollups.v1".into(), 1)],
            granted_scopes: vec!["telemetry.export".into()],
            issuer: "https://archive-import.invalid".into(),
            rp_id: "archive-import.invalid".into(),
            state: FleetConnectionStateRecord::Healthy,
            last_seen_at: None,
            created_at: now(),
            updated_at: now(),
            revoked_at: None,
        };
        let bucket_start = now().saturating_sub(600) / 300 * 300;
        let bucket = TelemetryBucket {
            realm_id: connection.realm_id.clone(),
            assignment_epoch: connection.assignment_epoch,
            bucket_start_unix_milliseconds: i64::try_from(bucket_start * 1_000)?,
            bucket_width_seconds: 300,
            revision: 1,
            first_event_sequence: 1,
            last_event_sequence: 1,
            metric_schema_version: MetricSchemaVersion::V1.into(),
            closed: true,
            sessions_and_tokens: SessionTokenMetrics {
                sessions_created: 1,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        let signing_key = SigningKey::from_slice(&[11; 32])?;
        let artifact = build_metric_bucket_archive_v1(
            std::slice::from_ref(&bucket),
            "rustyauth-telemetry/v1/archive-import-realm/buckets.parquet".into(),
            "archive-import-key-v1".into(),
            &signing_key,
        )?;
        let analytics = GreptimeAnalyticsStore::new(AnalyticsConfig {
            endpoint: Url::parse(&greptime_url)?,
            database: format!("rustyauth_archive_test_{}", uuid::Uuid::new_v4().simple()),
            username: SecretString::from("rustyauth"),
            password: SecretString::from("rustyauth-test-password"),
        })?;
        analytics.initialize().await?;
        let first = import_metric_bucket_archive_v1(
            &store,
            &analytics,
            &connection,
            &artifact.manifest,
            signing_key.verifying_key(),
            &artifact.parquet_bytes,
        )
        .await?;
        let retry = import_metric_bucket_archive_v1(
            &store,
            &analytics,
            &connection,
            &artifact.manifest,
            signing_key.verifying_key(),
            &artifact.parquet_bytes,
        )
        .await?;
        assert_eq!(first.state, FleetAnalyticsManifestStateRecord::Complete);
        assert_eq!(retry, first);
        let records = analytics
            .query(
                Some(organization.id),
                None,
                None,
                Some(connection.id),
                Some(&connection.realm_id),
                bucket.bucket_start_unix_milliseconds,
                bucket.bucket_start_unix_milliseconds + 300_000,
            )
            .await?;
        assert_eq!(records.len(), 1);
        Ok(())
    }
}
