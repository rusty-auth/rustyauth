//! Private GreptimeDB adapter for canonical Fleet Analytics buckets.
//!
//! Protocol handlers never expose SQL or database credentials. SableDB keeps
//! the authoritative hierarchy/revision ledger; this adapter stores and reads
//! the accepted, hierarchy-stamped numerical facts used for product queries.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use buffa::{Enumeration, Message};
use futures::StreamExt;
use reqwest::{Client, StatusCode, header};
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use uuid::Uuid;

use crate::{
    config::AnalyticsConfig,
    proto::rustyauth::analytics::v1::{
        AnalyticsServingState, AuthenticationFailureCount, AuthenticationMetrics, FailureClass,
        HistogramProfile, LatencyHistogram, MetricSchemaVersion, PlatformMetrics,
        RealmHealthMetrics, RegistrationMetrics, ServiceAccountMetrics, SessionTokenMetrics,
        TelemetryBucket, WebhookMetrics,
    },
    store::FleetTelemetryBucketRecord,
};

const CANONICAL_TABLE: &str = "rustyauth_auth_realm_5m";
const HOURLY_TABLE: &str = "rustyauth_auth_realm_1h";
const DAILY_TABLE: &str = "rustyauth_auth_realm_1d";
const HOURLY_FLOW: &str = "rustyauth_auth_realm_1h_flow";
const DAILY_FLOW: &str = "rustyauth_auth_realm_1d_flow";
const MAX_SQL_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_QUERY_RECORDS: usize = 100_000;

#[derive(Default)]
struct WideMetrics {
    auth_present: bool,
    auth: [u64; 5],
    auth_latency_profile: i32,
    auth_latency: [u64; 14],
    failures: [u64; 9],
    registration_present: bool,
    registration: [u64; 5],
    sessions_present: bool,
    sessions: [u64; 4],
    service_accounts_present: bool,
    service_accounts: [u64; 5],
    webhooks_present: bool,
    webhooks: [u64; 4],
    platform_present: bool,
    realm_health_present: bool,
}

impl WideMetrics {
    fn from_bucket(bucket: &TelemetryBucket) -> Self {
        let mut values = Self::default();
        if let Some(metrics) = bucket.authentication.as_option() {
            values.auth_present = true;
            values.auth = [
                metrics.attempts,
                metrics.successes,
                metrics.failures,
                metrics.denials,
                metrics.active_account_observations,
            ];
            if let Some(histogram) = metrics.latency.as_option() {
                values.auth_latency_profile = histogram.profile.to_i32();
                values.auth_latency[0] = histogram.count;
                values.auth_latency[1] = histogram.sum_milliseconds;
                for (target, source) in values.auth_latency[2..]
                    .iter_mut()
                    .zip(&histogram.cumulative_counts)
                {
                    *target = *source;
                }
            }
            for failure in &metrics.failure_classes {
                let index = match failure.failure_class.as_known() {
                    Some(FailureClass::InvalidCredential) => Some(0),
                    Some(FailureClass::ChallengeExpired) => Some(1),
                    Some(FailureClass::OriginRejected) => Some(2),
                    Some(FailureClass::PolicyDenied) => Some(3),
                    Some(FailureClass::RateLimited) => Some(4),
                    Some(FailureClass::StoreUnavailable) => Some(5),
                    Some(FailureClass::UpstreamUnavailable) => Some(6),
                    Some(FailureClass::Internal) => Some(7),
                    Some(FailureClass::Other) => Some(8),
                    Some(FailureClass::Unspecified) | None => None,
                };
                if let Some(index) = index {
                    values.failures[index] = failure.count;
                }
            }
        }
        if let Some(metrics) = bucket.registration.as_option() {
            values.registration_present = true;
            values.registration = [
                metrics.options_started,
                metrics.ceremonies_opened,
                metrics.responses_returned,
                metrics.registrations_completed,
                metrics.challenges_expired,
            ];
        }
        if let Some(metrics) = bucket.sessions_and_tokens.as_option() {
            values.sessions_present = true;
            values.sessions = [
                metrics.sessions_created,
                metrics.sessions_revoked,
                metrics.user_tokens_issued,
                metrics.service_tokens_issued,
            ];
        }
        if let Some(metrics) = bucket.service_accounts.as_option() {
            values.service_accounts_present = true;
            values.service_accounts = [
                metrics.calls,
                metrics.successes,
                metrics.failures,
                metrics.denials,
                metrics.credential_rotations,
            ];
        }
        if let Some(metrics) = bucket.webhooks.as_option() {
            values.webhooks_present = true;
            values.webhooks = [
                metrics.deliveries,
                metrics.successes,
                metrics.failures,
                metrics.backlog,
            ];
        }
        values.platform_present = bucket.platform.is_set();
        values.realm_health_present = bucket.realm_health.is_set();
        values
    }

    fn column_names() -> &'static str {
        "auth_present,auth_attempts,auth_successes,auth_failures,auth_denials,auth_active_accounts,auth_latency_profile,auth_latency_count,auth_latency_sum_ms,auth_latency_h00,auth_latency_h01,auth_latency_h02,auth_latency_h03,auth_latency_h04,auth_latency_h05,auth_latency_h06,auth_latency_h07,auth_latency_h08,auth_latency_h09,auth_latency_h10,auth_latency_h11,failure_invalid_credential,failure_challenge_expired,failure_origin_rejected,failure_policy_denied,failure_rate_limited,failure_store_unavailable,failure_upstream_unavailable,failure_internal,failure_other,registration_present,registration_options_started,registration_ceremonies_opened,registration_responses_returned,registrations_completed,registration_challenges_expired,sessions_present,sessions_created,sessions_revoked,user_tokens_issued,service_tokens_issued,service_accounts_present,service_account_calls,service_account_successes,service_account_failures,service_account_denials,service_account_rotations,webhooks_present,webhook_deliveries,webhook_successes,webhook_failures,webhook_backlog,platform_present,realm_health_present"
    }

    fn sql_values(&self) -> String {
        let mut values = Vec::with_capacity(54);
        values.push(self.auth_present.to_string());
        values.extend(self.auth.map(|value| value.to_string()));
        values.push(self.auth_latency_profile.to_string());
        values.extend(self.auth_latency.map(|value| value.to_string()));
        values.extend(self.failures.map(|value| value.to_string()));
        values.push(self.registration_present.to_string());
        values.extend(self.registration.map(|value| value.to_string()));
        values.push(self.sessions_present.to_string());
        values.extend(self.sessions.map(|value| value.to_string()));
        values.push(self.service_accounts_present.to_string());
        values.extend(self.service_accounts.map(|value| value.to_string()));
        values.push(self.webhooks_present.to_string());
        values.extend(self.webhooks.map(|value| value.to_string()));
        values.push(self.platform_present.to_string());
        values.push(self.realm_health_present.to_string());
        values.join(",")
    }
}

#[derive(Clone)]
pub struct GreptimeAnalyticsStore {
    client: Client,
    endpoint: Url,
    database: String,
    username: SecretString,
    password: SecretString,
}

impl GreptimeAnalyticsStore {
    pub fn new(config: AnalyticsConfig) -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("rustyauth/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build GreptimeDB analytics client")?;
        Ok(Self {
            client,
            endpoint: config.endpoint,
            database: config.database,
            username: config.username,
            password: config.password,
        })
    }

    pub async fn initialize(&self) -> Result<()> {
        self.execute_in(
            "public",
            &format!("CREATE DATABASE IF NOT EXISTS {}", self.database),
        )
        .await?;
        self.execute(&format!(
            "CREATE TABLE IF NOT EXISTS {CANONICAL_TABLE} (\
             organization_id STRING, project_id STRING, environment_id STRING, \
             connection_id STRING, realm_id STRING, assignment_epoch BIGINT UNSIGNED, \
             bucket_start TIMESTAMP(3) TIME INDEX, bucket_start_ms BIGINT, \
             bucket_width_seconds INT UNSIGNED, metric_schema_version INT, revision BIGINT UNSIGNED, \
             first_event_sequence BIGINT UNSIGNED, last_event_sequence BIGINT UNSIGNED, \
             batch_id STRING, payload_hex STRING, accepted_at_seconds BIGINT UNSIGNED, \
             PRIMARY KEY (organization_id, project_id, environment_id, connection_id, realm_id, assignment_epoch, bucket_width_seconds, metric_schema_version)\
             ) WITH ('ttl'='35d')"
        ))
        .await?;
        self.execute(&format!(
            "ALTER TABLE {CANONICAL_TABLE} \
             ADD COLUMN IF NOT EXISTS auth_present BOOLEAN, \
             ADD COLUMN IF NOT EXISTS auth_attempts BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_successes BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_failures BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_denials BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_active_accounts BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_latency_profile INT, \
             ADD COLUMN IF NOT EXISTS auth_latency_count BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_latency_sum_ms BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_latency_h00 BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_latency_h01 BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_latency_h02 BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_latency_h03 BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_latency_h04 BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_latency_h05 BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_latency_h06 BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_latency_h07 BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_latency_h08 BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_latency_h09 BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_latency_h10 BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS auth_latency_h11 BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS failure_invalid_credential BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS failure_challenge_expired BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS failure_origin_rejected BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS failure_policy_denied BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS failure_rate_limited BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS failure_store_unavailable BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS failure_upstream_unavailable BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS failure_internal BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS failure_other BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS registration_present BOOLEAN, \
             ADD COLUMN IF NOT EXISTS registration_options_started BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS registration_ceremonies_opened BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS registration_responses_returned BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS registrations_completed BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS registration_challenges_expired BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS sessions_present BOOLEAN, \
             ADD COLUMN IF NOT EXISTS sessions_created BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS sessions_revoked BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS user_tokens_issued BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS service_tokens_issued BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS service_accounts_present BOOLEAN, \
             ADD COLUMN IF NOT EXISTS service_account_calls BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS service_account_successes BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS service_account_failures BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS service_account_denials BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS service_account_rotations BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS webhooks_present BOOLEAN, \
             ADD COLUMN IF NOT EXISTS webhook_deliveries BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS webhook_successes BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS webhook_failures BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS webhook_backlog BIGINT UNSIGNED, \
             ADD COLUMN IF NOT EXISTS platform_present BOOLEAN, \
             ADD COLUMN IF NOT EXISTS realm_health_present BOOLEAN"
        ))
        .await?;
        self.initialize_materialization(HOURLY_TABLE, HOURLY_FLOW, "1 hour", "35d")
            .await?;
        self.initialize_materialization(DAILY_TABLE, DAILY_FLOW, "1 day", "400d")
            .await?;
        Ok(())
    }

    async fn initialize_materialization(
        &self,
        table: &str,
        flow: &str,
        interval: &str,
        ttl: &str,
    ) -> Result<()> {
        let flow = self.materialization_flow_name(flow);
        self.execute(&format!(
            "CREATE TABLE IF NOT EXISTS {table} (\
             organization_id STRING, project_id STRING, environment_id STRING, \
             connection_id STRING, realm_id STRING, assignment_epoch BIGINT UNSIGNED, \
             metric_schema_version INT, {}, \
             window_start TIMESTAMP(3) TIME INDEX, update_at TIMESTAMP(3), \
             PRIMARY KEY (organization_id, project_id, environment_id, connection_id, realm_id, assignment_epoch, metric_schema_version)\
             ) WITH ('ttl'='{ttl}')",
            materialized_column_schema()
        ))
        .await?;
        self.execute(&format!(
            "CREATE FLOW IF NOT EXISTS {flow} SINK TO {table} EXPIRE AFTER '35 days'::INTERVAL AS \
             SELECT organization_id,project_id,environment_id,connection_id,realm_id,assignment_epoch,metric_schema_version,{},date_bin('{interval}'::INTERVAL,bucket_start) AS window_start \
             FROM {CANONICAL_TABLE} GROUP BY organization_id,project_id,environment_id,connection_id,realm_id,assignment_epoch,metric_schema_version,window_start",
            materialized_select_columns()
        ))
        .await?;
        Ok(())
    }

    pub async fn upsert(&self, records: &[FleetTelemetryBucketRecord]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        if records.len() > 288 {
            bail!("canonical analytics write exceeds one replay unit");
        }
        let mut values = Vec::with_capacity(records.len());
        for record in records {
            let bucket_time = millisecond_timestamp(record.bucket_start_unix_milliseconds)?;
            let bucket = record.bucket()?;
            let metrics = WideMetrics::from_bucket(&bucket);
            values.push(format!(
                "('{}','{}','{}','{}','{}',{},'{}',{},{},{},{},{},{},'{}','{}',{}, {})",
                record.organization_id,
                record.project_id,
                record.environment_id,
                record.connection_id,
                sql_string(&record.realm_id),
                record.assignment_epoch,
                bucket_time,
                record.bucket_start_unix_milliseconds,
                record.bucket_width_seconds,
                record.metric_schema_version,
                record.revision,
                record.first_event_sequence,
                record.last_event_sequence,
                record.batch_id,
                sql_string(&hex::encode(record.payload()?)),
                record.accepted_at,
                metrics.sql_values(),
            ));
        }
        self.execute(&format!(
            "INSERT INTO {CANONICAL_TABLE} (organization_id,project_id,environment_id,connection_id,realm_id,assignment_epoch,bucket_start,bucket_start_ms,bucket_width_seconds,metric_schema_version,revision,first_event_sequence,last_event_sequence,batch_id,payload_hex,accepted_at_seconds,{}) VALUES {}",
            WideMetrics::column_names(),
            values.join(",")
        ))
        .await?;
        self.flush_materializations().await?;
        Ok(())
    }

    /// Forces the two bounded continuous aggregations to observe all accepted
    /// canonical writes. Normal Flow processing is automatic; explicit flushes
    /// make acknowledgement, recovery and correction tests deterministic.
    pub async fn flush_materializations(&self) -> Result<()> {
        self.execute(&format!(
            "ADMIN FLUSH_FLOW('{}')",
            self.materialization_flow_name(HOURLY_FLOW)
        ))
        .await?;
        self.execute(&format!(
            "ADMIN FLUSH_FLOW('{}')",
            self.materialization_flow_name(DAILY_FLOW)
        ))
        .await?;
        Ok(())
    }

    /// Removes rows beyond an organization's reduced retention window from
    /// canonical and derived stores. The caller remains responsible for the
    /// authorized, durable operator audit surrounding this data-plane action.
    pub async fn enforce_organization_retention(
        &self,
        organization_id: Uuid,
        retention_days: u32,
        evaluated_at_unix_milliseconds: i64,
    ) -> Result<()> {
        if !(1..=35).contains(&retention_days) {
            bail!("canonical analytics retention must be between 1 and 35 days");
        }
        let cutoff = evaluated_at_unix_milliseconds
            .checked_sub(i64::from(retention_days) * 86_400_000)
            .context("analytics retention cutoff is outside the supported range")?;
        let cutoff = millisecond_timestamp(cutoff)?;
        for (table, time_column) in [
            (CANONICAL_TABLE, "bucket_start"),
            (HOURLY_TABLE, "window_start"),
            (DAILY_TABLE, "window_start"),
        ] {
            self.execute(&format!(
                "DELETE FROM {table} WHERE organization_id='{organization_id}' AND {time_column} < '{cutoff}'"
            ))
            .await?;
        }
        Ok(())
    }

    /// Purges one disconnected realm connection without accepting a realm ID
    /// as authority. Requiring both trusted organization and connection IDs
    /// prevents an accidental cross-organization cleanup.
    pub async fn purge_connection(&self, organization_id: Uuid, connection_id: Uuid) -> Result<()> {
        for table in [CANONICAL_TABLE, HOURLY_TABLE, DAILY_TABLE] {
            self.execute(&format!(
                "DELETE FROM {table} WHERE organization_id='{organization_id}' AND connection_id='{connection_id}'"
            ))
            .await?;
        }
        Ok(())
    }

    /// Purges every canonical and derived row for an organization. This is a
    /// low-level primitive; product callers must persist a successful or failed
    /// maintenance audit around it.
    pub async fn purge_organization(&self, organization_id: Uuid) -> Result<()> {
        for table in [CANONICAL_TABLE, HOURLY_TABLE, DAILY_TABLE] {
            self.execute(&format!(
                "DELETE FROM {table} WHERE organization_id='{organization_id}'"
            ))
            .await?;
        }
        Ok(())
    }

    fn materialization_flow_name(&self, base: &str) -> String {
        format!("{base}_{}", self.database)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn query(
        &self,
        organization_id: Option<Uuid>,
        project_id: Option<Uuid>,
        environment_id: Option<Uuid>,
        connection_id: Option<Uuid>,
        realm_id: Option<&str>,
        starts_at_unix_milliseconds: i64,
        ends_at_unix_milliseconds: i64,
    ) -> Result<Vec<FleetTelemetryBucketRecord>> {
        let mut predicates = Vec::new();
        if let Some(organization_id) = organization_id {
            predicates.push(format!("organization_id='{organization_id}'"));
        }
        if let Some(project_id) = project_id {
            predicates.push(format!("project_id='{project_id}'"));
        }
        if let Some(environment_id) = environment_id {
            predicates.push(format!("environment_id='{environment_id}'"));
        }
        if let Some(connection_id) = connection_id {
            predicates.push(format!("connection_id='{connection_id}'"));
        }
        if let Some(realm_id) = realm_id {
            predicates.push(format!("realm_id='{}'", sql_string(realm_id)));
        }
        predicates.push(format!(
            "bucket_start_ms >= {starts_at_unix_milliseconds} AND bucket_start_ms < {ends_at_unix_milliseconds}"
        ));
        let response = self
            .execute(&format!(
                "SELECT organization_id,project_id,environment_id,connection_id,realm_id,assignment_epoch,bucket_start_ms,bucket_width_seconds,metric_schema_version,revision,first_event_sequence,last_event_sequence,batch_id,payload_hex,accepted_at_seconds FROM {CANONICAL_TABLE} WHERE {} ORDER BY bucket_start_ms,connection_id,assignment_epoch LIMIT {MAX_QUERY_RECORDS}",
                predicates.join(" AND ")
            ))
            .await?;
        decode_records(&response)
    }

    /// Executes the numerical reduction inside GreptimeDB and returns one
    /// bounded aggregate per organization/window. This keeps 28-day medium
    /// tier queries independent of the canonical row count while preserving
    /// ratio-of-sums and mergeable cumulative histograms in Rust.
    #[allow(clippy::too_many_arguments)]
    pub async fn query_rollups(
        &self,
        organization_id: Option<Uuid>,
        project_id: Option<Uuid>,
        environment_id: Option<Uuid>,
        connection_id: Option<Uuid>,
        realm_id: Option<&str>,
        starts_at_unix_milliseconds: i64,
        ends_at_unix_milliseconds: i64,
        step_milliseconds: i64,
    ) -> Result<Vec<FleetTelemetryBucketRecord>> {
        let (interval, table, boundary) = match step_milliseconds {
            300_000 => ("5 minutes", None, None),
            3_600_000 => (
                "1 hour",
                Some(HOURLY_TABLE),
                Some(current_window_start(3_600)),
            ),
            86_400_000 => (
                "1 day",
                Some(DAILY_TABLE),
                Some(current_window_start(86_400)),
            ),
            _ => bail!("unsupported canonical analytics aggregation step"),
        };
        let mut records = Vec::new();
        if let (Some(table), Some(boundary)) = (table, boundary) {
            let finalized_end = ends_at_unix_milliseconds.min(boundary);
            if starts_at_unix_milliseconds < finalized_end {
                records.extend(
                    self.query_rollups_from(
                        table,
                        "window_start",
                        interval,
                        organization_id,
                        project_id,
                        environment_id,
                        connection_id,
                        realm_id,
                        starts_at_unix_milliseconds,
                        finalized_end,
                        step_milliseconds,
                    )
                    .await?,
                );
            }
            let live_start = starts_at_unix_milliseconds.max(boundary);
            if live_start < ends_at_unix_milliseconds {
                records.extend(
                    self.query_rollups_from(
                        CANONICAL_TABLE,
                        "bucket_start",
                        interval,
                        organization_id,
                        project_id,
                        environment_id,
                        connection_id,
                        realm_id,
                        live_start,
                        ends_at_unix_milliseconds,
                        step_milliseconds,
                    )
                    .await?,
                );
            }
        } else {
            records = self
                .query_rollups_from(
                    CANONICAL_TABLE,
                    "bucket_start",
                    interval,
                    organization_id,
                    project_id,
                    environment_id,
                    connection_id,
                    realm_id,
                    starts_at_unix_milliseconds,
                    ends_at_unix_milliseconds,
                    step_milliseconds,
                )
                .await?;
        }
        records.sort_unstable_by_key(|record| record.bucket_start_unix_milliseconds);
        if records.len() > MAX_QUERY_RECORDS {
            bail!("combined analytics rollup exceeds the configured row bound");
        }
        Ok(records)
    }

    #[allow(clippy::too_many_arguments)]
    async fn query_rollups_from(
        &self,
        table: &str,
        time_column: &str,
        interval: &str,
        organization_id: Option<Uuid>,
        project_id: Option<Uuid>,
        environment_id: Option<Uuid>,
        connection_id: Option<Uuid>,
        realm_id: Option<&str>,
        starts_at_unix_milliseconds: i64,
        ends_at_unix_milliseconds: i64,
        step_milliseconds: i64,
    ) -> Result<Vec<FleetTelemetryBucketRecord>> {
        let mut predicates = Vec::new();
        if let Some(organization_id) = organization_id {
            predicates.push(format!("organization_id='{organization_id}'"));
        }
        if let Some(project_id) = project_id {
            predicates.push(format!("project_id='{project_id}'"));
        }
        if let Some(environment_id) = environment_id {
            predicates.push(format!("environment_id='{environment_id}'"));
        }
        if let Some(connection_id) = connection_id {
            predicates.push(format!("connection_id='{connection_id}'"));
        }
        if let Some(realm_id) = realm_id {
            predicates.push(format!("realm_id='{}'", sql_string(realm_id)));
        }
        if table == CANONICAL_TABLE {
            predicates.push(format!(
                "bucket_start_ms >= {starts_at_unix_milliseconds} AND bucket_start_ms < {ends_at_unix_milliseconds}"
            ));
        } else {
            predicates.push(format!(
                "window_start >= '{}' AND window_start < '{}'",
                millisecond_timestamp(starts_at_unix_milliseconds)?,
                millisecond_timestamp(ends_at_unix_milliseconds)?
            ));
        }
        let response = self
            .execute(&format!(
                "SELECT organization_id,date_bin('{interval}',{time_column}) AS aggregate_window_start,{} FROM {table} WHERE {} GROUP BY organization_id,aggregate_window_start ORDER BY aggregate_window_start,organization_id LIMIT {MAX_QUERY_RECORDS}",
                rollup_select_columns(),
                predicates.join(" AND ")
            ))
            .await?;
        decode_rollup_records(
            &response,
            project_id,
            environment_id,
            connection_id,
            step_milliseconds,
        )
    }

    async fn execute(&self, sql: &str) -> Result<Value> {
        self.execute_in(&self.database, sql).await
    }

    async fn execute_in(&self, database: &str, sql: &str) -> Result<Value> {
        let endpoint = self
            .endpoint
            .join("v1/sql")
            .context("compose GreptimeDB SQL endpoint")?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sql", sql)
            .finish();
        let response = self
            .client
            .post(endpoint)
            .query(&[("db", database)])
            .basic_auth(
                self.username.expose_secret(),
                Some(self.password.expose_secret()),
            )
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("x-greptime-timeout", "10s")
            .body(body)
            .send()
            .await
            .context("GreptimeDB request failed")?;
        if response.status() != StatusCode::OK {
            bail!("GreptimeDB returned HTTP {}", response.status());
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_SQL_RESPONSE_BYTES as u64)
        {
            bail!("GreptimeDB response exceeds the configured bound");
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("read GreptimeDB response")?;
            if bytes.len().saturating_add(chunk.len()) > MAX_SQL_RESPONSE_BYTES {
                bail!("GreptimeDB response exceeds the configured bound");
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes).context("decode GreptimeDB response")?;
        if value
            .get("code")
            .and_then(Value::as_i64)
            .is_some_and(|code| code != 0)
        {
            bail!("GreptimeDB rejected the bounded analytics operation");
        }
        Ok(value)
    }
}

fn materialized_column_schema() -> &'static str {
    "auth_present BOOLEAN,auth_attempts BIGINT UNSIGNED,auth_successes BIGINT UNSIGNED,auth_failures BIGINT UNSIGNED,auth_denials BIGINT UNSIGNED,auth_active_accounts BIGINT UNSIGNED,auth_latency_profile INT,auth_latency_count BIGINT UNSIGNED,auth_latency_sum_ms BIGINT UNSIGNED,auth_latency_h00 BIGINT UNSIGNED,auth_latency_h01 BIGINT UNSIGNED,auth_latency_h02 BIGINT UNSIGNED,auth_latency_h03 BIGINT UNSIGNED,auth_latency_h04 BIGINT UNSIGNED,auth_latency_h05 BIGINT UNSIGNED,auth_latency_h06 BIGINT UNSIGNED,auth_latency_h07 BIGINT UNSIGNED,auth_latency_h08 BIGINT UNSIGNED,auth_latency_h09 BIGINT UNSIGNED,auth_latency_h10 BIGINT UNSIGNED,auth_latency_h11 BIGINT UNSIGNED,failure_invalid_credential BIGINT UNSIGNED,failure_challenge_expired BIGINT UNSIGNED,failure_origin_rejected BIGINT UNSIGNED,failure_policy_denied BIGINT UNSIGNED,failure_rate_limited BIGINT UNSIGNED,failure_store_unavailable BIGINT UNSIGNED,failure_upstream_unavailable BIGINT UNSIGNED,failure_internal BIGINT UNSIGNED,failure_other BIGINT UNSIGNED,registration_present BOOLEAN,registration_options_started BIGINT UNSIGNED,registration_ceremonies_opened BIGINT UNSIGNED,registration_responses_returned BIGINT UNSIGNED,registrations_completed BIGINT UNSIGNED,registration_challenges_expired BIGINT UNSIGNED,sessions_present BOOLEAN,sessions_created BIGINT UNSIGNED,sessions_revoked BIGINT UNSIGNED,user_tokens_issued BIGINT UNSIGNED,service_tokens_issued BIGINT UNSIGNED,service_accounts_present BOOLEAN,service_account_calls BIGINT UNSIGNED,service_account_successes BIGINT UNSIGNED,service_account_failures BIGINT UNSIGNED,service_account_denials BIGINT UNSIGNED,service_account_rotations BIGINT UNSIGNED,webhooks_present BOOLEAN,webhook_deliveries BIGINT UNSIGNED,webhook_successes BIGINT UNSIGNED,webhook_failures BIGINT UNSIGNED,webhook_backlog BIGINT UNSIGNED,platform_present BOOLEAN,realm_health_present BOOLEAN"
}

fn materialized_select_columns() -> &'static str {
    "COALESCE(MAX(auth_present),false) AS auth_present,COALESCE(SUM(auth_attempts),0) AS auth_attempts,COALESCE(SUM(auth_successes),0) AS auth_successes,COALESCE(SUM(auth_failures),0) AS auth_failures,COALESCE(SUM(auth_denials),0) AS auth_denials,COALESCE(SUM(auth_active_accounts),0) AS auth_active_accounts,COALESCE(MAX(auth_latency_profile),0) AS auth_latency_profile,COALESCE(SUM(auth_latency_count),0) AS auth_latency_count,COALESCE(SUM(auth_latency_sum_ms),0) AS auth_latency_sum_ms,COALESCE(SUM(auth_latency_h00),0) AS auth_latency_h00,COALESCE(SUM(auth_latency_h01),0) AS auth_latency_h01,COALESCE(SUM(auth_latency_h02),0) AS auth_latency_h02,COALESCE(SUM(auth_latency_h03),0) AS auth_latency_h03,COALESCE(SUM(auth_latency_h04),0) AS auth_latency_h04,COALESCE(SUM(auth_latency_h05),0) AS auth_latency_h05,COALESCE(SUM(auth_latency_h06),0) AS auth_latency_h06,COALESCE(SUM(auth_latency_h07),0) AS auth_latency_h07,COALESCE(SUM(auth_latency_h08),0) AS auth_latency_h08,COALESCE(SUM(auth_latency_h09),0) AS auth_latency_h09,COALESCE(SUM(auth_latency_h10),0) AS auth_latency_h10,COALESCE(SUM(auth_latency_h11),0) AS auth_latency_h11,COALESCE(SUM(failure_invalid_credential),0) AS failure_invalid_credential,COALESCE(SUM(failure_challenge_expired),0) AS failure_challenge_expired,COALESCE(SUM(failure_origin_rejected),0) AS failure_origin_rejected,COALESCE(SUM(failure_policy_denied),0) AS failure_policy_denied,COALESCE(SUM(failure_rate_limited),0) AS failure_rate_limited,COALESCE(SUM(failure_store_unavailable),0) AS failure_store_unavailable,COALESCE(SUM(failure_upstream_unavailable),0) AS failure_upstream_unavailable,COALESCE(SUM(failure_internal),0) AS failure_internal,COALESCE(SUM(failure_other),0) AS failure_other,COALESCE(MAX(registration_present),false) AS registration_present,COALESCE(SUM(registration_options_started),0) AS registration_options_started,COALESCE(SUM(registration_ceremonies_opened),0) AS registration_ceremonies_opened,COALESCE(SUM(registration_responses_returned),0) AS registration_responses_returned,COALESCE(SUM(registrations_completed),0) AS registrations_completed,COALESCE(SUM(registration_challenges_expired),0) AS registration_challenges_expired,COALESCE(MAX(sessions_present),false) AS sessions_present,COALESCE(SUM(sessions_created),0) AS sessions_created,COALESCE(SUM(sessions_revoked),0) AS sessions_revoked,COALESCE(SUM(user_tokens_issued),0) AS user_tokens_issued,COALESCE(SUM(service_tokens_issued),0) AS service_tokens_issued,COALESCE(MAX(service_accounts_present),false) AS service_accounts_present,COALESCE(SUM(service_account_calls),0) AS service_account_calls,COALESCE(SUM(service_account_successes),0) AS service_account_successes,COALESCE(SUM(service_account_failures),0) AS service_account_failures,COALESCE(SUM(service_account_denials),0) AS service_account_denials,COALESCE(SUM(service_account_rotations),0) AS service_account_rotations,COALESCE(MAX(webhooks_present),false) AS webhooks_present,COALESCE(SUM(webhook_deliveries),0) AS webhook_deliveries,COALESCE(SUM(webhook_successes),0) AS webhook_successes,COALESCE(SUM(webhook_failures),0) AS webhook_failures,COALESCE(SUM(webhook_backlog),0) AS webhook_backlog,COALESCE(MAX(platform_present),false) AS platform_present,COALESCE(MAX(realm_health_present),false) AS realm_health_present"
}

fn rollup_select_columns() -> &'static str {
    "COALESCE(SUM(CASE WHEN auth_present THEN 1 ELSE 0 END),0),COALESCE(SUM(auth_attempts),0),COALESCE(SUM(auth_successes),0),COALESCE(SUM(auth_failures),0),COALESCE(SUM(auth_denials),0),COALESCE(SUM(auth_active_accounts),0),COALESCE(MAX(auth_latency_profile),0),COALESCE(SUM(auth_latency_count),0),COALESCE(SUM(auth_latency_sum_ms),0),COALESCE(SUM(auth_latency_h00),0),COALESCE(SUM(auth_latency_h01),0),COALESCE(SUM(auth_latency_h02),0),COALESCE(SUM(auth_latency_h03),0),COALESCE(SUM(auth_latency_h04),0),COALESCE(SUM(auth_latency_h05),0),COALESCE(SUM(auth_latency_h06),0),COALESCE(SUM(auth_latency_h07),0),COALESCE(SUM(auth_latency_h08),0),COALESCE(SUM(auth_latency_h09),0),COALESCE(SUM(auth_latency_h10),0),COALESCE(SUM(auth_latency_h11),0),COALESCE(SUM(failure_invalid_credential),0),COALESCE(SUM(failure_challenge_expired),0),COALESCE(SUM(failure_origin_rejected),0),COALESCE(SUM(failure_policy_denied),0),COALESCE(SUM(failure_rate_limited),0),COALESCE(SUM(failure_store_unavailable),0),COALESCE(SUM(failure_upstream_unavailable),0),COALESCE(SUM(failure_internal),0),COALESCE(SUM(failure_other),0),COALESCE(SUM(CASE WHEN registration_present THEN 1 ELSE 0 END),0),COALESCE(SUM(registration_options_started),0),COALESCE(SUM(registration_ceremonies_opened),0),COALESCE(SUM(registration_responses_returned),0),COALESCE(SUM(registrations_completed),0),COALESCE(SUM(registration_challenges_expired),0),COALESCE(SUM(CASE WHEN sessions_present THEN 1 ELSE 0 END),0),COALESCE(SUM(sessions_created),0),COALESCE(SUM(sessions_revoked),0),COALESCE(SUM(user_tokens_issued),0),COALESCE(SUM(service_tokens_issued),0),COALESCE(SUM(CASE WHEN service_accounts_present THEN 1 ELSE 0 END),0),COALESCE(SUM(service_account_calls),0),COALESCE(SUM(service_account_successes),0),COALESCE(SUM(service_account_failures),0),COALESCE(SUM(service_account_denials),0),COALESCE(SUM(service_account_rotations),0),COALESCE(SUM(CASE WHEN webhooks_present THEN 1 ELSE 0 END),0),COALESCE(SUM(webhook_deliveries),0),COALESCE(SUM(webhook_successes),0),COALESCE(SUM(webhook_failures),0),COALESCE(SUM(webhook_backlog),0),COALESCE(SUM(CASE WHEN platform_present THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN realm_health_present THEN 1 ELSE 0 END),0)"
}

fn decode_records(value: &Value) -> Result<Vec<FleetTelemetryBucketRecord>> {
    let rows = value
        .get("output")
        .and_then(Value::as_array)
        .and_then(|output| output.first())
        .and_then(|output| output.get("records"))
        .and_then(|records| records.get("rows"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if rows.len() > MAX_QUERY_RECORDS {
        bail!("GreptimeDB returned more rows than the query bound");
    }
    rows.into_iter().map(decode_record).collect()
}

fn decode_rollup_records(
    value: &Value,
    project_id: Option<Uuid>,
    environment_id: Option<Uuid>,
    connection_id: Option<Uuid>,
    step_milliseconds: i64,
) -> Result<Vec<FleetTelemetryBucketRecord>> {
    let rows = value
        .get("output")
        .and_then(Value::as_array)
        .and_then(|output| output.first())
        .and_then(|output| output.get("records"))
        .and_then(|records| records.get("rows"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if rows.len() > MAX_QUERY_RECORDS {
        bail!("GreptimeDB returned more aggregate rows than the query bound");
    }
    rows.into_iter()
        .map(|value| {
            decode_rollup_record(
                value,
                project_id,
                environment_id,
                connection_id,
                step_milliseconds,
            )
        })
        .collect()
}

fn decode_rollup_record(
    value: Value,
    project_id: Option<Uuid>,
    environment_id: Option<Uuid>,
    connection_id: Option<Uuid>,
    step_milliseconds: i64,
) -> Result<FleetTelemetryBucketRecord> {
    let row = value
        .as_array()
        .context("GreptimeDB aggregate row is not an array")?;
    if row.len() != 56 {
        bail!("GreptimeDB aggregate row has an unexpected shape");
    }
    let organization_id = uuid_value(&row[0], "organization_id")?;
    let bucket_start = timestamp_milliseconds(&row[1])?;
    let authentication = if u64_value(&row[2], "auth_present")? > 0 {
        let cumulative_counts = (11..=22)
            .map(|index| u64_value(&row[index], "auth_latency_bucket"))
            .collect::<Result<Vec<_>>>()?;
        let classes = [
            FailureClass::InvalidCredential,
            FailureClass::ChallengeExpired,
            FailureClass::OriginRejected,
            FailureClass::PolicyDenied,
            FailureClass::RateLimited,
            FailureClass::StoreUnavailable,
            FailureClass::UpstreamUnavailable,
            FailureClass::Internal,
            FailureClass::Other,
        ];
        let failure_classes = classes
            .into_iter()
            .zip(23..=31)
            .map(|(failure_class, index)| {
                Ok(AuthenticationFailureCount {
                    failure_class: failure_class.into(),
                    count: u64_value(&row[index], "failure_class")?,
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>>>()?;
        AuthenticationMetrics {
            attempts: u64_value(&row[3], "auth_attempts")?,
            successes: u64_value(&row[4], "auth_successes")?,
            failures: u64_value(&row[5], "auth_failures")?,
            denials: u64_value(&row[6], "auth_denials")?,
            active_account_observations: u64_value(&row[7], "auth_active_accounts")?,
            latency: LatencyHistogram {
                profile: HistogramProfile::from_i32(i32::try_from(i64_value(
                    &row[8],
                    "auth_latency_profile",
                )?)?)
                .unwrap_or(HistogramProfile::InteractiveMillisecondsV1)
                .into(),
                count: u64_value(&row[9], "auth_latency_count")?,
                sum_milliseconds: u64_value(&row[10], "auth_latency_sum_ms")?,
                cumulative_counts,
                ..Default::default()
            }
            .into(),
            failure_classes,
            ..Default::default()
        }
        .into()
    } else {
        Default::default()
    };
    let registration = if u64_value(&row[32], "registration_present")? > 0 {
        RegistrationMetrics {
            options_started: u64_value(&row[33], "registration_options_started")?,
            ceremonies_opened: u64_value(&row[34], "registration_ceremonies_opened")?,
            responses_returned: u64_value(&row[35], "registration_responses_returned")?,
            registrations_completed: u64_value(&row[36], "registrations_completed")?,
            challenges_expired: u64_value(&row[37], "registration_challenges_expired")?,
            ..Default::default()
        }
        .into()
    } else {
        Default::default()
    };
    let sessions_and_tokens = if u64_value(&row[38], "sessions_present")? > 0 {
        SessionTokenMetrics {
            sessions_created: u64_value(&row[39], "sessions_created")?,
            sessions_revoked: u64_value(&row[40], "sessions_revoked")?,
            user_tokens_issued: u64_value(&row[41], "user_tokens_issued")?,
            service_tokens_issued: u64_value(&row[42], "service_tokens_issued")?,
            ..Default::default()
        }
        .into()
    } else {
        Default::default()
    };
    let service_accounts = if u64_value(&row[43], "service_accounts_present")? > 0 {
        ServiceAccountMetrics {
            calls: u64_value(&row[44], "service_account_calls")?,
            successes: u64_value(&row[45], "service_account_successes")?,
            failures: u64_value(&row[46], "service_account_failures")?,
            denials: u64_value(&row[47], "service_account_denials")?,
            credential_rotations: u64_value(&row[48], "service_account_rotations")?,
            ..Default::default()
        }
        .into()
    } else {
        Default::default()
    };
    let webhooks = if u64_value(&row[49], "webhooks_present")? > 0 {
        WebhookMetrics {
            deliveries: u64_value(&row[50], "webhook_deliveries")?,
            successes: u64_value(&row[51], "webhook_successes")?,
            failures: u64_value(&row[52], "webhook_failures")?,
            backlog: u64_value(&row[53], "webhook_backlog")?,
            ..Default::default()
        }
        .into()
    } else {
        Default::default()
    };
    let platform = (u64_value(&row[54], "platform_present")? > 0)
        .then(PlatformMetrics::default)
        .into();
    let realm_health = (u64_value(&row[55], "realm_health_present")? > 0)
        .then(|| RealmHealthMetrics {
            serving_state: AnalyticsServingState::Healthy.into(),
            ..Default::default()
        })
        .into();
    let bucket = TelemetryBucket {
        realm_id: "aggregate".into(),
        assignment_epoch: 1,
        bucket_start_unix_milliseconds: bucket_start,
        bucket_width_seconds: u32::try_from(step_milliseconds / 1_000)
            .context("analytics aggregation step is out of range")?,
        revision: 1,
        metric_schema_version: MetricSchemaVersion::V1.into(),
        closed: true,
        authentication,
        registration,
        sessions_and_tokens,
        service_accounts,
        webhooks,
        platform,
        realm_health,
        ..Default::default()
    };
    Ok(FleetTelemetryBucketRecord {
        organization_id,
        project_id: project_id.unwrap_or_else(Uuid::nil),
        environment_id: environment_id.unwrap_or_else(Uuid::nil),
        connection_id: connection_id.unwrap_or_else(Uuid::nil),
        realm_id: "aggregate".into(),
        assignment_epoch: 1,
        bucket_start_unix_milliseconds: bucket_start,
        bucket_width_seconds: bucket.bucket_width_seconds,
        metric_schema_version: MetricSchemaVersion::V1 as i32,
        revision: 1,
        first_event_sequence: 0,
        last_event_sequence: 0,
        batch_id: Uuid::nil(),
        payload_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(bucket.encode_to_vec()),
        accepted_at: u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap_or(0),
    })
}

fn decode_record(value: Value) -> Result<FleetTelemetryBucketRecord> {
    let row = value
        .as_array()
        .context("GreptimeDB analytics row is not an array")?;
    if row.len() != 15 {
        bail!("GreptimeDB analytics row has an unexpected shape");
    }
    Ok(FleetTelemetryBucketRecord {
        organization_id: uuid_value(&row[0], "organization_id")?,
        project_id: uuid_value(&row[1], "project_id")?,
        environment_id: uuid_value(&row[2], "environment_id")?,
        connection_id: uuid_value(&row[3], "connection_id")?,
        realm_id: string_value(&row[4], "realm_id")?,
        assignment_epoch: u64_value(&row[5], "assignment_epoch")?,
        bucket_start_unix_milliseconds: i64_value(&row[6], "bucket_start_ms")?,
        bucket_width_seconds: u32::try_from(u64_value(&row[7], "bucket_width_seconds")?)
            .context("bucket_width_seconds is out of range")?,
        metric_schema_version: i32::try_from(i64_value(&row[8], "metric_schema_version")?)
            .context("metric_schema_version is out of range")?,
        revision: u64_value(&row[9], "revision")?,
        first_event_sequence: u64_value(&row[10], "first_event_sequence")?,
        last_event_sequence: u64_value(&row[11], "last_event_sequence")?,
        batch_id: uuid_value(&row[12], "batch_id")?,
        payload_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(hex::decode(string_value(&row[13], "payload_hex")?)?),
        accepted_at: u64_value(&row[14], "accepted_at_seconds")?,
    })
}

fn string_value(value: &Value, field: &'static str) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .with_context(|| format!("GreptimeDB {field} is not a string"))
}

fn i64_value(value: &Value, field: &'static str) -> Result<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .with_context(|| format!("GreptimeDB {field} is not an integer"))
}

fn u64_value(value: &Value, field: &'static str) -> Result<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .with_context(|| format!("GreptimeDB {field} is not an unsigned integer"))
}

fn timestamp_milliseconds(value: &Value) -> Result<i64> {
    let nanoseconds = i64_value(value, "window_start")?;
    Ok(nanoseconds / 1_000_000)
}

fn uuid_value(value: &Value, field: &'static str) -> Result<Uuid> {
    Uuid::parse_str(&string_value(value, field)?).with_context(|| format!("invalid {field}"))
}

fn sql_string(value: &str) -> String {
    value.replace('\'', "''")
}

fn millisecond_timestamp(value: i64) -> Result<String> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(value) * 1_000_000)
        .context("analytics bucket timestamp is invalid")?
        .format(&Rfc3339)
        .context("format analytics bucket timestamp")
}

fn current_window_start(width_seconds: i64) -> i64 {
    OffsetDateTime::now_utc().unix_timestamp() / width_seconds * width_seconds * 1_000
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::proto::rustyauth::analytics::v1::{
        AuthenticationFailureCount, AuthenticationMetrics, FailureClass, HistogramProfile,
        LatencyHistogram, MetricSchemaVersion, RegistrationMetrics, TelemetryBucket,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use buffa::Message;

    #[test]
    fn sql_literals_are_escaped_and_timestamps_keep_milliseconds() {
        assert_eq!(sql_string("realm'o"), "realm''o");
        assert_eq!(
            millisecond_timestamp(1_800_000_000_123).unwrap(),
            "2027-01-15T08:00:00.123Z"
        );
    }

    #[tokio::test]
    #[ignore = "requires the pinned GreptimeDB integration service"]
    async fn live_greptime_round_trip_preserves_the_trusted_record() -> Result<()> {
        let endpoint = match std::env::var("RUSTYAUTH_TEST_GREPTIME_URL") {
            Ok(value) => Url::parse(&value)?,
            Err(_) => return Ok(()),
        };
        let organization_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let environment_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let bucket_start = 1_800_000_000_000_i64;
        let bucket = TelemetryBucket {
            realm_id: "qualified-realm".into(),
            assignment_epoch: 7,
            bucket_start_unix_milliseconds: bucket_start,
            bucket_width_seconds: 300,
            metric_schema_version: MetricSchemaVersion::V1.into(),
            revision: 2,
            first_event_sequence: 10,
            last_event_sequence: 20,
            ..Default::default()
        };
        let expected = FleetTelemetryBucketRecord {
            organization_id,
            project_id,
            environment_id,
            connection_id,
            realm_id: bucket.realm_id.clone(),
            assignment_epoch: bucket.assignment_epoch,
            bucket_start_unix_milliseconds: bucket_start,
            bucket_width_seconds: bucket.bucket_width_seconds,
            metric_schema_version: bucket.metric_schema_version.to_i32(),
            revision: bucket.revision,
            first_event_sequence: bucket.first_event_sequence,
            last_event_sequence: bucket.last_event_sequence,
            batch_id: Uuid::new_v4(),
            payload_base64url: URL_SAFE_NO_PAD.encode(bucket.encode_to_vec()),
            accepted_at: 1_800_000_001,
        };
        let store = GreptimeAnalyticsStore::new(AnalyticsConfig {
            endpoint,
            database: format!("rustyauth_test_{}", Uuid::new_v4().simple()),
            username: SecretString::from("rustyauth"),
            password: SecretString::from("rustyauth-test-password"),
        })?;
        store.initialize().await?;
        store.upsert(std::slice::from_ref(&expected)).await?;
        let records = store
            .query(
                Some(organization_id),
                Some(project_id),
                Some(environment_id),
                Some(connection_id),
                Some(&expected.realm_id),
                bucket_start,
                bucket_start + 300_000,
            )
            .await?;
        assert_eq!(records, vec![expected]);
        let rollups = store
            .query_rollups(
                Some(organization_id),
                Some(project_id),
                Some(environment_id),
                Some(connection_id),
                Some("qualified-realm"),
                bucket_start,
                bucket_start + 300_000,
                300_000,
            )
            .await?;
        assert_eq!(rollups.len(), 1);
        assert_eq!(
            rollups[0].bucket_start_unix_milliseconds, bucket_start,
            "server-side reduction must preserve the requested window"
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires the pinned GreptimeDB integration service"]
    async fn live_greptime_reduces_wide_metrics_and_replaces_corrections() -> Result<()> {
        let endpoint = match std::env::var("RUSTYAUTH_TEST_GREPTIME_URL") {
            Ok(value) => Url::parse(&value)?,
            Err(_) => return Ok(()),
        };
        let organization_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let environment_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let bucket_start =
            (OffsetDateTime::now_utc().unix_timestamp() - 2 * 86_400) / 300 * 300 * 1_000;
        let record = |revision: u64, attempts: u64, successes: u64| {
            let rejected = attempts - successes;
            let bucket = TelemetryBucket {
                realm_id: "wide-metrics-realm".into(),
                assignment_epoch: 1,
                bucket_start_unix_milliseconds: bucket_start,
                bucket_width_seconds: 300,
                metric_schema_version: MetricSchemaVersion::V1.into(),
                revision,
                closed: true,
                authentication: AuthenticationMetrics {
                    attempts,
                    successes,
                    failures: rejected,
                    latency: LatencyHistogram {
                        profile: HistogramProfile::InteractiveMillisecondsV1.into(),
                        count: attempts,
                        sum_milliseconds: attempts * 100,
                        cumulative_counts: vec![attempts; 12],
                        ..Default::default()
                    }
                    .into(),
                    failure_classes: vec![AuthenticationFailureCount {
                        failure_class: FailureClass::Other.into(),
                        count: rejected,
                        ..Default::default()
                    }],
                    ..Default::default()
                }
                .into(),
                registration: RegistrationMetrics {
                    options_started: attempts,
                    ceremonies_opened: attempts,
                    responses_returned: successes,
                    registrations_completed: successes,
                    challenges_expired: rejected,
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            };
            FleetTelemetryBucketRecord {
                organization_id,
                project_id,
                environment_id,
                connection_id,
                realm_id: bucket.realm_id.clone(),
                assignment_epoch: 1,
                bucket_start_unix_milliseconds: bucket_start,
                bucket_width_seconds: 300,
                metric_schema_version: MetricSchemaVersion::V1 as i32,
                revision,
                first_event_sequence: 1,
                last_event_sequence: attempts,
                batch_id: Uuid::new_v4(),
                payload_base64url: URL_SAFE_NO_PAD.encode(bucket.encode_to_vec()),
                accepted_at: u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap(),
            }
        };
        let store = GreptimeAnalyticsStore::new(AnalyticsConfig {
            endpoint,
            database: format!("rustyauth_wide_test_{}", Uuid::new_v4().simple()),
            username: SecretString::from("rustyauth"),
            password: SecretString::from("rustyauth-test-password"),
        })?;
        store.initialize().await?;
        store.upsert(&[record(1, 10, 8)]).await?;
        store.upsert(&[record(2, 12, 11)]).await?;
        let rollups = store
            .query_rollups(
                Some(organization_id),
                Some(project_id),
                Some(environment_id),
                Some(connection_id),
                Some("wide-metrics-realm"),
                bucket_start,
                bucket_start + 300_000,
                300_000,
            )
            .await?;
        assert_eq!(rollups.len(), 1);
        let bucket = rollups[0].bucket()?;
        let authentication = bucket.authentication.as_option().context("missing auth")?;
        assert_eq!(authentication.attempts, 12);
        assert_eq!(authentication.successes, 11);
        assert_eq!(
            bucket
                .registration
                .as_option()
                .context("missing registration")?
                .registrations_completed,
            11
        );
        for (step, window_start) in [
            (3_600_000, bucket_start / 3_600_000 * 3_600_000),
            (86_400_000, bucket_start / 86_400_000 * 86_400_000),
        ] {
            let materialized = store
                .query_rollups(
                    Some(organization_id),
                    Some(project_id),
                    Some(environment_id),
                    Some(connection_id),
                    Some("wide-metrics-realm"),
                    window_start,
                    window_start + step,
                    step,
                )
                .await?;
            assert_eq!(materialized.len(), 1);
            let bucket = materialized[0].bucket()?;
            let authentication = bucket
                .authentication
                .as_option()
                .context("materialized authentication metrics are missing")?;
            assert_eq!(authentication.attempts, 12);
            assert_eq!(authentication.successes, 11);
        }
        store
            .purge_connection(Uuid::new_v4(), connection_id)
            .await?;
        assert_eq!(
            store
                .query(
                    Some(organization_id),
                    None,
                    None,
                    Some(connection_id),
                    None,
                    bucket_start,
                    bucket_start + 300_000,
                )
                .await?
                .len(),
            1,
            "a mismatched organization must not purge a connection"
        );
        store
            .purge_connection(organization_id, connection_id)
            .await?;
        assert!(
            store
                .query(
                    Some(organization_id),
                    None,
                    None,
                    Some(connection_id),
                    None,
                    bucket_start,
                    bucket_start + 300_000,
                )
                .await?
                .is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "explicit 1,000-realm / 28-day GreptimeDB qualification"]
    async fn medium_tier_organization_query_meets_the_two_second_p95_target() -> Result<()> {
        if std::env::var("RUSTYAUTH_RUN_MEDIUM_ANALYTICS_QUALIFICATION").as_deref() != Ok("1") {
            return Ok(());
        }
        let endpoint = Url::parse(&std::env::var("RUSTYAUTH_TEST_GREPTIME_URL")?)?;
        let organization_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let environment_id = Uuid::new_v4();
        let database = format!("rustyauth_medium_test_{}", Uuid::new_v4().simple());
        let store = GreptimeAnalyticsStore::new(AnalyticsConfig {
            endpoint,
            database: database.clone(),
            username: SecretString::from("rustyauth"),
            password: SecretString::from("rustyauth-test-password"),
        })?;
        store.initialize().await?;
        // Align the qualification window to the same UTC hour boundaries used by
        // `date_bin('1 hour', ...)`; otherwise two partial edge hours turn an
        // exact 28-day data range into 673 result windows.
        let ends_at_seconds = OffsetDateTime::now_utc().unix_timestamp() / 3_600 * 3_600;
        let starts_at_seconds = ends_at_seconds - 28 * 86_400;
        let seed_started = Instant::now();
        for first_realm in (1_i64..=1_000).step_by(25) {
            let last_realm = (first_realm + 24).min(1_000);
            store
                .execute(&format!(
                    "INSERT INTO {CANONICAL_TABLE} (organization_id,project_id,environment_id,connection_id,realm_id,assignment_epoch,bucket_start,bucket_start_ms,bucket_width_seconds,metric_schema_version,revision,first_event_sequence,last_event_sequence,batch_id,payload_hex,accepted_at_seconds,auth_present,auth_attempts,auth_successes,auth_failures,auth_denials,auth_active_accounts,auth_latency_profile,auth_latency_count,auth_latency_sum_ms,auth_latency_h00,auth_latency_h01,auth_latency_h02,auth_latency_h03,auth_latency_h04,auth_latency_h05,auth_latency_h06,auth_latency_h07,auth_latency_h08,auth_latency_h09,auth_latency_h10,auth_latency_h11) \
                     SELECT '{organization_id}' AS organization_id,'{project_id}' AS project_id,'{environment_id}' AS environment_id,concat('connection-',cast(realms.value as string)) AS connection_id,concat('realm-',cast(realms.value as string)) AS realm_id,1 AS assignment_epoch,to_timestamp({starts_at_seconds} + buckets.value * 300) AS bucket_start,({starts_at_seconds} + buckets.value * 300) * 1000 AS bucket_start_ms,300 AS bucket_width_seconds,1 AS metric_schema_version,1 AS revision,0 AS first_event_sequence,0 AS last_event_sequence,'qualification' AS batch_id,'' AS payload_hex,{} AS accepted_at_seconds,true AS auth_present,1 AS auth_attempts,1 AS auth_successes,0 AS auth_failures,0 AS auth_denials,1 AS auth_active_accounts,1 AS auth_latency_profile,1 AS auth_latency_count,100 AS auth_latency_sum_ms,1 AS auth_latency_h00,1 AS auth_latency_h01,1 AS auth_latency_h02,1 AS auth_latency_h03,1 AS auth_latency_h04,1 AS auth_latency_h05,1 AS auth_latency_h06,1 AS auth_latency_h07,1 AS auth_latency_h08,1 AS auth_latency_h09,1 AS auth_latency_h10,1 AS auth_latency_h11 \
                     FROM generate_series({first_realm},{last_realm}) realms CROSS JOIN generate_series(0,8063) buckets",
                    u64::try_from(ends_at_seconds).unwrap_or_default()
                ))
                .await?;
        }
        let seed_duration = seed_started.elapsed();
        store.flush_materializations().await?;
        let starts_at = starts_at_seconds * 1_000;
        let ends_at = ends_at_seconds * 1_000;
        let mut durations = Vec::new();
        for _ in 0..20 {
            let started = Instant::now();
            let rows = store
                .query_rollups(
                    Some(organization_id),
                    None,
                    None,
                    None,
                    None,
                    starts_at,
                    ends_at,
                    3_600_000,
                )
                .await?;
            assert_eq!(rows.len(), 28 * 24);
            durations.push(started.elapsed());
        }
        durations.sort_unstable();
        let p95 = durations[18];
        eprintln!(
            "medium analytics qualification: rows=8064000 seed={seed_duration:?} query_p95={p95:?}"
        );
        let _ = store
            .execute_in("public", &format!("DROP DATABASE {database}"))
            .await;
        assert!(
            p95 <= Duration::from_secs(2),
            "medium-tier 28-day organization query p95 was {p95:?}"
        );
        Ok(())
    }
}
