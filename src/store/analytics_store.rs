//! Restart-safe local metric projection and Fleet Analytics outbox.
//!
//! Authentication writes only the ordered event log. This projector runs out of
//! band and commits its source cursor, affected five-minute buckets, and closed
//! bucket outbox records in one SableDB transaction. Analytics availability can
//! therefore never enter the authentication request path.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use buffa::Message;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    analytics::{
        BUCKET_WIDTH_SECONDS_V1, DELIVERY_LATENCY_BOUNDS_MILLISECONDS_V1,
        INTERACTIVE_LATENCY_BOUNDS_MILLISECONDS_V1, MAX_BUCKETS_PER_BATCH,
        TRANSPORT_SCHEMA_VERSION_V1, validate_batch,
    },
    proto::rustyauth::analytics::v1::{
        AuthenticationFailureCount, AuthenticationFlow, AuthenticationFlowCount,
        AuthenticationMetrics, FailureClass, HistogramProfile, LatencyHistogram,
        MetricSchemaVersion, RegistrationMetrics, ServiceAccountMetrics, SessionTokenMetrics,
        TelemetryBucket, TelemetryBucketBatch, WebhookMetrics,
    },
};

use super::{AuthEvent, Store, now};

const PROJECTOR_CURSOR_KEY: &str = "analytics:projector-cursor";
const CLOSURE_CURSOR_KEY: &str = "analytics:closure-cursor";
const BUCKET_PREFIX: &str = "analytics:bucket:";
const OUTBOX_PREFIX: &str = "analytics:outbox:";
const MAX_PROJECTION_BATCH: u64 = 10_000;
const CLOSE_GRACE_SECONDS: u64 = 120;
const FAILURE_CLASS_COUNT: usize = 9;
const MAX_OUTBOX_RECORDS: usize = MAX_BUCKETS_PER_BATCH;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct LocalMetricBucket {
    pub bucket_start: u64,
    pub revision: u64,
    pub first_event_sequence: u64,
    pub last_event_sequence: u64,
    pub closed: bool,
    pub authentication_options_started: u64,
    pub authentication_attempts: u64,
    pub authentication_successes: u64,
    pub authentication_failures: u64,
    pub authentication_denials: u64,
    pub authentication_latency_count: u64,
    pub authentication_latency_sum_milliseconds: u64,
    pub authentication_latency_cumulative_counts: Vec<u64>,
    pub authentication_failure_classes: Vec<u64>,
    pub registration_options_started: u64,
    pub registration_ceremonies_opened: u64,
    pub registration_responses_returned: u64,
    pub registrations_completed: u64,
    pub registration_challenges_expired: u64,
    pub sessions_created: u64,
    pub sessions_revoked: u64,
    pub user_tokens_issued: u64,
    pub service_tokens_issued: u64,
    pub service_account_metrics_observed: bool,
    pub service_account_calls: u64,
    pub service_account_successes: u64,
    pub service_account_failures: u64,
    pub service_account_denials: u64,
    pub service_account_credential_rotations: u64,
    pub webhook_metrics_observed: bool,
    pub webhook_deliveries: u64,
    pub webhook_successes: u64,
    pub webhook_failures: u64,
    pub webhook_latency_count: u64,
    pub webhook_latency_sum_milliseconds: u64,
    pub webhook_latency_cumulative_counts: Vec<u64>,
    pub webhook_backlog: u64,
    /// Subject IDs remain inside the realm and are never copied to the wire.
    pub active_subjects: BTreeSet<Uuid>,
}

impl LocalMetricBucket {
    fn new(bucket_start: u64) -> Self {
        Self {
            bucket_start,
            revision: 1,
            authentication_latency_cumulative_counts: vec![
                0;
                INTERACTIVE_LATENCY_BOUNDS_MILLISECONDS_V1.len()
                    + 1
            ],
            authentication_failure_classes: vec![0; FAILURE_CLASS_COUNT],
            webhook_latency_cumulative_counts: vec![
                0;
                DELIVERY_LATENCY_BOUNDS_MILLISECONDS_V1.len()
                    + 1
            ],
            ..Self::default()
        }
    }

    fn normalize(&mut self) {
        self.authentication_latency_cumulative_counts
            .resize(INTERACTIVE_LATENCY_BOUNDS_MILLISECONDS_V1.len() + 1, 0);
        self.authentication_failure_classes
            .resize(FAILURE_CLASS_COUNT, 0);
        self.webhook_latency_cumulative_counts
            .resize(DELIVERY_LATENCY_BOUNDS_MILLISECONDS_V1.len() + 1, 0);
    }

    fn apply(&mut self, event: &AuthEvent) -> bool {
        self.normalize();
        let contributed = match event.event_type.as_str() {
            "authentication.options.started" => {
                increment(&mut self.authentication_options_started);
                true
            }
            "authentication.completed" => {
                increment(&mut self.authentication_attempts);
                increment(&mut self.authentication_successes);
                self.observe_authentication_latency(event);
                true
            }
            "authentication.failed" => {
                increment(&mut self.authentication_attempts);
                increment(&mut self.authentication_failures);
                self.observe_authentication_failure(event);
                self.observe_authentication_latency(event);
                true
            }
            "authentication.denied" => {
                increment(&mut self.authentication_attempts);
                increment(&mut self.authentication_denials);
                self.observe_authentication_failure(event);
                self.observe_authentication_latency(event);
                true
            }
            "registration.options.started" => {
                increment(&mut self.registration_options_started);
                true
            }
            "registration.ceremony.opened" => {
                increment(&mut self.registration_ceremonies_opened);
                true
            }
            "registration.response.returned" => {
                increment(&mut self.registration_responses_returned);
                true
            }
            "registration.challenge.expired" => {
                increment(&mut self.registration_challenges_expired);
                true
            }
            "registration.completed" => {
                increment(&mut self.registrations_completed);
                true
            }
            "session.created" => {
                increment(&mut self.sessions_created);
                true
            }
            "session.revoked_all" => {
                increment(&mut self.sessions_revoked);
                true
            }
            "token.user.issued" => {
                let count = event
                    .data
                    .get("count")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(1);
                self.user_tokens_issued = self.user_tokens_issued.saturating_add(count);
                true
            }
            "service_account.token.issued" => {
                increment(&mut self.service_tokens_issued);
                self.service_account_metrics_observed = true;
                increment(&mut self.service_account_calls);
                increment(&mut self.service_account_successes);
                true
            }
            "service_account.token.failed" => {
                self.service_account_metrics_observed = true;
                increment(&mut self.service_account_calls);
                increment(&mut self.service_account_failures);
                true
            }
            "service_account.token.denied" => {
                self.service_account_metrics_observed = true;
                increment(&mut self.service_account_calls);
                increment(&mut self.service_account_denials);
                true
            }
            "service_account.credential.created" => {
                self.service_account_metrics_observed = true;
                increment(&mut self.service_account_credential_rotations);
                true
            }
            "analytics.webhook.delivery.queued" => {
                self.webhook_metrics_observed = true;
                self.observe_webhook_backlog(event);
                true
            }
            "analytics.webhook.delivery.succeeded" => {
                self.webhook_metrics_observed = true;
                increment(&mut self.webhook_deliveries);
                increment(&mut self.webhook_successes);
                self.observe_webhook_latency(event);
                self.observe_webhook_backlog(event);
                true
            }
            "analytics.webhook.delivery.failed" => {
                self.webhook_metrics_observed = true;
                increment(&mut self.webhook_deliveries);
                increment(&mut self.webhook_failures);
                self.observe_webhook_latency(event);
                self.observe_webhook_backlog(event);
                true
            }
            _ => false,
        };
        if contributed {
            self.first_event_sequence = if self.first_event_sequence == 0 {
                event.sequence
            } else {
                self.first_event_sequence.min(event.sequence)
            };
            self.last_event_sequence = self.last_event_sequence.max(event.sequence);
            if event_observes_active_account(&event.event_type)
                && let Some(subject) = event.subject
            {
                self.active_subjects.insert(subject);
            }
            if event.event_type == "token.user.issued"
                && let Some(subjects) = event
                    .data
                    .get("subjectIds")
                    .and_then(serde_json::Value::as_array)
            {
                self.active_subjects.extend(
                    subjects
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .filter_map(|subject| Uuid::parse_str(subject).ok()),
                );
            }
        }
        contributed
    }

    fn observe_authentication_latency(&mut self, event: &AuthEvent) {
        let Some(value) = event
            .data
            .get("latencyMilliseconds")
            .and_then(serde_json::Value::as_u64)
        else {
            return;
        };
        increment(&mut self.authentication_latency_count);
        self.authentication_latency_sum_milliseconds = self
            .authentication_latency_sum_milliseconds
            .saturating_add(value);
        for (index, upper) in INTERACTIVE_LATENCY_BOUNDS_MILLISECONDS_V1
            .iter()
            .enumerate()
        {
            if value <= *upper {
                increment(&mut self.authentication_latency_cumulative_counts[index]);
            }
        }
        let infinite = self.authentication_latency_cumulative_counts.len() - 1;
        increment(&mut self.authentication_latency_cumulative_counts[infinite]);
    }

    fn observe_authentication_failure(&mut self, event: &AuthEvent) {
        let index = match event
            .data
            .get("outcomeClass")
            .and_then(serde_json::Value::as_str)
        {
            Some("invalidCredential") => 0,
            Some("challengeExpired") => 1,
            Some("originRejected") => 2,
            Some("policyDenied") => 3,
            Some("rateLimited") => 4,
            Some("storeUnavailable") => 5,
            Some("upstreamUnavailable") => 6,
            Some("internal") => 7,
            _ => 8,
        };
        increment(&mut self.authentication_failure_classes[index]);
    }

    fn observe_webhook_latency(&mut self, event: &AuthEvent) {
        let Some(value) = event
            .data
            .get("latencyMilliseconds")
            .and_then(serde_json::Value::as_u64)
        else {
            return;
        };
        increment(&mut self.webhook_latency_count);
        self.webhook_latency_sum_milliseconds =
            self.webhook_latency_sum_milliseconds.saturating_add(value);
        for (index, upper) in DELIVERY_LATENCY_BOUNDS_MILLISECONDS_V1.iter().enumerate() {
            if value <= *upper {
                increment(&mut self.webhook_latency_cumulative_counts[index]);
            }
        }
        let infinite = self.webhook_latency_cumulative_counts.len() - 1;
        increment(&mut self.webhook_latency_cumulative_counts[infinite]);
    }

    fn observe_webhook_backlog(&mut self, event: &AuthEvent) {
        if let Some(backlog) = event
            .data
            .get("backlog")
            .and_then(serde_json::Value::as_u64)
        {
            self.webhook_backlog = backlog;
        }
    }

    pub fn authentication_latency_p95_upper_bound(&self) -> Option<u64> {
        if self.authentication_latency_count == 0 {
            return None;
        }
        let rank = self
            .authentication_latency_count
            .saturating_mul(95)
            .div_ceil(100);
        INTERACTIVE_LATENCY_BOUNDS_MILLISECONDS_V1
            .iter()
            .zip(&self.authentication_latency_cumulative_counts)
            .find_map(|(upper, count)| (*count >= rank).then_some(*upper))
    }

    pub fn to_telemetry_bucket(&self, realm_id: &str, assignment_epoch: u64) -> TelemetryBucket {
        let failures = self
            .authentication_failure_classes
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, count)| *count > 0)
            .map(|(index, count)| AuthenticationFailureCount {
                failure_class: failure_class(index).into(),
                count,
                ..Default::default()
            })
            .collect();
        TelemetryBucket {
            realm_id: realm_id.to_owned(),
            assignment_epoch,
            bucket_start_unix_milliseconds: i64::try_from(self.bucket_start)
                .unwrap_or(i64::MAX / 1_000)
                .saturating_mul(1_000),
            bucket_width_seconds: BUCKET_WIDTH_SECONDS_V1,
            revision: self.revision.max(1),
            first_event_sequence: self.first_event_sequence,
            last_event_sequence: self.last_event_sequence,
            metric_schema_version: MetricSchemaVersion::V1.into(),
            closed: self.closed,
            authentication: AuthenticationMetrics {
                attempts: self.authentication_attempts,
                successes: self.authentication_successes,
                failures: self.authentication_failures,
                denials: self.authentication_denials,
                latency: LatencyHistogram {
                    profile: HistogramProfile::InteractiveMillisecondsV1.into(),
                    count: self.authentication_latency_count,
                    sum_milliseconds: self.authentication_latency_sum_milliseconds,
                    cumulative_counts: self.authentication_latency_cumulative_counts.clone(),
                    ..Default::default()
                }
                .into(),
                flows: vec![AuthenticationFlowCount {
                    flow: AuthenticationFlow::Passkey.into(),
                    attempts: self.authentication_attempts,
                    successes: self.authentication_successes,
                    failures: self.authentication_failures,
                    denials: self.authentication_denials,
                    ..Default::default()
                }],
                failure_classes: failures,
                active_account_observations: self.active_subjects.len() as u64,
                ..Default::default()
            }
            .into(),
            registration: RegistrationMetrics {
                options_started: self.registration_options_started,
                ceremonies_opened: self.registration_ceremonies_opened,
                responses_returned: self.registration_responses_returned,
                registrations_completed: self.registrations_completed,
                challenges_expired: self.registration_challenges_expired,
                ..Default::default()
            }
            .into(),
            sessions_and_tokens: SessionTokenMetrics {
                sessions_created: self.sessions_created,
                sessions_revoked: self.sessions_revoked,
                user_tokens_issued: self.user_tokens_issued,
                service_tokens_issued: self.service_tokens_issued,
                ..Default::default()
            }
            .into(),
            service_accounts: if self.service_account_metrics_observed {
                ServiceAccountMetrics {
                    calls: self.service_account_calls,
                    successes: self.service_account_successes,
                    failures: self.service_account_failures,
                    denials: self.service_account_denials,
                    credential_rotations: self.service_account_credential_rotations,
                    ..Default::default()
                }
                .into()
            } else {
                Default::default()
            },
            webhooks: if self.webhook_metrics_observed {
                WebhookMetrics {
                    deliveries: self.webhook_deliveries,
                    successes: self.webhook_successes,
                    failures: self.webhook_failures,
                    latency: LatencyHistogram {
                        profile: HistogramProfile::DeliveryMillisecondsV1.into(),
                        count: self.webhook_latency_count,
                        sum_milliseconds: self.webhook_latency_sum_milliseconds,
                        cumulative_counts: self.webhook_latency_cumulative_counts.clone(),
                        ..Default::default()
                    }
                    .into(),
                    backlog: self.webhook_backlog,
                    ..Default::default()
                }
                .into()
            } else {
                Default::default()
            },
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryOutboxRecord {
    pub bucket_start: u64,
    pub revision: u64,
    pub batch_id: Uuid,
    pub payload_base64url: String,
    pub first_queued_at: u64,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub next_attempt_at: u64,
}

impl TelemetryOutboxRecord {
    pub fn payload(&self) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(&self.payload_base64url)
            .context("decode telemetry outbox payload")
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProjectionResult {
    pub events_scanned: usize,
    pub events_contributed: usize,
    pub buckets_written: usize,
    pub outbox_records_written: usize,
}

impl Store {
    pub async fn analytics_projector_cursor(&self) -> Result<u64> {
        Ok(self.get::<u64>(PROJECTOR_CURSOR_KEY).await?.unwrap_or(0))
    }

    /// Advances the local projection by at most `limit` source events.
    pub async fn project_analytics_events(
        &self,
        realm_id: &str,
        limit: u64,
    ) -> Result<ProjectionResult> {
        let limit = limit.clamp(1, MAX_PROJECTION_BATCH);
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let stored_cursor = self.get::<u64>(PROJECTOR_CURSOR_KEY).await?;
        // An upgrade can introduce the projector after older auth events have
        // already aged out. Begin at the oldest retained event instead of
        // pretending the unavailable prefix can be reconstructed.
        let cursor = match stored_cursor {
            Some(cursor) => cursor,
            None => self.minimum_event_sequence().await?.saturating_sub(1),
        };
        let events = self.events(cursor, limit).await?;
        let mut result = ProjectionResult {
            events_scanned: events.len(),
            ..ProjectionResult::default()
        };
        let closure_before = now().saturating_sub(CLOSE_GRACE_SECONDS);
        let latest_closable =
            aligned_bucket_start(closure_before.saturating_sub(u64::from(BUCKET_WIDTH_SECONDS_V1)));
        let stored_closure_cursor = self.get::<u64>(CLOSURE_CURSOR_KEY).await?;

        // The projector wakes once per second, while buckets close only every
        // five minutes. A no-op tick must stay O(1): scanning the grant and
        // outbox prefixes walks the whole RocksDB keyspace in SableDB even when
        // MATCH returns nothing. On a large realm those two unnecessary scans
        // can consume a full core and periodically delay unrelated point reads.
        if events.is_empty()
            && stored_cursor.is_some()
            && stored_closure_cursor == Some(latest_closable)
        {
            return Ok(result);
        }

        let mut touched = BTreeMap::<u64, LocalMetricBucket>::new();
        for event in &events {
            let start = aligned_bucket_start(event.occurred_at);
            if let std::collections::btree_map::Entry::Vacant(slot) = touched.entry(start) {
                let record = self
                    .get_json::<LocalMetricBucket>(&bucket_key(start))
                    .await?
                    .unwrap_or_else(|| LocalMetricBucket::new(start));
                slot.insert(record);
            }
            let bucket = touched.get_mut(&start).expect("bucket was inserted");
            let was_closed = bucket.closed;
            if bucket.apply(event) {
                result.events_contributed += 1;
                if was_closed {
                    bucket.revision = bucket.revision.saturating_add(1).max(2);
                }
            }
        }

        let mut closure_cursor = stored_closure_cursor
            .unwrap_or_else(|| latest_closable.saturating_sub(u64::from(BUCKET_WIDTH_SECONDS_V1)));
        for _ in 0..MAX_PROJECTION_BATCH {
            let candidate = closure_cursor.saturating_add(u64::from(BUCKET_WIDTH_SECONDS_V1));
            if candidate > latest_closable {
                break;
            }
            if !touched.contains_key(&candidate)
                && let Some(record) = self
                    .get_json::<LocalMetricBucket>(&bucket_key(candidate))
                    .await?
            {
                touched.insert(candidate, record);
            }
            closure_cursor = candidate;
        }
        for bucket in touched.values_mut() {
            if bucket
                .bucket_start
                .saturating_add(u64::from(BUCKET_WIDTH_SECONDS_V1))
                <= closure_before
            {
                bucket.closed = true;
            }
        }

        let mut pipeline = redis::pipe();
        pipeline.atomic();
        let has_closed_bucket = touched.values().any(|bucket| bucket.closed);
        // Assignment and outbox state affect only a closed bucket's export.
        // Open-bucket projection therefore remains proportional to the small
        // event batch instead of performing two full-keyspace prefix scans.
        let assignment_epoch = if has_closed_bucket {
            self.realm_telemetry_export_grants()
                .await?
                .first()
                .map(|grant| grant.assignment_epoch)
                .unwrap_or(1)
        } else {
            1
        };
        let existing_outbox = if has_closed_bucket {
            self.telemetry_outbox_keys().await?
        } else {
            Vec::new()
        };
        let mut retained_outbox = existing_outbox.iter().cloned().collect::<BTreeSet<_>>();
        for bucket in touched.values() {
            pipeline
                .set(
                    bucket_key(bucket.bucket_start),
                    serde_json::to_string(bucket)?,
                )
                .ignore();
            result.buckets_written += 1;
            if bucket.closed {
                let outbox_key = outbox_key(bucket.bucket_start, bucket.revision);
                let exists: bool = self.get::<String>(&outbox_key).await?.is_some();
                if !exists {
                    let batch_id = Uuid::new_v4();
                    let batch = TelemetryBucketBatch {
                        transport_schema_version: TRANSPORT_SCHEMA_VERSION_V1,
                        batch_id: batch_id.to_string(),
                        realm_id: realm_id.to_owned(),
                        buckets: vec![bucket.to_telemetry_bucket(realm_id, assignment_epoch)],
                        ..Default::default()
                    };
                    validate_batch(&batch).context("validate projected telemetry batch")?;
                    let record = TelemetryOutboxRecord {
                        bucket_start: bucket.bucket_start,
                        revision: bucket.revision,
                        batch_id,
                        payload_base64url: URL_SAFE_NO_PAD.encode(batch.encode_to_vec()),
                        first_queued_at: now(),
                        attempts: 0,
                        next_attempt_at: 0,
                    };
                    // A correction supersedes the older full snapshot locally.
                    // If an acknowledgement for that older revision arrives
                    // later, its exact key can no longer delete this record.
                    for prior in existing_outbox.iter().filter(|key| {
                        key.starts_with(&format!("{OUTBOX_PREFIX}{:020}:", bucket.bucket_start))
                            && **key != outbox_key
                    }) {
                        pipeline.del(prior).ignore();
                        retained_outbox.remove(prior);
                    }
                    pipeline
                        .set(&outbox_key, serde_json::to_string(&record)?)
                        .ignore();
                    retained_outbox.insert(outbox_key);
                    result.outbox_records_written += 1;
                }
            }
        }
        // One record is one complete five-minute snapshot. Retaining exactly
        // 288 therefore proves a 24-hour disconnect without unbounded growth.
        for oldest in outbox_keys_to_trim(&retained_outbox) {
            pipeline.del(oldest).ignore();
        }
        if let Some(last) = events.last() {
            pipeline.set(PROJECTOR_CURSOR_KEY, last.sequence).ignore();
        } else if stored_cursor.is_none() {
            pipeline.set(PROJECTOR_CURSOR_KEY, cursor).ignore();
        }
        if stored_closure_cursor != Some(closure_cursor) {
            pipeline.set(CLOSURE_CURSOR_KEY, closure_cursor).ignore();
        }
        if result.buckets_written > 0
            || !events.is_empty()
            || stored_cursor.is_none()
            || stored_closure_cursor != Some(closure_cursor)
        {
            let mut connection = self.redis.clone();
            let _: () = pipeline
                .query_async(&mut connection)
                .await
                .context("commit analytics projection")?;
        }
        Ok(result)
    }

    pub async fn analytics_buckets(
        &self,
        starts_at: u64,
        ends_at: u64,
    ) -> Result<Vec<LocalMetricBucket>> {
        if ends_at <= starts_at {
            return Ok(Vec::new());
        }
        let first = aligned_bucket_start(starts_at);
        let last = aligned_bucket_start(ends_at.saturating_sub(1));
        let keys = (first..=last)
            .step_by(BUCKET_WIDTH_SECONDS_V1 as usize)
            .map(bucket_key)
            .collect::<Vec<_>>();
        if keys.len() > 8_064 {
            bail!("analytics query exceeds the 28-day five-minute bucket limit");
        }
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut connection = self.redis.clone();
        let values: Vec<Option<String>> = redis::cmd("MGET")
            .arg(keys)
            .query_async(&mut connection)
            .await
            .context("read local metric buckets")?;
        let mut buckets = values
            .into_iter()
            .flatten()
            .map(|value| {
                serde_json::from_str::<LocalMetricBucket>(&value)
                    .context("decode local metric bucket")
            })
            .collect::<Result<Vec<_>>>()?;
        for bucket in &mut buckets {
            bucket.normalize();
        }
        buckets.sort_unstable_by_key(|bucket| bucket.bucket_start);
        Ok(buckets)
    }

    pub async fn telemetry_outbox(&self, limit: usize) -> Result<Vec<TelemetryOutboxRecord>> {
        let keys = self.telemetry_outbox_keys().await?;
        let mut records = Vec::new();
        for key in keys.into_iter().take(limit.min(MAX_OUTBOX_RECORDS)) {
            if let Some(record) = self.get_json::<TelemetryOutboxRecord>(&key).await? {
                records.push(record);
            }
        }
        records.sort_unstable_by_key(|record| (record.bucket_start, record.revision));
        Ok(records)
    }

    async fn telemetry_outbox_keys(&self) -> Result<Vec<String>> {
        let mut cursor = 0_u64;
        let mut keys = BTreeSet::new();
        loop {
            let mut connection = self.redis.clone();
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{OUTBOX_PREFIX}*"))
                .arg("COUNT")
                .arg(500_u16)
                .query_async(&mut connection)
                .await
                .context("scan telemetry outbox")?;
            keys.extend(batch);
            if next == 0 {
                break;
            }
            cursor = next;
        }
        Ok(keys.into_iter().collect())
    }

    pub async fn defer_telemetry_bucket(
        &self,
        bucket_start: u64,
        revision: u64,
        next_attempt_at: u64,
    ) -> Result<bool> {
        let key = outbox_key(bucket_start, revision);
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let Some(mut record) = self.get_json::<TelemetryOutboxRecord>(&key).await? else {
            return Ok(false);
        };
        record.attempts = record.attempts.saturating_add(1);
        record.next_attempt_at = next_attempt_at;
        let mut connection = self.redis.clone();
        let _: () = connection
            .set(key, serde_json::to_string(&record)?)
            .await
            .context("defer telemetry outbox record")?;
        Ok(true)
    }

    /// Deletes only the exact acknowledged revision; newer corrections survive.
    pub async fn acknowledge_telemetry_bucket(
        &self,
        bucket_start: u64,
        revision: u64,
    ) -> Result<bool> {
        let key = outbox_key(bucket_start, revision);
        let mut connection = self.redis.clone();
        let removed: usize = connection
            .del(key)
            .await
            .context("acknowledge telemetry bucket")?;
        Ok(removed == 1)
    }
}

fn aligned_bucket_start(timestamp: u64) -> u64 {
    timestamp - timestamp % u64::from(BUCKET_WIDTH_SECONDS_V1)
}

fn bucket_key(start: u64) -> String {
    format!("{BUCKET_PREFIX}{start:020}")
}

fn outbox_key(start: u64, revision: u64) -> String {
    format!("{OUTBOX_PREFIX}{start:020}:{revision:020}")
}

fn outbox_keys_to_trim(keys: &BTreeSet<String>) -> Vec<&str> {
    keys.iter()
        .take(keys.len().saturating_sub(MAX_OUTBOX_RECORDS))
        .map(String::as_str)
        .collect()
}

fn increment(value: &mut u64) {
    *value = value.saturating_add(1);
}

fn failure_class(index: usize) -> FailureClass {
    match index {
        0 => FailureClass::InvalidCredential,
        1 => FailureClass::ChallengeExpired,
        2 => FailureClass::OriginRejected,
        3 => FailureClass::PolicyDenied,
        4 => FailureClass::RateLimited,
        5 => FailureClass::StoreUnavailable,
        6 => FailureClass::UpstreamUnavailable,
        7 => FailureClass::Internal,
        _ => FailureClass::Other,
    }
}

fn event_observes_active_account(event_type: &str) -> bool {
    event_type.starts_with("authentication.")
        || event_type.starts_with("registration.")
        || event_type.starts_with("session.")
        || event_type == "token.user.issued"
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn event(sequence: u64, event_type: &str, data: serde_json::Value) -> AuthEvent {
        AuthEvent {
            sequence,
            id: Uuid::new_v4(),
            tenant_id: "realm".into(),
            event_type: event_type.into(),
            subject: Some(Uuid::nil()),
            occurred_at: 1_722_000_001,
            data,
        }
    }

    #[test]
    fn aggregation_uses_bounded_failure_classes_and_cumulative_histograms() {
        let mut bucket = LocalMetricBucket::new(aligned_bucket_start(1_722_000_001));
        assert!(bucket.apply(&event(1, "authentication.options.started", json!({}))));
        assert!(bucket.apply(&event(
            2,
            "authentication.failed",
            json!({ "outcomeClass": "invalidCredential", "latencyMilliseconds": 42 })
        )));
        assert_eq!(bucket.authentication_options_started, 1);
        assert_eq!(bucket.authentication_attempts, 1);
        assert_eq!(bucket.authentication_failures, 1);
        assert_eq!(bucket.authentication_failure_classes[0], 1);
        assert_eq!(bucket.authentication_latency_count, 1);
        assert_eq!(
            bucket.authentication_latency_cumulative_counts.last(),
            Some(&1)
        );
        assert_eq!(bucket.authentication_latency_p95_upper_bound(), Some(50));
        assert_eq!(bucket.active_subjects.len(), 1);
    }

    #[test]
    fn wire_bucket_contains_counts_but_never_subject_ids() {
        let mut bucket = LocalMetricBucket::new(aligned_bucket_start(1_722_000_001));
        bucket.apply(&event(
            1,
            "authentication.completed",
            json!({ "latencyMilliseconds": 0 }),
        ));
        bucket.closed = true;
        let encoded = bucket.to_telemetry_bucket("realm-id", 7).encode_to_vec();
        assert!(
            !encoded
                .windows(36)
                .any(|window| window == Uuid::nil().to_string().as_bytes())
        );
        assert!(bucket.to_telemetry_bucket("realm-id", 7).closed);
        validate_batch(&TelemetryBucketBatch {
            transport_schema_version: TRANSPORT_SCHEMA_VERSION_V1,
            batch_id: Uuid::new_v4().to_string(),
            realm_id: "realm-id".into(),
            buckets: vec![bucket.to_telemetry_bucket("realm-id", 7)],
            ..Default::default()
        })
        .unwrap();
    }

    #[test]
    fn aggregated_token_telemetry_preserves_counts_and_active_accounts() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut aggregate = event(
            1,
            "token.user.issued",
            json!({
                "count": 17,
                "subjectIds": [first, second, first],
            }),
        );
        aggregate.subject = None;
        let mut bucket = LocalMetricBucket::new(aligned_bucket_start(1_722_000_001));

        assert!(bucket.apply(&aggregate));
        assert_eq!(bucket.user_tokens_issued, 17);
        assert_eq!(bucket.active_subjects, BTreeSet::from([first, second]));

        let encoded = bucket.to_telemetry_bucket("realm-id", 7).encode_to_vec();
        assert!(!encoded.windows(36).any(|window| {
            window == first.to_string().as_bytes() || window == second.to_string().as_bytes()
        }));
    }

    #[test]
    fn service_account_and_webhook_families_preserve_outcomes_without_user_cardinality() {
        let mut bucket = LocalMetricBucket::new(aligned_bucket_start(1_722_000_001));
        assert!(bucket.apply(&event(1, "service_account.credential.created", json!({}))));
        assert!(bucket.apply(&event(2, "service_account.token.issued", json!({}))));
        assert!(bucket.apply(&event(
            3,
            "analytics.webhook.delivery.queued",
            json!({ "backlog": 1 })
        )));
        assert!(bucket.apply(&event(
            4,
            "analytics.webhook.delivery.succeeded",
            json!({ "latencyMilliseconds": 42, "backlog": 0 })
        )));
        assert!(bucket.active_subjects.is_empty());
        bucket.closed = true;

        let wire = bucket.to_telemetry_bucket("realm-id", 7);
        let service_accounts = wire.service_accounts.as_option().unwrap();
        assert_eq!(service_accounts.calls, 1);
        assert_eq!(service_accounts.successes, 1);
        assert_eq!(service_accounts.credential_rotations, 1);
        let webhooks = wire.webhooks.as_option().unwrap();
        assert_eq!(webhooks.deliveries, 1);
        assert_eq!(webhooks.successes, 1);
        assert_eq!(webhooks.backlog, 0);
        assert_eq!(webhooks.latency.as_option().unwrap().count, 1);
        validate_batch(&TelemetryBucketBatch {
            transport_schema_version: TRANSPORT_SCHEMA_VERSION_V1,
            batch_id: Uuid::new_v4().to_string(),
            realm_id: "realm-id".into(),
            buckets: vec![wire],
            ..Default::default()
        })
        .unwrap();
    }

    #[test]
    fn keys_are_lexically_ordered_by_bucket_and_revision() {
        assert!(bucket_key(300) < bucket_key(600));
        assert!(outbox_key(300, 1) < outbox_key(300, 2));
    }

    #[test]
    fn queue_pressure_keeps_exactly_the_newest_24_hours() {
        let keys = (0_u64..=MAX_OUTBOX_RECORDS as u64)
            .map(|index| outbox_key(index * u64::from(BUCKET_WIDTH_SECONDS_V1), 1))
            .collect::<BTreeSet<_>>();
        let trimmed = outbox_keys_to_trim(&keys);
        assert_eq!(trimmed, vec![outbox_key(0, 1)]);
        assert_eq!(keys.len().saturating_sub(trimmed.len()), 288);
    }
}
