//! Bounded standalone operational metrics backed by durable five-minute buckets.

use std::collections::{BTreeMap, BTreeSet};

use buffa::Enumeration;
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    analytics::{BUCKET_WIDTH_SECONDS_V1, INTERACTIVE_LATENCY_BOUNDS_MILLISECONDS_V1},
    backup::BackupStore,
    proto::rustyauth::metrics::v1::{
        AuthenticationFunnel, FailureBreakdown, FailureCount, GetAuthenticationFunnelRequest,
        GetFailureBreakdownRequest, GetOverviewRequest, Granularity, Metric, MetricPoint,
        MetricSeries, MetricsOverview, MetricsService, QuerySeriesRequest,
    },
    store::{LocalMetricBucket, Store, WebhookDeliveryStatusRecord, now},
};

const MAX_QUERY_SECONDS: u64 = 28 * 24 * 60 * 60;
const MAX_FUTURE_SKEW_SECONDS: u64 = 5 * 60;

pub(crate) struct MetricsRpc {
    store: Store,
    backup: Option<BackupStore>,
}

impl MetricsRpc {
    pub(crate) fn new(store: Store, backup: Option<BackupStore>) -> Self {
        Self { store, backup }
    }

    pub(crate) async fn overview(
        &self,
        starts_at: &str,
        ends_at: &str,
    ) -> Result<MetricsOverview, ConnectError> {
        let range = validated_range(starts_at, ends_at)?;
        let buckets = self
            .store
            .analytics_buckets(range.starts_at, range.ends_at)
            .await
            .map_err(source_error)?;
        let counts = self
            .store
            .realm_summary_counts()
            .await
            .map_err(source_error)?;
        let service_accounts = self.store.service_accounts().await.map_err(source_error)?;
        let active_service_accounts = service_accounts
            .iter()
            .filter(|account| account.status.is_active())
            .count() as u64;
        let mut active_users = BTreeSet::new();
        let mut registrations = 0_u64;
        let mut attempts = 0_u64;
        let mut successes = 0_u64;
        let mut latency = HistogramAggregate::default();
        for bucket in &buckets {
            active_users.extend(bucket.active_subjects.iter().copied());
            registrations = registrations.saturating_add(bucket.registrations_completed);
            attempts = attempts.saturating_add(bucket.authentication_attempts);
            successes = successes.saturating_add(bucket.authentication_successes);
            latency.add_bucket(bucket);
        }
        let deliveries = self
            .store
            .webhook_deliveries()
            .await
            .map_err(source_error)?;
        let mut webhook_completed = 0_u64;
        let mut webhook_succeeded = 0_u64;
        let mut webhook_backlog = 0_u64;
        for delivery in deliveries {
            match delivery.status {
                WebhookDeliveryStatusRecord::Pending | WebhookDeliveryStatusRecord::Retrying => {
                    webhook_backlog = webhook_backlog.saturating_add(1);
                }
                WebhookDeliveryStatusRecord::Succeeded | WebhookDeliveryStatusRecord::Failed
                    if delivery.created_at >= range.starts_at
                        && delivery.created_at < range.ends_at =>
                {
                    webhook_completed = webhook_completed.saturating_add(1);
                    if delivery.status == WebhookDeliveryStatusRecord::Succeeded {
                        webhook_succeeded = webhook_succeeded.saturating_add(1);
                    }
                }
                _ => {}
            }
        }
        let (last_backup_at, backup_healthy) = match &self.backup {
            Some(backup) => {
                let status = backup
                    .persisted_status(&self.store)
                    .await
                    .map_err(source_error)?;
                (
                    status
                        .last_success_at
                        .map(format_timestamp)
                        .transpose()?
                        .unwrap_or_default(),
                    status.last_success_at.is_some() && !status.alerting && !status.overdue,
                )
            }
            None => (String::new(), false),
        };
        Ok(MetricsOverview {
            total_users: counts.users,
            active_users: active_users.len() as u64,
            registrations,
            authentication_attempts: attempts,
            authentication_success_rate: ratio(successes, attempts),
            authentication_latency_p95_milliseconds: latency.p95().unwrap_or(0) as f64,
            active_service_accounts,
            webhook_delivery_success_rate: ratio(webhook_succeeded, webhook_completed),
            webhook_delivery_backlog: webhook_backlog,
            last_backup_at,
            backup_healthy,
            ..Default::default()
        })
    }
}

#[allow(refining_impl_trait)]
impl MetricsService for MetricsRpc {
    async fn get_overview(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetOverviewRequest>,
    ) -> ServiceResult<MetricsOverview> {
        let range = request
            .range
            .as_option()
            .ok_or_else(|| invalid_argument("range is required"))?;
        Response::ok(self.overview(range.starts_at, range.ends_at).await?)
    }

    async fn query_series(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, QuerySeriesRequest>,
    ) -> ServiceResult<MetricSeries> {
        if !request.filters.is_empty() {
            return Err(invalid_argument(
                "filters are not defined for the local V1 metrics service",
            ));
        }
        let metric = parsed_metric(request.metric.to_i32())?;
        let range = request
            .range
            .as_option()
            .ok_or_else(|| invalid_argument("range is required"))?;
        let range = validated_range(range.starts_at, range.ends_at)?;
        let width = granularity_seconds(request.granularity.to_i32())?;
        let buckets = self
            .store
            .analytics_buckets(range.starts_at, range.ends_at)
            .await
            .map_err(source_error)?;
        let mut groups = BTreeMap::<u64, SeriesAggregate>::new();
        let mut point_start = align(range.starts_at, width);
        while point_start < range.ends_at {
            groups.insert(point_start, SeriesAggregate::default());
            point_start = point_start.saturating_add(width);
        }
        for bucket in &buckets {
            groups
                .entry(align(bucket.bucket_start, width))
                .or_default()
                .add_bucket(bucket);
        }
        if matches!(
            metric,
            Metric::WebhookDeliveries
                | Metric::WebhookFailures
                | Metric::WebhookLatencyMilliseconds
        ) {
            for delivery in self
                .store
                .webhook_deliveries()
                .await
                .map_err(source_error)?
                .into_iter()
                .filter(|delivery| {
                    delivery.created_at >= range.starts_at && delivery.created_at < range.ends_at
                })
            {
                groups
                    .entry(align(delivery.created_at, width))
                    .or_default()
                    .add_webhook_delivery(delivery.status, delivery.latency_milliseconds);
            }
        }
        let points = groups
            .into_iter()
            .filter(|(start, _)| *start < range.ends_at)
            .map(|(start, aggregate)| {
                Ok(MetricPoint {
                    starts_at: format_timestamp(start)?,
                    value: aggregate.value(metric),
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>, ConnectError>>()?;
        Response::ok(MetricSeries {
            metric: metric.into(),
            points,
            ..Default::default()
        })
    }

    async fn get_authentication_funnel(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetAuthenticationFunnelRequest>,
    ) -> ServiceResult<AuthenticationFunnel> {
        let range = request
            .range
            .as_option()
            .ok_or_else(|| invalid_argument("range is required"))?;
        let range = validated_range(range.starts_at, range.ends_at)?;
        let buckets = self
            .store
            .analytics_buckets(range.starts_at, range.ends_at)
            .await
            .map_err(source_error)?;
        let mut response = AuthenticationFunnel::default();
        for bucket in buckets {
            response.registration_options_started = response
                .registration_options_started
                .saturating_add(bucket.registration_options_started);
            response.registrations_completed = response
                .registrations_completed
                .saturating_add(bucket.registrations_completed);
            response.authentication_options_started = response
                .authentication_options_started
                .saturating_add(bucket.authentication_options_started);
            response.authentications_completed = response
                .authentications_completed
                .saturating_add(bucket.authentication_successes);
            response.challenges_expired = response
                .challenges_expired
                .saturating_add(bucket.registration_challenges_expired);
        }
        Response::ok(response)
    }

    async fn get_failure_breakdown(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetFailureBreakdownRequest>,
    ) -> ServiceResult<FailureBreakdown> {
        let range = request
            .range
            .as_option()
            .ok_or_else(|| invalid_argument("range is required"))?;
        let range = validated_range(range.starts_at, range.ends_at)?;
        let buckets = self
            .store
            .analytics_buckets(range.starts_at, range.ends_at)
            .await
            .map_err(source_error)?;
        let mut failures = vec![0_u64; FAILURE_NAMES.len()];
        for bucket in buckets {
            for (total, count) in failures
                .iter_mut()
                .zip(bucket.authentication_failure_classes)
            {
                *total = total.saturating_add(count);
            }
        }
        Response::ok(FailureBreakdown {
            failures: FAILURE_NAMES
                .into_iter()
                .zip(failures)
                .filter(|(_, count)| *count > 0)
                .map(|(error_class, count)| FailureCount {
                    error_class: error_class.into(),
                    count,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }
}

trait ActiveStatus {
    fn is_active(&self) -> bool;
}

impl ActiveStatus for crate::store::ServiceAccountStatusRecord {
    fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy)]
struct QueryRange {
    starts_at: u64,
    ends_at: u64,
}

fn validated_range(starts_at: &str, ends_at: &str) -> Result<QueryRange, ConnectError> {
    let starts_at = parse_timestamp(starts_at, "range.starts_at")?;
    let ends_at = parse_timestamp(ends_at, "range.ends_at")?;
    if ends_at <= starts_at {
        return Err(invalid_argument(
            "range.ends_at must be after range.starts_at",
        ));
    }
    if ends_at.saturating_sub(starts_at) > MAX_QUERY_SECONDS {
        return Err(invalid_argument("range must not exceed 28 days"));
    }
    if ends_at > now().saturating_add(MAX_FUTURE_SKEW_SECONDS) {
        return Err(invalid_argument("range.ends_at is too far in the future"));
    }
    Ok(QueryRange { starts_at, ends_at })
}

fn parse_timestamp(value: &str, field: &str) -> Result<u64, ConnectError> {
    let timestamp = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| invalid_argument(format!("{field} must be an RFC 3339 timestamp")))?
        .unix_timestamp();
    u64::try_from(timestamp).map_err(|_| invalid_argument(format!("{field} must be after 1970")))
}

fn format_timestamp(value: u64) -> Result<String, ConnectError> {
    let timestamp = i64::try_from(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "metric timestamp is invalid"))?;
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "metric timestamp is invalid"))?
        .format(&Rfc3339)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "format metric timestamp"))
}

fn parsed_metric(value: i32) -> Result<Metric, ConnectError> {
    Metric::from_i32(value)
        .filter(|metric| *metric != Metric::Unspecified)
        .ok_or_else(|| invalid_argument("metric is required and must be recognized"))
}

fn granularity_seconds(value: i32) -> Result<u64, ConnectError> {
    match Granularity::from_i32(value) {
        Some(Granularity::FiveMinutes) => Ok(u64::from(BUCKET_WIDTH_SECONDS_V1)),
        Some(Granularity::Hour) => Ok(Duration::HOUR.whole_seconds() as u64),
        Some(Granularity::Day) => Ok(Duration::DAY.whole_seconds() as u64),
        _ => Err(invalid_argument(
            "granularity must be FIVE_MINUTES, HOUR, or DAY",
        )),
    }
}

fn align(timestamp: u64, width: u64) -> u64 {
    timestamp - timestamp % width
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn invalid_argument(message: impl Into<String>) -> ConnectError {
    ConnectError::new(ErrorCode::InvalidArgument, message)
}

fn source_error(error: anyhow::Error) -> ConnectError {
    tracing::error!(error = %error, "metrics source failed");
    ConnectError::new(
        ErrorCode::Unavailable,
        "metrics are temporarily unavailable",
    )
}

#[derive(Default)]
struct HistogramAggregate {
    count: u64,
    cumulative: Vec<u64>,
}

impl HistogramAggregate {
    fn add_bucket(&mut self, bucket: &LocalMetricBucket) {
        self.count = self
            .count
            .saturating_add(bucket.authentication_latency_count);
        self.cumulative
            .resize(INTERACTIVE_LATENCY_BOUNDS_MILLISECONDS_V1.len() + 1, 0);
        for (total, count) in self
            .cumulative
            .iter_mut()
            .zip(&bucket.authentication_latency_cumulative_counts)
        {
            *total = total.saturating_add(*count);
        }
    }

    fn p95(&self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let rank = self.count.saturating_mul(95).div_ceil(100);
        INTERACTIVE_LATENCY_BOUNDS_MILLISECONDS_V1
            .iter()
            .zip(&self.cumulative)
            .find_map(|(upper, count)| (*count >= rank).then_some(*upper))
    }
}

#[derive(Default)]
struct SeriesAggregate {
    authentication_attempts: u64,
    authentication_successes: u64,
    authentication_failures: u64,
    registrations: u64,
    sessions_created: u64,
    tokens_issued: u64,
    service_account_calls: u64,
    service_account_denials: u64,
    webhook_deliveries: u64,
    webhook_failures: u64,
    webhook_latencies: Vec<u64>,
    active_users: BTreeSet<Uuid>,
    latency: HistogramAggregate,
}

impl SeriesAggregate {
    fn add_bucket(&mut self, bucket: &LocalMetricBucket) {
        self.authentication_attempts = self
            .authentication_attempts
            .saturating_add(bucket.authentication_attempts);
        self.authentication_successes = self
            .authentication_successes
            .saturating_add(bucket.authentication_successes);
        self.authentication_failures = self
            .authentication_failures
            .saturating_add(bucket.authentication_failures);
        self.registrations = self
            .registrations
            .saturating_add(bucket.registrations_completed);
        self.sessions_created = self
            .sessions_created
            .saturating_add(bucket.sessions_created);
        self.tokens_issued = self
            .tokens_issued
            .saturating_add(bucket.user_tokens_issued)
            .saturating_add(bucket.service_tokens_issued);
        self.active_users
            .extend(bucket.active_subjects.iter().copied());
        self.latency.add_bucket(bucket);
    }

    fn add_webhook_delivery(&mut self, status: WebhookDeliveryStatusRecord, latency: u64) {
        self.webhook_deliveries = self.webhook_deliveries.saturating_add(1);
        if status == WebhookDeliveryStatusRecord::Failed {
            self.webhook_failures = self.webhook_failures.saturating_add(1);
        }
        if matches!(
            status,
            WebhookDeliveryStatusRecord::Succeeded | WebhookDeliveryStatusRecord::Failed
        ) {
            self.webhook_latencies.push(latency);
        }
    }

    fn value(mut self, metric: Metric) -> f64 {
        match metric {
            Metric::AuthenticationAttempts => self.authentication_attempts as f64,
            Metric::AuthenticationSuccesses => self.authentication_successes as f64,
            Metric::AuthenticationFailures => self.authentication_failures as f64,
            Metric::AuthenticationLatencyMilliseconds => self.latency.p95().unwrap_or(0) as f64,
            Metric::Registrations => self.registrations as f64,
            Metric::ActiveUsers => self.active_users.len() as f64,
            Metric::SessionsCreated => self.sessions_created as f64,
            Metric::TokensIssued => self.tokens_issued as f64,
            Metric::ServiceAccountRpcCalls => self.service_account_calls as f64,
            Metric::ServiceAccountDenials => self.service_account_denials as f64,
            Metric::WebhookDeliveries => self.webhook_deliveries as f64,
            Metric::WebhookFailures => self.webhook_failures as f64,
            Metric::WebhookLatencyMilliseconds => {
                if self.webhook_latencies.is_empty() {
                    0.0
                } else {
                    self.webhook_latencies.sort_unstable();
                    let rank = self
                        .webhook_latencies
                        .len()
                        .saturating_mul(95)
                        .div_ceil(100);
                    self.webhook_latencies[rank.saturating_sub(1)] as f64
                }
            }
            Metric::SabledbLatencyMilliseconds | Metric::ApiErrors | Metric::Unspecified => 0.0,
        }
    }
}

const FAILURE_NAMES: [&str; 9] = [
    "invalidCredential",
    "challengeExpired",
    "originRejected",
    "policyDenied",
    "rateLimited",
    "storeUnavailable",
    "upstreamUnavailable",
    "internal",
    "other",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::rustyauth::metrics::v1::TimeRange;

    #[test]
    fn range_is_bounded_and_ordered() {
        let now = OffsetDateTime::now_utc();
        let range = TimeRange {
            starts_at: (now - Duration::DAY).format(&Rfc3339).unwrap(),
            ends_at: now.format(&Rfc3339).unwrap(),
            ..Default::default()
        };
        let parsed = validated_range(&range.starts_at, &range.ends_at).unwrap();
        assert!(parsed.ends_at > parsed.starts_at);
    }

    #[test]
    fn merged_histogram_percentile_uses_combined_counts() {
        let mut aggregate = HistogramAggregate::default();
        let first = LocalMetricBucket {
            authentication_latency_count: 100,
            authentication_latency_cumulative_counts: vec![
                0, 0, 0, 95, 100, 100, 100, 100, 100, 100, 100, 100,
            ],
            ..LocalMetricBucket::default()
        };
        aggregate.add_bucket(&first);
        assert_eq!(aggregate.p95(), Some(50));
    }
}
