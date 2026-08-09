//! Bounded, hierarchy-authorized Fleet Analytics product API.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

use buffa::{Enumeration, MessageView};
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use uuid::Uuid;

use crate::{
    analytics::aggregate_authentication,
    analytics_store::GreptimeAnalyticsStore,
    operator_auth::{OperatorAuthorizer, OperatorCapability},
    proto::rustyauth::analytics::v1::*,
    store::{
        FleetAnalyticsMaintenanceActionRecord, FleetAnalyticsMaintenanceAuditRecord,
        FleetAnalyticsMaintenanceOutcomeRecord, FleetAnalyticsPolicyRecord,
        FleetAnalyticsResidencyRecord, FleetConnectionRecord, FleetConnectionStateRecord,
        FleetResourceKindRecord, FleetTelemetryBucketRecord, Store, now,
    },
};

const MAX_RANGE_MILLISECONDS: i64 = 28 * 86_400 * 1_000;
const MAX_FUTURE_SKEW_MILLISECONDS: i64 = 5 * 60 * 1_000;
const MAX_COMPARISON_SCOPES: usize = 8;
const TELEMETRY_CAPABILITY: &str = "telemetry.rollups.v1";

pub(crate) struct AnalyticsRpc {
    store: Store,
    authorizer: OperatorAuthorizer,
    analytics: Option<GreptimeAnalyticsStore>,
}

impl AnalyticsRpc {
    pub(crate) fn new(
        store: Store,
        authorizer: OperatorAuthorizer,
        analytics: Option<GreptimeAnalyticsStore>,
    ) -> Self {
        Self {
            store,
            authorizer,
            analytics,
        }
    }

    async fn resolve_scope(
        &self,
        headers: &http::HeaderMap,
        scope: AnalyticsScope,
    ) -> Result<ResolvedScope, ConnectError> {
        match scope.kind.as_known() {
            Some(AnalyticsScopeKind::Fleet) => {
                require_empty_scope_ids(&scope)?;
                self.authorizer
                    .authorize(headers, OperatorCapability::Read)
                    .await?;
                Ok(ResolvedScope::fleet(scope))
            }
            Some(AnalyticsScopeKind::Organization) => {
                let organization_id = scope_uuid(&scope.organization_id, "organization_id")?;
                if !scope.project_id.is_empty()
                    || !scope.environment_id.is_empty()
                    || !scope.connection_id.is_empty()
                {
                    return Err(invalid("organization scope contains child identifiers"));
                }
                self.authorizer
                    .authorize_fleet(
                        headers,
                        OperatorCapability::Read,
                        FleetResourceKindRecord::Organization,
                        organization_id,
                    )
                    .await?;
                Ok(ResolvedScope {
                    proto: scope,
                    organization_id: Some(organization_id),
                    project_id: None,
                    environment_id: None,
                    connection_id: None,
                    realm_id: None,
                })
            }
            Some(AnalyticsScopeKind::Project) => {
                let organization_id = scope_uuid(&scope.organization_id, "organization_id")?;
                let project_id = scope_uuid(&scope.project_id, "project_id")?;
                if !scope.environment_id.is_empty() || !scope.connection_id.is_empty() {
                    return Err(invalid("project scope contains child identifiers"));
                }
                self.authorizer
                    .authorize_fleet(
                        headers,
                        OperatorCapability::Read,
                        FleetResourceKindRecord::Project,
                        project_id,
                    )
                    .await?;
                let project = self
                    .store
                    .fleet_project(project_id)
                    .await
                    .map_err(source)?
                    .filter(|record| record.organization_id == organization_id)
                    .ok_or_else(scope_not_found)?;
                Ok(ResolvedScope {
                    proto: scope,
                    organization_id: Some(project.organization_id),
                    project_id: Some(project.id),
                    environment_id: None,
                    connection_id: None,
                    realm_id: None,
                })
            }
            Some(AnalyticsScopeKind::Environment) => {
                let organization_id = scope_uuid(&scope.organization_id, "organization_id")?;
                let project_id = scope_uuid(&scope.project_id, "project_id")?;
                let environment_id = scope_uuid(&scope.environment_id, "environment_id")?;
                if !scope.connection_id.is_empty() {
                    return Err(invalid(
                        "environment scope contains a connection identifier",
                    ));
                }
                self.authorizer
                    .authorize_fleet(
                        headers,
                        OperatorCapability::Read,
                        FleetResourceKindRecord::Environment,
                        environment_id,
                    )
                    .await?;
                let environment = self
                    .store
                    .fleet_environment(environment_id)
                    .await
                    .map_err(source)?
                    .filter(|record| {
                        record.organization_id == organization_id && record.project_id == project_id
                    })
                    .ok_or_else(scope_not_found)?;
                Ok(ResolvedScope {
                    proto: scope,
                    organization_id: Some(environment.organization_id),
                    project_id: Some(environment.project_id),
                    environment_id: Some(environment.id),
                    connection_id: None,
                    realm_id: None,
                })
            }
            Some(AnalyticsScopeKind::Realm) => {
                let organization_id = scope_uuid(&scope.organization_id, "organization_id")?;
                let project_id = scope_uuid(&scope.project_id, "project_id")?;
                let environment_id = scope_uuid(&scope.environment_id, "environment_id")?;
                let connection_id = scope_uuid(&scope.connection_id, "connection_id")?;
                self.authorizer
                    .authorize_fleet(
                        headers,
                        OperatorCapability::Read,
                        FleetResourceKindRecord::Environment,
                        environment_id,
                    )
                    .await?;
                let connection = self
                    .store
                    .fleet_connection(connection_id)
                    .await
                    .map_err(source)?
                    .filter(|record| {
                        record.organization_id == organization_id
                            && record.project_id == project_id
                            && record.environment_id == environment_id
                    })
                    .ok_or_else(scope_not_found)?;
                Ok(ResolvedScope {
                    proto: scope,
                    organization_id: Some(connection.organization_id),
                    project_id: Some(connection.project_id),
                    environment_id: Some(connection.environment_id),
                    connection_id: Some(connection.id),
                    realm_id: Some(connection.realm_id),
                })
            }
            Some(AnalyticsScopeKind::Unspecified) | None => Err(invalid(
                "analytics scope kind is required and must be known",
            )),
        }
    }

    async fn data(
        &self,
        scope: ResolvedScope,
        range: EffectiveRange,
    ) -> Result<AnalyticsData, ConnectError> {
        let started = Instant::now();
        let scope_kind = analytics_scope_kind_label(scope.proto.kind.as_known());
        let (records, source_name) = if let Some(analytics) = &self.analytics {
            (
                analytics
                    .query_rollups(
                        scope.organization_id,
                        scope.project_id,
                        scope.environment_id,
                        scope.connection_id,
                        scope.realm_id.as_deref(),
                        range.starts_at,
                        range.ends_at,
                        range.step,
                    )
                    .await
                    .map_err(source)?,
                "canonical-greptimedb",
            )
        } else {
            (
                self.store
                    .fleet_telemetry_buckets(
                        scope.organization_id,
                        scope.project_id,
                        scope.environment_id,
                        scope.connection_id,
                        scope.realm_id.as_deref(),
                        range.starts_at,
                        range.ends_at,
                    )
                    .await
                    .map_err(source)?,
                "trusted-fleet-acceptance-ledger",
            )
        };
        let mut connections = self
            .store
            .fleet_connections(
                scope.organization_id,
                scope.project_id,
                scope.environment_id,
                false,
            )
            .await
            .map_err(source)?;
        if let Some(connection_id) = scope.connection_id {
            connections.retain(|connection| connection.id == connection_id);
        }

        let organization_ids = connections
            .iter()
            .map(|connection| connection.organization_id)
            .collect::<BTreeSet<_>>();
        let mut policies = BTreeMap::new();
        for organization_id in organization_ids {
            policies.insert(
                organization_id,
                self.store
                    .fleet_analytics_policy(organization_id)
                    .await
                    .map_err(source)?,
            );
        }
        let records = records
            .into_iter()
            .filter(|record| {
                policies
                    .get(&record.organization_id)
                    .is_some_and(|policy| policy.enabled)
            })
            .map(|record| {
                let bucket = record.bucket().map_err(source)?;
                Ok((record, bucket))
            })
            .collect::<Result<Vec<_>, ConnectError>>()?;
        // Coverage is registry-backed and needs only the freshness horizon,
        // never the full numerical query range. Keeping this bounded in the
        // authoritative SableDB ledger avoids turning an organization query
        // into a scan of millions of canonical GreptimeDB rows.
        let coverage_records = self
            .store
            .fleet_telemetry_buckets(
                scope.organization_id,
                scope.project_id,
                scope.environment_id,
                scope.connection_id,
                scope.realm_id.as_deref(),
                range.ends_at.saturating_sub(15 * 60 * 1_000),
                range.ends_at,
            )
            .await
            .map_err(source)?
            .into_iter()
            .map(|record| {
                let bucket = record.bucket().map_err(source)?;
                Ok((record, bucket))
            })
            .collect::<Result<Vec<_>, ConnectError>>()?;
        let coverage = coverage(&connections, &policies, &coverage_records, range.ends_at)?;
        let authentication_coverage = coverage.first().cloned().unwrap_or_default();
        tracing::info!(
            target: "rustyauth.analytics.query",
            scope_kind,
            step_milliseconds = range.step,
            source = source_name,
            record_count = records.len(),
            expected_realms = authentication_coverage.expected_realms,
            reporting_realms = authentication_coverage.reporting_realms,
            stale_realms = authentication_coverage.stale_realms,
            elapsed_milliseconds = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "Fleet analytics query completed"
        );
        Ok(AnalyticsData {
            scope,
            range,
            records,
            connections,
            policies,
            coverage,
            source: source_name,
        })
    }
}

fn analytics_scope_kind_label(kind: Option<AnalyticsScopeKind>) -> &'static str {
    match kind {
        Some(AnalyticsScopeKind::Fleet) => "fleet",
        Some(AnalyticsScopeKind::Organization) => "organization",
        Some(AnalyticsScopeKind::Project) => "project",
        Some(AnalyticsScopeKind::Environment) => "environment",
        Some(AnalyticsScopeKind::Realm) => "realm",
        Some(AnalyticsScopeKind::Unspecified) | None => "unspecified",
    }
}

#[allow(refining_impl_trait)]
impl AnalyticsService for AnalyticsRpc {
    async fn get_analytics_overview(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetAnalyticsOverviewRequest>,
    ) -> ServiceResult<AnalyticsOverview> {
        let scope = self
            .resolve_scope(ctx.headers(), required_scope(request.scope.as_option())?)
            .await?;
        let range = effective_range(request.range.as_option())?;
        Response::ok(overview(self.data(scope, range).await?)?)
    }

    async fn query_metric_series(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, QueryMetricSeriesRequest>,
    ) -> ServiceResult<MetricSeries> {
        let metric = request
            .metric
            .as_known()
            .filter(|metric| *metric != AnalyticsMetric::Unspecified)
            .ok_or_else(|| invalid("analytics metric is required and must be known"))?;
        let scope = self
            .resolve_scope(ctx.headers(), required_scope(request.scope.as_option())?)
            .await?;
        let data = self
            .data(scope, effective_range(request.range.as_option())?)
            .await?;
        let mut groups = BTreeMap::<i64, Vec<&TelemetryBucket>>::new();
        for (_, bucket) in &data.records {
            groups
                .entry(align(
                    bucket.bucket_start_unix_milliseconds,
                    data.range.step,
                ))
                .or_default()
                .push(bucket);
        }
        let mut points = Vec::with_capacity(groups.len());
        for (starts_at, buckets) in groups {
            points.push(metric_point(starts_at, metric, &buckets)?);
        }
        Response::ok(MetricSeries {
            scope: data.scope.proto.clone().into(),
            effective_range: data.range.proto().into(),
            metric: metric.into(),
            points,
            coverage: data.coverage.clone(),
            warnings: warnings(&data.coverage),
            calculated_at_unix_milliseconds: now_milliseconds(),
            source: data.source.into(),
            ..Default::default()
        })
    }

    async fn get_authentication_funnel(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetAuthenticationFunnelRequest>,
    ) -> ServiceResult<AuthenticationFunnel> {
        let scope = self
            .resolve_scope(ctx.headers(), required_scope(request.scope.as_option())?)
            .await?;
        let data = self
            .data(scope, effective_range(request.range.as_option())?)
            .await?;
        let mut options_started = 0_u64;
        let mut ceremonies_opened = 0_u64;
        let mut responses_returned = 0_u64;
        let mut completed = 0_u64;
        let mut expired = 0_u64;
        for (_, bucket) in &data.records {
            if let Some(metrics) = bucket.registration.as_option() {
                options_started = checked(options_started, metrics.options_started)?;
                ceremonies_opened = checked(ceremonies_opened, metrics.ceremonies_opened)?;
                responses_returned = checked(responses_returned, metrics.responses_returned)?;
                completed = checked(completed, metrics.registrations_completed)?;
                expired = checked(expired, metrics.challenges_expired)?;
            }
        }
        Response::ok(AuthenticationFunnel {
            scope: data.scope.proto.clone().into(),
            effective_range: data.range.proto().into(),
            stages: [
                ("registration_options_started", options_started),
                ("registration_ceremonies_opened", ceremonies_opened),
                ("registration_responses_returned", responses_returned),
                ("registrations_completed", completed),
                ("registration_challenges_expired", expired),
            ]
            .into_iter()
            .map(|(stage, count)| FunnelStage {
                stage: stage.into(),
                count,
                ..Default::default()
            })
            .collect(),
            coverage: data.coverage.clone(),
            warnings: warnings(&data.coverage),
            calculated_at_unix_milliseconds: now_milliseconds(),
            source: data.source.into(),
            ..Default::default()
        })
    }

    async fn get_failure_breakdown(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetFailureBreakdownRequest>,
    ) -> ServiceResult<FailureBreakdown> {
        let scope = self
            .resolve_scope(ctx.headers(), required_scope(request.scope.as_option())?)
            .await?;
        let data = self
            .data(scope, effective_range(request.range.as_option())?)
            .await?;
        let mut counts = BTreeMap::<i32, u64>::new();
        let mut total = 0_u64;
        for (_, bucket) in &data.records {
            if let Some(authentication) = bucket.authentication.as_option() {
                for failure in &authentication.failure_classes {
                    let value = counts.entry(failure.failure_class.to_i32()).or_default();
                    *value = checked(*value, failure.count)?;
                    total = checked(total, failure.count)?;
                }
            }
        }
        Response::ok(FailureBreakdown {
            scope: data.scope.proto.clone().into(),
            effective_range: data.range.proto().into(),
            failures: counts
                .into_iter()
                .filter_map(|(failure_class, count)| {
                    FailureClass::from_i32(failure_class).map(|failure_class| {
                        FailureBreakdownEntry {
                            failure_class: failure_class.into(),
                            count,
                            contribution: ratio(count, total),
                            ..Default::default()
                        }
                    })
                })
                .collect(),
            coverage: data.coverage.clone(),
            warnings: warnings(&data.coverage),
            calculated_at_unix_milliseconds: now_milliseconds(),
            source: data.source.into(),
            ..Default::default()
        })
    }

    async fn get_reporting_coverage(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetReportingCoverageRequest>,
    ) -> ServiceResult<AnalyticsCoverage> {
        let scope = self
            .resolve_scope(ctx.headers(), required_scope(request.scope.as_option())?)
            .await?;
        let data = self
            .data(scope, effective_range(request.range.as_option())?)
            .await?;
        Response::ok(AnalyticsCoverage {
            scope: data.scope.proto.clone().into(),
            effective_range: data.range.proto().into(),
            families: data.coverage.clone(),
            warnings: warnings(&data.coverage),
            calculated_at_unix_milliseconds: now_milliseconds(),
            ..Default::default()
        })
    }

    async fn compare_scopes(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CompareScopesRequest>,
    ) -> ServiceResult<CompareScopesResponse> {
        if request.scopes.len() < 2 || request.scopes.len() > MAX_COMPARISON_SCOPES {
            return Err(invalid("scope comparison requires between 2 and 8 scopes"));
        }
        let range = effective_range(request.range.as_option())?;
        let mut comparisons = Vec::with_capacity(request.scopes.len());
        let mut organization_id = None;
        let mut source_name = None;
        let mut combined_warnings = BTreeSet::new();
        for scope in &request.scopes {
            let scope = self
                .resolve_scope(ctx.headers(), scope.to_owned_message().map_err(source)?)
                .await?;
            if scope.proto.kind.as_known() == Some(AnalyticsScopeKind::Fleet)
                || organization_id.is_some_and(|id| scope.organization_id != Some(id))
            {
                return Err(invalid(
                    "scope comparisons must be siblings within one organization",
                ));
            }
            organization_id = scope.organization_id;
            let data = self.data(scope, range).await?;
            source_name.get_or_insert(data.source);
            let authentication = authentication(&data)?;
            for warning in warnings(&data.coverage) {
                combined_warnings.insert(warning.to_i32());
            }
            comparisons.push(ScopeComparison {
                scope: data.scope.proto.into(),
                authentication: authentication.into(),
                coverage: data.coverage,
                ..Default::default()
            });
        }
        Response::ok(CompareScopesResponse {
            effective_range: range.proto().into(),
            comparisons,
            warnings: combined_warnings
                .into_iter()
                .filter_map(AnalyticsWarning::from_i32)
                .map(Into::into)
                .collect(),
            calculated_at_unix_milliseconds: now_milliseconds(),
            source: source_name.unwrap_or("unavailable").into(),
            ..Default::default()
        })
    }

    async fn get_analytics_policy(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetAnalyticsPolicyRequest>,
    ) -> ServiceResult<AnalyticsPolicy> {
        let organization_id = scope_uuid(request.organization_id, "organization_id")?;
        self.authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Read,
                FleetResourceKindRecord::Organization,
                organization_id,
            )
            .await?;
        let policy = self
            .store
            .fleet_analytics_policy(organization_id)
            .await
            .map_err(source)?;
        Response::ok(policy_proto(policy)?)
    }

    async fn update_analytics_policy(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateAnalyticsPolicyRequest>,
    ) -> ServiceResult<AnalyticsPolicy> {
        let organization_id = scope_uuid(request.organization_id, "organization_id")?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                FleetResourceKindRecord::Organization,
                organization_id,
            )
            .await?;
        let request_id = scope_uuid(request.request_id, "request_id")?;
        let reason = bounded_reason(request.reason)?;
        let residency = match request.residency_mode.as_known() {
            Some(AnalyticsResidencyMode::RollupsOnly) => FleetAnalyticsResidencyRecord::RollupsOnly,
            Some(AnalyticsResidencyMode::CustomerOwnedArchive) => {
                FleetAnalyticsResidencyRecord::CustomerOwnedArchive
            }
            Some(AnalyticsResidencyMode::CentralLandingArchive) => {
                FleetAnalyticsResidencyRecord::CentralLandingArchive
            }
            _ => {
                return Err(invalid(
                    "analytics residency mode is required and must be known",
                ));
            }
        };
        if let Some(analytics) = &self.analytics {
            let retention_result = analytics
                .enforce_organization_retention(
                    organization_id,
                    request.canonical_retention_days,
                    now_milliseconds(),
                )
                .await;
            let maintenance = FleetAnalyticsMaintenanceAuditRecord {
                request_id,
                organization_id,
                connection_id: None,
                operator_id: actor.user.id,
                action: FleetAnalyticsMaintenanceActionRecord::EnforceRetention,
                outcome: if retention_result.is_ok() {
                    FleetAnalyticsMaintenanceOutcomeRecord::Succeeded
                } else {
                    FleetAnalyticsMaintenanceOutcomeRecord::Failed
                },
                reason: reason.clone(),
                occurred_at: now(),
            };
            self.store
                .record_fleet_analytics_maintenance(maintenance)
                .await
                .map_err(source)?;
            retention_result.map_err(source)?;
        }
        let policy = self
            .store
            .update_fleet_analytics_policy(
                organization_id,
                request.enabled,
                request.canonical_retention_days,
                residency,
                request.max_buckets_per_minute_per_realm,
                request_id,
                actor.user.id,
                reason,
            )
            .await
            .map_err(source)?;
        Response::ok(policy_proto(policy)?)
    }
}

#[derive(Clone)]
struct ResolvedScope {
    proto: AnalyticsScope,
    organization_id: Option<Uuid>,
    project_id: Option<Uuid>,
    environment_id: Option<Uuid>,
    connection_id: Option<Uuid>,
    realm_id: Option<String>,
}

impl ResolvedScope {
    fn fleet(proto: AnalyticsScope) -> Self {
        Self {
            proto,
            organization_id: None,
            project_id: None,
            environment_id: None,
            connection_id: None,
            realm_id: None,
        }
    }
}

#[derive(Clone, Copy)]
struct EffectiveRange {
    starts_at: i64,
    ends_at: i64,
    step: i64,
    granularity: AnalyticsGranularity,
}

impl EffectiveRange {
    fn proto(self) -> AnalyticsRange {
        AnalyticsRange {
            starts_at_unix_milliseconds: self.starts_at,
            ends_at_unix_milliseconds: self.ends_at,
            granularity: self.granularity.into(),
            ..Default::default()
        }
    }
}

struct AnalyticsData {
    scope: ResolvedScope,
    range: EffectiveRange,
    records: Vec<(FleetTelemetryBucketRecord, TelemetryBucket)>,
    #[allow(dead_code)]
    connections: Vec<FleetConnectionRecord>,
    #[allow(dead_code)]
    policies: BTreeMap<Uuid, FleetAnalyticsPolicyRecord>,
    coverage: Vec<ReportingCoverage>,
    source: &'static str,
}

fn required_scope<'a, V>(scope: Option<&V>) -> Result<AnalyticsScope, ConnectError>
where
    V: MessageView<'a, Owned = AnalyticsScope>,
{
    scope
        .ok_or_else(|| invalid("analytics scope is required"))?
        .to_owned_message()
        .map_err(source)
}

fn effective_range<'a, V>(range: Option<&V>) -> Result<EffectiveRange, ConnectError>
where
    V: MessageView<'a, Owned = AnalyticsRange>,
{
    let range = range
        .ok_or_else(|| invalid("analytics range is required"))?
        .to_owned_message()
        .map_err(source)?;
    effective_range_owned(&range)
}

fn effective_range_owned(range: &AnalyticsRange) -> Result<EffectiveRange, ConnectError> {
    let duration = range
        .ends_at_unix_milliseconds
        .checked_sub(range.starts_at_unix_milliseconds)
        .filter(|duration| *duration > 0 && *duration <= MAX_RANGE_MILLISECONDS)
        .ok_or_else(|| invalid("analytics range must be positive and no longer than 28 days"))?;
    if range.starts_at_unix_milliseconds < 0
        || range.ends_at_unix_milliseconds
            > now_milliseconds().saturating_add(MAX_FUTURE_SKEW_MILLISECONDS)
    {
        return Err(invalid(
            "analytics range is outside the supported clock bounds",
        ));
    }
    let granularity = match range.granularity.as_known() {
        Some(AnalyticsGranularity::Unspecified) => {
            if duration <= 7 * 86_400 * 1_000 {
                AnalyticsGranularity::FiveMinutes
            } else {
                AnalyticsGranularity::OneHour
            }
        }
        Some(value) => value,
        None => return Err(invalid("analytics granularity must be known")),
    };
    let step = match granularity {
        AnalyticsGranularity::FiveMinutes => 5 * 60 * 1_000,
        AnalyticsGranularity::OneHour => 60 * 60 * 1_000,
        AnalyticsGranularity::OneDay => 86_400 * 1_000,
        AnalyticsGranularity::Unspecified => unreachable!(),
    };
    Ok(EffectiveRange {
        starts_at: align(range.starts_at_unix_milliseconds, step),
        ends_at: align(
            range.ends_at_unix_milliseconds.saturating_add(step - 1),
            step,
        ),
        step,
        granularity,
    })
}

fn overview(data: AnalyticsData) -> Result<AnalyticsOverview, ConnectError> {
    let authentication = authentication(&data)?;
    let mut registrations_completed = 0;
    let mut sessions_created = 0;
    let mut service_account_calls = 0;
    let mut webhook_deliveries = 0;
    let mut webhook_failures = 0;
    for (_, bucket) in &data.records {
        if let Some(metrics) = bucket.registration.as_option() {
            registrations_completed =
                checked(registrations_completed, metrics.registrations_completed)?;
        }
        if let Some(metrics) = bucket.sessions_and_tokens.as_option() {
            sessions_created = checked(sessions_created, metrics.sessions_created)?;
        }
        if let Some(metrics) = bucket.service_accounts.as_option() {
            service_account_calls = checked(service_account_calls, metrics.calls)?;
        }
        if let Some(metrics) = bucket.webhooks.as_option() {
            webhook_deliveries = checked(webhook_deliveries, metrics.deliveries)?;
            webhook_failures = checked(webhook_failures, metrics.failures)?;
        }
    }
    Ok(AnalyticsOverview {
        scope: data.scope.proto.into(),
        effective_range: data.range.proto().into(),
        calculated_at_unix_milliseconds: now_milliseconds(),
        last_complete_window_start_unix_milliseconds: data
            .coverage
            .iter()
            .find(|coverage| {
                coverage.metric_family.as_known() == Some(MetricFamily::Authentication)
            })
            .map(|coverage| coverage.last_complete_window_start_unix_milliseconds)
            .unwrap_or_default(),
        authentication: authentication.into(),
        registrations_completed,
        sessions_created,
        service_account_calls,
        webhook_deliveries,
        webhook_failures,
        coverage: data.coverage.clone(),
        warnings: warnings(&data.coverage),
        source: data.source.into(),
        ..Default::default()
    })
}

fn authentication(data: &AnalyticsData) -> Result<AuthenticationAggregate, ConnectError> {
    let rollup =
        aggregate_authentication(data.records.iter().map(|(_, bucket)| bucket)).map_err(source)?;
    Ok(AuthenticationAggregate {
        attempts: rollup.attempts,
        successes: rollup.successes,
        failures: rollup.failures,
        denials: rollup.denials,
        success_rate_numerator: rollup.success_rate_numerator,
        success_rate_denominator: rollup.success_rate_denominator,
        latency_count: rollup.latency_count,
        latency_sum_milliseconds: rollup.latency_sum_milliseconds,
        latency_p95_upper_bound_milliseconds: rollup
            .latency_p95_upper_bound_milliseconds
            .unwrap_or_default(),
        latency_p95_available: rollup.latency_p95_upper_bound_milliseconds.is_some(),
        active_account_observations: rollup.active_account_observations,
        ..Default::default()
    })
}

fn metric_point(
    starts_at: i64,
    metric: AnalyticsMetric,
    buckets: &[&TelemetryBucket],
) -> Result<MetricPoint, ConnectError> {
    let authentication = aggregate_authentication(buckets.iter().copied()).map_err(source)?;
    let (value, numerator, denominator, available) = match metric {
        AnalyticsMetric::AuthenticationAttempts => (
            authentication.attempts as f64,
            authentication.attempts,
            0,
            true,
        ),
        AnalyticsMetric::AuthenticationSuccesses => (
            authentication.successes as f64,
            authentication.successes,
            0,
            true,
        ),
        AnalyticsMetric::AuthenticationFailures => (
            authentication.failures as f64,
            authentication.failures,
            0,
            true,
        ),
        AnalyticsMetric::AuthenticationDenials => (
            authentication.denials as f64,
            authentication.denials,
            0,
            true,
        ),
        AnalyticsMetric::AuthenticationSuccessRate => (
            ratio(authentication.successes, authentication.attempts),
            authentication.successes,
            authentication.attempts,
            authentication.attempts > 0,
        ),
        AnalyticsMetric::AuthenticationP95Milliseconds => {
            let value = authentication.latency_p95_upper_bound_milliseconds;
            (value.unwrap_or_default() as f64, 0, 0, value.is_some())
        }
        AnalyticsMetric::RegistrationsCompleted => {
            let value = family_sum(buckets, |bucket| {
                bucket
                    .registration
                    .as_option()
                    .map(|metrics| metrics.registrations_completed)
            })?;
            (value as f64, value, 0, true)
        }
        AnalyticsMetric::SessionsCreated => {
            let value = family_sum(buckets, |bucket| {
                bucket
                    .sessions_and_tokens
                    .as_option()
                    .map(|metrics| metrics.sessions_created)
            })?;
            (value as f64, value, 0, true)
        }
        AnalyticsMetric::ServiceAccountCalls => {
            let value = family_sum(buckets, |bucket| {
                bucket
                    .service_accounts
                    .as_option()
                    .map(|metrics| metrics.calls)
            })?;
            (value as f64, value, 0, true)
        }
        AnalyticsMetric::WebhookFailures => {
            let value = family_sum(buckets, |bucket| {
                bucket.webhooks.as_option().map(|metrics| metrics.failures)
            })?;
            (value as f64, value, 0, true)
        }
        AnalyticsMetric::Unspecified => return Err(invalid("analytics metric is unspecified")),
    };
    Ok(MetricPoint {
        starts_at_unix_milliseconds: starts_at,
        value,
        numerator,
        denominator,
        available,
        ..Default::default()
    })
}

fn family_sum(
    buckets: &[&TelemetryBucket],
    value: impl Fn(&TelemetryBucket) -> Option<u64>,
) -> Result<u64, ConnectError> {
    buckets.iter().try_fold(0, |total, bucket| {
        checked(total, value(bucket).unwrap_or_default())
    })
}

fn coverage(
    connections: &[FleetConnectionRecord],
    policies: &BTreeMap<Uuid, FleetAnalyticsPolicyRecord>,
    records: &[(FleetTelemetryBucketRecord, TelemetryBucket)],
    ends_at: i64,
) -> Result<Vec<ReportingCoverage>, ConnectError> {
    [
        MetricFamily::Authentication,
        MetricFamily::Registration,
        MetricFamily::SessionsAndTokens,
        MetricFamily::ServiceAccounts,
        MetricFamily::Webhooks,
        MetricFamily::Platform,
        MetricFamily::RealmHealth,
    ]
    .into_iter()
    .map(|family| coverage_family(connections, policies, records, ends_at, family))
    .collect()
}

fn coverage_family(
    connections: &[FleetConnectionRecord],
    policies: &BTreeMap<Uuid, FleetAnalyticsPolicyRecord>,
    records: &[(FleetTelemetryBucketRecord, TelemetryBucket)],
    ends_at: i64,
    family: MetricFamily,
) -> Result<ReportingCoverage, ConnectError> {
    let mut latest = BTreeMap::<Uuid, i64>::new();
    for (record, bucket) in records {
        if bucket_has_family(bucket, family) {
            latest
                .entry(record.connection_id)
                .and_modify(|value| *value = (*value).max(record.bucket_start_unix_milliseconds))
                .or_insert(record.bucket_start_unix_milliseconds);
        }
    }
    let stale_before = ends_at.saturating_sub(15 * 60 * 1_000);
    let mut reporting = 0_u64;
    let mut stale = 0_u64;
    let mut disabled = 0_u64;
    let mut unsupported = 0_u64;
    let mut complete_windows = Vec::new();
    for connection in connections {
        if !policies
            .get(&connection.organization_id)
            .is_some_and(|policy| policy.enabled)
        {
            disabled = checked(disabled, 1)?;
            continue;
        }
        if !connection
            .capabilities
            .iter()
            .any(|(name, version)| name == TELEMETRY_CAPABILITY && *version == 1)
        {
            unsupported = checked(unsupported, 1)?;
            continue;
        }
        match latest.get(&connection.id).copied() {
            Some(last)
                if last >= stale_before
                    && connection.state != FleetConnectionStateRecord::Offline =>
            {
                reporting = checked(reporting, 1)?;
                complete_windows.push(last);
            }
            _ => stale = checked(stale, 1)?,
        }
    }
    let expected = checked(reporting, stale)?;
    let total = checked(checked(expected, disabled)?, unsupported)?;
    Ok(ReportingCoverage {
        metric_family: family.into(),
        total_realms: total,
        expected_realms: expected,
        reporting_realms: reporting,
        stale_realms: stale,
        disabled_realms: disabled,
        unsupported_realms: unsupported,
        last_complete_window_start_unix_milliseconds: complete_windows
            .into_iter()
            .min()
            .unwrap_or_default(),
        partial: stale > 0 || disabled > 0 || unsupported > 0,
        ..Default::default()
    })
}

fn bucket_has_family(bucket: &TelemetryBucket, family: MetricFamily) -> bool {
    match family {
        MetricFamily::Authentication => bucket.authentication.is_set(),
        MetricFamily::Registration => bucket.registration.is_set(),
        MetricFamily::SessionsAndTokens => bucket.sessions_and_tokens.is_set(),
        MetricFamily::ServiceAccounts => bucket.service_accounts.is_set(),
        MetricFamily::Webhooks => bucket.webhooks.is_set(),
        MetricFamily::Platform => bucket.platform.is_set(),
        MetricFamily::RealmHealth => bucket.realm_health.is_set(),
        MetricFamily::Unspecified => false,
    }
}

fn warnings(coverage: &[ReportingCoverage]) -> Vec<buffa::EnumValue<AnalyticsWarning>> {
    let mut values = Vec::new();
    if coverage.iter().any(|coverage| coverage.partial) {
        values.push(AnalyticsWarning::PartialCoverage.into());
    }
    if coverage.iter().any(|coverage| coverage.stale_realms > 0) {
        values.push(AnalyticsWarning::StaleRealms.into());
    }
    if coverage.iter().any(|coverage| coverage.disabled_realms > 0) {
        values.push(AnalyticsWarning::DisabledRealms.into());
    }
    if coverage
        .iter()
        .any(|coverage| coverage.unsupported_realms > 0)
    {
        values.push(AnalyticsWarning::UnsupportedRealms.into());
    }
    values
}

fn policy_proto(record: FleetAnalyticsPolicyRecord) -> Result<AnalyticsPolicy, ConnectError> {
    Ok(AnalyticsPolicy {
        organization_id: record.organization_id.to_string(),
        enabled: record.enabled,
        canonical_retention_days: record.canonical_retention_days,
        residency_mode: match record.residency {
            FleetAnalyticsResidencyRecord::RollupsOnly => AnalyticsResidencyMode::RollupsOnly,
            FleetAnalyticsResidencyRecord::CustomerOwnedArchive => {
                AnalyticsResidencyMode::CustomerOwnedArchive
            }
            FleetAnalyticsResidencyRecord::CentralLandingArchive => {
                AnalyticsResidencyMode::CentralLandingArchive
            }
        }
        .into(),
        max_buckets_per_minute_per_realm: record.max_buckets_per_minute_per_realm,
        updated_at: if record.updated_at == 0 {
            String::new()
        } else {
            time::OffsetDateTime::from_unix_timestamp(record.updated_at as i64)
                .map_err(source)?
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(source)?
        },
        updated_by: record
            .updated_by
            .map(|id| id.to_string())
            .unwrap_or_default(),
        ..Default::default()
    })
}

fn required_empty(value: &str, field: &'static str) -> Result<(), ConnectError> {
    if value.is_empty() {
        Ok(())
    } else {
        Err(invalid(field))
    }
}

fn require_empty_scope_ids(scope: &AnalyticsScope) -> Result<(), ConnectError> {
    required_empty(
        &scope.organization_id,
        "fleet scope contains an organization identifier",
    )?;
    required_empty(
        &scope.project_id,
        "fleet scope contains a project identifier",
    )?;
    required_empty(
        &scope.environment_id,
        "fleet scope contains an environment identifier",
    )?;
    required_empty(
        &scope.connection_id,
        "fleet scope contains a connection identifier",
    )
}

fn scope_uuid(value: &str, field: &'static str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(value).map_err(|_| invalid(field))
}

fn bounded_reason(value: &str) -> Result<String, ConnectError> {
    let value = value.trim();
    if value.len() < 8 || value.len() > 500 || value.chars().any(char::is_control) {
        return Err(invalid(
            "policy mutation reason must contain 8-500 printable characters",
        ));
    }
    Ok(value.to_owned())
}

fn checked(left: u64, right: u64) -> Result<u64, ConnectError> {
    left.checked_add(right)
        .ok_or_else(|| ConnectError::new(ErrorCode::OutOfRange, "analytics aggregate overflow"))
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn align(value: i64, step: i64) -> i64 {
    value - value.rem_euclid(step)
}

fn now_milliseconds() -> i64 {
    i64::try_from(now())
        .unwrap_or(i64::MAX / 1_000)
        .saturating_mul(1_000)
}

fn invalid(message: &'static str) -> ConnectError {
    ConnectError::new(ErrorCode::InvalidArgument, message)
}

fn scope_not_found() -> ConnectError {
    ConnectError::new(ErrorCode::NotFound, "analytics scope was not found")
}

fn source(error: impl std::fmt::Display) -> ConnectError {
    tracing::error!(error = %error, "Fleet analytics operation failed");
    ConnectError::new(ErrorCode::Internal, "Fleet analytics operation failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_are_bounded_and_choose_an_effective_granularity() {
        let current = now_milliseconds();
        let range = AnalyticsRange {
            starts_at_unix_milliseconds: current - 8 * 86_400 * 1_000,
            ends_at_unix_milliseconds: current,
            ..Default::default()
        };
        let range = effective_range_owned(&range).unwrap();
        assert_eq!(range.granularity, AnalyticsGranularity::OneHour);
    }

    #[test]
    fn fleet_scope_rejects_smuggled_child_ids() {
        assert!(
            require_empty_scope_ids(&AnalyticsScope {
                kind: AnalyticsScopeKind::Fleet.into(),
                organization_id: Uuid::new_v4().to_string(),
                ..Default::default()
            })
            .is_err()
        );
    }
}
