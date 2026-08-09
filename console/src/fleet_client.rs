//! Browser-facing binary Connect client and passkey ceremony adapter.

use buffa::Message;

#[cfg(all(
    not(target_arch = "wasm32"),
    not(any(target_os = "ios", target_os = "android"))
))]
use keyring::{Entry as VaultEntry, Error as VaultError};
#[cfg(any(target_os = "ios", target_os = "android"))]
use keyring_core::{Entry as VaultEntry, Error as VaultError};

use crate::proto::rustyauth::fleet::v1::*;

const FLEET_PREFIX: &str = "/rustyauth.fleet.v1.FleetService/";
const ANALYTICS_PREFIX: &str = "/rustyauth.analytics.v1.AnalyticsService/";
const ORGANIZATION_PREFIX: &str = "/rustyauth.organization.v1.OrganizationService/";
const IDENTITY_PREFIX: &str = "/rustyauth.identity.v1.IdentityService/";
const METRICS_PREFIX: &str = "/rustyauth.metrics.v1.MetricsService/";
const SERVICE_ACCOUNT_PREFIX: &str = "/rustyauth.service_accounts.v1.ServiceAccountService/";
const WEBHOOK_PREFIX: &str = "/rustyauth.webhooks.v1.WebhookService/";
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
#[cfg(not(target_arch = "wasm32"))]
const DEVICE_TOKEN_PREFIX: &str = "rdt_";
#[cfg(not(target_arch = "wasm32"))]
const VAULT_SERVICE: &str = "dev.rustyauth.console";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientError(pub String);

impl std::fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentRole {
    Realm,
    FleetControlPlane,
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub enum EnrollmentCredential {
    DevelopmentBootstrap(String),
    ProductionInvitation(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentifierVerificationChallenge {
    pub challenge_id: String,
    pub expires_at: u64,
    pub delivered: bool,
    pub development_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceToken {
    pub token: String,
    pub expires_at: u64,
}

#[cfg(target_arch = "wasm32")]
pub async fn deployment_role() -> Result<DeploymentRole, ClientError> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::Response;

    let response = JsFuture::from(
        web_sys::window()
            .ok_or_else(|| ClientError("Browser window is unavailable.".into()))?
            .fetch_with_str("/.well-known/passkey-auth"),
    )
    .await
    .map_err(js_error)?
    .dyn_into::<Response>()
    .map_err(|_| ClientError("RustyAuth returned an invalid response.".into()))?;
    let body = JsFuture::from(response.text().map_err(js_error)?)
        .await
        .map_err(js_error)?
        .as_string()
        .unwrap_or_default();
    if !response.ok() {
        return Err(ClientError("RustyAuth discovery is unavailable.".into()));
    }
    match serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| value.get("deployment_role")?.as_str().map(str::to_owned))
        .as_deref()
    {
        Some("realm") => Ok(DeploymentRole::Realm),
        Some("fleetControlPlane") => Ok(DeploymentRole::FleetControlPlane),
        _ => Err(ClientError(
            "RustyAuth discovery did not declare a supported deployment role.".into(),
        )),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn deployment_role() -> Result<DeploymentRole, ClientError> {
    let response = native_client()?
        .get(native_url("/.well-known/passkey-auth")?)
        .send()
        .await
        .map_err(native_transport_error)?;
    let status = response.status();
    let body = read_native_response(response).await?;
    if !status.is_success() {
        return Err(ClientError(format!(
            "RustyAuth discovery failed with HTTP {}.",
            status.as_u16()
        )));
    }
    match serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| value.get("deployment_role")?.as_str().map(str::to_owned))
        .as_deref()
    {
        Some("realm") => Ok(DeploymentRole::Realm),
        Some("fleetControlPlane") => Ok(DeploymentRole::FleetControlPlane),
        _ => Err(ClientError(
            "RustyAuth discovery did not declare a supported deployment role.".into(),
        )),
    }
}

pub async fn realm_organization()
-> Result<crate::proto::rustyauth::organization::v1::Organization, ClientError> {
    use crate::proto::rustyauth::organization::v1::GetOrganizationRequest;
    rpc(
        ORGANIZATION_PREFIX,
        "GetOrganization",
        &GetOrganizationRequest::default(),
    )
    .await
}

pub async fn current_operator()
-> Result<crate::proto::rustyauth::organization::v1::Operator, ClientError> {
    use crate::proto::rustyauth::organization::v1::GetCurrentOperatorRequest;
    rpc(
        ORGANIZATION_PREFIX,
        "GetCurrentOperator",
        &GetCurrentOperatorRequest::default(),
    )
    .await
}

pub async fn update_realm_organization(
    name: &str,
) -> Result<crate::proto::rustyauth::organization::v1::Organization, ClientError> {
    use crate::proto::rustyauth::organization::v1::UpdateOrganizationRequest;
    rpc(
        ORGANIZATION_PREFIX,
        "UpdateOrganization",
        &UpdateOrganizationRequest {
            name: name.to_owned(),
            ..Default::default()
        },
    )
    .await
}

pub async fn users() -> Result<Vec<crate::proto::rustyauth::identity::v1::User>, ClientError> {
    use crate::proto::rustyauth::identity::v1::{ListUsersRequest, ListUsersResponse};
    let response: ListUsersResponse = rpc(
        IDENTITY_PREFIX,
        "ListUsers",
        &ListUsersRequest {
            page_size: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(response.users)
}

pub async fn set_identifier_verification(
    user_id: &str,
    identifier: &crate::proto::rustyauth::identity::v1::Identifier,
    verified: bool,
) -> Result<crate::proto::rustyauth::identity::v1::User, ClientError> {
    use crate::proto::rustyauth::identity::v1::{
        IdentifierValue, SetIdentifierVerificationRequest,
    };
    rpc(
        IDENTITY_PREFIX,
        "SetIdentifierVerification",
        &SetIdentifierVerificationRequest {
            user_id: user_id.to_owned(),
            identifier: IdentifierValue {
                r#type: identifier.r#type,
                value: identifier.value.clone(),
                ..Default::default()
            }
            .into(),
            verified,
            ..Default::default()
        },
    )
    .await
}

pub async fn revoke_user_passkey(
    user_id: &str,
    credential_id: &str,
) -> Result<crate::proto::rustyauth::identity::v1::User, ClientError> {
    use crate::proto::rustyauth::identity::v1::RevokePasskeyRequest;
    rpc(
        IDENTITY_PREFIX,
        "RevokePasskey",
        &RevokePasskeyRequest {
            user_id: user_id.to_owned(),
            credential_id: credential_id.to_owned(),
            ..Default::default()
        },
    )
    .await
}

pub async fn service_accounts()
-> Result<Vec<crate::proto::rustyauth::service_accounts::v1::ServiceAccount>, ClientError> {
    use crate::proto::rustyauth::service_accounts::v1::{
        ListServiceAccountsRequest, ListServiceAccountsResponse,
    };
    let response: ListServiceAccountsResponse = rpc(
        SERVICE_ACCOUNT_PREFIX,
        "ListServiceAccounts",
        &ListServiceAccountsRequest {
            page_size: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(response.service_accounts)
}

pub async fn create_service_account(
    name: &str,
    description: &str,
    scopes: Vec<String>,
) -> Result<crate::proto::rustyauth::service_accounts::v1::ServiceAccount, ClientError> {
    use crate::proto::rustyauth::service_accounts::v1::CreateServiceAccountRequest;
    rpc(
        SERVICE_ACCOUNT_PREFIX,
        "CreateServiceAccount",
        &CreateServiceAccountRequest {
            name: name.to_owned(),
            description: description.to_owned(),
            scopes,
            ..Default::default()
        },
    )
    .await
}

pub async fn create_service_credential(
    service_account_id: &str,
    name: &str,
) -> Result<crate::proto::rustyauth::service_accounts::v1::CreateCredentialResponse, ClientError> {
    use crate::proto::rustyauth::service_accounts::v1::CreateCredentialRequest;
    rpc(
        SERVICE_ACCOUNT_PREFIX,
        "CreateCredential",
        &CreateCredentialRequest {
            service_account_id: service_account_id.to_owned(),
            name: name.to_owned(),
            ..Default::default()
        },
    )
    .await
}

pub async fn set_service_account_enabled(
    account: &crate::proto::rustyauth::service_accounts::v1::ServiceAccount,
    enabled: bool,
) -> Result<crate::proto::rustyauth::service_accounts::v1::ServiceAccount, ClientError> {
    use crate::proto::rustyauth::service_accounts::v1::{
        ServiceAccountStatus, UpdateServiceAccountRequest,
    };
    rpc(
        SERVICE_ACCOUNT_PREFIX,
        "UpdateServiceAccount",
        &UpdateServiceAccountRequest {
            service_account_id: account.id.clone(),
            name: account.name.clone(),
            description: account.description.clone(),
            status: if enabled {
                ServiceAccountStatus::Active
            } else {
                ServiceAccountStatus::Disabled
            }
            .into(),
            scopes: account.scopes.clone(),
            reason: if enabled {
                "Enabled from the realm dashboard"
            } else {
                "Disabled from the realm dashboard"
            }
            .into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn revoke_service_credential(
    service_account_id: &str,
    credential_id: &str,
) -> Result<(), ClientError> {
    use crate::proto::rustyauth::service_accounts::v1::{
        RevokeCredentialRequest, RevokeCredentialResponse,
    };
    let _: RevokeCredentialResponse = rpc(
        SERVICE_ACCOUNT_PREFIX,
        "RevokeCredential",
        &RevokeCredentialRequest {
            service_account_id: service_account_id.to_owned(),
            credential_id: credential_id.to_owned(),
            reason: "Revoked from the realm dashboard".into(),
            ..Default::default()
        },
    )
    .await?;
    Ok(())
}

pub async fn webhooks() -> Result<Vec<crate::proto::rustyauth::webhooks::v1::Webhook>, ClientError>
{
    use crate::proto::rustyauth::webhooks::v1::{ListWebhooksRequest, ListWebhooksResponse};
    let response: ListWebhooksResponse = rpc(
        WEBHOOK_PREFIX,
        "ListWebhooks",
        &ListWebhooksRequest {
            page_size: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(response.webhooks)
}

pub async fn create_webhook(
    name: &str,
    url: &str,
    event_types: Vec<String>,
) -> Result<crate::proto::rustyauth::webhooks::v1::CreateWebhookResponse, ClientError> {
    use crate::proto::rustyauth::webhooks::v1::CreateWebhookRequest;
    rpc(
        WEBHOOK_PREFIX,
        "CreateWebhook",
        &CreateWebhookRequest {
            name: name.to_owned(),
            url: url.to_owned(),
            event_types,
            ..Default::default()
        },
    )
    .await
}

pub async fn test_webhook(
    webhook_id: &str,
) -> Result<crate::proto::rustyauth::webhooks::v1::WebhookDelivery, ClientError> {
    use crate::proto::rustyauth::webhooks::v1::TestWebhookRequest;
    rpc(
        WEBHOOK_PREFIX,
        "TestWebhook",
        &TestWebhookRequest {
            webhook_id: webhook_id.to_owned(),
            ..Default::default()
        },
    )
    .await
}

pub async fn rotate_webhook_secret(
    webhook_id: &str,
) -> Result<crate::proto::rustyauth::webhooks::v1::RotateSigningSecretResponse, ClientError> {
    use crate::proto::rustyauth::webhooks::v1::RotateSigningSecretRequest;
    rpc(
        WEBHOOK_PREFIX,
        "RotateSigningSecret",
        &RotateSigningSecretRequest {
            webhook_id: webhook_id.to_owned(),
            reason: "Rotated from the realm dashboard".into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn delete_webhook(webhook_id: &str) -> Result<(), ClientError> {
    use crate::proto::rustyauth::webhooks::v1::{DeleteWebhookRequest, DeleteWebhookResponse};
    let _: DeleteWebhookResponse = rpc(
        WEBHOOK_PREFIX,
        "DeleteWebhook",
        &DeleteWebhookRequest {
            webhook_id: webhook_id.to_owned(),
            reason: "Deleted from the realm dashboard".into(),
            ..Default::default()
        },
    )
    .await?;
    Ok(())
}

pub async fn webhook_deliveries(
    webhook_id: &str,
) -> Result<Vec<crate::proto::rustyauth::webhooks::v1::WebhookDelivery>, ClientError> {
    use crate::proto::rustyauth::webhooks::v1::{ListDeliveriesRequest, ListDeliveriesResponse};
    let response: ListDeliveriesResponse = rpc(
        WEBHOOK_PREFIX,
        "ListDeliveries",
        &ListDeliveriesRequest {
            webhook_id: webhook_id.to_owned(),
            page_size: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(response.deliveries)
}

pub struct RealmMetricsSnapshot {
    pub overview: crate::proto::rustyauth::metrics::v1::MetricsOverview,
    pub attempts: crate::proto::rustyauth::metrics::v1::MetricSeries,
    pub funnel: crate::proto::rustyauth::metrics::v1::AuthenticationFunnel,
    pub failures: crate::proto::rustyauth::metrics::v1::FailureBreakdown,
}

pub async fn realm_metrics(period_seconds: i64) -> Result<RealmMetricsSnapshot, ClientError> {
    use crate::proto::rustyauth::metrics::v1::{
        GetAuthenticationFunnelRequest, GetFailureBreakdownRequest, GetOverviewRequest,
        Granularity, Metric, QuerySeriesRequest, TimeRange,
    };
    use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

    let ends_at = OffsetDateTime::now_utc();
    let starts_at = ends_at - Duration::seconds(period_seconds.clamp(300, 28 * 24 * 60 * 60));
    let range = TimeRange {
        starts_at: starts_at
            .format(&Rfc3339)
            .map_err(|_| ClientError("Could not format the metrics range.".into()))?,
        ends_at: ends_at
            .format(&Rfc3339)
            .map_err(|_| ClientError("Could not format the metrics range.".into()))?,
        ..Default::default()
    };
    let overview = rpc(
        METRICS_PREFIX,
        "GetOverview",
        &GetOverviewRequest {
            range: range.clone().into(),
            ..Default::default()
        },
    )
    .await?;
    let attempts = rpc(
        METRICS_PREFIX,
        "QuerySeries",
        &QuerySeriesRequest {
            metric: Metric::AuthenticationAttempts.into(),
            range: range.clone().into(),
            granularity: if period_seconds <= 24 * 60 * 60 {
                Granularity::Hour
            } else {
                Granularity::Day
            }
            .into(),
            ..Default::default()
        },
    )
    .await?;
    let funnel = rpc(
        METRICS_PREFIX,
        "GetAuthenticationFunnel",
        &GetAuthenticationFunnelRequest {
            range: range.clone().into(),
            ..Default::default()
        },
    )
    .await?;
    let failures = rpc(
        METRICS_PREFIX,
        "GetFailureBreakdown",
        &GetFailureBreakdownRequest {
            range: range.into(),
            ..Default::default()
        },
    )
    .await?;
    Ok(RealmMetricsSnapshot {
        overview,
        attempts,
        funnel,
        failures,
    })
}

pub async fn create_invitation(
    identifier_type: &str,
    identifier_value: &str,
    expires_in_seconds: u64,
) -> Result<crate::proto::rustyauth::organization::v1::CreateAccountInvitationResponse, ClientError>
{
    use crate::proto::rustyauth::organization::v1::CreateAccountInvitationRequest;
    rpc(
        ORGANIZATION_PREFIX,
        "CreateAccountInvitation",
        &CreateAccountInvitationRequest {
            identifier_type: identifier_type.to_owned(),
            identifier_value: identifier_value.to_owned(),
            expires_in_seconds,
            ..Default::default()
        },
    )
    .await
}

pub async fn overview(organization_id: Option<&str>) -> Result<FleetOverview, ClientError> {
    rpc(
        FLEET_PREFIX,
        "GetFleetOverview",
        &GetFleetOverviewRequest {
            organization_id: organization_id.unwrap_or_default().to_owned(),
            ..Default::default()
        },
    )
    .await
}

pub async fn analytics_overview(
    organization_id: &str,
    project_id: Option<&str>,
    environment_id: Option<&str>,
    connection_id: Option<&str>,
    period_seconds: i64,
) -> Result<crate::proto::rustyauth::analytics::v1::AnalyticsOverview, ClientError> {
    use crate::proto::rustyauth::analytics::v1::GetAnalyticsOverviewRequest;
    let (scope, range) = analytics_query(
        organization_id,
        project_id,
        environment_id,
        connection_id,
        period_seconds,
    )?;
    rpc(
        ANALYTICS_PREFIX,
        "GetAnalyticsOverview",
        &GetAnalyticsOverviewRequest {
            scope: scope.into(),
            range: range.into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn analytics_series(
    organization_id: &str,
    project_id: Option<&str>,
    environment_id: Option<&str>,
    connection_id: Option<&str>,
    period_seconds: i64,
    metric: crate::proto::rustyauth::analytics::v1::AnalyticsMetric,
) -> Result<crate::proto::rustyauth::analytics::v1::MetricSeries, ClientError> {
    use crate::proto::rustyauth::analytics::v1::QueryMetricSeriesRequest;
    let (scope, range) = analytics_query(
        organization_id,
        project_id,
        environment_id,
        connection_id,
        period_seconds,
    )?;
    rpc(
        ANALYTICS_PREFIX,
        "QueryMetricSeries",
        &QueryMetricSeriesRequest {
            scope: scope.into(),
            range: range.into(),
            metric: metric.into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn analytics_funnel(
    organization_id: &str,
    project_id: Option<&str>,
    environment_id: Option<&str>,
    connection_id: Option<&str>,
    period_seconds: i64,
) -> Result<crate::proto::rustyauth::analytics::v1::AuthenticationFunnel, ClientError> {
    use crate::proto::rustyauth::analytics::v1::GetAuthenticationFunnelRequest;
    let (scope, range) = analytics_query(
        organization_id,
        project_id,
        environment_id,
        connection_id,
        period_seconds,
    )?;
    rpc(
        ANALYTICS_PREFIX,
        "GetAuthenticationFunnel",
        &GetAuthenticationFunnelRequest {
            scope: scope.into(),
            range: range.into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn analytics_failures(
    organization_id: &str,
    project_id: Option<&str>,
    environment_id: Option<&str>,
    connection_id: Option<&str>,
    period_seconds: i64,
) -> Result<crate::proto::rustyauth::analytics::v1::FailureBreakdown, ClientError> {
    use crate::proto::rustyauth::analytics::v1::GetFailureBreakdownRequest;
    let (scope, range) = analytics_query(
        organization_id,
        project_id,
        environment_id,
        connection_id,
        period_seconds,
    )?;
    rpc(
        ANALYTICS_PREFIX,
        "GetFailureBreakdown",
        &GetFailureBreakdownRequest {
            scope: scope.into(),
            range: range.into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn analytics_compare(
    scopes: Vec<crate::proto::rustyauth::analytics::v1::AnalyticsScope>,
    period_seconds: i64,
) -> Result<crate::proto::rustyauth::analytics::v1::CompareScopesResponse, ClientError> {
    use crate::proto::rustyauth::analytics::v1::CompareScopesRequest;
    let first = scopes.first().ok_or_else(|| {
        ClientError("At least one analytics comparison scope is required.".into())
    })?;
    let (_, range) = analytics_query(
        &first.organization_id,
        (!first.project_id.is_empty()).then_some(first.project_id.as_str()),
        (!first.environment_id.is_empty()).then_some(first.environment_id.as_str()),
        (!first.connection_id.is_empty()).then_some(first.connection_id.as_str()),
        period_seconds,
    )?;
    rpc(
        ANALYTICS_PREFIX,
        "CompareScopes",
        &CompareScopesRequest {
            scopes,
            range: range.into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn analytics_policy(
    organization_id: &str,
) -> Result<crate::proto::rustyauth::analytics::v1::AnalyticsPolicy, ClientError> {
    use crate::proto::rustyauth::analytics::v1::GetAnalyticsPolicyRequest;
    rpc(
        ANALYTICS_PREFIX,
        "GetAnalyticsPolicy",
        &GetAnalyticsPolicyRequest {
            organization_id: organization_id.to_owned(),
            ..Default::default()
        },
    )
    .await
}

pub async fn update_analytics_policy(
    policy: &crate::proto::rustyauth::analytics::v1::AnalyticsPolicy,
    enabled: bool,
) -> Result<crate::proto::rustyauth::analytics::v1::AnalyticsPolicy, ClientError> {
    use crate::proto::rustyauth::analytics::v1::UpdateAnalyticsPolicyRequest;
    rpc(
        ANALYTICS_PREFIX,
        "UpdateAnalyticsPolicy",
        &UpdateAnalyticsPolicyRequest {
            organization_id: policy.organization_id.clone(),
            enabled,
            canonical_retention_days: policy.canonical_retention_days,
            residency_mode: policy.residency_mode,
            max_buckets_per_minute_per_realm: policy.max_buckets_per_minute_per_realm,
            request_id: uuid::Uuid::new_v4().to_string(),
            reason: "Operator changed central analytics policy in the Fleet console.".into(),
            ..Default::default()
        },
    )
    .await
}

fn analytics_query(
    organization_id: &str,
    project_id: Option<&str>,
    environment_id: Option<&str>,
    connection_id: Option<&str>,
    period_seconds: i64,
) -> Result<
    (
        crate::proto::rustyauth::analytics::v1::AnalyticsScope,
        crate::proto::rustyauth::analytics::v1::AnalyticsRange,
    ),
    ClientError,
> {
    use crate::proto::rustyauth::analytics::v1::{
        AnalyticsGranularity, AnalyticsRange, AnalyticsScope, AnalyticsScopeKind,
    };
    let ends_at = time::OffsetDateTime::now_utc()
        .unix_timestamp_nanos()
        .checked_div(1_000_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| ClientError("The current clock is outside the supported range.".into()))?;
    let period_milliseconds = period_seconds
        .clamp(300, 28 * 24 * 60 * 60)
        .saturating_mul(1_000);
    let kind = if connection_id.is_some() {
        AnalyticsScopeKind::Realm
    } else if environment_id.is_some() {
        AnalyticsScopeKind::Environment
    } else if project_id.is_some() {
        AnalyticsScopeKind::Project
    } else {
        AnalyticsScopeKind::Organization
    };
    Ok((
        AnalyticsScope {
            kind: kind.into(),
            organization_id: organization_id.to_owned(),
            project_id: project_id.unwrap_or_default().to_owned(),
            environment_id: environment_id.unwrap_or_default().to_owned(),
            connection_id: connection_id.unwrap_or_default().to_owned(),
            ..Default::default()
        },
        AnalyticsRange {
            starts_at_unix_milliseconds: ends_at.saturating_sub(period_milliseconds),
            ends_at_unix_milliseconds: ends_at,
            granularity: if period_seconds > 7 * 24 * 60 * 60 {
                AnalyticsGranularity::OneHour
            } else {
                AnalyticsGranularity::FiveMinutes
            }
            .into(),
            ..Default::default()
        },
    ))
}

pub async fn realm_operations(
    connection: &RealmConnection,
    period_seconds: i64,
) -> Result<FleetRealmOperations, ClientError> {
    use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

    let ends_at = OffsetDateTime::now_utc();
    let starts_at = ends_at - Duration::seconds(period_seconds.clamp(300, 28 * 24 * 60 * 60));
    rpc(
        FLEET_PREFIX,
        "GetRealmOperations",
        &GetRealmOperationsRequest {
            organization_id: connection.organization_id.to_owned(),
            project_id: connection.project_id.to_owned(),
            environment_id: connection.environment_id.to_owned(),
            connection_id: connection.id.to_owned(),
            user_page_size: 25,
            event_page_size: 50,
            metrics_starts_at: starts_at
                .format(&Rfc3339)
                .map_err(|_| ClientError("Could not format the operations range.".into()))?,
            metrics_ends_at: ends_at
                .format(&Rfc3339)
                .map_err(|_| ClientError("Could not format the operations range.".into()))?,
            service_account_page_size: 25,
            webhook_page_size: 25,
            ..Default::default()
        },
    )
    .await
}

pub async fn execute_realm_mutation(
    connection: &RealmConnection,
    operation: crate::proto::rustyauth::management::v1::RemoteMutationOperation,
    target_id: &str,
    secondary_id: &str,
    enabled: bool,
    reason: &str,
) -> Result<FleetRealmMutationResult, ClientError> {
    use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

    let expires_at = (OffsetDateTime::now_utc() + Duration::minutes(2))
        .format(&Rfc3339)
        .map_err(|_| ClientError("Could not format the mutation deadline.".into()))?;
    rpc(
        FLEET_PREFIX,
        "ExecuteRealmMutation",
        &ExecuteRealmMutationRequest {
            organization_id: connection.organization_id.to_owned(),
            project_id: connection.project_id.to_owned(),
            environment_id: connection.environment_id.to_owned(),
            connection_id: connection.id.to_owned(),
            mutation: MutationContext {
                request_id: new_request_id(),
                reason: reason.trim().to_owned(),
                ..Default::default()
            }
            .into(),
            expires_at,
            operation: operation.into(),
            target_id: target_id.trim().to_owned(),
            secondary_id: secondary_id.trim().to_owned(),
            enabled,
            ..Default::default()
        },
    )
    .await
}

pub async fn organizations() -> Result<Vec<Organization>, ClientError> {
    let response: ListOrganizationsResponse = rpc(
        FLEET_PREFIX,
        "ListOrganizations",
        &ListOrganizationsRequest {
            page_size: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(response.organizations)
}

pub async fn create_organization(slug: &str, name: &str) -> Result<Organization, ClientError> {
    rpc(
        FLEET_PREFIX,
        "CreateOrganization",
        &CreateOrganizationRequest {
            slug: slug.to_owned(),
            name: name.to_owned(),
            mutation: MutationContext {
                request_id: new_request_id(),
                reason: "Created from the Fleet dashboard".into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn projects(organization_id: &str) -> Result<Vec<Project>, ClientError> {
    let response: ListProjectsResponse = rpc(
        FLEET_PREFIX,
        "ListProjects",
        &ListProjectsRequest {
            organization_id: organization_id.to_owned(),
            page_size: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(response.projects)
}

pub async fn create_project(
    organization_id: &str,
    slug: &str,
    name: &str,
) -> Result<Project, ClientError> {
    rpc(
        FLEET_PREFIX,
        "CreateProject",
        &CreateProjectRequest {
            organization_id: organization_id.to_owned(),
            slug: slug.to_owned(),
            name: name.to_owned(),
            description: String::new(),
            mutation: MutationContext {
                request_id: new_request_id(),
                reason: "Created from the Fleet dashboard".into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn environments(
    organization_id: &str,
    project_id: &str,
) -> Result<Vec<Environment>, ClientError> {
    let response: ListEnvironmentsResponse = rpc(
        FLEET_PREFIX,
        "ListEnvironments",
        &ListEnvironmentsRequest {
            organization_id: organization_id.to_owned(),
            project_id: project_id.to_owned(),
            page_size: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(response.environments)
}

pub async fn create_environment(
    organization_id: &str,
    project_id: &str,
    slug: &str,
    name: &str,
    kind: EnvironmentKind,
) -> Result<Environment, ClientError> {
    rpc(
        FLEET_PREFIX,
        "CreateEnvironment",
        &CreateEnvironmentRequest {
            organization_id: organization_id.to_owned(),
            project_id: project_id.to_owned(),
            slug: slug.to_owned(),
            name: name.to_owned(),
            kind: kind.into(),
            provider: "Railway".into(),
            region: "Auto".into(),
            mutation: MutationContext {
                request_id: new_request_id(),
                reason: "Created from the Fleet dashboard".into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn connections(
    organization_id: &str,
    project_id: Option<&str>,
    environment_id: Option<&str>,
) -> Result<Vec<RealmConnection>, ClientError> {
    let response: ListConnectionsResponse = rpc(
        FLEET_PREFIX,
        "ListConnections",
        &ListConnectionsRequest {
            organization_id: organization_id.to_owned(),
            project_id: project_id.unwrap_or_default().to_owned(),
            environment_id: environment_id.unwrap_or_default().to_owned(),
            page_size: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(response.connections)
}

pub async fn audit_events(organization_id: Option<&str>) -> Result<Vec<AuditEvent>, ClientError> {
    let response: ListAuditEventsResponse = rpc(
        FLEET_PREFIX,
        "ListAuditEvents",
        &ListAuditEventsRequest {
            organization_id: organization_id.unwrap_or_default().to_owned(),
            page_size: 100,
            ..Default::default()
        },
    )
    .await?;
    Ok(response.events)
}

pub async fn begin_connection(
    organization_id: &str,
    project_id: &str,
    environment_id: &str,
    endpoint: &str,
    mode: ConnectionMode,
    pairing_code: &str,
) -> Result<ConnectionAttempt, ClientError> {
    rpc(
        FLEET_PREFIX,
        "BeginConnection",
        &BeginConnectionRequest {
            organization_id: organization_id.to_owned(),
            project_id: project_id.to_owned(),
            environment_id: environment_id.to_owned(),
            mode: mode.into(),
            management_endpoint: endpoint.to_owned(),
            pairing_code: pairing_code.to_owned(),
            mutation: MutationContext {
                request_id: new_request_id(),
                reason: "Pair realm from the Fleet dashboard".into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn complete_connection(
    attempt_id: &str,
    pairing_code: &str,
) -> Result<RealmConnection, ClientError> {
    rpc(
        FLEET_PREFIX,
        "CompleteConnection",
        &CompleteConnectionRequest {
            attempt_id: attempt_id.to_owned(),
            pairing_code: pairing_code.to_owned(),
            mutation: MutationContext {
                request_id: new_request_id(),
                reason: "Complete realm pairing from the Fleet dashboard".into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        },
    )
    .await
}

pub async fn rotate_connection(
    connection: &RealmConnection,
    reason: &str,
) -> Result<RealmConnection, ClientError> {
    rpc(
        FLEET_PREFIX,
        "RotateConnection",
        &RotateConnectionRequest {
            organization_id: connection.organization_id.clone(),
            project_id: connection.project_id.clone(),
            environment_id: connection.environment_id.clone(),
            connection_id: connection.id.clone(),
            mutation: MutationContext {
                request_id: new_request_id(),
                reason: reason.to_owned(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        },
    )
    .await
}

#[cfg(target_arch = "wasm32")]
pub async fn sign_out() -> Result<(), ClientError> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{RequestCredentials, RequestInit, RequestMode, Response};

    let init = RequestInit::new();
    init.set_method("POST");
    init.set_mode(RequestMode::SameOrigin);
    init.set_credentials(RequestCredentials::SameOrigin);
    let request =
        web_sys::Request::new_with_str_and_init("/v1/sign-out", &init).map_err(js_error)?;
    let response = JsFuture::from(
        web_sys::window()
            .ok_or_else(|| ClientError("Browser window is unavailable.".into()))?
            .fetch_with_request(&request),
    )
    .await
    .map_err(js_error)?
    .dyn_into::<Response>()
    .map_err(|_| ClientError("RustyAuth returned an invalid response.".into()))?;
    if response.ok() {
        Ok(())
    } else {
        Err(ClientError("RustyAuth could not close the session.".into()))
    }
}

#[cfg(target_arch = "wasm32")]
pub async fn mint_device_token() -> Result<DeviceToken, ClientError> {
    let response = fetch_json(
        "/v1/device-tokens",
        &serde_json::Value::Object(Default::default()),
    )
    .await?;
    Ok(DeviceToken {
        token: response
            .get("token")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ClientError("RustyAuth returned an invalid device token.".into()))?
            .to_owned(),
        expires_at: response
            .get("expiresAt")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| ClientError("RustyAuth returned an invalid device expiry.".into()))?,
    })
}

#[cfg(target_arch = "wasm32")]
pub async fn rotate_recovery_codes() -> Result<Vec<String>, ClientError> {
    let response = fetch_json(
        "/v1/account/recovery-codes",
        &serde_json::Value::Object(Default::default()),
    )
    .await?;
    response
        .get("recoveryCodes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| ClientError("RustyAuth returned invalid recovery codes.".into()))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| ClientError("RustyAuth returned invalid recovery codes.".into()))
        })
        .collect()
}

#[cfg(target_arch = "wasm32")]
pub async fn request_identifier_verification(
    kind: &str,
    value: &str,
) -> Result<IdentifierVerificationChallenge, ClientError> {
    let response = fetch_json(
        "/v1/account/identifiers/verification/request",
        &serde_json::json!({ "identifier": { "type": kind, "value": value } }),
    )
    .await?;
    Ok(IdentifierVerificationChallenge {
        challenge_id: response
            .get("challengeId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ClientError("RustyAuth returned an invalid verification challenge.".into())
            })?
            .to_owned(),
        expires_at: response
            .get("expiresAt")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ClientError("RustyAuth returned an invalid verification expiry.".into())
            })?,
        delivered: response
            .get("delivered")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        development_code: response
            .get("developmentCode")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    })
}

#[cfg(target_arch = "wasm32")]
pub async fn complete_identifier_verification(
    challenge_id: &str,
    code: &str,
) -> Result<(), ClientError> {
    fetch_no_content(
        "/v1/account/identifiers/verification/verify",
        &serde_json::json!({ "challengeId": challenge_id, "code": code }),
    )
    .await
}

#[cfg(target_arch = "wasm32")]
pub async fn revoke_all_sessions() -> Result<(), ClientError> {
    fetch_no_content(
        "/v1/sessions/revoke-all",
        &serde_json::Value::Object(Default::default()),
    )
    .await
}

#[cfg(target_arch = "wasm32")]
pub async fn register_operator_passkey(
    email: &str,
    display_name: &str,
    enrolment: &EnrollmentCredential,
) -> Result<(), ClientError> {
    use js_sys::{Function, Promise, Reflect};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let (bootstrap_token, invitation_code) = match enrolment {
        EnrollmentCredential::DevelopmentBootstrap(value) => (Some(value.as_str()), None),
        EnrollmentCredential::ProductionInvitation(value) => (None, Some(value.as_str())),
    };
    let options = fetch_json_with_bootstrap(
        "/v1/passkeys/registration/options",
        &serde_json::json!({
            "email": email,
            "displayName": display_name,
            "invitationCode": invitation_code,
        }),
        bootstrap_token,
    )
    .await?;
    let ceremony_id = options
        .get("ceremonyId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ClientError("RustyAuth returned an invalid ceremony.".into()))?;
    let options_json = public_key_options(&options)?;
    let public_key = serde_wasm_bindgen::to_value(options_json)
        .map_err(|error| ClientError(error.to_string()))?;
    let constructor = Reflect::get(&js_sys::global(), &JsValue::from_str("PublicKeyCredential"))
        .map_err(js_error)?;
    let parser = Reflect::get(
        &constructor,
        &JsValue::from_str("parseCreationOptionsFromJSON"),
    )
    .map_err(js_error)?
    .dyn_into::<Function>()
    .map_err(|_| ClientError("This browser cannot parse passkey options.".into()))?;
    let parsed = parser.call1(&constructor, &public_key).map_err(js_error)?;
    let request = js_sys::Object::new();
    Reflect::set(&request, &JsValue::from_str("publicKey"), &parsed).map_err(js_error)?;
    let credentials = web_sys::window()
        .ok_or_else(|| ClientError("Browser window is unavailable.".into()))?
        .navigator()
        .credentials();
    let create = Reflect::get(credentials.as_ref(), &JsValue::from_str("create"))
        .map_err(js_error)?
        .dyn_into::<Function>()
        .map_err(|_| ClientError("This browser cannot create passkeys.".into()))?;
    let promise = create
        .call1(credentials.as_ref(), request.as_ref())
        .map_err(js_error)?
        .dyn_into::<Promise>()
        .map_err(|_| ClientError("This browser returned an invalid passkey request.".into()))?;
    let credential = JsFuture::from(promise).await.map_err(js_error)?;
    let to_json = Reflect::get(&credential, &JsValue::from_str("toJSON"))
        .map_err(js_error)?
        .dyn_into::<Function>()
        .map_err(|_| ClientError("This browser cannot serialize a passkey response.".into()))?;
    let response = to_json.call0(&credential).map_err(js_error)?;
    let response: serde_json::Value =
        serde_wasm_bindgen::from_value(response).map_err(|error| ClientError(error.to_string()))?;
    fetch_json_with_bootstrap(
        "/v1/passkeys/registration/verify",
        &serde_json::json!({ "ceremonyId": ceremony_id, "response": response }),
        bootstrap_token,
    )
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub async fn recover_operator_passkey(
    email: &str,
    recovery_code: &str,
    label: &str,
) -> Result<(), ClientError> {
    use js_sys::{Function, Promise, Reflect};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let options = fetch_json(
        "/v1/passkeys/recovery/options",
        &serde_json::json!({
            "email": email,
            "recoveryCode": recovery_code,
            "label": label,
        }),
    )
    .await?;
    let ceremony_id = options
        .get("ceremonyId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ClientError("RustyAuth returned an invalid recovery ceremony.".into()))?;
    let public_key = serde_wasm_bindgen::to_value(public_key_options(&options)?)
        .map_err(|error| ClientError(error.to_string()))?;
    let constructor = Reflect::get(&js_sys::global(), &JsValue::from_str("PublicKeyCredential"))
        .map_err(js_error)?;
    let parser = Reflect::get(
        &constructor,
        &JsValue::from_str("parseCreationOptionsFromJSON"),
    )
    .map_err(js_error)?
    .dyn_into::<Function>()
    .map_err(|_| ClientError("This browser cannot parse passkey options.".into()))?;
    let parsed = parser.call1(&constructor, &public_key).map_err(js_error)?;
    let request = js_sys::Object::new();
    Reflect::set(&request, &JsValue::from_str("publicKey"), &parsed).map_err(js_error)?;
    let credentials = web_sys::window()
        .ok_or_else(|| ClientError("Browser window is unavailable.".into()))?
        .navigator()
        .credentials();
    let create = Reflect::get(credentials.as_ref(), &JsValue::from_str("create"))
        .map_err(js_error)?
        .dyn_into::<Function>()
        .map_err(|_| ClientError("This browser cannot create passkeys.".into()))?;
    let promise = create
        .call1(credentials.as_ref(), request.as_ref())
        .map_err(js_error)?
        .dyn_into::<Promise>()
        .map_err(|_| ClientError("This browser returned an invalid passkey request.".into()))?;
    let credential = JsFuture::from(promise).await.map_err(js_error)?;
    let to_json = Reflect::get(&credential, &JsValue::from_str("toJSON"))
        .map_err(js_error)?
        .dyn_into::<Function>()
        .map_err(|_| ClientError("This browser cannot serialize a passkey response.".into()))?;
    let response = to_json.call0(&credential).map_err(js_error)?;
    let response: serde_json::Value =
        serde_wasm_bindgen::from_value(response).map_err(|error| ClientError(error.to_string()))?;
    fetch_json(
        "/v1/passkeys/recovery/verify",
        &serde_json::json!({ "ceremonyId": ceremony_id, "response": response }),
    )
    .await?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn register_operator_passkey(
    _email: &str,
    _display_name: &str,
    _enrolment: &EnrollmentCredential,
) -> Result<(), ClientError> {
    Err(ClientError(
        "Native passkey enrolment requires the platform credential adapter.".into(),
    ))
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn recover_operator_passkey(
    _email: &str,
    _recovery_code: &str,
    _label: &str,
) -> Result<(), ClientError> {
    Err(ClientError(
        "Native passkey recovery requires the platform credential adapter.".into(),
    ))
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn sign_out() -> Result<(), ClientError> {
    let entry = vault_entry()?;
    let token = entry.get_password().ok();
    let server_result = match token {
        Some(token) if valid_device_token(&token) => {
            let response = native_client()?
                .post(native_url("/v1/sign-out")?)
                .bearer_auth(token)
                .send()
                .await
                .map_err(native_transport_error)?;
            let status = response.status();
            let _ = read_native_response(response).await?;
            if status.is_success() {
                Ok(())
            } else {
                Err(ClientError(format!(
                    "RustyAuth could not close the device session (HTTP {}).",
                    status.as_u16()
                )))
            }
        }
        _ => Ok(()),
    };
    match entry.delete_credential() {
        Ok(()) | Err(VaultError::NoEntry) => server_result,
        Err(error) => Err(ClientError(format!(
            "The device token could not be removed from the operating-system vault: {error}"
        ))),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn mint_device_token() -> Result<DeviceToken, ClientError> {
    Err(ClientError(
        "Create a native-console token from Account security in the browser dashboard.".into(),
    ))
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn rotate_recovery_codes() -> Result<Vec<String>, ClientError> {
    Err(ClientError(
        "Native account security requires the platform transport adapter.".into(),
    ))
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn request_identifier_verification(
    _kind: &str,
    _value: &str,
) -> Result<IdentifierVerificationChallenge, ClientError> {
    Err(ClientError(
        "Native account security requires the platform transport adapter.".into(),
    ))
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn complete_identifier_verification(
    _challenge_id: &str,
    _code: &str,
) -> Result<(), ClientError> {
    Err(ClientError(
        "Native account security requires the platform transport adapter.".into(),
    ))
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn revoke_all_sessions() -> Result<(), ClientError> {
    Err(ClientError(
        "Native account security requires the platform transport adapter.".into(),
    ))
}

#[cfg(target_arch = "wasm32")]
pub async fn authenticate_passkey(email: &str) -> Result<(), ClientError> {
    use js_sys::{Function, Promise, Reflect};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let options = fetch_json(
        "/v1/passkeys/authentication/options",
        &serde_json::json!({ "email": email }),
    )
    .await?;
    let ceremony_id = options
        .get("ceremonyId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ClientError("RustyAuth returned an invalid ceremony.".into()))?;
    let public_key = serde_wasm_bindgen::to_value(public_key_options(&options)?)
        .map_err(|error| ClientError(error.to_string()))?;
    let constructor = Reflect::get(&js_sys::global(), &JsValue::from_str("PublicKeyCredential"))
        .map_err(js_error)?;
    let parser = Reflect::get(
        &constructor,
        &JsValue::from_str("parseRequestOptionsFromJSON"),
    )
    .map_err(js_error)?
    .dyn_into::<Function>()
    .map_err(|_| ClientError("This browser cannot parse passkey options.".into()))?;
    let parsed = parser.call1(&constructor, &public_key).map_err(js_error)?;
    let request = js_sys::Object::new();
    Reflect::set(&request, &JsValue::from_str("publicKey"), &parsed).map_err(js_error)?;
    let credentials = web_sys::window()
        .ok_or_else(|| ClientError("Browser window is unavailable.".into()))?
        .navigator()
        .credentials();
    let get = Reflect::get(credentials.as_ref(), &JsValue::from_str("get"))
        .map_err(js_error)?
        .dyn_into::<Function>()
        .map_err(|_| ClientError("This browser cannot request passkeys.".into()))?;
    let promise = get
        .call1(credentials.as_ref(), request.as_ref())
        .map_err(js_error)?
        .dyn_into::<Promise>()
        .map_err(|_| ClientError("This browser returned an invalid passkey request.".into()))?;
    let credential = JsFuture::from(promise).await.map_err(js_error)?;
    let to_json = Reflect::get(&credential, &JsValue::from_str("toJSON"))
        .map_err(js_error)?
        .dyn_into::<Function>()
        .map_err(|_| ClientError("This browser cannot serialize a passkey response.".into()))?;
    let response = to_json.call0(&credential).map_err(js_error)?;
    let response: serde_json::Value =
        serde_wasm_bindgen::from_value(response).map_err(|error| ClientError(error.to_string()))?;
    fetch_json(
        "/v1/passkeys/authentication/verify",
        &serde_json::json!({ "ceremonyId": ceremony_id, "response": response }),
    )
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub async fn step_up_passkey() -> Result<(), ClientError> {
    use js_sys::{Function, Promise, Reflect};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let options = fetch_json(
        "/v1/passkeys/step-up/options",
        &serde_json::Value::Object(Default::default()),
    )
    .await?;
    let ceremony_id = options
        .get("ceremonyId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ClientError("RustyAuth returned an invalid step-up ceremony.".into()))?;
    let public_key = serde_wasm_bindgen::to_value(public_key_options(&options)?)
        .map_err(|error| ClientError(error.to_string()))?;
    let constructor = Reflect::get(&js_sys::global(), &JsValue::from_str("PublicKeyCredential"))
        .map_err(js_error)?;
    let parser = Reflect::get(
        &constructor,
        &JsValue::from_str("parseRequestOptionsFromJSON"),
    )
    .map_err(js_error)?
    .dyn_into::<Function>()
    .map_err(|_| ClientError("This browser cannot parse passkey options.".into()))?;
    let parsed = parser.call1(&constructor, &public_key).map_err(js_error)?;
    let request = js_sys::Object::new();
    Reflect::set(&request, &JsValue::from_str("publicKey"), &parsed).map_err(js_error)?;
    let credentials = web_sys::window()
        .ok_or_else(|| ClientError("Browser window is unavailable.".into()))?
        .navigator()
        .credentials();
    let get = Reflect::get(credentials.as_ref(), &JsValue::from_str("get"))
        .map_err(js_error)?
        .dyn_into::<Function>()
        .map_err(|_| ClientError("This browser cannot request passkeys.".into()))?;
    let promise = get
        .call1(credentials.as_ref(), request.as_ref())
        .map_err(js_error)?
        .dyn_into::<Promise>()
        .map_err(|_| ClientError("This browser returned an invalid passkey request.".into()))?;
    let credential = JsFuture::from(promise).await.map_err(js_error)?;
    let to_json = Reflect::get(&credential, &JsValue::from_str("toJSON"))
        .map_err(js_error)?
        .dyn_into::<Function>()
        .map_err(|_| ClientError("This browser cannot serialize a passkey response.".into()))?;
    let response = to_json.call0(&credential).map_err(js_error)?;
    let response: serde_json::Value =
        serde_wasm_bindgen::from_value(response).map_err(|error| ClientError(error.to_string()))?;
    fetch_json(
        "/v1/passkeys/step-up/verify",
        &serde_json::json!({ "ceremonyId": ceremony_id, "response": response }),
    )
    .await?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn authenticate_passkey(device_token: &str) -> Result<(), ClientError> {
    let token = device_token.trim();
    if !valid_device_token(token) {
        return Err(ClientError(
            "Paste a valid RustyAuth native-console token (rdt_…).".into(),
        ));
    }
    let entry = vault_entry()?;
    entry.set_password(token).map_err(|error| {
        ClientError(format!(
            "The device token could not be saved in the operating-system vault: {error}"
        ))
    })?;
    if let Err(error) = current_operator().await {
        let _ = entry.delete_credential();
        return Err(ClientError(format!(
            "RustyAuth rejected the native-console token: {}",
            error.0
        )));
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn step_up_passkey() -> Result<(), ClientError> {
    // The device token itself was minted by a fresh browser passkey step-up.
    // The server enforces the remaining five-minute window on every Administer
    // RPC and will require a newly minted token after it closes.
    current_device_token().map(|_| ())
}

#[cfg(target_arch = "wasm32")]
async fn rpc<Request, Response>(
    service_prefix: &str,
    method: &str,
    request: &Request,
) -> Result<Response, ClientError>
where
    Request: Message,
    Response: Message,
{
    use js_sys::Uint8Array;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{RequestCredentials, RequestInit, RequestMode, Response as WebResponse};

    let bytes = request.encode_to_vec();
    let body = Uint8Array::from(bytes.as_slice());
    let init = RequestInit::new();
    init.set_method("POST");
    init.set_mode(RequestMode::SameOrigin);
    init.set_credentials(RequestCredentials::SameOrigin);
    init.set_body(&body);
    let web_request =
        web_sys::Request::new_with_str_and_init(&format!("{service_prefix}{method}"), &init)
            .map_err(js_error)?;
    web_request
        .headers()
        .set("Content-Type", "application/proto")
        .map_err(js_error)?;
    web_request
        .headers()
        .set("Connect-Protocol-Version", "1")
        .map_err(js_error)?;
    let response = JsFuture::from(
        web_sys::window()
            .ok_or_else(|| ClientError("Browser window is unavailable.".into()))?
            .fetch_with_request(&web_request),
    )
    .await
    .map_err(js_error)?
    .dyn_into::<WebResponse>()
    .map_err(|_| ClientError("Fleet returned an invalid response.".into()))?;
    if !response.ok() {
        return Err(ClientError(connect_error_message(&response).await));
    }
    let buffer = JsFuture::from(response.array_buffer().map_err(js_error)?)
        .await
        .map_err(js_error)?;
    let bytes = Uint8Array::new(&buffer).to_vec();
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ClientError(
            "Fleet response exceeded the safety limit.".into(),
        ));
    }
    Response::decode_from_slice(&bytes)
        .map_err(|_| ClientError("Fleet returned invalid Protobuf.".into()))
}

#[cfg(not(target_arch = "wasm32"))]
async fn rpc<Request, Response>(
    service_prefix: &str,
    method: &str,
    request: &Request,
) -> Result<Response, ClientError>
where
    Request: Message,
    Response: Message,
{
    let token = current_device_token()?;
    let response = native_client()?
        .post(native_url(&format!("{service_prefix}{method}"))?)
        .header("Connect-Protocol-Version", "1")
        .header(reqwest::header::CONTENT_TYPE, "application/proto")
        .bearer_auth(token)
        .body(request.encode_to_vec())
        .send()
        .await
        .map_err(native_transport_error)?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = read_native_response(response).await?;
    if !status.is_success() {
        let message = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| value.get("message")?.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("Fleet request failed with HTTP {}.", status.as_u16()));
        return Err(ClientError(message));
    }
    if !content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/proto"))
    {
        return Err(ClientError(
            "Fleet returned an unexpected response content type.".into(),
        ));
    }
    Response::decode_from_slice(&bytes)
        .map_err(|_| ClientError("Fleet returned invalid Protobuf.".into()))
}

#[cfg(not(target_arch = "wasm32"))]
fn native_origin() -> Result<reqwest::Url, ClientError> {
    let configured = std::env::var("RUSTYAUTH_DASHBOARD_API_ORIGIN").map_err(|_| {
        ClientError("Set RUSTYAUTH_DASHBOARD_API_ORIGIN to the RustyAuth HTTPS origin.".into())
    })?;
    validate_native_origin(&configured)
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_native_origin(configured: &str) -> Result<reqwest::Url, ClientError> {
    let url = reqwest::Url::parse(configured)
        .map_err(|_| ClientError("The RustyAuth API origin is not a valid URL.".into()))?;
    let clean_path = matches!(url.path(), "" | "/");
    let clean_authority = url.username().is_empty() && url.password().is_none();
    let clean_suffix = url.query().is_none() && url.fragment().is_none();
    let secure_transport = match url.scheme() {
        "https" => url.host().is_some(),
        "http" => url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        }),
        _ => false,
    };
    if !clean_path || !clean_authority || !clean_suffix || !secure_transport {
        return Err(ClientError(
            "Use an HTTPS RustyAuth origin; plain HTTP is allowed only on loopback.".into(),
        ));
    }
    Ok(url)
}

#[cfg(not(target_arch = "wasm32"))]
fn native_url(path: &str) -> Result<reqwest::Url, ClientError> {
    let mut url = native_origin()?;
    url.set_path(path);
    Ok(url)
}

#[cfg(not(target_arch = "wasm32"))]
fn native_client() -> Result<&'static reqwest::Client, ClientError> {
    use std::sync::OnceLock;

    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(10))
                .timeout(std::time::Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| ClientError(format!("The native HTTP client could not start: {error}")))
}

#[cfg(not(target_arch = "wasm32"))]
async fn read_native_response(mut response: reqwest::Response) -> Result<Vec<u8>, ClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(ClientError(
            "RustyAuth response exceeded the safety limit.".into(),
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(native_transport_error)? {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(ClientError(
                "RustyAuth response exceeded the safety limit.".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(not(target_arch = "wasm32"))]
fn native_transport_error(error: reqwest::Error) -> ClientError {
    if error.is_timeout() {
        ClientError("RustyAuth did not respond before the native safety timeout.".into())
    } else {
        ClientError("The native console could not reach RustyAuth securely.".into())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn vault_entry() -> Result<VaultEntry, ClientError> {
    initialize_mobile_vault()?;
    let origin = native_origin()?;
    VaultEntry::new(VAULT_SERVICE, origin.as_str()).map_err(|error| {
        ClientError(format!(
            "The operating-system credential vault is unavailable: {error}"
        ))
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn current_device_token() -> Result<String, ClientError> {
    let token = vault_entry()?.get_password().map_err(|error| match error {
        VaultError::NoEntry => ClientError(
            "This device is not connected. Mint a native-console token in the browser first."
                .into(),
        ),
        other => ClientError(format!(
            "The operating-system credential vault could not be read: {other}"
        )),
    })?;
    valid_device_token(&token)
        .then_some(token)
        .ok_or_else(|| ClientError("The stored native-console token is invalid.".into()))
}

#[cfg(all(
    not(target_arch = "wasm32"),
    not(any(target_os = "ios", target_os = "android"))
))]
fn initialize_mobile_vault() -> Result<(), ClientError> {
    Ok(())
}

#[cfg(target_os = "ios")]
fn initialize_mobile_vault() -> Result<(), ClientError> {
    use std::sync::OnceLock;

    static INITIALIZED: OnceLock<Result<(), String>> = OnceLock::new();
    INITIALIZED
        .get_or_init(|| {
            let store = apple_native_keyring_store::protected::Store::new()
                .map_err(|error| error.to_string())?;
            keyring_core::set_default_store(store);
            Ok(())
        })
        .as_ref()
        .map_err(|error| ClientError(format!("The iOS protected-data vault failed: {error}")))
}

#[cfg(target_os = "android")]
fn initialize_mobile_vault() -> Result<(), ClientError> {
    use std::sync::OnceLock;

    static INITIALIZED: OnceLock<Result<(), String>> = OnceLock::new();
    INITIALIZED
        .get_or_init(|| {
            let store =
                android_native_keyring_store::Store::new().map_err(|error| error.to_string())?;
            keyring_core::set_default_store(store);
            Ok(())
        })
        .as_ref()
        .map_err(|error| ClientError(format!("The Android Keystore vault failed: {error}")))
}

#[cfg(not(target_arch = "wasm32"))]
fn valid_device_token(token: &str) -> bool {
    token.starts_with(DEVICE_TOKEN_PREFIX)
        && token.len() >= 36
        && token.len() <= 256
        && !token.chars().any(char::is_whitespace)
}

#[cfg(target_arch = "wasm32")]
async fn fetch_json(
    path: &str,
    value: &serde_json::Value,
) -> Result<serde_json::Value, ClientError> {
    fetch_json_with_bootstrap(path, value, None).await
}

#[cfg(target_arch = "wasm32")]
async fn fetch_json_with_bootstrap(
    path: &str,
    value: &serde_json::Value,
    bootstrap_token: Option<&str>,
) -> Result<serde_json::Value, ClientError> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{RequestCredentials, RequestInit, RequestMode, Response};

    let init = RequestInit::new();
    init.set_method("POST");
    init.set_mode(RequestMode::SameOrigin);
    init.set_credentials(RequestCredentials::SameOrigin);
    init.set_body(&wasm_bindgen::JsValue::from_str(&value.to_string()));
    let request = web_sys::Request::new_with_str_and_init(path, &init).map_err(js_error)?;
    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(js_error)?;
    if let Some(token) = bootstrap_token {
        request
            .headers()
            .set("X-Bootstrap-Token", token)
            .map_err(js_error)?;
    }
    let response = JsFuture::from(
        web_sys::window()
            .ok_or_else(|| ClientError("Browser window is unavailable.".into()))?
            .fetch_with_request(&request),
    )
    .await
    .map_err(js_error)?
    .dyn_into::<Response>()
    .map_err(|_| ClientError("RustyAuth returned an invalid response.".into()))?;
    let body = JsFuture::from(response.text().map_err(js_error)?)
        .await
        .map_err(js_error)?
        .as_string()
        .unwrap_or_default();
    if !response.ok() {
        return Err(ClientError(
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| value.get("error")?.as_str().map(str::to_owned))
                .unwrap_or_else(|| "RustyAuth rejected the request.".into()),
        ));
    }
    serde_json::from_str(&body).map_err(|_| ClientError("RustyAuth returned invalid JSON.".into()))
}

#[cfg(target_arch = "wasm32")]
async fn fetch_no_content(path: &str, value: &serde_json::Value) -> Result<(), ClientError> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{RequestCredentials, RequestInit, RequestMode, Response};

    let init = RequestInit::new();
    init.set_method("POST");
    init.set_mode(RequestMode::SameOrigin);
    init.set_credentials(RequestCredentials::SameOrigin);
    init.set_body(&wasm_bindgen::JsValue::from_str(&value.to_string()));
    let request = web_sys::Request::new_with_str_and_init(path, &init).map_err(js_error)?;
    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(js_error)?;
    let response = JsFuture::from(
        web_sys::window()
            .ok_or_else(|| ClientError("Browser window is unavailable.".into()))?
            .fetch_with_request(&request),
    )
    .await
    .map_err(js_error)?
    .dyn_into::<Response>()
    .map_err(|_| ClientError("RustyAuth returned an invalid response.".into()))?;
    if response.ok() {
        return Ok(());
    }
    Err(ClientError(connect_error_message(&response).await))
}

#[cfg(target_arch = "wasm32")]
fn public_key_options(value: &serde_json::Value) -> Result<&serde_json::Value, ClientError> {
    let options = value
        .get("options")
        .ok_or_else(|| ClientError("RustyAuth returned invalid passkey options.".into()))?;
    Ok(options.get("publicKey").unwrap_or(options))
}

#[cfg(target_arch = "wasm32")]
async fn connect_error_message(response: &web_sys::Response) -> String {
    use wasm_bindgen_futures::JsFuture;
    let body = match response.text() {
        Ok(promise) => JsFuture::from(promise)
            .await
            .ok()
            .and_then(|value| value.as_string())
            .unwrap_or_default(),
        Err(_) => String::new(),
    };
    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| value.get("message")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("Fleet request failed with HTTP {}.", response.status()))
}

#[cfg(target_arch = "wasm32")]
fn js_error(value: wasm_bindgen::JsValue) -> ClientError {
    ClientError(
        value
            .as_string()
            .unwrap_or_else(|| "Browser operation failed.".into()),
    )
}

fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod native_tests {
    use super::{valid_device_token, validate_native_origin};

    #[test]
    fn native_origins_require_tls_except_on_loopback() {
        for allowed in [
            "https://auth.example.com",
            "https://auth.example.com:8443/",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://[::1]:3000",
        ] {
            assert!(validate_native_origin(allowed).is_ok(), "{allowed}");
        }
        for refused in [
            "http://auth.example.com",
            "ftp://auth.example.com",
            "https://user:secret@auth.example.com",
            "https://auth.example.com/control-plane",
            "https://auth.example.com?token=secret",
            "https://auth.example.com/#fragment",
            "not a URL",
        ] {
            assert!(validate_native_origin(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn native_tokens_use_the_dedicated_opaque_namespace() {
        assert!(valid_device_token(&format!("rdt_{}", "a".repeat(43))));
        assert!(!valid_device_token(&"a".repeat(43)));
        assert!(!valid_device_token("rdt_short"));
        assert!(!valid_device_token(&format!(
            "rdt_{} trailing",
            "a".repeat(43)
        )));
    }
}
