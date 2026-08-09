//! Composition and authentication for RustyAuth's private RPC services.

use std::sync::Arc;

use connectrpc::interceptor::{StreamRequest, StreamResponse, UnaryRequest, UnaryResponse};
use connectrpc::{
    ConnectError, ConnectRpcService, ErrorCode, Interceptor, Limits, Next, NextStream,
    PayloadStream,
};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    analytics_rpc::AnalyticsRpc,
    analytics_store::GreptimeAnalyticsStore,
    backup::BackupStore,
    config::{DeploymentRole, Environment, KeyRing},
    event_rpc::EventRpc,
    fleet_rpc::FleetRpc,
    identity_rpc::IdentityRpc,
    jwt::JwtIssuer,
    management_rpc::{ManagementRpc, ManagementRpcConfig},
    metrics_rpc::MetricsRpc,
    operator_auth::{OperatorAuthorizer, OperatorCapability},
    organization_rpc::OrganizationRpc,
    rate_limit::RateLimiter,
    service_account_rpc::ServiceAccountRpc,
    store::Store,
    telemetry::{ConnectorHub, ConnectorRpc},
    webhook::WebhookRuntime,
    webhook_rpc::WebhookRpc,
};

const EVENT_SERVICE_PREFIX: &str = "/rustyauth.events.v1.AuthEventService/";
const ANALYTICS_SERVICE_PREFIX: &str = "/rustyauth.analytics.v1.AnalyticsService/";
const FLEET_SERVICE_PREFIX: &str = "/rustyauth.fleet.v1.FleetService/";
const IDENTITY_SERVICE_PREFIX: &str = "/rustyauth.identity.v1.IdentityService/";
const ORGANIZATION_SERVICE_PREFIX: &str = "/rustyauth.organization.v1.OrganizationService/";
const MANAGEMENT_SERVICE_PREFIX: &str = "/rustyauth.management.v1.RealmManagementService/";
const CONNECTOR_SERVICE_PREFIX: &str = "/rustyauth.management.v1.RealmConnectorService/";
const METRICS_SERVICE_PREFIX: &str = "/rustyauth.metrics.v1.MetricsService/";
const SERVICE_ACCOUNT_SERVICE_PREFIX: &str =
    "/rustyauth.service_accounts.v1.ServiceAccountService/";
const WEBHOOK_SERVICE_PREFIX: &str = "/rustyauth.webhooks.v1.WebhookService/";

pub type RpcService = ConnectRpcService<connectrpc::Router>;

/// How one RPC method is authorized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MethodPolicy {
    /// Machine-to-machine only: the service-scoped bearer token.
    Bearer,
    /// The service-scoped bearer token, or a browser operator session holding
    /// the named capability.
    BearerOrOperator(OperatorCapability),
    /// A browser operator session holding the named capability.
    Operator(OperatorCapability),
    /// Unauthenticated at the transport; the handler validates a credential.
    PublicCredentialExchange,
    /// The streaming handler resolves a connection-scoped proof from HELLO.
    HandlerAuthenticatedStreaming,
}

/// Authentication result inserted by the interceptor for handlers that need
/// to apply resource-level checks without re-running transport authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RpcPrincipal {
    Machine,
    Operator,
    PublicCredentialExchange,
    HandlerAuthenticatedStreaming,
}

/// Every RPC method's authorization policy, named one by one.
///
/// This table is deliberately exhaustive rather than pattern-matched on method
/// name prefixes. A new proto method that nobody adds here is denied by
/// `authorize_unary`, and `every_proto_method_has_an_explicit_policy` fails until
/// someone assigns it a policy — so widening the surface is never silent.
const METHOD_POLICIES: &[(&str, &str, MethodPolicy)] = &[
    (
        ANALYTICS_SERVICE_PREFIX,
        "GetAnalyticsOverview",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        ANALYTICS_SERVICE_PREFIX,
        "QueryMetricSeries",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        ANALYTICS_SERVICE_PREFIX,
        "GetAuthenticationFunnel",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        ANALYTICS_SERVICE_PREFIX,
        "GetFailureBreakdown",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        ANALYTICS_SERVICE_PREFIX,
        "GetReportingCoverage",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        ANALYTICS_SERVICE_PREFIX,
        "CompareScopes",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        ANALYTICS_SERVICE_PREFIX,
        "GetAnalyticsPolicy",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        ANALYTICS_SERVICE_PREFIX,
        "UpdateAnalyticsPolicy",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        CONNECTOR_SERVICE_PREFIX,
        "PairOutbound",
        MethodPolicy::PublicCredentialExchange,
    ),
    (
        CONNECTOR_SERVICE_PREFIX,
        "Connect",
        MethodPolicy::HandlerAuthenticatedStreaming,
    ),
    // Event log: consumed by trusted backend services only.
    (EVENT_SERVICE_PREFIX, "Subscribe", MethodPolicy::Bearer),
    // Standalone aggregate metrics contain no identity dimensions, but still
    // require either an operator session or a scoped service-account token.
    (
        METRICS_SERVICE_PREFIX,
        "GetOverview",
        MethodPolicy::BearerOrOperator(OperatorCapability::Read),
    ),
    (
        METRICS_SERVICE_PREFIX,
        "QuerySeries",
        MethodPolicy::BearerOrOperator(OperatorCapability::Read),
    ),
    (
        METRICS_SERVICE_PREFIX,
        "GetAuthenticationFunnel",
        MethodPolicy::BearerOrOperator(OperatorCapability::Read),
    ),
    (
        METRICS_SERVICE_PREFIX,
        "GetFailureBreakdown",
        MethodPolicy::BearerOrOperator(OperatorCapability::Read),
    ),
    // Identity: reads are available to any operator; every mutation needs Support.
    (
        IDENTITY_SERVICE_PREFIX,
        "GetUser",
        MethodPolicy::BearerOrOperator(OperatorCapability::Read),
    ),
    (
        IDENTITY_SERVICE_PREFIX,
        "ListUsers",
        MethodPolicy::BearerOrOperator(OperatorCapability::Read),
    ),
    (
        IDENTITY_SERVICE_PREFIX,
        "SearchUsers",
        MethodPolicy::BearerOrOperator(OperatorCapability::Read),
    ),
    (
        IDENTITY_SERVICE_PREFIX,
        "UpdateProfile",
        MethodPolicy::BearerOrOperator(OperatorCapability::Support),
    ),
    (
        IDENTITY_SERVICE_PREFIX,
        "AddIdentifier",
        MethodPolicy::BearerOrOperator(OperatorCapability::Support),
    ),
    (
        IDENTITY_SERVICE_PREFIX,
        "RemoveIdentifier",
        MethodPolicy::BearerOrOperator(OperatorCapability::Support),
    ),
    (
        IDENTITY_SERVICE_PREFIX,
        "SetPrimaryIdentifier",
        MethodPolicy::BearerOrOperator(OperatorCapability::Support),
    ),
    // Operator-only, deliberately with no bearer path. `BearerOrOperator` accepts
    // the service token *before* consulting the capability, so allowing it here
    // would make AUTH_IDENTITY_RPC_TOKEN Owner-equivalent: attach an allowlisted
    // operator address to any account, mark it verified, and browser bootstrap
    // then mints Owner. Verification is an identity-proofing decision that a
    // machine integration must never make on its own.
    (
        IDENTITY_SERVICE_PREFIX,
        "SetIdentifierVerification",
        MethodPolicy::Operator(OperatorCapability::Administer),
    ),
    (
        IDENTITY_SERVICE_PREFIX,
        "RenamePasskey",
        MethodPolicy::BearerOrOperator(OperatorCapability::Support),
    ),
    (
        IDENTITY_SERVICE_PREFIX,
        "RevokePasskey",
        MethodPolicy::BearerOrOperator(OperatorCapability::Support),
    ),
    // Organization.
    (
        ORGANIZATION_SERVICE_PREFIX,
        "GetOrganization",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        ORGANIZATION_SERVICE_PREFIX,
        "GetCurrentOperator",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        ORGANIZATION_SERVICE_PREFIX,
        "UpdateOrganization",
        MethodPolicy::Operator(OperatorCapability::Administer),
    ),
    (
        ORGANIZATION_SERVICE_PREFIX,
        "ListOperators",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        ORGANIZATION_SERVICE_PREFIX,
        "CreateAccountInvitation",
        MethodPolicy::Operator(OperatorCapability::Administer),
    ),
    (
        ORGANIZATION_SERVICE_PREFIX,
        "ListAccountInvitations",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        ORGANIZATION_SERVICE_PREFIX,
        "RevokeAccountInvitation",
        MethodPolicy::Operator(OperatorCapability::Administer),
    ),
    // Service accounts.
    (
        SERVICE_ACCOUNT_SERVICE_PREFIX,
        "ListServiceAccounts",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        SERVICE_ACCOUNT_SERVICE_PREFIX,
        "GetServiceAccount",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        SERVICE_ACCOUNT_SERVICE_PREFIX,
        "CreateServiceAccount",
        MethodPolicy::Operator(OperatorCapability::Administer),
    ),
    (
        SERVICE_ACCOUNT_SERVICE_PREFIX,
        "UpdateServiceAccount",
        MethodPolicy::Operator(OperatorCapability::Administer),
    ),
    (
        SERVICE_ACCOUNT_SERVICE_PREFIX,
        "CreateCredential",
        MethodPolicy::Operator(OperatorCapability::Administer),
    ),
    (
        SERVICE_ACCOUNT_SERVICE_PREFIX,
        "RevokeCredential",
        MethodPolicy::Operator(OperatorCapability::Administer),
    ),
    (
        SERVICE_ACCOUNT_SERVICE_PREFIX,
        "ExchangeCredential",
        MethodPolicy::PublicCredentialExchange,
    ),
    // Durable signed webhooks.
    (
        WEBHOOK_SERVICE_PREFIX,
        "ListWebhooks",
        MethodPolicy::BearerOrOperator(OperatorCapability::Read),
    ),
    (
        WEBHOOK_SERVICE_PREFIX,
        "GetWebhook",
        MethodPolicy::BearerOrOperator(OperatorCapability::Read),
    ),
    (
        WEBHOOK_SERVICE_PREFIX,
        "CreateWebhook",
        MethodPolicy::BearerOrOperator(OperatorCapability::Administer),
    ),
    (
        WEBHOOK_SERVICE_PREFIX,
        "UpdateWebhook",
        MethodPolicy::BearerOrOperator(OperatorCapability::Administer),
    ),
    (
        WEBHOOK_SERVICE_PREFIX,
        "RotateSigningSecret",
        MethodPolicy::BearerOrOperator(OperatorCapability::Administer),
    ),
    (
        WEBHOOK_SERVICE_PREFIX,
        "TestWebhook",
        MethodPolicy::BearerOrOperator(OperatorCapability::Administer),
    ),
    (
        WEBHOOK_SERVICE_PREFIX,
        "ListDeliveries",
        MethodPolicy::BearerOrOperator(OperatorCapability::Read),
    ),
    (
        WEBHOOK_SERVICE_PREFIX,
        "ReplayDelivery",
        MethodPolicy::BearerOrOperator(OperatorCapability::Administer),
    ),
    (
        WEBHOOK_SERVICE_PREFIX,
        "DeleteWebhook",
        MethodPolicy::BearerOrOperator(OperatorCapability::Administer),
    ),
    // Fleet registry. The handler performs the second, resource-scoped check as
    // delegated role bindings land; the transport gate always requires a real
    // passkey operator session and never accepts the realm bearer tokens.
    (
        FLEET_SERVICE_PREFIX,
        "GetFleetOverview",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "GetAnalyticsOverview",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "GetRealmOperations",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "ExecuteRealmMutation",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "ListOrganizations",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "GetOrganization",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "CreateOrganization",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "UpdateOrganization",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "ArchiveOrganization",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "ListProjects",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "GetProject",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "CreateProject",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "UpdateProject",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "ArchiveProject",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "ListEnvironments",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "GetEnvironment",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "CreateEnvironment",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "UpdateEnvironment",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "ArchiveEnvironment",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "ListConnections",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "GetConnection",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "BeginConnection",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "CompleteConnection",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "RotateConnection",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "RevokeConnection",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "ListRoleBindings",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "UpsertRoleBinding",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "RevokeRoleBinding",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        FLEET_SERVICE_PREFIX,
        "ListAuditEvents",
        MethodPolicy::Operator(OperatorCapability::Read),
    ),
    (
        MANAGEMENT_SERVICE_PREFIX,
        "GetDiscovery",
        MethodPolicy::PublicCredentialExchange,
    ),
    (
        MANAGEMENT_SERVICE_PREFIX,
        "GetHealth",
        MethodPolicy::PublicCredentialExchange,
    ),
    (
        MANAGEMENT_SERVICE_PREFIX,
        "GetSummary",
        MethodPolicy::PublicCredentialExchange,
    ),
    (
        MANAGEMENT_SERVICE_PREFIX,
        "GetOperationalSnapshot",
        MethodPolicy::PublicCredentialExchange,
    ),
    (
        MANAGEMENT_SERVICE_PREFIX,
        "ExecuteRemoteMutation",
        MethodPolicy::PublicCredentialExchange,
    ),
    (
        MANAGEMENT_SERVICE_PREFIX,
        "CreatePairingCode",
        MethodPolicy::Operator(OperatorCapability::Administer),
    ),
    (
        MANAGEMENT_SERVICE_PREFIX,
        "ExchangePairingCode",
        MethodPolicy::PublicCredentialExchange,
    ),
    (
        MANAGEMENT_SERVICE_PREFIX,
        "RotateFleetCredential",
        MethodPolicy::PublicCredentialExchange,
    ),
    (
        MANAGEMENT_SERVICE_PREFIX,
        "RevokeFleetConnection",
        MethodPolicy::PublicCredentialExchange,
    ),
];

/// Resolves a request path to its policy, or `None` when the service is unknown
/// or the method has no entry in [`METHOD_POLICIES`].
///
/// Matching is on the whole `(service, method)` pair. Keying on the method name
/// alone would let a name carry its policy onto another service's path — an
/// `ExchangeCredential` under the event-service prefix would inherit the
/// unauthenticated exchange policy.
fn method_policy(path: &str) -> Option<MethodPolicy> {
    METHOD_POLICIES
        .iter()
        .find(|(service, method, _)| path.strip_prefix(*service) == Some(*method))
        .map(|(_, _, policy)| *policy)
}

/// Resolves the least-privilege service-account scope for bearer-capable RPCs.
/// The match remains method-exact so adding a proto method never inherits a
/// nearby method's authority by accident.
fn required_service_account_scope(path: &str) -> Option<&'static str> {
    if path == format!("{EVENT_SERVICE_PREFIX}Subscribe") {
        return Some("events.read");
    }
    if matches!(
        path.strip_prefix(IDENTITY_SERVICE_PREFIX),
        Some("GetUser" | "ListUsers" | "SearchUsers")
    ) {
        return Some("identity.read");
    }
    if matches!(
        path.strip_prefix(IDENTITY_SERVICE_PREFIX),
        Some(
            "UpdateProfile"
                | "AddIdentifier"
                | "RemoveIdentifier"
                | "SetPrimaryIdentifier"
                | "RenamePasskey"
                | "RevokePasskey"
        )
    ) {
        return Some("identity.write");
    }
    if matches!(
        path.strip_prefix(METRICS_SERVICE_PREFIX),
        Some("GetOverview" | "QuerySeries" | "GetAuthenticationFunnel" | "GetFailureBreakdown")
    ) {
        return Some("metrics.read");
    }
    if matches!(
        path.strip_prefix(WEBHOOK_SERVICE_PREFIX),
        Some(
            "ListWebhooks"
                | "GetWebhook"
                | "CreateWebhook"
                | "UpdateWebhook"
                | "RotateSigningSecret"
                | "TestWebhook"
                | "ListDeliveries"
                | "ReplayDelivery"
                | "DeleteWebhook"
        )
    ) {
        return Some("webhooks.manage");
    }
    None
}

/// Everything the RPC surface needs from configuration and the composition root.
pub struct RpcServiceConfig<'a> {
    pub store: Store,
    pub event_token: &'a SecretString,
    pub identity_token: &'a SecretString,
    pub rp_origin: &'a str,
    pub session_idle_seconds: u64,
    pub operator_emails: Vec<String>,
    pub jwt: JwtIssuer,
    pub rate_limiter: Arc<RateLimiter>,
    pub deployment_role: DeploymentRole,
    pub environment: Environment,
    pub master_keys: KeyRing,
    pub control_plane_instance_id: String,
    pub issuer: String,
    pub rp_id: String,
    pub webhook_runtime: Option<WebhookRuntime>,
    pub backup: Option<BackupStore>,
    pub analytics: Option<GreptimeAnalyticsStore>,
}

pub fn service(config: RpcServiceConfig<'_>) -> RpcService {
    let RpcServiceConfig {
        store,
        event_token,
        identity_token,
        rp_origin,
        session_idle_seconds,
        operator_emails,
        jwt,
        rate_limiter,
        deployment_role,
        environment,
        master_keys,
        control_plane_instance_id,
        issuer,
        rp_id,
        webhook_runtime,
        backup,
        analytics,
    } = config;
    let authorizer = OperatorAuthorizer::new(
        store.clone(),
        rp_origin.to_owned(),
        session_idle_seconds,
        environment == Environment::Production,
        operator_emails,
    );
    let service_token_issuer = jwt.clone();
    let router = match deployment_role {
        DeploymentRole::Realm => connectrpc::Router::new()
            .add_service(Arc::new(EventRpc::new(store.clone())))
            .add_service(Arc::new(MetricsRpc::new(store.clone(), backup.clone())))
            .add_service(Arc::new(IdentityRpc::with_authorizer(
                store.clone(),
                authorizer.clone(),
            )))
            .add_service(Arc::new(ManagementRpc::new(
                store.clone(),
                authorizer.clone(),
                ManagementRpcConfig {
                    environment,
                    realm_id: control_plane_instance_id.clone(),
                    issuer,
                    rp_id,
                    rate_limiter: Arc::clone(&rate_limiter),
                    jwt: jwt.clone(),
                    backup: backup.clone(),
                },
            )))
            .add_service(Arc::new(OrganizationRpc::new(
                store.clone(),
                authorizer.clone(),
            )))
            .add_service(Arc::new(ServiceAccountRpc::new(
                store.clone(),
                authorizer.clone(),
                jwt,
                rate_limiter,
            )))
            .add_service(Arc::new(WebhookRpc::new(
                store.clone(),
                authorizer.clone(),
                webhook_runtime.expect("realm RPC composition requires webhook runtime"),
            ))),
        DeploymentRole::FleetControlPlane => {
            let connector_hub = ConnectorHub::default();
            connectrpc::Router::new()
                .add_service(Arc::new(AnalyticsRpc::new(
                    store.clone(),
                    authorizer.clone(),
                    analytics.clone(),
                )))
                .add_service(Arc::new(FleetRpc::new(
                    store.clone(),
                    authorizer.clone(),
                    master_keys.clone(),
                    environment,
                    rp_origin.to_owned(),
                    control_plane_instance_id.clone(),
                    connector_hub.clone(),
                    analytics.clone(),
                )))
                .add_service(Arc::new(ConnectorRpc::new(
                    store.clone(),
                    master_keys,
                    connector_hub,
                    Arc::clone(&rate_limiter),
                    control_plane_instance_id,
                    analytics,
                )))
        }
    };
    ConnectRpcService::new(router)
        .with_limits(
            Limits::default()
                .max_request_body_size(64 * 1024)
                .max_message_size(256 * 1024),
        )
        .with_interceptor(RpcAuth::with_operator(
            event_token,
            identity_token,
            authorizer,
            service_token_issuer,
        ))
}

#[derive(Clone)]
pub(crate) struct RpcAuth {
    event_digest: [u8; 32],
    identity_digest: [u8; 32],
    operator: Option<OperatorAuthorizer>,
    service_token_issuer: Option<JwtIssuer>,
}

impl RpcAuth {
    fn with_operator(
        event_token: &SecretString,
        identity_token: &SecretString,
        operator: OperatorAuthorizer,
        service_token_issuer: JwtIssuer,
    ) -> Self {
        Self {
            event_digest: token_digest(event_token.expose_secret()),
            identity_digest: token_digest(identity_token.expose_secret()),
            operator: Some(operator),
            service_token_issuer: Some(service_token_issuer),
        }
    }

    #[cfg(test)]
    pub(crate) fn new(event_token: &SecretString, identity_token: &SecretString) -> Self {
        Self {
            event_digest: token_digest(event_token.expose_secret()),
            identity_digest: token_digest(identity_token.expose_secret()),
            operator: None,
            service_token_issuer: None,
        }
    }

    fn bearer_authorized(&self, path: Option<&str>, headers: &http::HeaderMap) -> bool {
        if bearer_authorized(&self.event_digest, &self.identity_digest, path, headers) {
            return true;
        }
        let Some((issuer, path, token)) = self
            .service_token_issuer
            .as_ref()
            .zip(path)
            .zip(bearer_token(headers))
            .map(|((issuer, path), token)| (issuer, path, token))
        else {
            return false;
        };
        required_service_account_scope(path)
            .is_some_and(|scope| issuer.authorizes_service_account(token, scope))
    }

    async fn authorize_unary(
        &self,
        path: Option<&str>,
        headers: &http::HeaderMap,
    ) -> Result<RpcPrincipal, ConnectError> {
        let Some(path) = path else {
            return Err(unauthenticated());
        };
        match method_policy(path) {
            // Deliberately public: the caller proves possession of a service-account
            // secret inside the handler, which is the only credential it has.
            Some(MethodPolicy::PublicCredentialExchange) => {
                Ok(RpcPrincipal::PublicCredentialExchange)
            }
            Some(MethodPolicy::Operator(capability)) => {
                self.operator_authorizer()?
                    .authorize(headers, capability)
                    .await?;
                Ok(RpcPrincipal::Operator)
            }
            Some(MethodPolicy::BearerOrOperator(capability)) => {
                if self.bearer_authorized(Some(path), headers) {
                    return Ok(RpcPrincipal::Machine);
                }
                self.operator_authorizer()?
                    .authorize(headers, capability)
                    .await?;
                Ok(RpcPrincipal::Operator)
            }
            Some(MethodPolicy::Bearer) => self
                .bearer_authorized(Some(path), headers)
                .then_some(RpcPrincipal::Machine)
                .ok_or_else(unauthenticated),
            Some(MethodPolicy::HandlerAuthenticatedStreaming) => Err(unauthenticated()),
            None => Err(unauthenticated()),
        }
    }

    fn operator_authorizer(&self) -> Result<&OperatorAuthorizer, ConnectError> {
        self.operator.as_ref().ok_or_else(unauthenticated)
    }

    /// Streaming shares the same policy table as unary. Operator sessions are not
    /// accepted here: `authorize` is async and this hook is not, so any method
    /// needing an operator check must stay unary rather than silently downgrade.
    fn authorize_streaming(
        &self,
        path: Option<&str>,
        headers: &http::HeaderMap,
    ) -> Result<RpcPrincipal, ConnectError> {
        match path.and_then(method_policy) {
            Some(MethodPolicy::HandlerAuthenticatedStreaming) => {
                Ok(RpcPrincipal::HandlerAuthenticatedStreaming)
            }
            Some(MethodPolicy::Bearer) => self
                .bearer_authorized(path, headers)
                .then_some(RpcPrincipal::Machine)
                .ok_or_else(unauthenticated),
            _ => Err(unauthenticated()),
        }
    }
}

fn bearer_authorized(
    event_digest: &[u8; 32],
    identity_digest: &[u8; 32],
    path: Option<&str>,
    headers: &http::HeaderMap,
) -> bool {
    let expected = match path {
        Some(path) if path.starts_with(EVENT_SERVICE_PREFIX) => event_digest,
        Some(path) if path.starts_with(IDENTITY_SERVICE_PREFIX) => identity_digest,
        _ => return false,
    };
    let supplied = bearer_token(headers).unwrap_or_default();
    bool::from(expected.ct_eq(&token_digest(supplied)))
}

fn bearer_token(headers: &http::HeaderMap) -> Option<&str> {
    headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
}

#[connectrpc::async_trait]
impl Interceptor for RpcAuth {
    async fn intercept_unary(
        &self,
        mut request: UnaryRequest,
        next: Next<'_>,
    ) -> Result<UnaryResponse, ConnectError> {
        let principal = self
            .authorize_unary(request.ctx.path(), request.ctx.headers())
            .await?;
        request.ctx.extensions_mut().insert(principal);
        next.run(request).await
    }

    async fn intercept_streaming(
        &self,
        mut request: StreamRequest,
        inbound: PayloadStream,
        next: NextStream<'_>,
    ) -> Result<StreamResponse, ConnectError> {
        let principal = self.authorize_streaming(request.ctx.path(), request.ctx.headers())?;
        request.ctx.extensions_mut().insert(principal);
        next.run(request, inbound).await
    }
}

fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn unauthenticated() -> ConnectError {
    ConnectError::new(ErrorCode::Unauthenticated, "authentication required")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const EVENT_TOKEN: &str = "event-rpc-test-token-longer-than-32-characters";
    const IDENTITY_TOKEN: &str = "identity-rpc-test-token-longer-than-32-characters";

    /// Every service whose methods must appear in [`METHOD_POLICIES`].
    const ROUTED_PROTOS: &[(&str, &str)] = &[
        (
            ANALYTICS_SERVICE_PREFIX,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/proto/rustyauth/analytics/v1/analytics.proto"
            ),
        ),
        (
            EVENT_SERVICE_PREFIX,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/proto/rustyauth/events/v1/events.proto"
            ),
        ),
        (
            IDENTITY_SERVICE_PREFIX,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/proto/rustyauth/identity/v1/identity.proto"
            ),
        ),
        (
            FLEET_SERVICE_PREFIX,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/proto/rustyauth/fleet/v1/fleet.proto"
            ),
        ),
        (
            ORGANIZATION_SERVICE_PREFIX,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/proto/rustyauth/organization/v1/organization.proto"
            ),
        ),
        (
            CONNECTOR_SERVICE_PREFIX,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/proto/rustyauth/management/v1/connector.proto"
            ),
        ),
        (
            MANAGEMENT_SERVICE_PREFIX,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/proto/rustyauth/management/v1/management.proto"
            ),
        ),
        (
            SERVICE_ACCOUNT_SERVICE_PREFIX,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/proto/rustyauth/service_accounts/v1/service_accounts.proto"
            ),
        ),
        (
            WEBHOOK_SERVICE_PREFIX,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/proto/rustyauth/webhooks/v1/webhooks.proto"
            ),
        ),
        (
            METRICS_SERVICE_PREFIX,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/proto/rustyauth/metrics/v1/metrics.proto"
            ),
        ),
    ];

    /// Services that are declared in proto but not served. They have no policy on
    /// purpose; the assertion below pins that they stay denied until someone
    /// implements them and assigns capabilities deliberately.
    const UNSERVED_PROTOS: &[(&str, &str)] = &[];

    const ALL_ROUTED_PREFIXES: &[&str] = &[
        ANALYTICS_SERVICE_PREFIX,
        EVENT_SERVICE_PREFIX,
        CONNECTOR_SERVICE_PREFIX,
        FLEET_SERVICE_PREFIX,
        IDENTITY_SERVICE_PREFIX,
        MANAGEMENT_SERVICE_PREFIX,
        METRICS_SERVICE_PREFIX,
        ORGANIZATION_SERVICE_PREFIX,
        SERVICE_ACCOUNT_SERVICE_PREFIX,
        WEBHOOK_SERVICE_PREFIX,
    ];

    fn proto_methods(path: &str) -> Vec<String> {
        let source = std::fs::read_to_string(path).unwrap();
        let methods: Vec<String> = source
            .lines()
            .filter_map(|line| line.trim_start().strip_prefix("rpc "))
            .filter_map(|rest| rest.split_once('('))
            .map(|(name, _)| name.trim().to_owned())
            .collect();
        assert!(!methods.is_empty(), "no rpc methods parsed from {path}");
        methods
    }

    fn test_auth() -> RpcAuth {
        RpcAuth::new(
            &secrecy::SecretString::from(EVENT_TOKEN),
            &secrecy::SecretString::from(IDENTITY_TOKEN),
        )
    }

    fn bearer_headers(token: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    #[test]
    fn every_proto_method_has_an_explicit_policy() {
        let mut declared = BTreeSet::new();
        for &(prefix, file) in ROUTED_PROTOS {
            for method in proto_methods(file) {
                assert!(
                    method_policy(&format!("{prefix}{method}")).is_some(),
                    "{method} is declared in {file} but has no METHOD_POLICIES entry; \
                     assign it a capability instead of leaving it silently denied"
                );
                declared.insert(method);
            }
        }
        for &(_, name, _) in METHOD_POLICIES {
            assert!(
                declared.contains(name),
                "METHOD_POLICIES entry {name} matches no proto method and is dead"
            );
        }
        for &(prefix, file) in UNSERVED_PROTOS {
            for method in proto_methods(file) {
                assert_eq!(
                    method_policy(&format!("{prefix}{method}")),
                    None,
                    "{method} from the unimplemented service in {file} resolved to a policy"
                );
            }
        }
    }

    #[test]
    fn sensitive_methods_keep_the_capability_they_were_reviewed_with() {
        assert_eq!(
            method_policy("/rustyauth.organization.v1.OrganizationService/UpdateOrganization"),
            Some(MethodPolicy::Operator(OperatorCapability::Administer))
        );
        assert_eq!(
            method_policy("/rustyauth.identity.v1.IdentityService/SetIdentifierVerification"),
            Some(MethodPolicy::Operator(OperatorCapability::Administer))
        );
        assert_eq!(
            method_policy("/rustyauth.identity.v1.IdentityService/GetUser"),
            Some(MethodPolicy::BearerOrOperator(OperatorCapability::Read))
        );
        assert_eq!(
            method_policy("/rustyauth.service_accounts.v1.ServiceAccountService/CreateCredential"),
            Some(MethodPolicy::Operator(OperatorCapability::Administer))
        );
        assert_eq!(
            method_policy(
                "/rustyauth.service_accounts.v1.ServiceAccountService/ExchangeCredential"
            ),
            Some(MethodPolicy::PublicCredentialExchange)
        );
        assert_eq!(
            method_policy("/rustyauth.metrics.v1.MetricsService/GetOverview"),
            Some(MethodPolicy::BearerOrOperator(OperatorCapability::Read))
        );
        assert_eq!(
            method_policy("/rustyauth.webhooks.v1.WebhookService/DeleteWebhook"),
            Some(MethodPolicy::BearerOrOperator(
                OperatorCapability::Administer
            ))
        );
    }

    #[test]
    fn service_account_scopes_are_exact_per_rpc_method() {
        for (path, scope) in [
            (
                "/rustyauth.events.v1.AuthEventService/Subscribe",
                "events.read",
            ),
            (
                "/rustyauth.identity.v1.IdentityService/GetUser",
                "identity.read",
            ),
            (
                "/rustyauth.identity.v1.IdentityService/UpdateProfile",
                "identity.write",
            ),
            (
                "/rustyauth.metrics.v1.MetricsService/GetOverview",
                "metrics.read",
            ),
            (
                "/rustyauth.webhooks.v1.WebhookService/CreateWebhook",
                "webhooks.manage",
            ),
        ] {
            assert_eq!(required_service_account_scope(path), Some(scope));
        }
        for path in [
            "/rustyauth.identity.v1.IdentityService/SetIdentifierVerification",
            "/rustyauth.organization.v1.OrganizationService/UpdateOrganization",
            "/rustyauth.service_accounts.v1.ServiceAccountService/CreateCredential",
            "/rustyauth.webhooks.v1.WebhookService/CreateWebhook/extra",
            "/rustyauth.metrics.v1.MetricsService/GetUser",
        ] {
            assert_eq!(required_service_account_scope(path), None, "{path}");
        }
    }

    /// The identity bearer token must not be able to reach identity proofing.
    ///
    /// `BearerOrOperator` accepts the token before it consults the capability, so
    /// any method left on that policy is reachable by anyone holding the token
    /// regardless of the capability named. Verification is the one identity
    /// mutation that grants operator status downstream, so it must be
    /// operator-only — otherwise a machine credential is Owner-equivalent.
    #[tokio::test]
    async fn the_identity_bearer_token_cannot_verify_an_identifier() {
        let auth = test_auth();
        let path = "/rustyauth.identity.v1.IdentityService/SetIdentifierVerification";
        for token in [EVENT_TOKEN, IDENTITY_TOKEN] {
            let verdict = auth
                .authorize_unary(Some(path), &bearer_headers(token))
                .await;
            assert!(
                verdict.is_err(),
                "{path} must not be reachable with a bearer token"
            );
        }
        // A method that is legitimately bearer-reachable still is, so the test
        // above is about this method rather than about the token being rejected.
        assert!(
            auth.authorize_unary(
                Some("/rustyauth.identity.v1.IdentityService/GetUser"),
                &bearer_headers(IDENTITY_TOKEN),
            )
            .await
            .is_ok()
        );
    }

    #[test]
    fn unrecognised_paths_resolve_to_no_policy() {
        for path in [
            "",
            "/",
            "rustyauth.identity.v1.IdentityService/GetUser",
            "/rustyauth.identity.v1.IdentityService/DropDatabase",
            "/rustyauth.metrics.v1.MetricsService/GetUser",
            "/rustyauth.identity.v1.IdentityServiceEvil/GetUser",
            "/rustyauth.identity.v1.IdentityService/AdminGetUser",
            "/rustyauth.identity.v1.IdentityService/GetUserSessions",
            "/rustyauth.identity.v1.IdentityService/GetUser/escalate",
            "/rustyauth.identity.v1.IdentityService/getuser",
        ] {
            assert_eq!(method_policy(path), None, "{path} resolved to a policy");
        }
    }

    #[test]
    fn streaming_admits_only_bearer_methods() {
        let auth = test_auth();
        for token in [EVENT_TOKEN, IDENTITY_TOKEN] {
            let headers = bearer_headers(token);
            for &(_, method, policy) in METHOD_POLICIES {
                if matches!(
                    policy,
                    MethodPolicy::Bearer | MethodPolicy::HandlerAuthenticatedStreaming
                ) {
                    continue;
                }
                for prefix in ALL_ROUTED_PREFIXES {
                    let path = format!("{prefix}{method}");
                    assert!(
                        auth.authorize_streaming(Some(&path), &headers).is_err(),
                        "{path} is reachable over the streaming path under {policy:?}"
                    );
                }
            }
        }
        // An operator-only method must never be reachable here: the streaming hook
        // is synchronous and cannot run the async operator session check.
        assert!(
            auth.authorize_streaming(
                Some("/rustyauth.organization.v1.OrganizationService/UpdateOrganization"),
                &bearer_headers(IDENTITY_TOKEN)
            )
            .is_err()
        );
        assert!(
            auth.authorize_streaming(
                Some("/rustyauth.events.v1.AuthEventService/Subscribe"),
                &bearer_headers(EVENT_TOKEN)
            )
            .is_ok()
        );
        assert!(
            auth.authorize_streaming(
                Some("/rustyauth.events.v1.AuthEventService/Subscribe"),
                &bearer_headers(IDENTITY_TOKEN)
            )
            .is_err()
        );
        assert!(
            auth.authorize_streaming(None, &bearer_headers(EVENT_TOKEN))
                .is_err()
        );
    }

    #[test]
    fn tokens_are_scoped_to_their_service_and_fail_closed() {
        let event_digest = token_digest(EVENT_TOKEN);
        let identity_digest = token_digest(IDENTITY_TOKEN);
        let mut headers = http::HeaderMap::new();
        assert!(!bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/rustyauth.identity.v1.IdentityService/GetUser"),
            &headers
        ));
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {EVENT_TOKEN}")).unwrap(),
        );
        assert!(bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/rustyauth.events.v1.AuthEventService/Subscribe"),
            &headers
        ));
        assert!(!bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/rustyauth.identity.v1.IdentityService/GetUser"),
            &headers
        ));
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {IDENTITY_TOKEN}")).unwrap(),
        );
        assert!(bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/rustyauth.identity.v1.IdentityService/GetUser"),
            &headers
        ));
        assert!(!bearer_authorized(
            &event_digest,
            &identity_digest,
            None,
            &headers
        ));
        assert!(!bearer_authorized(
            &event_digest,
            &identity_digest,
            Some("/unknown.Service/Method"),
            &headers
        ));
    }
}
