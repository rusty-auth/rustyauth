//! Fleet control-plane resource RPCs.
//!
//! This service is mounted only by the Fleet deployment role. It implements
//! durable organization/project/environment hierarchy, central audit history,
//! scoped delegated roles, and origin-bound realm pairing.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Generate, Nonce, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use buffa::Message;
use bytes::{Bytes, BytesMut};
use connectrpc::{
    ConnectError, ErrorCode, Protocol, RequestContext, Response, ServiceRequest, ServiceResult,
    client::{CallOptions, ClientConfig, ClientTransport},
};
use futures::{StreamExt, future::BoxFuture};
use http_body_util::{BodyExt, Full};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use uuid::Uuid;

use crate::{
    analytics_store::GreptimeAnalyticsStore,
    config::{Environment as RuntimeEnvironment, KeyRing},
    operator_auth::{OperatorAuthorizer, OperatorCapability},
    proto::rustyauth::{fleet::v1::*, management::v1::*},
    store::{
        EncryptedFleetCredential, FleetAnalyticsMaintenanceActionRecord,
        FleetAnalyticsMaintenanceAuditRecord, FleetAnalyticsMaintenanceOutcomeRecord,
        FleetAuditRecord, FleetConnectionAttemptRecord, FleetConnectionModeRecord,
        FleetConnectionRecord, FleetConnectionStateRecord, FleetEnvironmentKindRecord,
        FleetEnvironmentRecord, FleetOrganizationRecord, FleetProjectRecord,
        FleetResourceKindRecord, FleetResourceStateRecord, FleetRoleBindingRecord, FleetRoleRecord,
        Store, StorePolicyError, now,
    },
    telemetry::{
        ConnectorHub, connector_expiry_after, connector_signing_key_from_credential,
        sign_connector_frame, validate_management_discovery,
    },
};

const DEFAULT_PAGE_SIZE: usize = 25;
const MAX_PAGE_SIZE: u32 = 100;
const PAGE_TOKEN_LENGTH: usize = 22;
const MANAGEMENT_TIMEOUT: Duration = Duration::from_secs(8);
const MANAGEMENT_DNS_TIMEOUT: Duration = Duration::from_secs(3);
const MANAGEMENT_RESPONSE_MAX_BYTES: usize = 4 * 1024 * 1024 + 64 * 1024;
const FLEET_CREDENTIAL_AAD_VERSION: &str = "rustyauth-fleet-credential-v1";
const OPERATIONAL_SNAPSHOT_REQUEST_TYPE: &str =
    "rustyauth.management.v1.GetOperationalSnapshotRequest";
const OPERATIONAL_SNAPSHOT_RESPONSE_TYPE: &str = "rustyauth.management.v1.RealmOperationalSnapshot";
const REMOTE_MUTATION_REQUEST_TYPE: &str = "rustyauth.management.v1.RemoteMutationRequest";
const REMOTE_MUTATION_RESPONSE_TYPE: &str = "rustyauth.management.v1.RemoteMutationResult";
const REVOKE_CONNECTION_REQUEST_TYPE: &str = "rustyauth.management.v1.RevokeFleetConnectionRequest";
const REVOKE_CONNECTION_RESPONSE_TYPE: &str = "rustyauth.management.v1.FleetConnectionState";
const ROTATE_CONNECTION_REQUEST_TYPE: &str = "rustyauth.management.v1.RotateFleetCredentialRequest";
const ROTATE_CONNECTION_RESPONSE_TYPE: &str = "rustyauth.management.v1.PairingGrant";

pub(crate) struct FleetRpc {
    store: Store,
    authorizer: OperatorAuthorizer,
    credential_keys: KeyRing,
    runtime_environment: RuntimeEnvironment,
    control_plane_origin: String,
    control_plane_instance_id: String,
    connector_hub: ConnectorHub,
    analytics: Option<GreptimeAnalyticsStore>,
}

impl FleetRpc {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        store: Store,
        authorizer: OperatorAuthorizer,
        credential_keys: KeyRing,
        runtime_environment: RuntimeEnvironment,
        control_plane_origin: String,
        control_plane_instance_id: String,
        connector_hub: ConnectorHub,
        analytics: Option<GreptimeAnalyticsStore>,
    ) -> Self {
        Self {
            store,
            authorizer,
            credential_keys,
            runtime_environment,
            control_plane_origin,
            control_plane_instance_id,
            connector_hub,
            analytics,
        }
    }

    async fn outbound_operational_snapshot(
        &self,
        connection: &FleetConnectionRecord,
        request: GetOperationalSnapshotRequest,
    ) -> Result<RealmOperationalSnapshot, ConnectError> {
        let payload = self
            .outbound_command(
                connection,
                Uuid::new_v4(),
                "realm.operations",
                connector_expiry_after(MANAGEMENT_TIMEOUT)?,
                request.encode_to_vec(),
                OPERATIONAL_SNAPSHOT_REQUEST_TYPE,
                OPERATIONAL_SNAPSHOT_RESPONSE_TYPE,
            )
            .await?;
        RealmOperationalSnapshot::decode_from_slice(&payload).map_err(|_| {
            ConnectError::new(
                ErrorCode::DataLoss,
                "realm connector returned an invalid operational snapshot",
            )
        })
    }

    async fn outbound_remote_mutation(
        &self,
        connection: &FleetConnectionRecord,
        request: RemoteMutationRequest,
    ) -> Result<RemoteMutationResult, ConnectError> {
        let request_id = required_uuid(&request.request_id, "request_id")?;
        let expires_at = request.expires_at.clone();
        let payload = self
            .outbound_command(
                connection,
                request_id,
                "realm.remote-admin",
                expires_at,
                request.encode_to_vec(),
                REMOTE_MUTATION_REQUEST_TYPE,
                REMOTE_MUTATION_RESPONSE_TYPE,
            )
            .await?;
        RemoteMutationResult::decode_from_slice(&payload).map_err(|_| {
            ConnectError::new(
                ErrorCode::DataLoss,
                "realm connector returned an invalid mutation result",
            )
        })
    }

    async fn outbound_revoke_connection(
        &self,
        connection: &FleetConnectionRecord,
        request: RevokeFleetConnectionRequest,
    ) -> Result<FleetConnectionState, ConnectError> {
        let request_id = required_uuid(&request.request_id, "request_id")?;
        let payload = self
            .outbound_command(
                connection,
                request_id,
                "realm.connection.revoke",
                connector_expiry_after(MANAGEMENT_TIMEOUT)?,
                request.encode_to_vec(),
                REVOKE_CONNECTION_REQUEST_TYPE,
                REVOKE_CONNECTION_RESPONSE_TYPE,
            )
            .await?;
        FleetConnectionState::decode_from_slice(&payload).map_err(|_| {
            ConnectError::new(
                ErrorCode::DataLoss,
                "realm connector returned an invalid revocation result",
            )
        })
    }

    async fn outbound_rotate_connection(
        &self,
        connection: &FleetConnectionRecord,
        request: RotateFleetCredentialRequest,
        credential: &SecretString,
    ) -> Result<PairingGrant, ConnectError> {
        let request_id = required_uuid(&request.request_id, "request_id")?;
        let payload = self
            .outbound_command_with_credential(
                connection,
                credential,
                request_id,
                "realm.connection.rotate",
                connector_expiry_after(MANAGEMENT_TIMEOUT)?,
                request.encode_to_vec(),
                ROTATE_CONNECTION_REQUEST_TYPE,
                ROTATE_CONNECTION_RESPONSE_TYPE,
            )
            .await?;
        PairingGrant::decode_from_slice(&payload).map_err(|_| {
            ConnectError::new(
                ErrorCode::DataLoss,
                "realm connector returned an invalid credential rotation result",
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn outbound_command(
        &self,
        connection: &FleetConnectionRecord,
        request_id: Uuid,
        capability: &'static str,
        expires_at: String,
        payload: Vec<u8>,
        request_type: &'static str,
        response_type: &'static str,
    ) -> Result<Vec<u8>, ConnectError> {
        let credential =
            open_fleet_credential(&self.credential_keys, connection.id, &connection.credential)?;
        self.outbound_command_with_credential(
            connection,
            &credential,
            request_id,
            capability,
            expires_at,
            payload,
            request_type,
            response_type,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn outbound_command_with_credential(
        &self,
        connection: &FleetConnectionRecord,
        credential: &SecretString,
        request_id: Uuid,
        capability: &'static str,
        expires_at: String,
        payload: Vec<u8>,
        request_type: &'static str,
        response_type: &'static str,
    ) -> Result<Vec<u8>, ConnectError> {
        let signing_key = connector_signing_key_from_credential(credential.expose_secret());
        let mut command = ConnectorFrame {
            realm_id: connection.realm_id.clone(),
            connection_id: connection.id.to_string(),
            request_id: request_id.to_string(),
            kind: ConnectorFrameKind::Command.into(),
            capability: capability.into(),
            expires_at: expires_at.clone(),
            payload,
            payload_type: request_type.into(),
            ..Default::default()
        };
        sign_connector_frame(&mut command, &signing_key)?;
        let response = self.connector_hub.command(connection.id, command).await?;
        if response.realm_id != connection.realm_id
            || response.connection_id != connection.id.to_string()
            || response.request_id != request_id.to_string()
            || response.capability != capability
            || response.expires_at != expires_at
        {
            return Err(ConnectError::new(
                ErrorCode::DataLoss,
                "realm connector response does not match the command",
            ));
        }
        match response.kind.as_known() {
            Some(ConnectorFrameKind::Result) if response.payload_type == response_type => {
                Ok(response.payload)
            }
            Some(ConnectorFrameKind::Error) => Err(ConnectError::new(
                ErrorCode::FailedPrecondition,
                "realm rejected the connector command",
            )),
            _ => Err(ConnectError::new(
                ErrorCode::DataLoss,
                "realm connector response type does not match the command",
            )),
        }
    }
}

#[allow(refining_impl_trait)]
impl FleetService for FleetRpc {
    async fn get_fleet_overview(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetFleetOverviewRequest>,
    ) -> ServiceResult<FleetOverview> {
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Read)
            .await?;
        let organization_id = optional_uuid(request.organization_id, "organization_id")?;
        let organizations = self
            .store
            .fleet_organizations(false)
            .await
            .map_err(source_error)?;
        let selected = organizations
            .iter()
            .filter(|record| organization_id.is_none_or(|id| record.id == id));
        let mut organization_count = 0_u64;
        let mut project_count = 0_u64;
        let mut environment_count = 0_u64;
        for organization in selected {
            organization_count += 1;
            let projects = self
                .store
                .fleet_projects(organization.id, false)
                .await
                .map_err(source_error)?;
            project_count = project_count.saturating_add(projects.len() as u64);
            for project in projects {
                environment_count = environment_count.saturating_add(
                    self.store
                        .fleet_environments(organization.id, project.id, false)
                        .await
                        .map_err(source_error)?
                        .len() as u64,
                );
            }
        }
        let connections = self
            .store
            .fleet_connections(organization_id, None, None, false)
            .await
            .map_err(source_error)?;
        Response::ok(FleetOverview {
            organizations: organization_count,
            projects: project_count,
            environments: environment_count,
            healthy_connections: connections
                .iter()
                .filter(|record| record.state == FleetConnectionStateRecord::Healthy)
                .count() as u64,
            degraded_connections: connections
                .iter()
                .filter(|record| record.state == FleetConnectionStateRecord::Degraded)
                .count() as u64,
            offline_connections: connections
                .iter()
                .filter(|record| record.state == FleetConnectionStateRecord::Offline)
                .count() as u64,
            calculated_at: format_timestamp(now())?,
            ..Default::default()
        })
    }

    async fn get_analytics_overview(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetAnalyticsOverviewRequest>,
    ) -> ServiceResult<FleetAnalyticsOverview> {
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        self.authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Read,
                FleetResourceKindRecord::Organization,
                organization_id,
            )
            .await?;
        let project_id = optional_uuid(request.project_id, "project_id")?;
        let environment_id = optional_uuid(request.environment_id, "environment_id")?;
        let realm_id = optional_realm_id(request.realm_id)?;
        let (starts_at, ends_at) = analytics_range(request.starts_at, request.ends_at)?;
        let (records, source) = if let Some(analytics) = &self.analytics {
            (
                analytics
                    .query(
                        Some(organization_id),
                        project_id,
                        environment_id,
                        None,
                        realm_id.as_deref(),
                        starts_at,
                        ends_at,
                    )
                    .await
                    .map_err(source_error)?,
                "canonical-greptimedb",
            )
        } else {
            (
                self.store
                    .fleet_telemetry_buckets(
                        Some(organization_id),
                        project_id,
                        environment_id,
                        None,
                        realm_id.as_deref(),
                        starts_at,
                        ends_at,
                    )
                    .await
                    .map_err(source_error)?,
                "trusted-fleet-acceptance-ledger",
            )
        };

        let mut response = FleetAnalyticsOverview {
            source: source.into(),
            calculated_at: format_timestamp(now())?,
            ..Default::default()
        };
        let mut points = BTreeMap::<i64, FleetAnalyticsPoint>::new();
        let mut latest_bucket = BTreeMap::<Uuid, i64>::new();
        for record in records {
            let bucket = record.bucket().map_err(source_error)?;
            latest_bucket
                .entry(record.connection_id)
                .and_modify(|value| *value = (*value).max(record.bucket_start_unix_milliseconds))
                .or_insert(record.bucket_start_unix_milliseconds);
            let point_starts_at =
                format_millisecond_timestamp(record.bucket_start_unix_milliseconds)?;
            let point = points
                .entry(record.bucket_start_unix_milliseconds)
                .or_insert_with(|| FleetAnalyticsPoint {
                    starts_at: point_starts_at,
                    ..Default::default()
                });
            if let Some(metrics) = bucket.authentication.as_option() {
                add_analytics_count(&mut response.authentication_attempts, metrics.attempts)?;
                add_analytics_count(&mut response.authentication_successes, metrics.successes)?;
                add_analytics_count(&mut response.authentication_failures, metrics.failures)?;
                add_analytics_count(&mut response.authentication_denials, metrics.denials)?;
                add_analytics_count(&mut point.authentication_attempts, metrics.attempts)?;
                add_analytics_count(&mut point.authentication_successes, metrics.successes)?;
                add_analytics_count(&mut point.authentication_failures, metrics.failures)?;
                add_analytics_count(&mut point.authentication_denials, metrics.denials)?;
            }
            if let Some(metrics) = bucket.registration.as_option() {
                add_analytics_count(
                    &mut response.registrations_completed,
                    metrics.registrations_completed,
                )?;
            }
            if let Some(metrics) = bucket.sessions_and_tokens.as_option() {
                add_analytics_count(&mut response.sessions_created, metrics.sessions_created)?;
            }
            if let Some(metrics) = bucket.service_accounts.as_option() {
                add_analytics_count(&mut response.service_account_calls, metrics.calls)?;
            }
            if let Some(metrics) = bucket.webhooks.as_option() {
                add_analytics_count(&mut response.webhook_deliveries, metrics.deliveries)?;
                add_analytics_count(&mut response.webhook_failures, metrics.failures)?;
            }
        }
        response.points = points.into_values().collect();

        let mut connections = self
            .store
            .fleet_connections(Some(organization_id), project_id, environment_id, false)
            .await
            .map_err(source_error)?;
        if let Some(realm_id) = realm_id.as_deref() {
            connections.retain(|connection| connection.realm_id == realm_id);
        }
        let stale_before = ends_at.saturating_sub(15 * 60 * 1_000);
        response.expected_realms = analytics_cardinality(connections.len())?;
        let mut stale_realms = 0_u64;
        let mut coverage = Vec::with_capacity(connections.len());
        for connection in connections {
            let last = latest_bucket.get(&connection.id).copied();
            let (reporting, stale) =
                analytics_reporting_status(last, stale_before, connection.state);
            add_analytics_count(&mut response.reporting_realms, u64::from(reporting))?;
            add_analytics_count(&mut stale_realms, u64::from(stale))?;
            coverage.push(RealmAnalyticsCoverage {
                connection_id: connection.id.to_string(),
                realm_id: connection.realm_id,
                connection_state: connection_state_proto(connection.state).into(),
                reporting,
                stale,
                last_bucket_at: last
                    .map(format_millisecond_timestamp)
                    .transpose()?
                    .unwrap_or_default(),
                ..Default::default()
            });
        }
        response.stale_realms = stale_realms;
        response.coverage = coverage;
        Response::ok(response)
    }

    async fn get_realm_operations(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetRealmOperationsRequest>,
    ) -> ServiceResult<FleetRealmOperations> {
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let project_id = required_uuid(request.project_id, "project_id")?;
        let environment_id = required_uuid(request.environment_id, "environment_id")?;
        self.authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Read,
                FleetResourceKindRecord::Environment,
                environment_id,
            )
            .await?;
        let connection_id = required_uuid(request.connection_id, "connection_id")?;
        let connection = self
            .store
            .fleet_connection(connection_id)
            .await
            .map_err(source_error)?
            .filter(|record| {
                record.organization_id == organization_id
                    && record.project_id == project_id
                    && record.environment_id == environment_id
                    && connector_connection_usable(record)
            })
            .ok_or_else(not_found)?;
        if !connection
            .capabilities
            .iter()
            .any(|(name, version)| name == "realm.operations" && *version == 1)
        {
            return Err(ConnectError::new(
                ErrorCode::FailedPrecondition,
                "realm does not support the operational snapshot capability",
            ));
        }
        let remote_request = GetOperationalSnapshotRequest {
            connection_id: connection.id.to_string(),
            user_page_size: request.user_page_size,
            user_page_token: request.user_page_token.to_owned(),
            event_after_sequence: request.event_after_sequence,
            event_page_size: request.event_page_size,
            metrics_starts_at: request.metrics_starts_at.to_owned(),
            metrics_ends_at: request.metrics_ends_at.to_owned(),
            service_account_page_size: request.service_account_page_size,
            service_account_page_token: request.service_account_page_token.to_owned(),
            webhook_page_size: request.webhook_page_size,
            webhook_page_token: request.webhook_page_token.to_owned(),
            ..Default::default()
        };
        let live_source = match connection.mode {
            FleetConnectionModeRecord::PublicEndpoint => "live-public-endpoint",
            FleetConnectionModeRecord::OutboundConnector => "live-outbound-connector",
        };
        let response = match connection.mode {
            FleetConnectionModeRecord::PublicEndpoint => {
                let credential = open_fleet_credential(
                    &self.credential_keys,
                    connection.id,
                    &connection.credential,
                )?;
                let mut client =
                    management_client(&connection.management_endpoint, &self.runtime_environment)
                        .await?;
                let authorized_config = client.config().clone().with_default_header(
                    http::header::AUTHORIZATION,
                    format!("Bearer {}", credential.expose_secret()),
                );
                *client.config_mut() = authorized_config;
                client
                    .get_operational_snapshot_with_options(
                        remote_request,
                        CallOptions::default().with_timeout(MANAGEMENT_TIMEOUT),
                    )
                    .await
                    .map(|response| response.into_owned())
                    .map_err(management_error)
            }
            FleetConnectionModeRecord::OutboundConnector => {
                self.outbound_operational_snapshot(&connection, remote_request)
                    .await
            }
        };
        let snapshot = match response {
            Ok(snapshot) => snapshot,
            Err(error) => {
                if let Err(observe_error) = self
                    .store
                    .observe_fleet_connection(connection.id, FleetConnectionStateRecord::Degraded)
                    .await
                {
                    tracing::warn!(
                        connection_id = %connection.id,
                        error = %observe_error,
                        "could not persist degraded Fleet connection state"
                    );
                }
                let cached = self
                    .store
                    .fleet_operational_snapshot(connection.id, &connection.realm_id)
                    .await
                    .map_err(source_error)?;
                let Some(cached) = cached else {
                    return Err(error);
                };
                let snapshot = cached.snapshot().map_err(source_error)?;
                return Response::ok(FleetRealmOperations {
                    snapshot: snapshot.into(),
                    connection_id: connection.id.to_string(),
                    connection_state: ConnectionState::Degraded.into(),
                    source: "stale-bounded-cache".into(),
                    stale: true,
                    observed_at: format_timestamp(cached.observed_at)?,
                    ..Default::default()
                });
            }
        };
        if snapshot.realm_id != connection.realm_id || snapshot.source != "live-realm" {
            return Err(ConnectError::new(
                ErrorCode::DataLoss,
                "realm operational response does not match the authenticated connection",
            ));
        }
        let observed = self
            .store
            .observe_fleet_connection(connection.id, FleetConnectionStateRecord::Healthy)
            .await
            .map_err(source_error)?;
        if let Err(error) = self
            .store
            .cache_fleet_operational_snapshot(connection.id, &connection.realm_id, &snapshot)
            .await
        {
            tracing::warn!(
                connection_id = %connection.id,
                error = %error,
                "could not persist bounded Fleet operational cache"
            );
        }
        Response::ok(FleetRealmOperations {
            snapshot: snapshot.into(),
            connection_id: connection.id.to_string(),
            connection_state: connection_state_proto(observed.state).into(),
            source: live_source.into(),
            stale: false,
            observed_at: format_timestamp(now())?,
            ..Default::default()
        })
    }

    async fn execute_realm_mutation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ExecuteRealmMutationRequest>,
    ) -> ServiceResult<FleetRealmMutationResult> {
        require_mutation(&request.mutation)?;
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let project_id = required_uuid(request.project_id, "project_id")?;
        let environment_id = required_uuid(request.environment_id, "environment_id")?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                FleetResourceKindRecord::Environment,
                environment_id,
            )
            .await?;
        let connection_id = required_uuid(request.connection_id, "connection_id")?;
        let connection = self
            .store
            .fleet_connection(connection_id)
            .await
            .map_err(source_error)?
            .filter(|record| {
                record.organization_id == organization_id
                    && record.project_id == project_id
                    && record.environment_id == environment_id
                    && connector_connection_usable(record)
            })
            .ok_or_else(not_found)?;
        if !connection
            .capabilities
            .iter()
            .any(|(name, version)| name == "realm.remote-admin" && *version == 1)
        {
            return Err(ConnectError::new(
                ErrorCode::FailedPrecondition,
                "realm does not support controlled remote administration",
            ));
        }
        let request_id = required_uuid(request.mutation.request_id, "mutation.request_id")?;
        let reason = safe_remote_reason(request.mutation.reason)?;
        validate_remote_expiry(request.expires_at)?;
        let operation = request
            .operation
            .as_known()
            .filter(|value| *value != RemoteMutationOperation::Unspecified)
            .ok_or_else(|| invalid("remote mutation operation is required"))?;
        let target_id = safe_remote_target(request.target_id, 1_024)?;
        let secondary_id = if request.secondary_id.trim().is_empty() {
            String::new()
        } else {
            safe_remote_target(request.secondary_id, 1_024)?
        };
        let remote_request = RemoteMutationRequest {
            connection_id: connection.id.to_string(),
            request_id: request_id.to_string(),
            reason: reason.clone(),
            expires_at: request.expires_at.to_owned(),
            operation: operation.into(),
            target_id,
            secondary_id,
            enabled: request.enabled,
            ..Default::default()
        };
        let live_source = match connection.mode {
            FleetConnectionModeRecord::PublicEndpoint => "live-public-endpoint",
            FleetConnectionModeRecord::OutboundConnector => "live-outbound-connector",
        };
        let remote = match connection.mode {
            FleetConnectionModeRecord::PublicEndpoint => {
                let credential = open_fleet_credential(
                    &self.credential_keys,
                    connection.id,
                    &connection.credential,
                )?;
                let mut client =
                    management_client(&connection.management_endpoint, &self.runtime_environment)
                        .await?;
                let authorized_config = client.config().clone().with_default_header(
                    http::header::AUTHORIZATION,
                    format!("Bearer {}", credential.expose_secret()),
                );
                *client.config_mut() = authorized_config;
                client
                    .execute_remote_mutation_with_options(
                        remote_request,
                        CallOptions::default().with_timeout(MANAGEMENT_TIMEOUT),
                    )
                    .await
                    .map(|response| response.into_owned())
                    .map_err(management_error)
            }
            FleetConnectionModeRecord::OutboundConnector => {
                self.outbound_remote_mutation(&connection, remote_request)
                    .await
            }
        };
        let remote = match remote {
            Ok(response) => response,
            Err(error) => {
                let _ = self
                    .store
                    .observe_fleet_connection(connection.id, FleetConnectionStateRecord::Degraded)
                    .await;
                return Err(error);
            }
        };
        if remote.connection_id != connection.id.to_string()
            || remote.request_id != request_id.to_string()
            || remote.operation.as_known() != Some(operation)
        {
            return Err(ConnectError::new(
                ErrorCode::DataLoss,
                "realm mutation response does not match the authenticated request",
            ));
        }
        let action = format!("realm.remote.{}", remote_mutation_action(operation));
        let audit = self
            .store
            .record_fleet_remote_mutation(connection.id, request_id, actor.user.id, action, reason)
            .await
            .map_err(source_error)?;
        self.store
            .observe_fleet_connection(connection.id, FleetConnectionStateRecord::Healthy)
            .await
            .map_err(source_error)?;
        Response::ok(FleetRealmMutationResult {
            result: remote.into(),
            source: live_source.into(),
            centrally_audited_at: format_timestamp(audit.occurred_at)?,
            ..Default::default()
        })
    }

    async fn list_organizations(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListOrganizationsRequest>,
    ) -> ServiceResult<ListOrganizationsResponse> {
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Read)
            .await?;
        let after = decode_page_token(request.page_token)?;
        let page_size = page_size(request.page_size)?;
        let mut records = self
            .store
            .fleet_organizations(request.include_archived)
            .await
            .map_err(source_error)?;
        records.retain(|record| after.is_none_or(|after| record.id > after));
        let next_page_token = next_page_token(&records, page_size, |record| record.id);
        records.truncate(page_size);
        Response::ok(ListOrganizationsResponse {
            organizations: records
                .into_iter()
                .map(organization_to_proto)
                .collect::<Result<_, _>>()?,
            next_page_token,
            ..Default::default()
        })
    }

    async fn get_organization(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetOrganizationRequest>,
    ) -> ServiceResult<Organization> {
        let id = required_uuid(request.organization_id, "organization_id")?;
        self.authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Read,
                FleetResourceKindRecord::Organization,
                id,
            )
            .await?;
        let record = self
            .store
            .fleet_organization(id)
            .await
            .map_err(source_error)?
            .ok_or_else(not_found)?;
        Response::ok(organization_to_proto(record)?)
    }

    async fn create_organization(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateOrganizationRequest>,
    ) -> ServiceResult<Organization> {
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .create_fleet_organization(
                safe_slug(request.slug)?,
                safe_text(request.name, "name", 120, false)?,
                required_uuid(request.mutation.request_id, "mutation.request_id")?,
                actor.user.id,
                safe_text(request.mutation.reason, "mutation.reason", 500, true)?,
            )
            .await
            .map_err(source_error)?;
        Response::ok(organization_to_proto(record)?)
    }

    async fn update_organization(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateOrganizationRequest>,
    ) -> ServiceResult<Organization> {
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                FleetResourceKindRecord::Organization,
                organization_id,
            )
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .update_fleet_organization(
                organization_id,
                safe_text(request.name, "name", 120, false)?,
                required_uuid(request.mutation.request_id, "mutation.request_id")?,
                actor.user.id,
                safe_text(request.mutation.reason, "mutation.reason", 500, true)?,
            )
            .await
            .map_err(source_error)?;
        Response::ok(organization_to_proto(record)?)
    }

    async fn archive_organization(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ArchiveOrganizationRequest>,
    ) -> ServiceResult<Organization> {
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                FleetResourceKindRecord::Organization,
                organization_id,
            )
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .archive_fleet_organization(
                organization_id,
                required_uuid(request.mutation.request_id, "mutation.request_id")?,
                actor.user.id,
                safe_text(request.mutation.reason, "mutation.reason", 500, true)?,
            )
            .await
            .map_err(source_error)?;
        Response::ok(organization_to_proto(record)?)
    }

    async fn list_projects(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListProjectsRequest>,
    ) -> ServiceResult<ListProjectsResponse> {
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        self.authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Read,
                FleetResourceKindRecord::Organization,
                organization_id,
            )
            .await?;
        let after = decode_page_token(request.page_token)?;
        let page_size = page_size(request.page_size)?;
        let mut records = self
            .store
            .fleet_projects(organization_id, request.include_archived)
            .await
            .map_err(source_error)?;
        records.retain(|record| after.is_none_or(|after| record.id > after));
        let next_page_token = next_page_token(&records, page_size, |record| record.id);
        records.truncate(page_size);
        Response::ok(ListProjectsResponse {
            projects: records
                .into_iter()
                .map(project_to_proto)
                .collect::<Result<_, _>>()?,
            next_page_token,
            ..Default::default()
        })
    }

    async fn get_project(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetProjectRequest>,
    ) -> ServiceResult<Project> {
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let project_id = required_uuid(request.project_id, "project_id")?;
        self.authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Read,
                FleetResourceKindRecord::Project,
                project_id,
            )
            .await?;
        let record = self
            .store
            .fleet_project(project_id)
            .await
            .map_err(source_error)?
            .filter(|record| record.organization_id == organization_id)
            .ok_or_else(not_found)?;
        Response::ok(project_to_proto(record)?)
    }

    async fn create_project(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateProjectRequest>,
    ) -> ServiceResult<Project> {
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                FleetResourceKindRecord::Organization,
                organization_id,
            )
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .create_fleet_project(
                organization_id,
                safe_slug(request.slug)?,
                safe_text(request.name, "name", 120, false)?,
                safe_text(request.description, "description", 500, true)?,
                required_uuid(request.mutation.request_id, "mutation.request_id")?,
                actor.user.id,
                safe_text(request.mutation.reason, "mutation.reason", 500, true)?,
            )
            .await
            .map_err(source_error)?;
        Response::ok(project_to_proto(record)?)
    }

    async fn update_project(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateProjectRequest>,
    ) -> ServiceResult<Project> {
        let project_id = required_uuid(request.project_id, "project_id")?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                FleetResourceKindRecord::Project,
                project_id,
            )
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .update_fleet_project(
                required_uuid(request.organization_id, "organization_id")?,
                project_id,
                safe_text(request.name, "name", 120, false)?,
                safe_text(request.description, "description", 500, true)?,
                required_uuid(request.mutation.request_id, "mutation.request_id")?,
                actor.user.id,
                safe_text(request.mutation.reason, "mutation.reason", 500, true)?,
            )
            .await
            .map_err(source_error)?;
        Response::ok(project_to_proto(record)?)
    }

    async fn archive_project(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ArchiveProjectRequest>,
    ) -> ServiceResult<Project> {
        let project_id = required_uuid(request.project_id, "project_id")?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                FleetResourceKindRecord::Project,
                project_id,
            )
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .archive_fleet_project(
                required_uuid(request.organization_id, "organization_id")?,
                project_id,
                required_uuid(request.mutation.request_id, "mutation.request_id")?,
                actor.user.id,
                safe_text(request.mutation.reason, "mutation.reason", 500, true)?,
            )
            .await
            .map_err(source_error)?;
        Response::ok(project_to_proto(record)?)
    }

    async fn list_environments(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListEnvironmentsRequest>,
    ) -> ServiceResult<ListEnvironmentsResponse> {
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let project_id = required_uuid(request.project_id, "project_id")?;
        self.authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Read,
                FleetResourceKindRecord::Project,
                project_id,
            )
            .await?;
        let after = decode_page_token(request.page_token)?;
        let page_size = page_size(request.page_size)?;
        let mut records = self
            .store
            .fleet_environments(organization_id, project_id, request.include_archived)
            .await
            .map_err(source_error)?;
        records.retain(|record| after.is_none_or(|after| record.id > after));
        let next_page_token = next_page_token(&records, page_size, |record| record.id);
        records.truncate(page_size);
        Response::ok(ListEnvironmentsResponse {
            environments: records
                .into_iter()
                .map(environment_to_proto)
                .collect::<Result<_, _>>()?,
            next_page_token,
            ..Default::default()
        })
    }

    async fn get_environment(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetEnvironmentRequest>,
    ) -> ServiceResult<Environment> {
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let project_id = required_uuid(request.project_id, "project_id")?;
        let environment_id = required_uuid(request.environment_id, "environment_id")?;
        self.authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Read,
                FleetResourceKindRecord::Environment,
                environment_id,
            )
            .await?;
        let record = self
            .store
            .fleet_environment(environment_id)
            .await
            .map_err(source_error)?
            .filter(|record| {
                record.organization_id == organization_id && record.project_id == project_id
            })
            .ok_or_else(not_found)?;
        Response::ok(environment_to_proto(record)?)
    }

    async fn create_environment(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateEnvironmentRequest>,
    ) -> ServiceResult<Environment> {
        let project_id = required_uuid(request.project_id, "project_id")?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                FleetResourceKindRecord::Project,
                project_id,
            )
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .create_fleet_environment(
                required_uuid(request.organization_id, "organization_id")?,
                project_id,
                safe_slug(request.slug)?,
                safe_text(request.name, "name", 120, false)?,
                environment_kind(request.kind.as_known())?,
                safe_text(request.provider, "provider", 80, true)?,
                safe_text(request.region, "region", 80, true)?,
                required_uuid(request.mutation.request_id, "mutation.request_id")?,
                actor.user.id,
                safe_text(request.mutation.reason, "mutation.reason", 500, true)?,
            )
            .await
            .map_err(source_error)?;
        Response::ok(environment_to_proto(record)?)
    }

    async fn update_environment(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateEnvironmentRequest>,
    ) -> ServiceResult<Environment> {
        let environment_id = required_uuid(request.environment_id, "environment_id")?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                FleetResourceKindRecord::Environment,
                environment_id,
            )
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .update_fleet_environment(
                required_uuid(request.organization_id, "organization_id")?,
                required_uuid(request.project_id, "project_id")?,
                environment_id,
                safe_text(request.name, "name", 120, false)?,
                environment_kind(request.kind.as_known())?,
                safe_text(request.provider, "provider", 80, true)?,
                safe_text(request.region, "region", 80, true)?,
                required_uuid(request.mutation.request_id, "mutation.request_id")?,
                actor.user.id,
                safe_text(request.mutation.reason, "mutation.reason", 500, true)?,
            )
            .await
            .map_err(source_error)?;
        Response::ok(environment_to_proto(record)?)
    }

    async fn archive_environment(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ArchiveEnvironmentRequest>,
    ) -> ServiceResult<Environment> {
        let environment_id = required_uuid(request.environment_id, "environment_id")?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                FleetResourceKindRecord::Environment,
                environment_id,
            )
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .archive_fleet_environment(
                required_uuid(request.organization_id, "organization_id")?,
                required_uuid(request.project_id, "project_id")?,
                environment_id,
                required_uuid(request.mutation.request_id, "mutation.request_id")?,
                actor.user.id,
                safe_text(request.mutation.reason, "mutation.reason", 500, true)?,
            )
            .await
            .map_err(source_error)?;
        Response::ok(environment_to_proto(record)?)
    }

    async fn list_connections(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListConnectionsRequest>,
    ) -> ServiceResult<ListConnectionsResponse> {
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let project_id = optional_uuid(request.project_id, "project_id")?;
        let environment_id = optional_uuid(request.environment_id, "environment_id")?;
        let (scope_kind, scope_id) = if let Some(id) = environment_id {
            (FleetResourceKindRecord::Environment, id)
        } else if let Some(id) = project_id {
            (FleetResourceKindRecord::Project, id)
        } else {
            (FleetResourceKindRecord::Organization, organization_id)
        };
        self.authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Read,
                scope_kind,
                scope_id,
            )
            .await?;
        let after = decode_page_token(request.page_token)?;
        let page_size = page_size(request.page_size)?;
        let mut records = self
            .store
            .fleet_connections(
                Some(organization_id),
                project_id,
                environment_id,
                request.include_revoked,
            )
            .await
            .map_err(source_error)?;
        records.retain(|record| after.is_none_or(|after| record.id > after));
        let next_page_token = next_page_token(&records, page_size, |record| record.id);
        records.truncate(page_size);
        Response::ok(ListConnectionsResponse {
            connections: records
                .into_iter()
                .map(connection_to_proto)
                .collect::<Result<_, _>>()?,
            next_page_token,
            ..Default::default()
        })
    }

    async fn get_connection(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetConnectionRequest>,
    ) -> ServiceResult<RealmConnection> {
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let project_id = required_uuid(request.project_id, "project_id")?;
        let environment_id = required_uuid(request.environment_id, "environment_id")?;
        self.authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Read,
                FleetResourceKindRecord::Environment,
                environment_id,
            )
            .await?;
        let connection_id = required_uuid(request.connection_id, "connection_id")?;
        let record = self
            .store
            .fleet_connection(connection_id)
            .await
            .map_err(source_error)?
            .filter(|record| {
                record.organization_id == organization_id
                    && record.project_id == project_id
                    && record.environment_id == environment_id
            })
            .ok_or_else(not_found)?;
        Response::ok(connection_to_proto(record)?)
    }

    async fn begin_connection(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, BeginConnectionRequest>,
    ) -> ServiceResult<ConnectionAttempt> {
        let environment_id = required_uuid(request.environment_id, "environment_id")?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                FleetResourceKindRecord::Environment,
                environment_id,
            )
            .await?;
        require_mutation(&request.mutation)?;
        let mode = connection_mode(request.mode.as_known())?;
        let pairing_code = match mode {
            FleetConnectionModeRecord::OutboundConnector => {
                Some(safe_secret(request.pairing_code, "pairing code", 16, 256)?)
            }
            FleetConnectionModeRecord::PublicEndpoint if request.pairing_code.is_empty() => None,
            FleetConnectionModeRecord::PublicEndpoint => {
                return Err(invalid(
                    "pairing_code is valid only for an outbound connection",
                ));
            }
        };
        let endpoint = match mode {
            FleetConnectionModeRecord::PublicEndpoint => {
                safe_management_endpoint(request.management_endpoint, &self.runtime_environment)?
                    .to_string()
                    .trim_end_matches('/')
                    .to_owned()
            }
            FleetConnectionModeRecord::OutboundConnector => self.control_plane_origin.clone(),
        };
        let record = self
            .store
            .create_fleet_connection_attempt(
                required_uuid(request.organization_id, "organization_id")?,
                required_uuid(request.project_id, "project_id")?,
                environment_id,
                mode,
                endpoint,
                pairing_code.as_ref().map(|code| code.expose_secret()),
                required_uuid(request.mutation.request_id, "mutation.request_id")?,
                actor.user.id,
                safe_text(request.mutation.reason, "mutation.reason", 500, true)?,
            )
            .await
            .map_err(source_error)?;
        Response::ok(connection_attempt_to_proto(record)?)
    }

    async fn complete_connection(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CompleteConnectionRequest>,
    ) -> ServiceResult<RealmConnection> {
        require_mutation(&request.mutation)?;
        let attempt_id = required_uuid(request.attempt_id, "attempt_id")?;
        let pairing_code = safe_secret(request.pairing_code, "pairing code", 16, 256)?;
        let attempt = self
            .store
            .fleet_connection_attempt(attempt_id)
            .await
            .map_err(source_error)?
            .filter(|attempt| attempt.expires_at > now())
            .ok_or_else(|| source_error(StorePolicyError::FleetConnectionAttemptExpired.into()))?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                FleetResourceKindRecord::Environment,
                attempt.environment_id,
            )
            .await?;
        if attempt.mode == FleetConnectionModeRecord::OutboundConnector {
            return Err(ConnectError::new(
                ErrorCode::FailedPrecondition,
                "outbound attempt must be completed from the private realm",
            ));
        }
        let client =
            management_client(&attempt.management_endpoint, &self.runtime_environment).await?;
        let discovery = client
            .get_discovery_with_options(
                GetDiscoveryRequest::default(),
                CallOptions::default().with_timeout(MANAGEMENT_TIMEOUT),
            )
            .await
            .map_err(management_error)?
            .into_owned();
        validate_management_discovery(&discovery, false)?;
        let assignment_epoch = self
            .store
            .reserve_fleet_assignment_epoch(&discovery.realm_id)
            .await
            .map_err(source_error)?;
        let mut grant = client
            .exchange_pairing_code_with_options(
                ExchangePairingCodeRequest {
                    code: pairing_code.expose_secret().to_owned(),
                    control_plane_origin: self.control_plane_origin.clone(),
                    control_plane_instance_id: self.control_plane_instance_id.clone(),
                    request_id: request.mutation.request_id.to_string(),
                    assignment_epoch,
                    ..Default::default()
                },
                CallOptions::default().with_timeout(MANAGEMENT_TIMEOUT),
            )
            .await
            .map_err(management_error)?
            .into_owned();
        if grant.realm_id != discovery.realm_id
            || grant.connection_id.is_empty()
            || grant.assignment_epoch != assignment_epoch
        {
            return Err(ConnectError::new(
                ErrorCode::DataLoss,
                "realm pairing response is inconsistent",
            ));
        }
        let id = required_uuid(&grant.connection_id, "pairing connection_id")?;
        // Move the plaintext into a zeroizing wrapper instead of retaining a second
        // allocation until the complete pairing response is dropped.
        let credential = SecretString::from(std::mem::take(&mut grant.credential));
        let encrypted = seal_fleet_credential(&self.credential_keys, id, &credential)?;
        let record = FleetConnectionRecord {
            id,
            organization_id: attempt.organization_id,
            project_id: attempt.project_id,
            environment_id: attempt.environment_id,
            realm_id: safe_text(&discovery.realm_id, "realm_id", 128, false)?,
            assignment_epoch,
            display_name: safe_text(&discovery.realm_id, "realm_id", 128, false)?,
            mode: attempt.mode,
            management_endpoint: attempt.management_endpoint,
            credential: encrypted,
            credential_hint: safe_text(&grant.credential_hint, "credential_hint", 32, true)?,
            staged_credential: None,
            staged_credential_hint: None,
            credential_rotation_request_id: None,
            deployment_version: safe_text(
                &discovery.deployment_version,
                "deployment_version",
                64,
                true,
            )?,
            protocol_version: safe_text(
                &discovery.management_protocol_version,
                "protocol_version",
                32,
                true,
            )?,
            capabilities: discovery
                .capabilities
                .iter()
                .map(|capability| (capability.name.to_string(), capability.version))
                .collect(),
            granted_scopes: grant.granted_scopes,
            issuer: safe_text(&discovery.issuer, "issuer", 512, true)?,
            rp_id: safe_text(&discovery.rp_id, "rp_id", 253, true)?,
            state: FleetConnectionStateRecord::Healthy,
            last_seen_at: Some(now()),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
        };
        let record = self
            .store
            .complete_fleet_connection(
                attempt_id,
                record,
                required_uuid(request.mutation.request_id, "mutation.request_id")?,
                actor.user.id,
                safe_text(request.mutation.reason, "mutation.reason", 500, true)?,
            )
            .await
            .map_err(source_error)?;
        Response::ok(connection_to_proto(record)?)
    }

    async fn rotate_connection(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RotateConnectionRequest>,
    ) -> ServiceResult<RealmConnection> {
        require_mutation(&request.mutation)?;
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let project_id = required_uuid(request.project_id, "project_id")?;
        let environment_id = required_uuid(request.environment_id, "environment_id")?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                FleetResourceKindRecord::Environment,
                environment_id,
            )
            .await?;
        let connection_id = required_uuid(request.connection_id, "connection_id")?;
        let request_id = required_uuid(request.mutation.request_id, "mutation.request_id")?;
        let reason = safe_remote_reason(request.mutation.reason)?;
        let existing = self
            .store
            .fleet_connection(connection_id)
            .await
            .map_err(source_error)?
            .filter(|record| {
                record.organization_id == organization_id
                    && record.project_id == project_id
                    && record.environment_id == environment_id
                    && connector_connection_usable(record)
            })
            .ok_or_else(not_found)?;
        if let Some(completed) = self
            .store
            .fleet_connection_for_credential_rotation_request(request_id)
            .await
            .map_err(source_error)?
        {
            if completed.id != existing.id {
                return Err(ConnectError::new(
                    ErrorCode::AlreadyExists,
                    "credential rotation request belongs to another connection",
                ));
            }
            return Response::ok(connection_to_proto(completed)?);
        }

        let staged = if existing.credential_rotation_request_id == Some(request_id) {
            existing
        } else {
            let mut random = [0_u8; 32];
            rand::rng().fill_bytes(&mut random);
            let credential = SecretString::from(format!("rfg_{}", URL_SAFE_NO_PAD.encode(random)));
            let hint = credential
                .expose_secret()
                .chars()
                .rev()
                .take(6)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>();
            let encrypted =
                seal_fleet_credential(&self.credential_keys, connection_id, &credential)?;
            self.store
                .stage_fleet_connection_credential(connection_id, encrypted, hint, request_id)
                .await
                .map_err(source_error)?
        };
        let active_credential =
            open_fleet_credential(&self.credential_keys, staged.id, &staged.credential)?;
        let staged_encrypted = staged.staged_credential.as_ref().ok_or_else(|| {
            ConnectError::new(ErrorCode::DataLoss, "staged realm credential is missing")
        })?;
        let staged_credential =
            open_fleet_credential(&self.credential_keys, staged.id, staged_encrypted)?;
        let staged_hint = staged.staged_credential_hint.clone().ok_or_else(|| {
            ConnectError::new(ErrorCode::DataLoss, "staged credential hint is missing")
        })?;
        let remote_request = RotateFleetCredentialRequest {
            connection_id: connection_id.to_string(),
            request_id: request_id.to_string(),
            reason: reason.clone(),
            new_credential: staged_credential.expose_secret().to_owned(),
            new_credential_hint: staged_hint,
            ..Default::default()
        };
        let first = match staged.mode {
            FleetConnectionModeRecord::PublicEndpoint => {
                rotate_remote_connection(
                    &staged.management_endpoint,
                    &active_credential,
                    remote_request.clone(),
                    &self.runtime_environment,
                )
                .await
            }
            FleetConnectionModeRecord::OutboundConnector => {
                self.outbound_rotate_connection(&staged, remote_request.clone(), &active_credential)
                    .await
            }
        };
        let remote = match first {
            Ok(response) => response,
            Err(first_error) => {
                tracing::warn!(
                    connection_id = %connection_id,
                    code = ?first_error.code,
                    "active Fleet credential did not complete rotation; retrying the durable staged credential"
                );
                match staged.mode {
                    FleetConnectionModeRecord::PublicEndpoint => {
                        rotate_remote_connection(
                            &staged.management_endpoint,
                            &staged_credential,
                            remote_request,
                            &self.runtime_environment,
                        )
                        .await?
                    }
                    FleetConnectionModeRecord::OutboundConnector => {
                        self.outbound_rotate_connection(&staged, remote_request, &staged_credential)
                            .await?
                    }
                }
            }
        };
        if remote.connection_id != connection_id.to_string()
            || remote.realm_id != staged.realm_id
            || remote.assignment_epoch != staged.assignment_epoch
            || remote.granted_scopes != staged.granted_scopes
            || !remote.credential.is_empty()
        {
            return Err(ConnectError::new(
                ErrorCode::DataLoss,
                "realm credential rotation response is inconsistent",
            ));
        }
        let record = self
            .store
            .rotate_fleet_connection_credential(
                organization_id,
                project_id,
                environment_id,
                connection_id,
                request_id,
                actor.user.id,
                reason,
            )
            .await
            .map_err(source_error)?;
        Response::ok(connection_to_proto(record)?)
    }

    async fn revoke_connection(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeConnectionRequest>,
    ) -> ServiceResult<RealmConnection> {
        require_mutation(&request.mutation)?;
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let project_id = required_uuid(request.project_id, "project_id")?;
        let environment_id = required_uuid(request.environment_id, "environment_id")?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                FleetResourceKindRecord::Environment,
                environment_id,
            )
            .await?;
        let connection_id = required_uuid(request.connection_id, "connection_id")?;
        let existing = self
            .store
            .fleet_connection(connection_id)
            .await
            .map_err(source_error)?
            .filter(|record| {
                record.organization_id == organization_id
                    && record.project_id == project_id
                    && record.environment_id == environment_id
            })
            .ok_or_else(not_found)?;
        if existing.state != FleetConnectionStateRecord::Revoked {
            let remote = match existing.mode {
                FleetConnectionModeRecord::PublicEndpoint => {
                    let credential = open_fleet_credential(
                        &self.credential_keys,
                        existing.id,
                        &existing.credential,
                    )?;
                    revoke_remote_connection(
                        &existing.management_endpoint,
                        &credential,
                        request.connection_id,
                        request.mutation.request_id,
                        request.mutation.reason,
                        &self.runtime_environment,
                    )
                    .await
                    .map(|_| ())
                }
                FleetConnectionModeRecord::OutboundConnector => self
                    .outbound_revoke_connection(
                        &existing,
                        RevokeFleetConnectionRequest {
                            connection_id: request.connection_id.to_owned(),
                            request_id: request.mutation.request_id.to_owned(),
                            reason: request.mutation.reason.to_owned(),
                            ..Default::default()
                        },
                    )
                    .await
                    .map(|_| ()),
            };
            if let Err(error) = remote {
                tracing::warn!(
                    connection_id = %connection_id,
                    error = %error,
                    "realm did not confirm connection revocation; local credential is being revoked"
                );
            }
        }
        let request_id = required_uuid(request.mutation.request_id, "mutation.request_id")?;
        let reason = safe_text(request.mutation.reason, "mutation.reason", 500, true)?;
        let record = self
            .store
            .revoke_fleet_connection(
                organization_id,
                project_id,
                environment_id,
                connection_id,
                request_id,
                actor.user.id,
                reason.clone(),
            )
            .await
            .map_err(source_error)?;
        if let Some(analytics) = &self.analytics {
            let purge_result = analytics
                .purge_connection(organization_id, connection_id)
                .await;
            self.store
                .record_fleet_analytics_maintenance(FleetAnalyticsMaintenanceAuditRecord {
                    request_id,
                    organization_id,
                    connection_id: Some(connection_id),
                    operator_id: actor.user.id,
                    action: FleetAnalyticsMaintenanceActionRecord::PurgeConnection,
                    outcome: if purge_result.is_ok() {
                        FleetAnalyticsMaintenanceOutcomeRecord::Succeeded
                    } else {
                        FleetAnalyticsMaintenanceOutcomeRecord::Failed
                    },
                    reason,
                    occurred_at: now(),
                })
                .await
                .map_err(source_error)?;
            purge_result.map_err(source_error)?;
        }
        Response::ok(connection_to_proto(record)?)
    }

    async fn list_role_bindings(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListRoleBindingsRequest>,
    ) -> ServiceResult<ListRoleBindingsResponse> {
        let kind = resource_kind_record(request.resource_kind.as_known())?;
        let resource_id = required_uuid(request.resource_id, "resource_id")?;
        self.authorizer
            .authorize_fleet(ctx.headers(), OperatorCapability::Read, kind, resource_id)
            .await?;
        let after = decode_page_token(request.page_token)?;
        let page_size = page_size(request.page_size)?;
        let mut records = self
            .store
            .fleet_role_bindings(kind, resource_id, request.include_revoked)
            .await
            .map_err(source_error)?;
        records.retain(|record| after.is_none_or(|after| record.id > after));
        let next_page_token = next_page_token(&records, page_size, |record| record.id);
        records.truncate(page_size);
        Response::ok(ListRoleBindingsResponse {
            role_bindings: records
                .into_iter()
                .map(role_binding_to_proto)
                .collect::<Result<_, _>>()?,
            next_page_token,
            ..Default::default()
        })
    }

    async fn upsert_role_binding(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpsertRoleBindingRequest>,
    ) -> ServiceResult<RoleBinding> {
        let kind = resource_kind_record(request.resource_kind.as_known())?;
        let resource_id = required_uuid(request.resource_id, "resource_id")?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                kind,
                resource_id,
            )
            .await?;
        require_mutation(&request.mutation)?;
        let target_role = fleet_role_record(request.role.as_known())?;
        self.authorizer
            .require_fleet_role_dominance(&actor, kind, resource_id, target_role)
            .await?;
        let record = self
            .store
            .upsert_fleet_role_binding(
                required_uuid(request.operator_id, "operator_id")?,
                kind,
                resource_id,
                target_role,
                required_uuid(request.mutation.request_id, "mutation.request_id")?,
                actor.user.id,
                safe_text(request.mutation.reason, "mutation.reason", 500, true)?,
            )
            .await
            .map_err(source_error)?;
        Response::ok(role_binding_to_proto(record)?)
    }

    async fn revoke_role_binding(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeRoleBindingRequest>,
    ) -> ServiceResult<RoleBinding> {
        let role_binding_id = required_uuid(request.role_binding_id, "role_binding_id")?;
        let binding = self
            .store
            .fleet_role_binding(role_binding_id)
            .await
            .map_err(source_error)?
            .ok_or_else(not_found)?;
        let actor = self
            .authorizer
            .authorize_fleet(
                ctx.headers(),
                OperatorCapability::Administer,
                binding.resource_kind,
                binding.resource_id,
            )
            .await?;
        require_mutation(&request.mutation)?;
        self.authorizer
            .require_fleet_role_dominance(
                &actor,
                binding.resource_kind,
                binding.resource_id,
                binding.role,
            )
            .await?;
        let record = self
            .store
            .revoke_fleet_role_binding(
                role_binding_id,
                required_uuid(request.mutation.request_id, "mutation.request_id")?,
                actor.user.id,
                safe_text(request.mutation.reason, "mutation.reason", 500, true)?,
            )
            .await
            .map_err(source_error)?;
        Response::ok(role_binding_to_proto(record)?)
    }

    async fn list_audit_events(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListAuditEventsRequest>,
    ) -> ServiceResult<ListAuditEventsResponse> {
        let organization_id = optional_uuid(request.organization_id, "organization_id")?;
        let project_id = optional_uuid(request.project_id, "project_id")?;
        let environment_id = optional_uuid(request.environment_id, "environment_id")?;
        if let Some(id) = environment_id {
            self.authorizer
                .authorize_fleet(
                    ctx.headers(),
                    OperatorCapability::Read,
                    FleetResourceKindRecord::Environment,
                    id,
                )
                .await?;
        } else if let Some(id) = project_id {
            self.authorizer
                .authorize_fleet(
                    ctx.headers(),
                    OperatorCapability::Read,
                    FleetResourceKindRecord::Project,
                    id,
                )
                .await?;
        } else if let Some(id) = organization_id {
            self.authorizer
                .authorize_fleet(
                    ctx.headers(),
                    OperatorCapability::Read,
                    FleetResourceKindRecord::Organization,
                    id,
                )
                .await?;
        } else {
            self.authorizer
                .authorize(ctx.headers(), OperatorCapability::Read)
                .await?;
        }
        let after = decode_page_token(request.page_token)?;
        let page_size = page_size(request.page_size)?;
        let mut records = self
            .store
            .fleet_audit_records()
            .await
            .map_err(source_error)?;
        records.retain(|record| {
            organization_id.is_none_or(|id| record.organization_id == Some(id))
                && project_id.is_none_or(|id| record.project_id == Some(id))
                && environment_id.is_none_or(|id| record.environment_id == Some(id))
                && after.is_none_or(|after| record.id > after)
        });
        records.sort_unstable_by_key(|record| record.id);
        let next_page_token = next_page_token(&records, page_size, |record| record.id);
        records.truncate(page_size);
        Response::ok(ListAuditEventsResponse {
            events: records
                .into_iter()
                .map(audit_to_proto)
                .collect::<Result<_, _>>()?,
            next_page_token,
            ..Default::default()
        })
    }
}

fn organization_to_proto(record: FleetOrganizationRecord) -> Result<Organization, ConnectError> {
    Ok(Organization {
        id: record.id.to_string(),
        slug: record.slug,
        name: record.name,
        state: resource_state(record.state).into(),
        created_at: format_timestamp(record.created_at)?,
        updated_at: format_timestamp(record.updated_at)?,
        archived_at: format_optional_timestamp(record.archived_at)?,
        ..Default::default()
    })
}

fn project_to_proto(record: FleetProjectRecord) -> Result<Project, ConnectError> {
    Ok(Project {
        id: record.id.to_string(),
        organization_id: record.organization_id.to_string(),
        slug: record.slug,
        name: record.name,
        description: record.description,
        state: resource_state(record.state).into(),
        created_at: format_timestamp(record.created_at)?,
        updated_at: format_timestamp(record.updated_at)?,
        archived_at: format_optional_timestamp(record.archived_at)?,
        ..Default::default()
    })
}

fn environment_to_proto(record: FleetEnvironmentRecord) -> Result<Environment, ConnectError> {
    Ok(Environment {
        id: record.id.to_string(),
        organization_id: record.organization_id.to_string(),
        project_id: record.project_id.to_string(),
        slug: record.slug,
        name: record.name,
        kind: match record.kind {
            FleetEnvironmentKindRecord::Development => EnvironmentKind::Development.into(),
            FleetEnvironmentKindRecord::Preview => EnvironmentKind::Preview.into(),
            FleetEnvironmentKindRecord::Staging => EnvironmentKind::Staging.into(),
            FleetEnvironmentKindRecord::Production => EnvironmentKind::Production.into(),
        },
        provider: record.provider,
        region: record.region,
        state: resource_state(record.state).into(),
        created_at: format_timestamp(record.created_at)?,
        updated_at: format_timestamp(record.updated_at)?,
        archived_at: format_optional_timestamp(record.archived_at)?,
        ..Default::default()
    })
}

fn connection_attempt_to_proto(
    record: FleetConnectionAttemptRecord,
) -> Result<ConnectionAttempt, ConnectError> {
    Ok(ConnectionAttempt {
        id: record.id.to_string(),
        environment_id: record.environment_id.to_string(),
        mode: connection_mode_proto(record.mode).into(),
        expires_at: format_timestamp(record.expires_at)?,
        state: ConnectionState::Pending.into(),
        ..Default::default()
    })
}

fn connection_to_proto(record: FleetConnectionRecord) -> Result<RealmConnection, ConnectError> {
    Ok(RealmConnection {
        id: record.id.to_string(),
        organization_id: record.organization_id.to_string(),
        project_id: record.project_id.to_string(),
        environment_id: record.environment_id.to_string(),
        realm_id: record.realm_id,
        display_name: record.display_name,
        mode: connection_mode_proto(record.mode).into(),
        management_endpoint: record.management_endpoint,
        credential_reference: format!("fleet-credential://{}", record.id),
        deployment_version: record.deployment_version,
        protocol_version: record.protocol_version,
        capabilities: record
            .capabilities
            .into_iter()
            .map(|(name, version)| Capability {
                name,
                version,
                ..Default::default()
            })
            .collect(),
        issuer: record.issuer,
        rp_id: record.rp_id,
        state: connection_state_proto(record.state).into(),
        last_seen_at: format_optional_timestamp(record.last_seen_at)?,
        created_at: format_timestamp(record.created_at)?,
        updated_at: format_timestamp(record.updated_at)?,
        revoked_at: format_optional_timestamp(record.revoked_at)?,
        ..Default::default()
    })
}

fn role_binding_to_proto(record: FleetRoleBindingRecord) -> Result<RoleBinding, ConnectError> {
    Ok(RoleBinding {
        id: record.id.to_string(),
        operator_id: record.operator_id.to_string(),
        resource_kind: resource_kind_proto(record.resource_kind).into(),
        resource_id: record.resource_id.to_string(),
        role: fleet_role_proto(record.role).into(),
        created_by: record.created_by.to_string(),
        created_at: format_timestamp(record.created_at)?,
        revoked_by: record
            .revoked_by
            .map_or_else(String::new, |id| id.to_string()),
        revoked_at: format_optional_timestamp(record.revoked_at)?,
        ..Default::default()
    })
}

fn audit_to_proto(record: FleetAuditRecord) -> Result<AuditEvent, ConnectError> {
    Ok(AuditEvent {
        id: record.id.to_string(),
        request_id: record.request_id.to_string(),
        operator_id: record.operator_id.to_string(),
        action: record.action,
        resource_kind: match record.resource_kind.as_str() {
            "organization" => ResourceKind::Organization.into(),
            "project" => ResourceKind::Project.into(),
            "environment" => ResourceKind::Environment.into(),
            _ => ResourceKind::Unspecified.into(),
        },
        resource_id: record.resource_id.to_string(),
        organization_id: record
            .organization_id
            .map_or_else(String::new, |id| id.to_string()),
        project_id: record
            .project_id
            .map_or_else(String::new, |id| id.to_string()),
        environment_id: record
            .environment_id
            .map_or_else(String::new, |id| id.to_string()),
        outcome: AuditOutcome::Succeeded.into(),
        reason: record.reason,
        occurred_at: format_timestamp(record.occurred_at)?,
        ..Default::default()
    })
}

fn environment_kind(
    kind: Option<EnvironmentKind>,
) -> Result<FleetEnvironmentKindRecord, ConnectError> {
    match kind {
        Some(EnvironmentKind::Development) => Ok(FleetEnvironmentKindRecord::Development),
        Some(EnvironmentKind::Preview) => Ok(FleetEnvironmentKindRecord::Preview),
        Some(EnvironmentKind::Staging) => Ok(FleetEnvironmentKindRecord::Staging),
        Some(EnvironmentKind::Production) => Ok(FleetEnvironmentKindRecord::Production),
        Some(EnvironmentKind::Unspecified) | None => Err(invalid("environment kind is required")),
    }
}

fn connection_mode(
    mode: Option<ConnectionMode>,
) -> Result<FleetConnectionModeRecord, ConnectError> {
    match mode {
        Some(ConnectionMode::PublicEndpoint) => Ok(FleetConnectionModeRecord::PublicEndpoint),
        Some(ConnectionMode::OutboundConnector) => Ok(FleetConnectionModeRecord::OutboundConnector),
        Some(ConnectionMode::Unspecified) | None => Err(invalid("connection mode is required")),
    }
}

fn connection_mode_proto(mode: FleetConnectionModeRecord) -> ConnectionMode {
    match mode {
        FleetConnectionModeRecord::PublicEndpoint => ConnectionMode::PublicEndpoint,
        FleetConnectionModeRecord::OutboundConnector => ConnectionMode::OutboundConnector,
    }
}

fn connection_state_proto(state: FleetConnectionStateRecord) -> ConnectionState {
    match state {
        FleetConnectionStateRecord::Pending => ConnectionState::Pending,
        FleetConnectionStateRecord::Verifying => ConnectionState::Verifying,
        FleetConnectionStateRecord::Healthy => ConnectionState::Healthy,
        FleetConnectionStateRecord::Degraded => ConnectionState::Degraded,
        FleetConnectionStateRecord::Offline => ConnectionState::Offline,
        FleetConnectionStateRecord::Revoked => ConnectionState::Revoked,
    }
}

fn connector_connection_usable(record: &FleetConnectionRecord) -> bool {
    record.revoked_at.is_none()
        && matches!(
            record.state,
            FleetConnectionStateRecord::Healthy
                | FleetConnectionStateRecord::Degraded
                | FleetConnectionStateRecord::Offline
        )
}

fn resource_kind_record(
    kind: Option<ResourceKind>,
) -> Result<FleetResourceKindRecord, ConnectError> {
    match kind {
        Some(ResourceKind::Organization) => Ok(FleetResourceKindRecord::Organization),
        Some(ResourceKind::Project) => Ok(FleetResourceKindRecord::Project),
        Some(ResourceKind::Environment) => Ok(FleetResourceKindRecord::Environment),
        Some(ResourceKind::Unspecified) | None => Err(invalid("resource kind is required")),
    }
}

fn resource_kind_proto(kind: FleetResourceKindRecord) -> ResourceKind {
    match kind {
        FleetResourceKindRecord::Organization => ResourceKind::Organization,
        FleetResourceKindRecord::Project => ResourceKind::Project,
        FleetResourceKindRecord::Environment => ResourceKind::Environment,
    }
}

fn fleet_role_record(role: Option<FleetRole>) -> Result<FleetRoleRecord, ConnectError> {
    match role {
        Some(FleetRole::Owner) => Ok(FleetRoleRecord::Owner),
        Some(FleetRole::Administrator) => Ok(FleetRoleRecord::Administrator),
        Some(FleetRole::Operator) => Ok(FleetRoleRecord::Operator),
        Some(FleetRole::Support) => Ok(FleetRoleRecord::Support),
        Some(FleetRole::Auditor) => Ok(FleetRoleRecord::Auditor),
        Some(FleetRole::Unspecified) | None => Err(invalid("Fleet role is required")),
    }
}

fn fleet_role_proto(role: FleetRoleRecord) -> FleetRole {
    match role {
        FleetRoleRecord::Owner => FleetRole::Owner,
        FleetRoleRecord::Administrator => FleetRole::Administrator,
        FleetRoleRecord::Operator => FleetRole::Operator,
        FleetRoleRecord::Support => FleetRole::Support,
        FleetRoleRecord::Auditor => FleetRole::Auditor,
    }
}

fn safe_management_endpoint(
    value: &str,
    environment: &RuntimeEnvironment,
) -> Result<Url, ConnectError> {
    let endpoint =
        Url::parse(value.trim()).map_err(|_| invalid("management endpoint is invalid"))?;
    if endpoint.username() != ""
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !matches!(endpoint.path(), "" | "/")
    {
        return Err(invalid("management endpoint must be an origin"));
    }
    let host = endpoint
        .host_str()
        .ok_or_else(|| invalid("management endpoint has no host"))?;
    if environment == &RuntimeEnvironment::Production && !public_management_host(host) {
        return Err(invalid("management endpoint must use a public host"));
    }
    match endpoint.scheme() {
        "https" => {}
        "http"
            if environment == &RuntimeEnvironment::Development
                && (matches!(
                    host,
                    "localhost" | "127.0.0.1" | "::1" | "host.docker.internal"
                ) || !host.contains('.')) =>
        {
            // Development Compose needs container DNS and host.docker.internal.
            // Production still requires HTTPS even for similarly named hosts.
        }
        _ => return Err(invalid("management endpoint must use HTTPS")),
    }
    Ok(endpoint)
}

/// Rejects endpoints that can address the control plane itself, a private
/// service, or cloud instance metadata. Public-endpoint mode is deliberately
/// internet-routable; private realms use the outbound connector instead.
///
/// The outbound client separately validates every resolved address and pins the
/// accepted set into its connector. Production deployments must still deny
/// private/link-local egress at the network layer as independent containment.
fn public_management_host(host: &str) -> bool {
    if let Ok(address) = host.parse::<IpAddr>() {
        return match address {
            IpAddr::V4(address) => {
                let octets = address.octets();
                !(address.is_unspecified()
                    || address.is_private()
                    || address.is_loopback()
                    || address.is_link_local()
                    || address.is_broadcast()
                    || address.is_multicast()
                    || octets[0] == 0
                    || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                    || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                    || (octets[0] == 198 && matches!(octets[1], 18 | 19))
                    || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                    || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                    || octets[0] >= 240)
            }
            IpAddr::V6(address) => {
                if let Some(mapped) = address.to_ipv4_mapped() {
                    return public_management_host(&mapped.to_string());
                }
                let octets = address.octets();
                let blocked = address.is_unspecified()
                    || address.is_loopback()
                    || address.is_multicast()
                    || octets[0] & 0xfe == 0xfc
                    || (octets[0] == 0xfe && octets[1] & 0xc0 == 0x80)
                    || (octets[0] == 0x20
                        && octets[1] == 0x01
                        && octets[2] == 0x0d
                        && octets[3] == 0xb8);
                !blocked && octets[0] & 0xe0 == 0x20
            }
        };
    }

    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.contains('.')
        && !matches!(
            host.as_str(),
            "localhost" | "metadata.google.internal" | "metadata.amazonaws.com"
        )
        && ![
            ".localhost",
            ".local",
            ".internal",
            ".home.arpa",
            ".invalid",
        ]
        .iter()
        .any(|suffix| host.ends_with(suffix))
}

fn safe_secret(
    value: &str,
    label: &'static str,
    minimum: usize,
    maximum: usize,
) -> Result<SecretString, ConnectError> {
    let value = value.trim();
    if !(minimum..=maximum).contains(&value.len())
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        tracing::debug!(label, "rejected malformed secret");
        return Err(invalid("secret is invalid"));
    }
    Ok(SecretString::from(value.to_owned()))
}

#[derive(Clone)]
struct PinnedManagementTransport(reqwest::Client);

#[derive(Debug, thiserror::Error)]
enum PinnedTransportError {
    #[error("encode management request body: {0}")]
    RequestBody(String),
    #[error("send pinned management request: {0}")]
    Request(#[from] reqwest::Error),
    #[error("management response exceeds the configured byte limit")]
    ResponseTooLarge,
    #[error("construct management response: {0}")]
    Response(#[from] http::Error),
}

impl ClientTransport for PinnedManagementTransport {
    type ResponseBody = Full<Bytes>;
    type Error = PinnedTransportError;

    fn send(
        &self,
        request: http::Request<connectrpc::client::ClientBody>,
    ) -> BoxFuture<'static, Result<http::Response<Self::ResponseBody>, Self::Error>> {
        let client = self.0.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let body = body
                .collect()
                .await
                .map_err(|error| PinnedTransportError::RequestBody(error.to_string()))?
                .to_bytes();
            let response = client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body)
                .send()
                .await?;
            let status = response.status();
            let version = response.version();
            let headers = response.headers().clone();
            if response
                .content_length()
                .is_some_and(|length| length > MANAGEMENT_RESPONSE_MAX_BYTES as u64)
            {
                return Err(PinnedTransportError::ResponseTooLarge);
            }
            let mut stream = response.bytes_stream();
            let mut body = BytesMut::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                if body.len().saturating_add(chunk.len()) > MANAGEMENT_RESPONSE_MAX_BYTES {
                    return Err(PinnedTransportError::ResponseTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            let mut response = http::Response::builder().status(status).version(version);
            *response
                .headers_mut()
                .expect("HTTP response builder exposes headers before body") = headers;
            Ok(response.body(Full::new(body.freeze()))?)
        })
    }
}

async fn management_client(
    endpoint: &str,
    environment: &RuntimeEnvironment,
) -> Result<RealmManagementServiceClient<PinnedManagementTransport>, ConnectError> {
    let url = safe_management_endpoint(endpoint, environment)?;
    let host = url
        .host_str()
        .ok_or_else(|| invalid("stored management endpoint has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| invalid("stored management endpoint has no port"))?;
    let addresses = tokio::time::timeout(
        MANAGEMENT_DNS_TIMEOUT,
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| ConnectError::new(ErrorCode::Unavailable, "management endpoint DNS timed out"))?
    .map_err(|_| ConnectError::new(ErrorCode::Unavailable, "management endpoint DNS failed"))?
    .collect::<Vec<_>>();
    let addresses = validated_management_addresses(addresses, environment)?;
    let transport = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(MANAGEMENT_DNS_TIMEOUT)
        .timeout(MANAGEMENT_TIMEOUT)
        .resolve_to_addrs(host, &addresses)
        .build()
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "build pinned management transport"))?;
    let config = ClientConfig::new(
        endpoint
            .parse()
            .map_err(|_| invalid("stored management endpoint is invalid"))?,
    )
    .with_protocol(Protocol::Connect)
    .with_default_timeout(MANAGEMENT_TIMEOUT);
    Ok(RealmManagementServiceClient::new(
        PinnedManagementTransport(transport),
        config,
    ))
}

fn validated_management_addresses(
    mut addresses: Vec<SocketAddr>,
    environment: &RuntimeEnvironment,
) -> Result<Vec<SocketAddr>, ConnectError> {
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(ConnectError::new(
            ErrorCode::Unavailable,
            "management endpoint DNS returned no addresses",
        ));
    }
    if environment == &RuntimeEnvironment::Production
        && addresses
            .iter()
            .any(|address| !public_management_host(&address.ip().to_string()))
    {
        return Err(invalid(
            "management endpoint DNS resolved to a non-public address",
        ));
    }
    Ok(addresses)
}

pub(crate) fn seal_fleet_credential(
    keys: &KeyRing,
    connection_id: Uuid,
    credential: &SecretString,
) -> Result<EncryptedFleetCredential, ConnectError> {
    let (key_id, key) = keys.active();
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "initialize credential encryption"))?;
    let nonce = Nonce::<Aes256Gcm>::generate();
    let aad = fleet_credential_aad(connection_id, key_id);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: credential.expose_secret().as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "encrypt realm credential"))?;
    Ok(EncryptedFleetCredential {
        wrapping_key_id: key_id.to_owned(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub(crate) fn open_fleet_credential(
    keys: &KeyRing,
    connection_id: Uuid,
    encrypted: &EncryptedFleetCredential,
) -> Result<SecretString, ConnectError> {
    let key = keys.get(&encrypted.wrapping_key_id).ok_or_else(|| {
        ConnectError::new(
            ErrorCode::FailedPrecondition,
            "realm credential requires an unavailable wrapping key",
        )
    })?;
    let nonce = URL_SAFE_NO_PAD
        .decode(&encrypted.nonce)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "decode realm credential nonce"))?;
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| {
        ConnectError::new(
            ErrorCode::DataLoss,
            "realm credential nonce has wrong length",
        )
    })?;
    let nonce = Nonce::<Aes256Gcm>::from(nonce);
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&encrypted.ciphertext)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "decode encrypted realm credential"))?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "initialize credential encryption"))?;
    let aad = fleet_credential_aad(connection_id, &encrypted.wrapping_key_id);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "decrypt realm credential"))?;
    let value = String::from_utf8(plaintext)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "realm credential is invalid"))?;
    Ok(SecretString::from(value))
}

fn fleet_credential_aad(connection_id: Uuid, key_id: &str) -> String {
    format!("{FLEET_CREDENTIAL_AAD_VERSION}:{connection_id}:{key_id}")
}

async fn revoke_remote_connection(
    endpoint: &str,
    credential: &SecretString,
    connection_id: &str,
    request_id: &str,
    reason: &str,
    environment: &RuntimeEnvironment,
) -> Result<(), ConnectError> {
    let mut client = management_client(endpoint, environment).await?;
    let authorized_config = client.config().clone().with_default_header(
        http::header::AUTHORIZATION,
        format!("Bearer {}", credential.expose_secret()),
    );
    *client.config_mut() = authorized_config;
    client
        .revoke_fleet_connection_with_options(
            RevokeFleetConnectionRequest {
                connection_id: connection_id.to_owned(),
                request_id: request_id.to_owned(),
                reason: reason.to_owned(),
                ..Default::default()
            },
            CallOptions::default().with_timeout(MANAGEMENT_TIMEOUT),
        )
        .await?;
    Ok(())
}

async fn rotate_remote_connection(
    endpoint: &str,
    credential: &SecretString,
    request: RotateFleetCredentialRequest,
    environment: &RuntimeEnvironment,
) -> Result<PairingGrant, ConnectError> {
    let mut client = management_client(endpoint, environment).await?;
    let authorized_config = client.config().clone().with_default_header(
        http::header::AUTHORIZATION,
        format!("Bearer {}", credential.expose_secret()),
    );
    *client.config_mut() = authorized_config;
    client
        .rotate_fleet_credential_with_options(
            request,
            CallOptions::default().with_timeout(MANAGEMENT_TIMEOUT),
        )
        .await
        .map(|response| response.into_owned())
}

fn management_error(error: ConnectError) -> ConnectError {
    tracing::warn!(code = ?error.code, "realm management RPC failed");
    match error.code {
        ErrorCode::InvalidArgument
        | ErrorCode::Unauthenticated
        | ErrorCode::PermissionDenied
        | ErrorCode::FailedPrecondition
        | ErrorCode::AlreadyExists
        | ErrorCode::ResourceExhausted => error,
        _ => ConnectError::new(
            ErrorCode::Unavailable,
            "realm management endpoint is unavailable",
        ),
    }
}

fn resource_state(state: FleetResourceStateRecord) -> ResourceState {
    match state {
        FleetResourceStateRecord::Active => ResourceState::Active,
        FleetResourceStateRecord::Archived => ResourceState::Archived,
    }
}

fn require_mutation<V>(mutation: &buffa::MessageFieldView<V>) -> Result<(), ConnectError> {
    mutation
        .is_set()
        .then_some(())
        .ok_or_else(|| invalid("mutation context is required"))
}

fn safe_slug(value: &str) -> Result<String, ConnectError> {
    let value = value.trim();
    if !(2..=63).contains(&value.len())
        || value.starts_with('-')
        || value.ends_with('-')
        || value.contains("--")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(invalid(
            "slug must be 2-63 lowercase letters, digits or single hyphens",
        ));
    }
    Ok(value.to_owned())
}

fn safe_text(
    value: &str,
    field: &'static str,
    maximum: usize,
    allow_empty: bool,
) -> Result<String, ConnectError> {
    let value = value.trim();
    let allow_empty = allow_empty && field != "mutation.reason";
    if (!allow_empty && value.is_empty())
        || value.len() > maximum
        || value.chars().any(char::is_control)
    {
        return Err(invalid(match field {
            "name" => "name is invalid",
            "description" => "description is invalid",
            "provider" => "provider is invalid",
            "region" => "region is invalid",
            "mutation.reason" => "mutation reason is invalid",
            _ => "text field is invalid",
        }));
    }
    Ok(value.to_owned())
}

fn safe_remote_reason(value: &str) -> Result<String, ConnectError> {
    let value = value.trim();
    if !(10..=500).contains(&value.len()) || value.chars().any(char::is_control) {
        return Err(invalid(
            "remote mutation reason must contain 10-500 safe characters",
        ));
    }
    Ok(value.to_owned())
}

fn safe_remote_target(value: &str, maximum: usize) -> Result<String, ConnectError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > maximum
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(invalid("remote mutation target is invalid"));
    }
    Ok(value.to_owned())
}

fn validate_remote_expiry(value: &str) -> Result<(), ConnectError> {
    let value = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| invalid("remote mutation expiry must be an RFC 3339 timestamp"))?;
    let value = u64::try_from(value.unix_timestamp())
        .map_err(|_| invalid("remote mutation expiry is invalid"))?;
    let current = now();
    if value <= current || value > current.saturating_add(5 * 60) {
        return Err(invalid(
            "remote mutation expiry must be in the next five minutes",
        ));
    }
    Ok(())
}

const fn remote_mutation_action(operation: RemoteMutationOperation) -> &'static str {
    match operation {
        RemoteMutationOperation::Unspecified => "unspecified",
        RemoteMutationOperation::RevokeUserPasskey => "revoke-user-passkey",
        RemoteMutationOperation::SetServiceAccountEnabled => "set-service-account-enabled",
        RemoteMutationOperation::RevokeServiceAccountCredential => {
            "revoke-service-account-credential"
        }
        RemoteMutationOperation::PauseWebhook => "pause-webhook",
        RemoteMutationOperation::DeleteWebhook => "delete-webhook",
    }
}

fn required_uuid(value: &str, field: &'static str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(value).map_err(|_| invalid_uuid(field))
}

fn optional_uuid(value: &str, field: &'static str) -> Result<Option<Uuid>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    required_uuid(value, field).map(Some)
}

fn optional_realm_id(value: &str) -> Result<Option<String>, ConnectError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(invalid("realm_id is invalid"));
    }
    Ok(Some(value.to_owned()))
}

fn analytics_range(starts_at: &str, ends_at: &str) -> Result<(i64, i64), ConnectError> {
    let parse = |value: &str| {
        OffsetDateTime::parse(value, &Rfc3339)
            .map_err(|_| invalid("analytics range must contain RFC 3339 timestamps"))?
            .unix_timestamp()
            .checked_mul(1_000)
            .ok_or_else(|| invalid("analytics range is outside the supported timestamp range"))
    };
    let starts_at = parse(starts_at)?;
    let ends_at = parse(ends_at)?;
    const MAX_RANGE_MILLISECONDS: i64 = 28 * 24 * 60 * 60 * 1_000;
    if ends_at <= starts_at || ends_at.saturating_sub(starts_at) > MAX_RANGE_MILLISECONDS {
        return Err(invalid(
            "analytics range must be positive and no longer than 28 days",
        ));
    }
    let future_limit = i64::try_from(now())
        .unwrap_or(i64::MAX / 1_000)
        .saturating_add(5 * 60)
        .saturating_mul(1_000);
    if ends_at > future_limit {
        return Err(invalid("analytics range ends too far in the future"));
    }
    Ok((starts_at, ends_at))
}

fn invalid_uuid(field: &'static str) -> ConnectError {
    tracing::debug!(field, "invalid Fleet resource id");
    invalid("resource id is invalid")
}

fn page_size(value: u32) -> Result<usize, ConnectError> {
    match value {
        0 => Ok(DEFAULT_PAGE_SIZE),
        1..=MAX_PAGE_SIZE => Ok(value as usize),
        _ => Err(invalid("page_size must be between 1 and 100")),
    }
}

fn next_page_token<T>(records: &[T], page_size: usize, id: impl Fn(&T) -> Uuid) -> String {
    if records.len() > page_size {
        encode_page_token(id(&records[page_size - 1]))
    } else {
        String::new()
    }
}

fn encode_page_token(id: Uuid) -> String {
    URL_SAFE_NO_PAD.encode(id.as_bytes())
}

fn decode_page_token(value: &str) -> Result<Option<Uuid>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() != PAGE_TOKEN_LENGTH {
        return Err(invalid("page_token is invalid"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid("page_token is invalid"))?;
    Uuid::from_slice(&bytes)
        .map(Some)
        .map_err(|_| invalid("page_token is invalid"))
}

fn format_timestamp(value: u64) -> Result<String, ConnectError> {
    let value = i64::try_from(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "stored timestamp is invalid"))?;
    OffsetDateTime::from_unix_timestamp(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "stored timestamp is invalid"))?
        .format(&Rfc3339)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "format Fleet timestamp"))
}

fn format_millisecond_timestamp(value: i64) -> Result<String, ConnectError> {
    OffsetDateTime::from_unix_timestamp(value.div_euclid(1_000))
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "stored timestamp is invalid"))?
        .format(&Rfc3339)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "format Fleet timestamp"))
}

fn format_optional_timestamp(value: Option<u64>) -> Result<String, ConnectError> {
    value
        .map(format_timestamp)
        .transpose()
        .map(Option::unwrap_or_default)
}

fn add_analytics_count(total: &mut u64, value: u64) -> Result<(), ConnectError> {
    *total = total.checked_add(value).ok_or_else(|| {
        ConnectError::new(
            ErrorCode::DataLoss,
            "Fleet analytics counter exceeds the V1 numeric range",
        )
    })?;
    Ok(())
}

fn analytics_cardinality(value: usize) -> Result<u64, ConnectError> {
    u64::try_from(value).map_err(|_| {
        ConnectError::new(
            ErrorCode::DataLoss,
            "Fleet analytics cardinality exceeds the V1 numeric range",
        )
    })
}

fn analytics_reporting_status(
    last_bucket_at: Option<i64>,
    stale_before: i64,
    connection_state: FleetConnectionStateRecord,
) -> (bool, bool) {
    let stale = last_bucket_at.is_none_or(|timestamp| timestamp < stale_before)
        || matches!(
            connection_state,
            FleetConnectionStateRecord::Degraded | FleetConnectionStateRecord::Offline
        );
    (!stale, stale)
}

fn invalid(message: &'static str) -> ConnectError {
    ConnectError::new(ErrorCode::InvalidArgument, message)
}

fn not_found() -> ConnectError {
    ConnectError::new(ErrorCode::NotFound, "Fleet resource is missing")
}

fn source_error(error: anyhow::Error) -> ConnectError {
    if let Some(policy) = error.downcast_ref::<StorePolicyError>() {
        let (code, message) = match policy {
            StorePolicyError::FleetResourceMissing => {
                (ErrorCode::NotFound, "Fleet resource is missing")
            }
            StorePolicyError::FleetSlugConflict => (
                ErrorCode::AlreadyExists,
                "Fleet resource slug is already in use",
            ),
            StorePolicyError::FleetParentArchived => {
                (ErrorCode::FailedPrecondition, "Fleet resource is archived")
            }
            StorePolicyError::FleetHasActiveChildren => (
                ErrorCode::FailedPrecondition,
                "Fleet resource has active children",
            ),
            StorePolicyError::FleetIdempotencyConflict => (
                ErrorCode::AlreadyExists,
                "mutation request id was already used",
            ),
            StorePolicyError::FleetConnectionAttemptExpired => (
                ErrorCode::FailedPrecondition,
                "connection attempt expired or was already consumed",
            ),
            StorePolicyError::FleetConnectionConflict => (
                ErrorCode::AlreadyExists,
                "realm is already connected to this environment",
            ),
            _ => (ErrorCode::Internal, "Fleet operation failed"),
        };
        return ConnectError::new(code, message);
    }
    tracing::error!(error = %error, "Fleet operation failed");
    ConnectError::new(ErrorCode::Internal, "Fleet operation failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_are_canonical_and_unambiguous() {
        assert_eq!(safe_slug("acme-prod").unwrap(), "acme-prod");
        for invalid_slug in ["A", "Acme", "-acme", "acme-", "acme--prod", "acme_prod"] {
            assert!(safe_slug(invalid_slug).is_err());
        }
    }

    #[test]
    fn page_tokens_round_trip_without_exposing_ordering_format() {
        let id = Uuid::new_v4();
        let token = encode_page_token(id);
        assert_eq!(token.len(), PAGE_TOKEN_LENGTH);
        assert_eq!(decode_page_token(&token).unwrap(), Some(id));
    }

    #[test]
    fn analytics_scope_and_range_are_bounded_before_ledger_access() {
        assert_eq!(
            optional_realm_id("realm.prod_1").unwrap().as_deref(),
            Some("realm.prod_1")
        );
        assert!(optional_realm_id("realm/escape").is_err());
        assert!(analytics_range("2026-08-08T00:00:00Z", "2026-08-09T00:00:00Z").is_ok());
        assert!(analytics_range("2026-01-01T00:00:00Z", "2026-08-09T00:00:00Z").is_err());
        assert!(analytics_range("2026-08-09T00:00:00Z", "2026-08-08T00:00:00Z").is_err());
    }

    #[test]
    fn analytics_counts_fail_closed_instead_of_saturating() {
        let mut total = u64::MAX - 1;
        add_analytics_count(&mut total, 1).unwrap();
        assert_eq!(total, u64::MAX);
        assert!(add_analytics_count(&mut total, 1).is_err());
    }

    #[test]
    fn analytics_reporting_and_stale_coverage_are_disjoint() {
        let stale_before = 1_000;
        assert_eq!(
            analytics_reporting_status(
                Some(stale_before),
                stale_before,
                FleetConnectionStateRecord::Healthy,
            ),
            (true, false)
        );
        assert_eq!(
            analytics_reporting_status(
                Some(stale_before - 1),
                stale_before,
                FleetConnectionStateRecord::Healthy,
            ),
            (false, true)
        );
        assert_eq!(
            analytics_reporting_status(
                Some(stale_before),
                stale_before,
                FleetConnectionStateRecord::Offline,
            ),
            (false, true)
        );
    }

    #[test]
    fn insecure_management_endpoints_are_confined_to_local_development() {
        assert!(
            safe_management_endpoint(
                "http://host.docker.internal:8081",
                &RuntimeEnvironment::Development,
            )
            .is_ok()
        );
        assert!(
            safe_management_endpoint("http://realm:8080", &RuntimeEnvironment::Development,)
                .is_ok()
        );
        assert!(
            safe_management_endpoint(
                "http://host.docker.internal:8081",
                &RuntimeEnvironment::Production,
            )
            .is_err()
        );
        assert!(
            safe_management_endpoint(
                "http://metadata.google.internal",
                &RuntimeEnvironment::Development,
            )
            .is_err()
        );
        assert!(
            safe_management_endpoint(
                "http://metadata.google.internal/path",
                &RuntimeEnvironment::Development,
            )
            .is_err()
        );
    }

    #[test]
    fn production_management_endpoints_cannot_target_private_or_metadata_networks() {
        assert!(
            safe_management_endpoint(
                "https://auth.customer.example",
                &RuntimeEnvironment::Production,
            )
            .is_ok()
        );
        assert!(
            safe_management_endpoint("https://1.1.1.1", &RuntimeEnvironment::Production).is_ok()
        );
        for endpoint in [
            "https://127.0.0.1",
            "https://10.0.0.1",
            "https://100.64.0.1",
            "https://169.254.169.254",
            "https://192.168.1.1",
            "https://[::1]",
            "https://[fd00::1]",
            "https://[fe80::1]",
            "https://metadata.google.internal",
            "https://realm.railway.internal",
            "https://realm",
        ] {
            assert!(
                safe_management_endpoint(endpoint, &RuntimeEnvironment::Production).is_err(),
                "{endpoint} must not pass the public-endpoint SSRF boundary"
            );
        }
    }

    #[test]
    fn dns_results_are_all_public_deduplicated_and_fail_closed() {
        let public: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let private: SocketAddr = "169.254.169.254:443".parse().unwrap();
        assert_eq!(
            validated_management_addresses(vec![public, public], &RuntimeEnvironment::Production)
                .unwrap(),
            vec![public]
        );
        assert!(
            validated_management_addresses(vec![public, private], &RuntimeEnvironment::Production)
                .is_err(),
            "one private answer poisons the entire pinned resolution set"
        );
        assert!(
            validated_management_addresses(Vec::new(), &RuntimeEnvironment::Production).is_err()
        );
        assert!(
            validated_management_addresses(vec![private], &RuntimeEnvironment::Development).is_ok(),
            "loopback/private Compose endpoints remain available only in development"
        );
    }
}
