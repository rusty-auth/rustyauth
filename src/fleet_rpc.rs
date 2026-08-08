//! Fleet control-plane resource RPCs.
//!
//! This service is mounted only by the Fleet deployment role. It implements
//! durable organization/project/environment hierarchy, central audit history,
//! scoped delegated roles, and origin-bound realm pairing.

use std::{sync::Arc, time::Duration};

use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit,
    aead::{Aead, OsRng, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use connectrpc::{
    ConnectError, ErrorCode, Protocol, RequestContext, Response, ServiceRequest, ServiceResult,
    client::{CallOptions, ClientConfig, HttpClient},
};
use secrecy::{ExposeSecret, SecretString};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use uuid::Uuid;

use crate::{
    config::{Environment as RuntimeEnvironment, KeyRing},
    operator_auth::{OperatorAuthorizer, OperatorCapability},
    proto::rustyauth::{fleet::v1::*, management::v1::*},
    store::{
        EncryptedFleetCredential, FleetAuditRecord, FleetConnectionAttemptRecord,
        FleetConnectionModeRecord, FleetConnectionRecord, FleetConnectionStateRecord,
        FleetEnvironmentKindRecord, FleetEnvironmentRecord, FleetOrganizationRecord,
        FleetProjectRecord, FleetResourceKindRecord, FleetResourceStateRecord,
        FleetRoleBindingRecord, FleetRoleRecord, Store, StorePolicyError, now,
    },
};

const DEFAULT_PAGE_SIZE: usize = 25;
const MAX_PAGE_SIZE: u32 = 100;
const PAGE_TOKEN_LENGTH: usize = 22;
const MANAGEMENT_TIMEOUT: Duration = Duration::from_secs(8);
const FLEET_CREDENTIAL_AAD_VERSION: &str = "rustyauth-fleet-credential-v1";

pub(crate) struct FleetRpc {
    store: Store,
    authorizer: OperatorAuthorizer,
    credential_keys: KeyRing,
    runtime_environment: RuntimeEnvironment,
    control_plane_origin: String,
    control_plane_instance_id: String,
}

impl FleetRpc {
    pub(crate) fn new(
        store: Store,
        authorizer: OperatorAuthorizer,
        credential_keys: KeyRing,
        runtime_environment: RuntimeEnvironment,
        control_plane_origin: String,
        control_plane_instance_id: String,
    ) -> Self {
        Self {
            store,
            authorizer,
            credential_keys,
            runtime_environment,
            control_plane_origin,
            control_plane_instance_id,
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
        if mode == FleetConnectionModeRecord::OutboundConnector {
            return Err(ConnectError::new(
                ErrorCode::Unimplemented,
                "outbound connectors require workload identity and are not enabled in this release",
            ));
        }
        let endpoint =
            safe_management_endpoint(request.management_endpoint, &self.runtime_environment)?;
        let record = self
            .store
            .create_fleet_connection_attempt(
                required_uuid(request.organization_id, "organization_id")?,
                required_uuid(request.project_id, "project_id")?,
                environment_id,
                mode,
                endpoint.to_string().trim_end_matches('/').to_owned(),
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
        let client = management_client(&attempt.management_endpoint)?;
        let discovery = client
            .get_discovery_with_options(
                GetDiscoveryRequest::default(),
                CallOptions::default().with_timeout(MANAGEMENT_TIMEOUT),
            )
            .await
            .map_err(management_error)?
            .into_owned();
        let grant = client
            .exchange_pairing_code_with_options(
                ExchangePairingCodeRequest {
                    code: pairing_code.expose_secret().to_owned(),
                    control_plane_origin: self.control_plane_origin.clone(),
                    control_plane_instance_id: self.control_plane_instance_id.clone(),
                    request_id: request.mutation.request_id.to_string(),
                    ..Default::default()
                },
                CallOptions::default().with_timeout(MANAGEMENT_TIMEOUT),
            )
            .await
            .map_err(management_error)?
            .into_owned();
        if grant.realm_id != discovery.realm_id || grant.connection_id.is_empty() {
            return Err(ConnectError::new(
                ErrorCode::DataLoss,
                "realm pairing response is inconsistent",
            ));
        }
        let id = required_uuid(&grant.connection_id, "pairing connection_id")?;
        let credential = SecretString::from(grant.credential.clone());
        let encrypted = seal_fleet_credential(&self.credential_keys, id, &credential)?;
        let record = FleetConnectionRecord {
            id,
            organization_id: attempt.organization_id,
            project_id: attempt.project_id,
            environment_id: attempt.environment_id,
            realm_id: safe_text(&discovery.realm_id, "realm_id", 128, false)?,
            display_name: safe_text(&discovery.realm_id, "realm_id", 128, false)?,
            mode: attempt.mode,
            management_endpoint: attempt.management_endpoint,
            credential: encrypted,
            credential_hint: safe_text(&grant.credential_hint, "credential_hint", 32, true)?,
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
            let credential =
                open_fleet_credential(&self.credential_keys, existing.id, &existing.credential)?;
            if let Err(error) = revoke_remote_connection(
                &existing.management_endpoint,
                &credential,
                request.connection_id,
                request.mutation.request_id,
                request.mutation.reason,
            )
            .await
            {
                tracing::warn!(
                    connection_id = %connection_id,
                    error = %error,
                    "realm did not confirm connection revocation; local credential is being revoked"
                );
            }
        }
        let record = self
            .store
            .revoke_fleet_connection(
                organization_id,
                project_id,
                environment_id,
                connection_id,
                required_uuid(request.mutation.request_id, "mutation.request_id")?,
                actor.user.id,
                safe_text(request.mutation.reason, "mutation.reason", 500, true)?,
            )
            .await
            .map_err(source_error)?;
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
        let record = self
            .store
            .upsert_fleet_role_binding(
                required_uuid(request.operator_id, "operator_id")?,
                kind,
                resource_id,
                fleet_role_record(request.role.as_known())?,
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

fn management_client(
    endpoint: &str,
) -> Result<RealmManagementServiceClient<HttpClient>, ConnectError> {
    let url = Url::parse(endpoint).map_err(|_| invalid("stored management endpoint is invalid"))?;
    let transport = match url.scheme() {
        "http" => HttpClient::plaintext(),
        "https" => {
            let roots = connectrpc::rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            );
            let tls = connectrpc::rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            HttpClient::with_tls(Arc::new(tls))
        }
        _ => return Err(invalid("stored management endpoint has invalid scheme")),
    };
    let config = ClientConfig::new(
        endpoint
            .parse()
            .map_err(|_| invalid("stored management endpoint is invalid"))?,
    )
    .with_protocol(Protocol::Connect)
    .with_default_timeout(MANAGEMENT_TIMEOUT);
    Ok(RealmManagementServiceClient::new(transport, config))
}

fn seal_fleet_credential(
    keys: &KeyRing,
    connection_id: Uuid,
    credential: &SecretString,
) -> Result<EncryptedFleetCredential, ConnectError> {
    let (key_id, key) = keys.active();
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "initialize credential encryption"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
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

fn open_fleet_credential(
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
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&encrypted.ciphertext)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "decode encrypted realm credential"))?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "initialize credential encryption"))?;
    let aad = fleet_credential_aad(connection_id, &encrypted.wrapping_key_id);
    let plaintext = cipher
        .decrypt(
            nonce.as_slice().into(),
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
) -> Result<(), ConnectError> {
    let mut client = management_client(endpoint)?;
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

fn required_uuid(value: &str, field: &'static str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(value).map_err(|_| invalid_uuid(field))
}

fn optional_uuid(value: &str, field: &'static str) -> Result<Option<Uuid>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    required_uuid(value, field).map(Some)
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

fn format_optional_timestamp(value: Option<u64>) -> Result<String, ConnectError> {
    value
        .map(format_timestamp)
        .transpose()
        .map(Option::unwrap_or_default)
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
}
