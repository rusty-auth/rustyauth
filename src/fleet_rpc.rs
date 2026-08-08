//! Fleet control-plane resource RPCs.
//!
//! This service is mounted only by the Fleet deployment role. The first live
//! slice implements the durable organization/project/environment hierarchy and
//! its central audit trail. Pairing, connections and scoped delegated role
//! bindings remain fail-closed until their storage and rejection tests land.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    operator_auth::{OperatorAuthorizer, OperatorCapability},
    proto::rustyauth::fleet::v1::*,
    store::{
        FleetAuditRecord, FleetEnvironmentKindRecord, FleetEnvironmentRecord,
        FleetOrganizationRecord, FleetProjectRecord, FleetResourceStateRecord, Store,
        StorePolicyError, now,
    },
};

const DEFAULT_PAGE_SIZE: usize = 25;
const MAX_PAGE_SIZE: u32 = 100;
const PAGE_TOKEN_LENGTH: usize = 22;

pub(crate) struct FleetRpc {
    store: Store,
    authorizer: OperatorAuthorizer,
}

impl FleetRpc {
    pub(crate) fn new(store: Store, authorizer: OperatorAuthorizer) -> Self {
        Self { store, authorizer }
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
        Response::ok(FleetOverview {
            organizations: organization_count,
            projects: project_count,
            environments: environment_count,
            healthy_connections: 0,
            degraded_connections: 0,
            offline_connections: 0,
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
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Read)
            .await?;
        let id = required_uuid(request.organization_id, "organization_id")?;
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
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .update_fleet_organization(
                required_uuid(request.organization_id, "organization_id")?,
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
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .archive_fleet_organization(
                required_uuid(request.organization_id, "organization_id")?,
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
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Read)
            .await?;
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
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
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Read)
            .await?;
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let record = self
            .store
            .fleet_project(required_uuid(request.project_id, "project_id")?)
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
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .create_fleet_project(
                required_uuid(request.organization_id, "organization_id")?,
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
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .update_fleet_project(
                required_uuid(request.organization_id, "organization_id")?,
                required_uuid(request.project_id, "project_id")?,
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
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .archive_fleet_project(
                required_uuid(request.organization_id, "organization_id")?,
                required_uuid(request.project_id, "project_id")?,
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
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Read)
            .await?;
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let project_id = required_uuid(request.project_id, "project_id")?;
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
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Read)
            .await?;
        let organization_id = required_uuid(request.organization_id, "organization_id")?;
        let project_id = required_uuid(request.project_id, "project_id")?;
        let record = self
            .store
            .fleet_environment(required_uuid(request.environment_id, "environment_id")?)
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
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .create_fleet_environment(
                required_uuid(request.organization_id, "organization_id")?,
                required_uuid(request.project_id, "project_id")?,
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
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .update_fleet_environment(
                required_uuid(request.organization_id, "organization_id")?,
                required_uuid(request.project_id, "project_id")?,
                required_uuid(request.environment_id, "environment_id")?,
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
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        require_mutation(&request.mutation)?;
        let record = self
            .store
            .archive_fleet_environment(
                required_uuid(request.organization_id, "organization_id")?,
                required_uuid(request.project_id, "project_id")?,
                required_uuid(request.environment_id, "environment_id")?,
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
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ListConnectionsRequest>,
    ) -> ServiceResult<ListConnectionsResponse> {
        unimplemented("realm connections are not enabled until pairing storage lands")
    }

    async fn get_connection(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetConnectionRequest>,
    ) -> ServiceResult<RealmConnection> {
        unimplemented("realm connections are not enabled until pairing storage lands")
    }

    async fn begin_connection(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, BeginConnectionRequest>,
    ) -> ServiceResult<ConnectionAttempt> {
        unimplemented("realm pairing is not enabled until endpoint verification lands")
    }

    async fn complete_connection(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, CompleteConnectionRequest>,
    ) -> ServiceResult<RealmConnection> {
        unimplemented("realm pairing is not enabled until secret custody lands")
    }

    async fn revoke_connection(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, RevokeConnectionRequest>,
    ) -> ServiceResult<RealmConnection> {
        unimplemented("realm connections are not enabled until dual revocation lands")
    }

    async fn list_role_bindings(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ListRoleBindingsRequest>,
    ) -> ServiceResult<ListRoleBindingsResponse> {
        unimplemented("delegated Fleet role bindings are not enabled yet")
    }

    async fn upsert_role_binding(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, UpsertRoleBindingRequest>,
    ) -> ServiceResult<RoleBinding> {
        unimplemented("delegated Fleet role bindings are not enabled yet")
    }

    async fn revoke_role_binding(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, RevokeRoleBindingRequest>,
    ) -> ServiceResult<RoleBinding> {
        unimplemented("delegated Fleet role bindings are not enabled yet")
    }

    async fn list_audit_events(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListAuditEventsRequest>,
    ) -> ServiceResult<ListAuditEventsResponse> {
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Read)
            .await?;
        let organization_id = optional_uuid(request.organization_id, "organization_id")?;
        let project_id = optional_uuid(request.project_id, "project_id")?;
        let environment_id = optional_uuid(request.environment_id, "environment_id")?;
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

fn unimplemented<T>(message: &'static str) -> ServiceResult<T> {
    Err(ConnectError::new(ErrorCode::Unimplemented, message))
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
}
