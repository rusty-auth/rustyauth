//! Durable Fleet resource hierarchy and central audit records.
//!
//! Fleet state lives only in the control-plane SableDB. These key families are
//! never used by a realm data-plane deployment and never contain remote realm
//! database credentials.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Store, StorePolicyError, now};

const ORGANIZATION_PREFIX: &str = "fleet:organization:";
const ORGANIZATION_SLUG_PREFIX: &str = "fleet:organization-slug:";
const PROJECT_PREFIX: &str = "fleet:project:";
const PROJECT_SLUG_PREFIX: &str = "fleet:project-slug:";
const ENVIRONMENT_PREFIX: &str = "fleet:environment:";
const ENVIRONMENT_SLUG_PREFIX: &str = "fleet:environment-slug:";
const IDEMPOTENCY_PREFIX: &str = "fleet:idempotency:";
const AUDIT_PREFIX: &str = "fleet:audit:";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FleetResourceStateRecord {
    Active,
    Archived,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FleetEnvironmentKindRecord {
    Development,
    Preview,
    Staging,
    Production,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetOrganizationRecord {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub state: FleetResourceStateRecord,
    pub created_at: u64,
    pub updated_at: u64,
    pub archived_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetProjectRecord {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub state: FleetResourceStateRecord,
    pub created_at: u64,
    pub updated_at: u64,
    pub archived_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetEnvironmentRecord {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub slug: String,
    pub name: String,
    pub kind: FleetEnvironmentKindRecord,
    pub provider: String,
    pub region: String,
    pub state: FleetResourceStateRecord,
    pub created_at: u64,
    pub updated_at: u64,
    pub archived_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetAuditRecord {
    pub id: Uuid,
    pub request_id: Uuid,
    pub operator_id: Uuid,
    pub action: String,
    pub resource_kind: String,
    pub resource_id: Uuid,
    pub organization_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub environment_id: Option<Uuid>,
    pub reason: String,
    pub occurred_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FleetIdempotencyRecord {
    action: String,
    resource_id: Uuid,
}

struct MutationAudit<'a> {
    request_id: Uuid,
    operator_id: Uuid,
    action: &'a str,
    resource_kind: &'a str,
    resource_id: Uuid,
    organization_id: Option<Uuid>,
    project_id: Option<Uuid>,
    environment_id: Option<Uuid>,
    reason: &'a str,
}

impl Store {
    pub async fn fleet_organizations(
        &self,
        include_archived: bool,
    ) -> Result<Vec<FleetOrganizationRecord>> {
        let _snapshot = self.snapshot_gate.read().await;
        let ids = self
            .record_ids(ORGANIZATION_PREFIX, "scan Fleet organizations")
            .await?;
        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(record) = self.fleet_organization(id).await?
                && (include_archived || record.state == FleetResourceStateRecord::Active)
            {
                records.push(record);
            }
        }
        records.sort_unstable_by_key(|record| record.id);
        Ok(records)
    }

    pub async fn fleet_organization(&self, id: Uuid) -> Result<Option<FleetOrganizationRecord>> {
        self.get_json(&organization_key(id)).await
    }

    pub async fn create_fleet_organization(
        &self,
        slug: String,
        name: String,
        request_id: Uuid,
        operator_id: Uuid,
        reason: String,
    ) -> Result<FleetOrganizationRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        if let Some(resource_id) = self
            .fleet_idempotent_resource("organization.create", request_id)
            .await?
        {
            return self
                .fleet_organization(resource_id)
                .await?
                .ok_or_else(|| StorePolicyError::FleetResourceMissing.into());
        }
        if self
            .get::<String>(&organization_slug_key(&slug))
            .await?
            .is_some()
        {
            return Err(StorePolicyError::FleetSlugConflict.into());
        }
        let timestamp = now();
        let record = FleetOrganizationRecord {
            id: Uuid::new_v4(),
            slug,
            name,
            state: FleetResourceStateRecord::Active,
            created_at: timestamp,
            updated_at: timestamp,
            archived_at: None,
        };
        self.persist_fleet_mutation(
            &organization_key(record.id),
            &record,
            Some((organization_slug_key(&record.slug), record.id)),
            MutationAudit {
                request_id,
                operator_id,
                action: "organization.create",
                resource_kind: "organization",
                resource_id: record.id,
                organization_id: Some(record.id),
                project_id: None,
                environment_id: None,
                reason: &reason,
            },
        )
        .await?;
        Ok(record)
    }

    pub async fn update_fleet_organization(
        &self,
        id: Uuid,
        name: String,
        request_id: Uuid,
        operator_id: Uuid,
        reason: String,
    ) -> Result<FleetOrganizationRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        if let Some(resource_id) = self
            .fleet_idempotent_resource("organization.update", request_id)
            .await?
        {
            return self
                .fleet_organization(resource_id)
                .await?
                .ok_or_else(|| StorePolicyError::FleetResourceMissing.into());
        }
        let mut record = self
            .fleet_organization(id)
            .await?
            .ok_or(StorePolicyError::FleetResourceMissing)?;
        if record.state == FleetResourceStateRecord::Archived {
            return Err(StorePolicyError::FleetParentArchived.into());
        }
        record.name = name;
        record.updated_at = now();
        self.persist_fleet_mutation(
            &organization_key(id),
            &record,
            None,
            MutationAudit {
                request_id,
                operator_id,
                action: "organization.update",
                resource_kind: "organization",
                resource_id: id,
                organization_id: Some(id),
                project_id: None,
                environment_id: None,
                reason: &reason,
            },
        )
        .await?;
        Ok(record)
    }

    pub async fn archive_fleet_organization(
        &self,
        id: Uuid,
        request_id: Uuid,
        operator_id: Uuid,
        reason: String,
    ) -> Result<FleetOrganizationRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        if let Some(resource_id) = self
            .fleet_idempotent_resource("organization.archive", request_id)
            .await?
        {
            return self
                .fleet_organization(resource_id)
                .await?
                .ok_or_else(|| StorePolicyError::FleetResourceMissing.into());
        }
        if self
            .fleet_projects(id, false)
            .await?
            .into_iter()
            .any(|record| record.state == FleetResourceStateRecord::Active)
        {
            return Err(StorePolicyError::FleetHasActiveChildren.into());
        }
        let mut record = self
            .fleet_organization(id)
            .await?
            .ok_or(StorePolicyError::FleetResourceMissing)?;
        if record.state == FleetResourceStateRecord::Active {
            let timestamp = now();
            record.state = FleetResourceStateRecord::Archived;
            record.updated_at = timestamp;
            record.archived_at = Some(timestamp);
        }
        self.persist_fleet_mutation(
            &organization_key(id),
            &record,
            None,
            MutationAudit {
                request_id,
                operator_id,
                action: "organization.archive",
                resource_kind: "organization",
                resource_id: id,
                organization_id: Some(id),
                project_id: None,
                environment_id: None,
                reason: &reason,
            },
        )
        .await?;
        Ok(record)
    }

    pub async fn fleet_projects(
        &self,
        organization_id: Uuid,
        include_archived: bool,
    ) -> Result<Vec<FleetProjectRecord>> {
        let ids = self
            .record_ids(PROJECT_PREFIX, "scan Fleet projects")
            .await?;
        let mut records = Vec::new();
        for id in ids {
            if let Some(record) = self.fleet_project(id).await?
                && record.organization_id == organization_id
                && (include_archived || record.state == FleetResourceStateRecord::Active)
            {
                records.push(record);
            }
        }
        records.sort_unstable_by_key(|record| record.id);
        Ok(records)
    }

    pub async fn fleet_project(&self, id: Uuid) -> Result<Option<FleetProjectRecord>> {
        self.get_json(&project_key(id)).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_fleet_project(
        &self,
        organization_id: Uuid,
        slug: String,
        name: String,
        description: String,
        request_id: Uuid,
        operator_id: Uuid,
        reason: String,
    ) -> Result<FleetProjectRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        if let Some(resource_id) = self
            .fleet_idempotent_resource("project.create", request_id)
            .await?
        {
            return self
                .fleet_project(resource_id)
                .await?
                .ok_or_else(|| StorePolicyError::FleetResourceMissing.into());
        }
        let organization = self
            .fleet_organization(organization_id)
            .await?
            .ok_or(StorePolicyError::FleetResourceMissing)?;
        if organization.state == FleetResourceStateRecord::Archived {
            return Err(StorePolicyError::FleetParentArchived.into());
        }
        if self
            .get::<String>(&project_slug_key(organization_id, &slug))
            .await?
            .is_some()
        {
            return Err(StorePolicyError::FleetSlugConflict.into());
        }
        let timestamp = now();
        let record = FleetProjectRecord {
            id: Uuid::new_v4(),
            organization_id,
            slug,
            name,
            description,
            state: FleetResourceStateRecord::Active,
            created_at: timestamp,
            updated_at: timestamp,
            archived_at: None,
        };
        self.persist_fleet_mutation(
            &project_key(record.id),
            &record,
            Some((project_slug_key(organization_id, &record.slug), record.id)),
            MutationAudit {
                request_id,
                operator_id,
                action: "project.create",
                resource_kind: "project",
                resource_id: record.id,
                organization_id: Some(organization_id),
                project_id: Some(record.id),
                environment_id: None,
                reason: &reason,
            },
        )
        .await?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_fleet_project(
        &self,
        organization_id: Uuid,
        id: Uuid,
        name: String,
        description: String,
        request_id: Uuid,
        operator_id: Uuid,
        reason: String,
    ) -> Result<FleetProjectRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        if let Some(resource_id) = self
            .fleet_idempotent_resource("project.update", request_id)
            .await?
        {
            return self
                .fleet_project(resource_id)
                .await?
                .ok_or_else(|| StorePolicyError::FleetResourceMissing.into());
        }
        let mut record = self
            .fleet_project(id)
            .await?
            .filter(|record| record.organization_id == organization_id)
            .ok_or(StorePolicyError::FleetResourceMissing)?;
        if record.state == FleetResourceStateRecord::Archived {
            return Err(StorePolicyError::FleetParentArchived.into());
        }
        record.name = name;
        record.description = description;
        record.updated_at = now();
        self.persist_fleet_mutation(
            &project_key(id),
            &record,
            None,
            MutationAudit {
                request_id,
                operator_id,
                action: "project.update",
                resource_kind: "project",
                resource_id: id,
                organization_id: Some(organization_id),
                project_id: Some(id),
                environment_id: None,
                reason: &reason,
            },
        )
        .await?;
        Ok(record)
    }

    pub async fn archive_fleet_project(
        &self,
        organization_id: Uuid,
        id: Uuid,
        request_id: Uuid,
        operator_id: Uuid,
        reason: String,
    ) -> Result<FleetProjectRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        if let Some(resource_id) = self
            .fleet_idempotent_resource("project.archive", request_id)
            .await?
        {
            return self
                .fleet_project(resource_id)
                .await?
                .ok_or_else(|| StorePolicyError::FleetResourceMissing.into());
        }
        if self
            .fleet_environments(organization_id, id, false)
            .await?
            .into_iter()
            .any(|record| record.state == FleetResourceStateRecord::Active)
        {
            return Err(StorePolicyError::FleetHasActiveChildren.into());
        }
        let mut record = self
            .fleet_project(id)
            .await?
            .filter(|record| record.organization_id == organization_id)
            .ok_or(StorePolicyError::FleetResourceMissing)?;
        if record.state == FleetResourceStateRecord::Active {
            let timestamp = now();
            record.state = FleetResourceStateRecord::Archived;
            record.updated_at = timestamp;
            record.archived_at = Some(timestamp);
        }
        self.persist_fleet_mutation(
            &project_key(id),
            &record,
            None,
            MutationAudit {
                request_id,
                operator_id,
                action: "project.archive",
                resource_kind: "project",
                resource_id: id,
                organization_id: Some(organization_id),
                project_id: Some(id),
                environment_id: None,
                reason: &reason,
            },
        )
        .await?;
        Ok(record)
    }

    pub async fn fleet_environments(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        include_archived: bool,
    ) -> Result<Vec<FleetEnvironmentRecord>> {
        let ids = self
            .record_ids(ENVIRONMENT_PREFIX, "scan Fleet environments")
            .await?;
        let mut records = Vec::new();
        for id in ids {
            if let Some(record) = self.fleet_environment(id).await?
                && record.organization_id == organization_id
                && record.project_id == project_id
                && (include_archived || record.state == FleetResourceStateRecord::Active)
            {
                records.push(record);
            }
        }
        records.sort_unstable_by_key(|record| record.id);
        Ok(records)
    }

    pub async fn fleet_environment(&self, id: Uuid) -> Result<Option<FleetEnvironmentRecord>> {
        self.get_json(&environment_key(id)).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_fleet_environment(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        slug: String,
        name: String,
        kind: FleetEnvironmentKindRecord,
        provider: String,
        region: String,
        request_id: Uuid,
        operator_id: Uuid,
        reason: String,
    ) -> Result<FleetEnvironmentRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        if let Some(resource_id) = self
            .fleet_idempotent_resource("environment.create", request_id)
            .await?
        {
            return self
                .fleet_environment(resource_id)
                .await?
                .ok_or_else(|| StorePolicyError::FleetResourceMissing.into());
        }
        let project = self
            .fleet_project(project_id)
            .await?
            .filter(|project| project.organization_id == organization_id)
            .ok_or(StorePolicyError::FleetResourceMissing)?;
        if project.state == FleetResourceStateRecord::Archived {
            return Err(StorePolicyError::FleetParentArchived.into());
        }
        if self
            .get::<String>(&environment_slug_key(project_id, &slug))
            .await?
            .is_some()
        {
            return Err(StorePolicyError::FleetSlugConflict.into());
        }
        let timestamp = now();
        let record = FleetEnvironmentRecord {
            id: Uuid::new_v4(),
            organization_id,
            project_id,
            slug,
            name,
            kind,
            provider,
            region,
            state: FleetResourceStateRecord::Active,
            created_at: timestamp,
            updated_at: timestamp,
            archived_at: None,
        };
        self.persist_fleet_mutation(
            &environment_key(record.id),
            &record,
            Some((environment_slug_key(project_id, &record.slug), record.id)),
            MutationAudit {
                request_id,
                operator_id,
                action: "environment.create",
                resource_kind: "environment",
                resource_id: record.id,
                organization_id: Some(organization_id),
                project_id: Some(project_id),
                environment_id: Some(record.id),
                reason: &reason,
            },
        )
        .await?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_fleet_environment(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        id: Uuid,
        name: String,
        kind: FleetEnvironmentKindRecord,
        provider: String,
        region: String,
        request_id: Uuid,
        operator_id: Uuid,
        reason: String,
    ) -> Result<FleetEnvironmentRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        if let Some(resource_id) = self
            .fleet_idempotent_resource("environment.update", request_id)
            .await?
        {
            return self
                .fleet_environment(resource_id)
                .await?
                .ok_or_else(|| StorePolicyError::FleetResourceMissing.into());
        }
        let mut record = self
            .fleet_environment(id)
            .await?
            .filter(|record| {
                record.organization_id == organization_id && record.project_id == project_id
            })
            .ok_or(StorePolicyError::FleetResourceMissing)?;
        if record.state == FleetResourceStateRecord::Archived {
            return Err(StorePolicyError::FleetParentArchived.into());
        }
        record.name = name;
        record.kind = kind;
        record.provider = provider;
        record.region = region;
        record.updated_at = now();
        self.persist_fleet_mutation(
            &environment_key(id),
            &record,
            None,
            MutationAudit {
                request_id,
                operator_id,
                action: "environment.update",
                resource_kind: "environment",
                resource_id: id,
                organization_id: Some(organization_id),
                project_id: Some(project_id),
                environment_id: Some(id),
                reason: &reason,
            },
        )
        .await?;
        Ok(record)
    }

    pub async fn archive_fleet_environment(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        id: Uuid,
        request_id: Uuid,
        operator_id: Uuid,
        reason: String,
    ) -> Result<FleetEnvironmentRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        if let Some(resource_id) = self
            .fleet_idempotent_resource("environment.archive", request_id)
            .await?
        {
            return self
                .fleet_environment(resource_id)
                .await?
                .ok_or_else(|| StorePolicyError::FleetResourceMissing.into());
        }
        let mut record = self
            .fleet_environment(id)
            .await?
            .filter(|record| {
                record.organization_id == organization_id && record.project_id == project_id
            })
            .ok_or(StorePolicyError::FleetResourceMissing)?;
        if record.state == FleetResourceStateRecord::Active {
            let timestamp = now();
            record.state = FleetResourceStateRecord::Archived;
            record.updated_at = timestamp;
            record.archived_at = Some(timestamp);
        }
        self.persist_fleet_mutation(
            &environment_key(id),
            &record,
            None,
            MutationAudit {
                request_id,
                operator_id,
                action: "environment.archive",
                resource_kind: "environment",
                resource_id: id,
                organization_id: Some(organization_id),
                project_id: Some(project_id),
                environment_id: Some(id),
                reason: &reason,
            },
        )
        .await?;
        Ok(record)
    }

    pub async fn fleet_audit_records(&self) -> Result<Vec<FleetAuditRecord>> {
        let ids = self
            .record_ids(AUDIT_PREFIX, "scan Fleet audit records")
            .await?;
        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(record) = self.get_json(&audit_key(id)).await? {
                records.push(record);
            }
        }
        records.sort_unstable_by_key(|record: &FleetAuditRecord| (record.occurred_at, record.id));
        Ok(records)
    }

    async fn fleet_idempotent_resource(
        &self,
        action: &str,
        request_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let Some(record) = self
            .get_json::<FleetIdempotencyRecord>(&idempotency_key(request_id))
            .await?
        else {
            return Ok(None);
        };
        if record.action != action {
            return Err(StorePolicyError::FleetIdempotencyConflict.into());
        }
        Ok(Some(record.resource_id))
    }

    async fn persist_fleet_mutation<T: Serialize>(
        &self,
        resource_key: &str,
        resource: &T,
        slug_index: Option<(String, Uuid)>,
        audit: MutationAudit<'_>,
    ) -> Result<()> {
        let audit_record = FleetAuditRecord {
            id: Uuid::new_v4(),
            request_id: audit.request_id,
            operator_id: audit.operator_id,
            action: audit.action.to_owned(),
            resource_kind: audit.resource_kind.to_owned(),
            resource_id: audit.resource_id,
            organization_id: audit.organization_id,
            project_id: audit.project_id,
            environment_id: audit.environment_id,
            reason: audit.reason.to_owned(),
            occurred_at: now(),
        };
        let idempotency = FleetIdempotencyRecord {
            action: audit.action.to_owned(),
            resource_id: audit.resource_id,
        };
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(resource_key, serde_json::to_string(resource)?)
            .ignore();
        if let Some((key, id)) = slug_index {
            pipeline.set(key, id.to_string()).ignore();
        }
        pipeline
            .set(
                idempotency_key(audit.request_id),
                serde_json::to_string(&idempotency)?,
            )
            .ignore()
            .set(
                audit_key(audit_record.id),
                serde_json::to_string(&audit_record)?,
            )
            .ignore();
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("persist Fleet mutation and audit")?;
        Ok(())
    }
}

fn organization_key(id: Uuid) -> String {
    format!("{ORGANIZATION_PREFIX}{id}")
}

fn organization_slug_key(slug: &str) -> String {
    format!("{ORGANIZATION_SLUG_PREFIX}{slug}")
}

fn project_key(id: Uuid) -> String {
    format!("{PROJECT_PREFIX}{id}")
}

fn project_slug_key(organization_id: Uuid, slug: &str) -> String {
    format!("{PROJECT_SLUG_PREFIX}{organization_id}:{slug}")
}

fn environment_key(id: Uuid) -> String {
    format!("{ENVIRONMENT_PREFIX}{id}")
}

fn environment_slug_key(project_id: Uuid, slug: &str) -> String {
    format!("{ENVIRONMENT_SLUG_PREFIX}{project_id}:{slug}")
}

fn idempotency_key(request_id: Uuid) -> String {
    format!("{IDEMPOTENCY_PREFIX}{request_id}")
}

fn audit_key(id: Uuid) -> String {
    format!("{AUDIT_PREFIX}{id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_keys_keep_resource_and_slug_families_disjoint() {
        let id = Uuid::nil();
        assert!(organization_key(id).starts_with(ORGANIZATION_PREFIX));
        assert!(!organization_slug_key("example").starts_with(ORGANIZATION_PREFIX));
        assert!(project_key(id).starts_with(PROJECT_PREFIX));
        assert!(!project_slug_key(id, "example").starts_with(PROJECT_PREFIX));
        assert!(environment_key(id).starts_with(ENVIRONMENT_PREFIX));
        assert!(!environment_slug_key(id, "example").starts_with(ENVIRONMENT_PREFIX));
    }
}
