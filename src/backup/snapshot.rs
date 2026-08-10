//! Logical snapshot capture and manifest construction, with fail-closed validation
//! of format, tenant, key families, event continuity and cross-record ownership.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::Write,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

#[cfg(test)]
use crate::config::KeyRing;
use crate::{
    jwt::KEYSET_KEY,
    store::{
        AuthEvent, FleetAuditRecord, FleetConnectionRecord, FleetEnvironmentRecord,
        FleetOrganizationRecord, FleetProjectRecord, FleetResourceKindRecord,
        FleetRoleBindingRecord, IdentifierKind, OperatorRecord, OrganizationRecord,
        RealmFleetGrantRecord, ServiceAccountRecord, ServiceCredentialLocator, Session, Store,
        StoreRecord, User,
    },
};

const SNAPSHOT_VERSION: u8 = 2;

/// Stable compact representation carried by the `RAUTHBK3` envelope.
///
/// This is deliberately separate from [`BackupSnapshot`]. Adding a serde field to
/// the in-memory model must not silently change the bytes needed to recover an old
/// backup; a future incompatible representation gets a new envelope magic and DTO.
#[derive(Serialize, Deserialize)]
struct BinarySnapshotV3 {
    snapshot_id: [u8; 16],
    tenant_id: String,
    captured_at: u64,
    records: Vec<StoreRecord>,
    record_count: u64,
    content_sha256: [u8; 32],
    key_families: BTreeMap<String, u64>,
    event_sequence: u64,
}

#[derive(Serialize)]
struct BinarySnapshotV3Ref<'a> {
    snapshot_id: [u8; 16],
    tenant_id: &'a str,
    captured_at: u64,
    records: &'a [StoreRecord],
    record_count: u64,
    content_sha256: [u8; 32],
    key_families: &'a BTreeMap<String, u64>,
    event_sequence: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FleetIdempotencySnapshot {
    action: String,
    resource_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSnapshot {
    format_version: u8,
    pub(super) snapshot_id: Uuid,
    tenant_id: String,
    pub(super) captured_at: u64,
    records: Vec<StoreRecord>,
    pub(super) manifest: SnapshotManifest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SnapshotManifest {
    pub(super) record_count: u64,
    pub(super) content_sha256: String,
    key_families: BTreeMap<String, u64>,
    event_sequence: u64,
}

impl BackupSnapshot {
    pub(super) async fn capture(store: &Store, tenant_id: &str) -> Result<Self> {
        let (captured_at, records) = store.export_records().await?;
        // Canonicalising and hashing the whole export is unbounded CPU work.
        let tenant_id = tenant_id.to_owned();
        tokio::task::spawn_blocking(move || Self::from_records(&tenant_id, captured_at, records))
            .await
            .context("capture backup snapshot")?
    }

    fn from_records(tenant_id: &str, captured_at: u64, records: Vec<StoreRecord>) -> Result<Self> {
        let content_sha256 = canonical_records_sha256(&records)?;
        let event_sequence = records
            .iter()
            .find(|record| record.key == "auth:event-sequence")
            .map(|record| {
                record
                    .value
                    .parse::<u64>()
                    .context("event sequence is invalid")
            })
            .transpose()?
            .unwrap_or(0);
        let mut key_families = BTreeMap::new();
        for record in &records {
            *key_families.entry(record_family(&record.key)?).or_insert(0) += 1;
        }
        let snapshot = Self {
            format_version: SNAPSHOT_VERSION,
            snapshot_id: Uuid::new_v4(),
            tenant_id: tenant_id.to_owned(),
            captured_at,
            manifest: SnapshotManifest {
                record_count: records.len() as u64,
                content_sha256,
                key_families,
                event_sequence,
            },
            records,
        };
        snapshot.validate(tenant_id)?;
        Ok(snapshot)
    }

    pub fn records(&self) -> &[StoreRecord] {
        &self.records
    }

    pub fn snapshot_id(&self) -> Uuid {
        self.snapshot_id
    }

    pub fn captured_at(&self) -> u64 {
        self.captured_at
    }

    pub fn record_count(&self) -> u64 {
        self.manifest.record_count
    }

    pub fn signing_keyset(&self) -> Result<&str> {
        self.records
            .iter()
            .find(|record| record.key == KEYSET_KEY)
            .map(|record| record.value.as_str())
            .context("snapshot does not contain a signing keyset")
    }

    pub(super) fn encode_binary_v3(&self) -> Result<Vec<u8>> {
        let digest = hex::decode(&self.manifest.content_sha256)
            .context("backup manifest digest is not hexadecimal")?;
        let content_sha256: [u8; 32] = digest
            .try_into()
            .map_err(|_| anyhow::anyhow!("backup manifest digest is not 32 bytes"))?;
        postcard::to_allocvec(&BinarySnapshotV3Ref {
            snapshot_id: *self.snapshot_id.as_bytes(),
            tenant_id: &self.tenant_id,
            captured_at: self.captured_at,
            records: &self.records,
            record_count: self.manifest.record_count,
            content_sha256,
            key_families: &self.manifest.key_families,
            event_sequence: self.manifest.event_sequence,
        })
        .context("serialize compact binary backup snapshot")
    }

    pub(super) fn decode_binary_v3(bytes: &[u8]) -> Result<Self> {
        let binary: BinarySnapshotV3 =
            postcard::from_bytes(bytes).context("decode compact binary backup snapshot")?;
        Ok(Self {
            format_version: SNAPSHOT_VERSION,
            snapshot_id: Uuid::from_bytes(binary.snapshot_id),
            tenant_id: binary.tenant_id,
            captured_at: binary.captured_at,
            records: binary.records,
            manifest: SnapshotManifest {
                record_count: binary.record_count,
                content_sha256: hex::encode(binary.content_sha256),
                key_families: binary.key_families,
                event_sequence: binary.event_sequence,
            },
        })
    }

    pub(super) fn validate(&self, expected_tenant: &str) -> Result<()> {
        self.validate_format(expected_tenant)?;
        let index = self.index_records()?;
        self.validate_key_families(&index)?;
        self.validate_event_sequence(&index)?;
        validate_user_indexes(&index)?;
        validate_index_ownership(&index)?;
        validate_record_ownership(&index)?;
        validate_fleet_workspace(&index)
    }

    fn validate_format(&self, expected_tenant: &str) -> Result<()> {
        if self.format_version != SNAPSHOT_VERSION {
            bail!(
                "unsupported backup snapshot version {}",
                self.format_version
            );
        }
        // Restoring another tenant's snapshot would import its accounts, sessions
        // and wrapped signing keys wholesale. The object key is attacker-influenced
        // and the envelope is decryptable by anyone holding the backup key, so the
        // tenant recorded inside the manifest is what has to be checked.
        if self.tenant_id != expected_tenant {
            bail!(
                "backup tenant {} does not match configured tenant {expected_tenant}",
                self.tenant_id
            );
        }
        if self.manifest.record_count != self.records.len() as u64 {
            bail!("backup manifest record count does not match its contents");
        }
        if self
            .records
            .windows(2)
            .any(|pair| pair[0].key >= pair[1].key)
        {
            bail!("backup records must be uniquely sorted by key");
        }
        let digest = canonical_records_sha256(&self.records)?;
        if digest != self.manifest.content_sha256 {
            bail!("backup manifest digest does not match its contents");
        }
        Ok(())
    }

    fn index_records(&self) -> Result<SnapshotIndex> {
        let mut index = SnapshotIndex::default();
        for record in &self.records {
            let family = record_family(&record.key)?;
            *index.families.entry(family.clone()).or_insert(0) += 1;
            if !record_family_allows_expiry(&family) && record.expires_at.is_some() {
                bail!(
                    "durable backup record {} unexpectedly has an expiry",
                    record.key
                );
            }
            match family.as_str() {
                "user" => {
                    let mut user: User = serde_json::from_str(&record.value)
                        .with_context(|| format!("decode backup user {}", record.key))?;
                    user.normalize_and_validate()
                        .with_context(|| format!("validate backup user {}", record.key))?;
                    if record.key != format!("auth:user:{}", user.id) {
                        bail!("backup user key does not match its record id");
                    }
                    if index.users.insert(user.id, user).is_some() {
                        bail!("backup contains duplicate records for one user id");
                    }
                }
                "email-index" => {
                    let id = Uuid::parse_str(&record.value)
                        .context("backup email index has an invalid user id")?;
                    index
                        .email_indexes
                        .insert(record.key.trim_start_matches("auth:email:").to_owned(), id);
                }
                "identifier-index" => {
                    let id = Uuid::parse_str(&record.value)
                        .context("backup identifier index has an invalid user id")?;
                    index.identifier_indexes.insert(
                        record.key.trim_start_matches("auth:identifier:").to_owned(),
                        id,
                    );
                }
                "credential-index" => {
                    let id = Uuid::parse_str(&record.value)
                        .context("backup credential index has an invalid user id")?;
                    index.credential_indexes.insert(
                        record.key.trim_start_matches("auth:credential:").to_owned(),
                        id,
                    );
                }
                "session" => {
                    if record.expires_at.is_none() {
                        bail!("backup session {} has no expiry", record.key);
                    }
                    index.sessions.push(
                        serde_json::from_str::<Session>(&record.value)
                            .with_context(|| format!("decode backup session {}", record.key))?,
                    );
                }
                "organization" => {
                    let _: OrganizationRecord = serde_json::from_str(&record.value)
                        .context("decode backup organization")?;
                    index.organizations = index.organizations.saturating_add(1);
                }
                "operator" => {
                    let operator: OperatorRecord = serde_json::from_str(&record.value)
                        .with_context(|| format!("decode backup operator {}", record.key))?;
                    if record.key != format!("auth:operator:{}", operator.user_id) {
                        bail!("backup operator key does not match its user id");
                    }
                    index.operators.push(operator);
                }
                "service-account" => {
                    let account: ServiceAccountRecord = serde_json::from_str(&record.value)
                        .with_context(|| format!("decode backup service account {}", record.key))?;
                    if record.key != format!("auth:service-account:{}", account.id) {
                        bail!("backup service-account key does not match its id");
                    }
                    index.service_accounts.insert(account.id, account);
                }
                "service-credential" => {
                    let locator: ServiceCredentialLocator = serde_json::from_str(&record.value)
                        .with_context(|| {
                            format!("decode backup service credential {}", record.key)
                        })?;
                    index.service_credentials.push(locator);
                }
                "realm-fleet-grant" => {
                    let value: RealmFleetGrantRecord = serde_json::from_str(&record.value)
                        .with_context(|| format!("decode realm Fleet grant {}", record.key))?;
                    if record.key != format!("auth:fleet-grant:{}", value.connection_id) {
                        bail!("backup realm Fleet grant key does not match its connection id");
                    }
                    if index
                        .realm_fleet_grants
                        .insert(value.connection_id, value)
                        .is_some()
                    {
                        bail!("backup contains duplicate realm Fleet grants");
                    }
                }
                "realm-fleet-grant-secret" => {
                    let digest = record.key.trim_start_matches("auth:fleet-grant-secret:");
                    let id = Uuid::parse_str(&record.value)
                        .context("backup realm Fleet grant locator has an invalid id")?;
                    if index
                        .realm_fleet_grant_secrets
                        .insert(digest.to_owned(), id)
                        .is_some()
                    {
                        bail!("backup contains duplicate realm Fleet grant locators");
                    }
                }
                "remote-mutation" => {
                    Uuid::parse_str(record.key.trim_start_matches("auth:remote-mutation:"))
                        .context("backup remote mutation key has an invalid request id")?;
                    if record.expires_at.is_none() {
                        bail!("backup remote mutation receipt has no expiry");
                    }
                    let value: serde_json::Value = serde_json::from_str(&record.value)
                        .context("decode backup remote mutation receipt")?;
                    if value
                        .get("digest")
                        .and_then(serde_json::Value::as_str)
                        .is_none()
                        || value
                            .get("state")
                            .and_then(serde_json::Value::as_str)
                            .is_none()
                        || value
                            .get("claimedAt")
                            .and_then(serde_json::Value::as_u64)
                            .is_none()
                    {
                        bail!("backup remote mutation receipt is malformed");
                    }
                }
                "event" => {
                    let sequence = record
                        .key
                        .trim_start_matches("auth:event:")
                        .parse::<u64>()
                        .context("backup event key has an invalid sequence")?;
                    let event: AuthEvent = serde_json::from_str(&record.value)
                        .with_context(|| format!("decode backup event {}", record.key))?;
                    if event.sequence != sequence || event.tenant_id != self.tenant_id {
                        bail!("backup event metadata does not match its key or tenant");
                    }
                    index.event_numbers.insert(sequence);
                }
                "keyset" => index.keyset_count = index.keyset_count.saturating_add(1),
                "event-sequence" => {
                    index.event_sequence_record = Some(
                        record
                            .value
                            .parse::<u64>()
                            .context("backup event sequence record is invalid")?,
                    );
                }
                "fleet-organization" => {
                    let value: FleetOrganizationRecord = serde_json::from_str(&record.value)
                        .with_context(|| {
                            format!("decode backup Fleet organization {}", record.key)
                        })?;
                    if record.key != format!("fleet:organization:{}", value.id) {
                        bail!("backup Fleet organization key does not match its id");
                    }
                    if index.fleet_organizations.insert(value.id, value).is_some() {
                        bail!("backup contains duplicate Fleet organizations");
                    }
                }
                "fleet-organization-slug" => {
                    let slug = record.key.trim_start_matches("fleet:organization-slug:");
                    let id = Uuid::parse_str(&record.value)
                        .context("backup Fleet organization slug index has an invalid id")?;
                    if index
                        .fleet_organization_slugs
                        .insert(slug.to_owned(), id)
                        .is_some()
                    {
                        bail!("backup contains duplicate Fleet organization slug indexes");
                    }
                }
                "fleet-project" => {
                    let value: FleetProjectRecord = serde_json::from_str(&record.value)
                        .with_context(|| format!("decode backup Fleet project {}", record.key))?;
                    if record.key != format!("fleet:project:{}", value.id) {
                        bail!("backup Fleet project key does not match its id");
                    }
                    if index.fleet_projects.insert(value.id, value).is_some() {
                        bail!("backup contains duplicate Fleet projects");
                    }
                }
                "fleet-project-slug" => {
                    let key = record.key.trim_start_matches("fleet:project-slug:");
                    let (organization_id, slug) = parse_parent_slug(key, "Fleet project")?;
                    let id = Uuid::parse_str(&record.value)
                        .context("backup Fleet project slug index has an invalid id")?;
                    if index
                        .fleet_project_slugs
                        .insert((organization_id, slug.to_owned()), id)
                        .is_some()
                    {
                        bail!("backup contains duplicate Fleet project slug indexes");
                    }
                }
                "fleet-environment" => {
                    let value: FleetEnvironmentRecord = serde_json::from_str(&record.value)
                        .with_context(|| {
                            format!("decode backup Fleet environment {}", record.key)
                        })?;
                    if record.key != format!("fleet:environment:{}", value.id) {
                        bail!("backup Fleet environment key does not match its id");
                    }
                    if index.fleet_environments.insert(value.id, value).is_some() {
                        bail!("backup contains duplicate Fleet environments");
                    }
                }
                "fleet-environment-slug" => {
                    let key = record.key.trim_start_matches("fleet:environment-slug:");
                    let (project_id, slug) = parse_parent_slug(key, "Fleet environment")?;
                    let id = Uuid::parse_str(&record.value)
                        .context("backup Fleet environment slug index has an invalid id")?;
                    if index
                        .fleet_environment_slugs
                        .insert((project_id, slug.to_owned()), id)
                        .is_some()
                    {
                        bail!("backup contains duplicate Fleet environment slug indexes");
                    }
                }
                "fleet-connection" => {
                    let value: FleetConnectionRecord = serde_json::from_str(&record.value)
                        .with_context(|| {
                            format!("decode backup Fleet connection {}", record.key)
                        })?;
                    if record.key != format!("fleet:connection:{}", value.id) {
                        bail!("backup Fleet connection key does not match its id");
                    }
                    if index.fleet_connections.insert(value.id, value).is_some() {
                        bail!("backup contains duplicate Fleet connections");
                    }
                }
                "fleet-role-binding" => {
                    let value: FleetRoleBindingRecord = serde_json::from_str(&record.value)
                        .with_context(|| {
                            format!("decode backup Fleet role binding {}", record.key)
                        })?;
                    if record.key != format!("fleet:role-binding:{}", value.id) {
                        bail!("backup Fleet role binding key does not match its id");
                    }
                    if index.fleet_role_bindings.insert(value.id, value).is_some() {
                        bail!("backup contains duplicate Fleet role bindings");
                    }
                }
                "fleet-role-binding-subject" => {
                    let value = record.key.trim_start_matches("fleet:role-binding-subject:");
                    let mut parts = value.split(':');
                    let operator_id = Uuid::parse_str(parts.next().unwrap_or_default())
                        .context("backup Fleet role binding subject has an invalid operator id")?;
                    let kind = match parts.next() {
                        Some("organization") => FleetResourceKindRecord::Organization,
                        Some("project") => FleetResourceKindRecord::Project,
                        Some("environment") => FleetResourceKindRecord::Environment,
                        _ => {
                            bail!("backup Fleet role binding subject has an invalid resource kind")
                        }
                    };
                    let resource_id = Uuid::parse_str(parts.next().unwrap_or_default())
                        .context("backup Fleet role binding subject has an invalid resource id")?;
                    if parts.next().is_some() {
                        bail!("backup Fleet role binding subject index is malformed");
                    }
                    let binding_id = Uuid::parse_str(&record.value)
                        .context("backup Fleet role binding subject has an invalid binding id")?;
                    if index
                        .fleet_role_binding_subjects
                        .insert((operator_id, kind, resource_id), binding_id)
                        .is_some()
                    {
                        bail!("backup contains duplicate Fleet role binding subject indexes");
                    }
                }
                "fleet-idempotency" => {
                    let request_id =
                        Uuid::parse_str(record.key.trim_start_matches("fleet:idempotency:"))
                            .context("backup Fleet idempotency key has an invalid request id")?;
                    let value: FleetIdempotencySnapshot = serde_json::from_str(&record.value)
                        .with_context(|| {
                            format!("decode backup Fleet idempotency {}", record.key)
                        })?;
                    if index.fleet_idempotency.insert(request_id, value).is_some() {
                        bail!("backup contains duplicate Fleet idempotency records");
                    }
                }
                "fleet-audit" => {
                    let value: FleetAuditRecord = serde_json::from_str(&record.value)
                        .with_context(|| format!("decode backup Fleet audit {}", record.key))?;
                    if record.key != format!("fleet:audit:{}", value.id) {
                        bail!("backup Fleet audit key does not match its id");
                    }
                    if index.fleet_audits.insert(value.id, value).is_some() {
                        bail!("backup contains duplicate Fleet audit records");
                    }
                }
                "event-min-sequence" => {
                    index.event_min_sequence_record = Some(
                        record
                            .value
                            .parse::<u64>()
                            .context("backup minimum event sequence record is invalid")?,
                    );
                }
                "invitation"
                | "invitation-code"
                | "webhook"
                | "webhook-cursor"
                | "webhook-delivery"
                | "webhook-delivery-event"
                | "fleet-assignment-epoch"
                | "fleet-analytics-bucket"
                | "fleet-analytics-policy"
                | "fleet-analytics-policy-idempotency"
                | "fleet-analytics-quarantine"
                | "fleet-analytics-ingestion-audit"
                | "fleet-analytics-operator-audit"
                | "fleet-analytics-maintenance-audit"
                | "fleet-analytics-manifest"
                | "analytics-projector-cursor"
                | "analytics-closure-cursor"
                | "analytics-bucket"
                | "analytics-outbox" => {}
                _ => unreachable!("record_family returns known families"),
            }
        }
        Ok(index)
    }

    fn validate_key_families(&self, index: &SnapshotIndex) -> Result<()> {
        if index.families != self.manifest.key_families {
            bail!("backup key-family manifest does not match its contents");
        }
        if index.keyset_count != 1 {
            bail!("backup must contain exactly one signing keyset");
        }
        Ok(())
    }

    fn validate_event_sequence(&self, index: &SnapshotIndex) -> Result<()> {
        if index.event_sequence_record.unwrap_or_default() != self.manifest.event_sequence
            || (self.manifest.event_sequence > 0 && index.event_sequence_record.is_none())
        {
            bail!("backup event sequence record does not match its manifest");
        }
        let minimum = index.event_min_sequence_record.unwrap_or(1);
        if minimum == 0 || minimum > self.manifest.event_sequence.saturating_add(1) {
            bail!("backup minimum event sequence is outside the retained window");
        }
        let expected_events: BTreeSet<u64> = (minimum..=self.manifest.event_sequence).collect();
        if index.event_numbers != expected_events {
            bail!("backup retained event sequence is not contiguous");
        }
        Ok(())
    }
}

fn record_family_allows_expiry(family: &str) -> bool {
    matches!(
        family,
        "session"
            | "remote-mutation"
            | "fleet-analytics-quarantine"
            | "fleet-analytics-ingestion-audit"
            | "fleet-analytics-maintenance-audit"
    )
}

#[derive(Default)]
struct SnapshotIndex {
    families: BTreeMap<String, u64>,
    users: HashMap<Uuid, User>,
    email_indexes: HashMap<String, Uuid>,
    identifier_indexes: HashMap<String, Uuid>,
    credential_indexes: HashMap<String, Uuid>,
    sessions: Vec<Session>,
    operators: Vec<OperatorRecord>,
    organizations: u8,
    service_accounts: HashMap<Uuid, ServiceAccountRecord>,
    service_credentials: Vec<ServiceCredentialLocator>,
    realm_fleet_grants: HashMap<Uuid, RealmFleetGrantRecord>,
    realm_fleet_grant_secrets: HashMap<String, Uuid>,
    event_numbers: BTreeSet<u64>,
    event_sequence_record: Option<u64>,
    event_min_sequence_record: Option<u64>,
    keyset_count: u8,
    fleet_organizations: HashMap<Uuid, FleetOrganizationRecord>,
    fleet_organization_slugs: HashMap<String, Uuid>,
    fleet_projects: HashMap<Uuid, FleetProjectRecord>,
    fleet_project_slugs: HashMap<(Uuid, String), Uuid>,
    fleet_environments: HashMap<Uuid, FleetEnvironmentRecord>,
    fleet_environment_slugs: HashMap<(Uuid, String), Uuid>,
    fleet_connections: HashMap<Uuid, FleetConnectionRecord>,
    fleet_role_bindings: HashMap<Uuid, FleetRoleBindingRecord>,
    fleet_role_binding_subjects: HashMap<(Uuid, FleetResourceKindRecord, Uuid), Uuid>,
    fleet_idempotency: HashMap<Uuid, FleetIdempotencySnapshot>,
    fleet_audits: HashMap<Uuid, FleetAuditRecord>,
}

fn parse_parent_slug<'a>(value: &'a str, label: &str) -> Result<(Uuid, &'a str)> {
    let (parent, slug) = value
        .split_once(':')
        .with_context(|| format!("backup {label} slug index is malformed"))?;
    if slug.is_empty() {
        bail!("backup {label} slug index has an empty slug");
    }
    Ok((
        Uuid::parse_str(parent)
            .with_context(|| format!("backup {label} slug parent is invalid"))?,
        slug,
    ))
}

fn validate_user_indexes(index: &SnapshotIndex) -> Result<()> {
    for user in index.users.values() {
        if !user.email.is_empty() && index.email_indexes.get(&user.email) != Some(&user.id) {
            bail!(
                "backup email index is missing or inconsistent for {}",
                user.id
            );
        }
        for identifier in &user.identifiers {
            let key = format!("{}:{}", identifier.kind.as_str(), identifier.value);
            let identifier_matches = index.identifier_indexes.get(&key) == Some(&user.id);
            let legacy_email_matches = identifier.kind == IdentifierKind::Email
                && index.email_indexes.get(&identifier.value) == Some(&user.id);
            if !identifier_matches && !legacy_email_matches {
                bail!(
                    "backup identifier index is missing or inconsistent for {}",
                    user.id
                );
            }
        }
        for credential in &user.passkeys {
            if index.credential_indexes.get(&credential.id) != Some(&user.id) {
                bail!(
                    "backup credential index is missing or inconsistent for {}",
                    user.id
                );
            }
        }
    }
    Ok(())
}

fn validate_index_ownership(index: &SnapshotIndex) -> Result<()> {
    for (email, user_id) in &index.email_indexes {
        let user = index
            .users
            .get(user_id)
            .context("backup email index points to an unknown user")?;
        if !user.identifiers.iter().any(|identifier| {
            identifier.kind == IdentifierKind::Email && identifier.value == *email
        }) {
            bail!("backup email index does not belong to its referenced user");
        }
    }
    for (key, user_id) in &index.identifier_indexes {
        let (kind, value) = key
            .split_once(':')
            .context("backup identifier index has an invalid key")?;
        let kind = match kind {
            "email" => IdentifierKind::Email,
            "phone" => IdentifierKind::Phone,
            _ => bail!("backup identifier index has an unsupported type"),
        };
        let user = index
            .users
            .get(user_id)
            .context("backup identifier index points to an unknown user")?;
        if !user
            .identifiers
            .iter()
            .any(|identifier| identifier.kind == kind && identifier.value == value)
        {
            bail!("backup identifier index does not belong to its referenced user");
        }
    }
    for (credential_id, user_id) in &index.credential_indexes {
        let user = index
            .users
            .get(user_id)
            .context("backup credential index points to an unknown user")?;
        if !user
            .passkeys
            .iter()
            .any(|credential| credential.id == *credential_id)
        {
            bail!("backup credential index does not belong to its referenced user");
        }
    }
    Ok(())
}

fn validate_record_ownership(index: &SnapshotIndex) -> Result<()> {
    if index
        .sessions
        .iter()
        .any(|session| !index.users.contains_key(&session.user_id))
    {
        bail!("backup contains a session for an unknown user");
    }
    if index.organizations > 1 {
        bail!("backup contains more than one organization");
    }
    if index
        .operators
        .iter()
        .any(|operator| !index.users.contains_key(&operator.user_id))
    {
        bail!("backup contains an operator for an unknown user");
    }
    for locator in &index.service_credentials {
        let account = index
            .service_accounts
            .get(&locator.service_account_id)
            .context("backup service credential points to an unknown service account")?;
        if !account
            .credentials
            .iter()
            .any(|credential| credential.id == locator.credential_id)
        {
            bail!("backup service credential is absent from its service account");
        }
    }
    for grant in index.realm_fleet_grants.values() {
        if grant.revoked_at.is_none()
            && index
                .realm_fleet_grant_secrets
                .get(&grant.credential_digest)
                != Some(&grant.connection_id)
        {
            bail!("backup realm Fleet grant locator is missing or inconsistent");
        }
        if grant.revoked_at.is_some()
            && index
                .realm_fleet_grant_secrets
                .contains_key(&grant.credential_digest)
        {
            bail!("backup revoked realm Fleet grant still has a live credential locator");
        }
    }
    for (digest, id) in &index.realm_fleet_grant_secrets {
        let grant = index
            .realm_fleet_grants
            .get(id)
            .context("backup realm Fleet grant locator points to an unknown grant")?;
        if grant.credential_digest != *digest || grant.revoked_at.is_some() {
            bail!("backup realm Fleet grant locator does not belong to a live grant");
        }
    }
    Ok(())
}

fn validate_fleet_workspace(index: &SnapshotIndex) -> Result<()> {
    for organization in index.fleet_organizations.values() {
        if index.fleet_organization_slugs.get(&organization.slug) != Some(&organization.id) {
            bail!("backup Fleet organization slug index is missing or inconsistent");
        }
    }
    for (slug, id) in &index.fleet_organization_slugs {
        let organization = index
            .fleet_organizations
            .get(id)
            .context("backup Fleet organization slug points to an unknown organization")?;
        if organization.slug != *slug {
            bail!("backup Fleet organization slug does not belong to its record");
        }
    }
    for project in index.fleet_projects.values() {
        if !index
            .fleet_organizations
            .contains_key(&project.organization_id)
        {
            bail!("backup Fleet project points to an unknown organization");
        }
        if index
            .fleet_project_slugs
            .get(&(project.organization_id, project.slug.clone()))
            != Some(&project.id)
        {
            bail!("backup Fleet project slug index is missing or inconsistent");
        }
    }
    for ((organization_id, slug), id) in &index.fleet_project_slugs {
        let project = index
            .fleet_projects
            .get(id)
            .context("backup Fleet project slug points to an unknown project")?;
        if project.organization_id != *organization_id || project.slug != *slug {
            bail!("backup Fleet project slug does not belong to its record");
        }
    }
    for environment in index.fleet_environments.values() {
        if !index
            .fleet_organizations
            .contains_key(&environment.organization_id)
        {
            bail!("backup Fleet environment points to an unknown organization");
        }
        let project = index
            .fleet_projects
            .get(&environment.project_id)
            .context("backup Fleet environment points to an unknown project")?;
        if project.organization_id != environment.organization_id {
            bail!("backup Fleet environment crosses organization boundaries");
        }
        if index
            .fleet_environment_slugs
            .get(&(environment.project_id, environment.slug.clone()))
            != Some(&environment.id)
        {
            bail!("backup Fleet environment slug index is missing or inconsistent");
        }
    }
    for ((project_id, slug), id) in &index.fleet_environment_slugs {
        let environment = index
            .fleet_environments
            .get(id)
            .context("backup Fleet environment slug points to an unknown environment")?;
        if environment.project_id != *project_id || environment.slug != *slug {
            bail!("backup Fleet environment slug does not belong to its record");
        }
    }
    for connection in index.fleet_connections.values() {
        let environment = index
            .fleet_environments
            .get(&connection.environment_id)
            .context("backup Fleet connection points to an unknown environment")?;
        if environment.organization_id != connection.organization_id
            || environment.project_id != connection.project_id
        {
            bail!("backup Fleet connection crosses workspace boundaries");
        }
        if connection.credential.wrapping_key_id.is_empty()
            || connection.credential.nonce.is_empty()
            || connection.credential.ciphertext.is_empty()
        {
            bail!("backup Fleet connection contains an invalid encrypted credential");
        }
    }
    for binding in index.fleet_role_bindings.values() {
        let resource_exists = match binding.resource_kind {
            FleetResourceKindRecord::Organization => {
                index.fleet_organizations.contains_key(&binding.resource_id)
            }
            FleetResourceKindRecord::Project => {
                index.fleet_projects.contains_key(&binding.resource_id)
            }
            FleetResourceKindRecord::Environment => {
                index.fleet_environments.contains_key(&binding.resource_id)
            }
        };
        if !resource_exists {
            bail!("backup Fleet role binding points to an unknown resource");
        }
        if index.fleet_role_binding_subjects.get(&(
            binding.operator_id,
            binding.resource_kind,
            binding.resource_id,
        )) != Some(&binding.id)
        {
            bail!("backup Fleet role binding subject index is missing or inconsistent");
        }
    }
    for ((operator_id, kind, resource_id), binding_id) in &index.fleet_role_binding_subjects {
        let binding = index
            .fleet_role_bindings
            .get(binding_id)
            .context("backup Fleet role binding subject points to an unknown binding")?;
        if binding.operator_id != *operator_id
            || binding.resource_kind != *kind
            || binding.resource_id != *resource_id
        {
            bail!("backup Fleet role binding subject does not belong to its record");
        }
    }
    for audit in index.fleet_audits.values() {
        let (action_kind, action) = audit
            .action
            .split_once('.')
            .context("backup Fleet audit action is malformed")?;
        let supported = match action_kind {
            "organization" | "project" | "environment" => {
                matches!(action, "create" | "update" | "archive")
            }
            "connection" => matches!(action, "begin" | "complete" | "revoke"),
            "role-binding" => matches!(action, "upsert" | "revoke"),
            _ => false,
        };
        if action_kind != audit.resource_kind || !supported {
            bail!("backup Fleet audit action does not match its resource kind");
        }
        match audit.resource_kind.as_str() {
            "organization" => {
                let organization = index
                    .fleet_organizations
                    .get(&audit.resource_id)
                    .context("backup Fleet audit points to an unknown organization")?;
                if audit.organization_id != Some(organization.id)
                    || audit.project_id.is_some()
                    || audit.environment_id.is_some()
                {
                    bail!("backup Fleet organization audit has inconsistent ownership");
                }
            }
            "project" => {
                let project = index
                    .fleet_projects
                    .get(&audit.resource_id)
                    .context("backup Fleet audit points to an unknown project")?;
                if audit.organization_id != Some(project.organization_id)
                    || audit.project_id != Some(project.id)
                    || audit.environment_id.is_some()
                {
                    bail!("backup Fleet project audit has inconsistent ownership");
                }
            }
            "environment" => {
                let environment = index
                    .fleet_environments
                    .get(&audit.resource_id)
                    .context("backup Fleet audit points to an unknown environment")?;
                if audit.organization_id != Some(environment.organization_id)
                    || audit.project_id != Some(environment.project_id)
                    || audit.environment_id != Some(environment.id)
                {
                    bail!("backup Fleet environment audit has inconsistent ownership");
                }
            }
            "connection" if action == "begin" => {
                if audit.organization_id.is_none()
                    || audit.project_id.is_none()
                    || audit.environment_id.is_none()
                {
                    bail!("backup Fleet connection attempt audit has inconsistent ownership");
                }
            }
            "connection" => {
                let connection = index
                    .fleet_connections
                    .get(&audit.resource_id)
                    .context("backup Fleet audit points to an unknown connection")?;
                if audit.organization_id != Some(connection.organization_id)
                    || audit.project_id != Some(connection.project_id)
                    || audit.environment_id != Some(connection.environment_id)
                {
                    bail!("backup Fleet connection audit has inconsistent ownership");
                }
            }
            "role-binding" => {
                let binding = index
                    .fleet_role_bindings
                    .get(&audit.resource_id)
                    .context("backup Fleet audit points to an unknown role binding")?;
                let (organization_id, project_id, environment_id) = match binding.resource_kind {
                    FleetResourceKindRecord::Organization => {
                        (Some(binding.resource_id), None, None)
                    }
                    FleetResourceKindRecord::Project => {
                        let project = index
                            .fleet_projects
                            .get(&binding.resource_id)
                            .context("backup Fleet role binding project is missing")?;
                        (Some(project.organization_id), Some(project.id), None)
                    }
                    FleetResourceKindRecord::Environment => {
                        let environment = index
                            .fleet_environments
                            .get(&binding.resource_id)
                            .context("backup Fleet role binding environment is missing")?;
                        (
                            Some(environment.organization_id),
                            Some(environment.project_id),
                            Some(environment.id),
                        )
                    }
                };
                if audit.organization_id != organization_id
                    || audit.project_id != project_id
                    || audit.environment_id != environment_id
                {
                    bail!("backup Fleet role binding audit has inconsistent ownership");
                }
            }
            _ => bail!("backup Fleet audit has an unsupported resource kind"),
        }
        let idempotency = index
            .fleet_idempotency
            .get(&audit.request_id)
            .context("backup Fleet audit has no idempotency record")?;
        if idempotency.action != audit.action || idempotency.resource_id != audit.resource_id {
            bail!("backup Fleet audit and idempotency record disagree");
        }
    }
    for (request_id, idempotency) in &index.fleet_idempotency {
        if !index.fleet_audits.values().any(|audit| {
            audit.request_id == *request_id
                && audit.action == idempotency.action
                && audit.resource_id == idempotency.resource_id
        }) {
            bail!("backup Fleet idempotency record has no matching audit");
        }
    }
    Ok(())
}

impl Drop for BackupSnapshot {
    fn drop(&mut self) {
        for record in &mut self.records {
            record.value.zeroize();
        }
    }
}

struct DigestWriter(Sha256);

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn canonical_records_sha256(records: &[StoreRecord]) -> Result<String> {
    let mut writer = DigestWriter(Sha256::new());
    serde_json::to_writer(&mut writer, records).context("hash canonical backup records")?;
    Ok(hex::encode(writer.0.finalize()))
}

fn record_family(key: &str) -> Result<String> {
    if key == "auth:event-sequence" {
        return Ok("event-sequence".into());
    }
    if key == "auth:event-min-sequence" {
        return Ok("event-min-sequence".into());
    }
    if key == KEYSET_KEY {
        return Ok("keyset".into());
    }
    if key == "auth:organization" {
        return Ok("organization".into());
    }
    for (prefix, family) in [
        ("auth:user:", "user"),
        ("auth:email:", "email-index"),
        ("auth:identifier:", "identifier-index"),
        ("auth:credential:", "credential-index"),
        ("auth:session:", "session"),
        ("auth:event:", "event"),
        ("auth:invitation:", "invitation"),
        ("auth:invitation-code:", "invitation-code"),
        ("auth:webhook:", "webhook"),
        ("auth:webhook-cursor:", "webhook-cursor"),
        ("auth:webhook-delivery:", "webhook-delivery"),
        ("auth:webhook-delivery-event:", "webhook-delivery-event"),
        ("auth:operator:", "operator"),
        ("auth:service-account:", "service-account"),
        ("auth:service-credential:", "service-credential"),
        ("auth:fleet-grant:", "realm-fleet-grant"),
        ("auth:fleet-grant-secret:", "realm-fleet-grant-secret"),
        ("auth:remote-mutation:", "remote-mutation"),
        ("fleet:organization:", "fleet-organization"),
        ("fleet:organization-slug:", "fleet-organization-slug"),
        ("fleet:project:", "fleet-project"),
        ("fleet:project-slug:", "fleet-project-slug"),
        ("fleet:environment:", "fleet-environment"),
        ("fleet:environment-slug:", "fleet-environment-slug"),
        ("fleet:connection:", "fleet-connection"),
        ("fleet:role-binding:", "fleet-role-binding"),
        ("fleet:role-binding-subject:", "fleet-role-binding-subject"),
        ("fleet:idempotency:", "fleet-idempotency"),
        ("fleet:assignment-epoch:", "fleet-assignment-epoch"),
        ("fleet:audit:", "fleet-audit"),
        ("fleet:analytics-bucket:", "fleet-analytics-bucket"),
        ("fleet:analytics-policy:", "fleet-analytics-policy"),
        (
            "fleet:analytics-policy-idempotency:",
            "fleet-analytics-policy-idempotency",
        ),
        ("fleet:analytics-quarantine:", "fleet-analytics-quarantine"),
        (
            "fleet:analytics-ingestion-audit:",
            "fleet-analytics-ingestion-audit",
        ),
        (
            "fleet:analytics-operator-audit:",
            "fleet-analytics-operator-audit",
        ),
        (
            "fleet:analytics-maintenance-audit:",
            "fleet-analytics-maintenance-audit",
        ),
        ("fleet:analytics-manifest:", "fleet-analytics-manifest"),
        ("analytics:bucket:", "analytics-bucket"),
        ("analytics:outbox:", "analytics-outbox"),
    ] {
        if key.starts_with(prefix) && key.len() > prefix.len() {
            return Ok(family.into());
        }
    }
    if key == "analytics:projector-cursor" {
        return Ok("analytics-projector-cursor".into());
    }
    if key == "analytics:closure-cursor" {
        return Ok("analytics-closure-cursor".into());
    }
    bail!("backup contains unsupported key {key}")
}

#[cfg(test)]
fn keyset_value() -> String {
    // Snapshot validation deliberately treats the keyset as opaque; jwt validates
    // its cryptographic contents before a restore writes anything.
    "{\"version\":1}".into()
}

#[cfg(test)]
pub(super) fn minimal_snapshot(keys: &KeyRing) -> BackupSnapshot {
    let _ = keys;
    BackupSnapshot::from_records(
        "tenant-a",
        1_000,
        vec![StoreRecord {
            key: KEYSET_KEY.into(),
            value: keyset_value(),
            expires_at: None,
        }],
    )
    .unwrap()
}

#[cfg(test)]
fn identity_snapshot() -> BackupSnapshot {
    let user_id = Uuid::new_v4();
    let email = "person@example.com";
    let user = User {
        id: user_id,
        email: email.into(),
        email_verified: true,
        profile: crate::store::AccountProfile::default(),
        identifiers: vec![crate::store::AccountIdentifier {
            kind: IdentifierKind::Email,
            value: email.into(),
            verified: true,
            verified_at: Some(1_000),
            primary: true,
            created_at: 1_000,
        }],
        session_version: 1,
        recovery_codes: Vec::new(),
        created_at: 1_000,
        passkeys: Vec::new(),
    };
    BackupSnapshot::from_records(
        "tenant-a",
        1_000,
        vec![
            StoreRecord {
                key: format!("auth:email:{email}"),
                value: user_id.to_string(),
                expires_at: None,
            },
            StoreRecord {
                key: format!("auth:identifier:email:{email}"),
                value: user_id.to_string(),
                expires_at: None,
            },
            StoreRecord {
                key: KEYSET_KEY.into(),
                value: keyset_value(),
                expires_at: None,
            },
            StoreRecord {
                key: format!("auth:user:{user_id}"),
                value: serde_json::to_string(&user).unwrap(),
                expires_at: None,
            },
        ],
    )
    .unwrap()
}

#[cfg(test)]
fn fleet_snapshot() -> BackupSnapshot {
    use crate::store::FleetResourceStateRecord;

    let organization_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let audit_id = Uuid::new_v4();
    let operator_id = Uuid::new_v4();
    let organization = FleetOrganizationRecord {
        id: organization_id,
        slug: "acme".into(),
        name: "Acme".into(),
        state: FleetResourceStateRecord::Active,
        created_at: 1_000,
        updated_at: 1_000,
        archived_at: None,
    };
    let audit = FleetAuditRecord {
        id: audit_id,
        request_id,
        operator_id,
        action: "organization.create".into(),
        resource_kind: "organization".into(),
        resource_id: organization_id,
        organization_id: Some(organization_id),
        project_id: None,
        environment_id: None,
        reason: "initial setup".into(),
        occurred_at: 1_000,
    };
    let idempotency = FleetIdempotencySnapshot {
        action: audit.action.clone(),
        resource_id: organization_id,
    };
    let mut records = vec![
        StoreRecord {
            key: KEYSET_KEY.into(),
            value: keyset_value(),
            expires_at: None,
        },
        StoreRecord {
            key: format!("fleet:audit:{audit_id}"),
            value: serde_json::to_string(&audit).unwrap(),
            expires_at: None,
        },
        StoreRecord {
            key: format!("fleet:idempotency:{request_id}"),
            value: serde_json::to_string(&idempotency).unwrap(),
            expires_at: None,
        },
        StoreRecord {
            key: format!("fleet:organization:{organization_id}"),
            value: serde_json::to_string(&organization).unwrap(),
            expires_at: None,
        },
        StoreRecord {
            key: "fleet:organization-slug:acme".into(),
            value: organization_id.to_string(),
            expires_at: None,
        },
    ];
    records.sort_unstable_by(|left, right| left.key.cmp(&right.key));
    BackupSnapshot::from_records("fleet-control-plane", 1_000, records).unwrap()
}

#[cfg(test)]
fn rehash(snapshot: &mut BackupSnapshot) {
    snapshot.manifest.content_sha256 = canonical_records_sha256(&snapshot.records).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_analytics_records_are_covered_by_the_backup_manifest() {
        let snapshot = BackupSnapshot::from_records(
            "tenant-a",
            1_000,
            vec![
                StoreRecord {
                    key: "analytics:bucket:00000000001786127100".into(),
                    value: "bucket".into(),
                    expires_at: None,
                },
                StoreRecord {
                    key: KEYSET_KEY.into(),
                    value: keyset_value(),
                    expires_at: None,
                },
            ],
        )
        .unwrap();

        assert_eq!(snapshot.manifest.key_families["analytics-bucket"], 1);
        snapshot.validate("tenant-a").unwrap();
    }

    #[test]
    fn compact_binary_snapshot_round_trips_without_json_field_names() {
        let keys = KeyRing::new("backup", [19; 32], Vec::new()).unwrap();
        let snapshot = minimal_snapshot(&keys);
        let encoded = snapshot.encode_binary_v3().unwrap();
        assert!(
            !encoded
                .windows(b"contentSha256".len())
                .any(|window| window == b"contentSha256")
        );
        assert_eq!(
            BackupSnapshot::decode_binary_v3(&encoded).unwrap(),
            snapshot
        );
    }

    #[test]
    fn retained_event_window_is_valid_after_prefix_pruning() {
        let mut records = vec![
            StoreRecord {
                key: "auth:event-min-sequence".into(),
                value: "100".into(),
                expires_at: None,
            },
            StoreRecord {
                key: "auth:event-sequence".into(),
                value: "102".into(),
                expires_at: None,
            },
            StoreRecord {
                key: KEYSET_KEY.into(),
                value: keyset_value(),
                expires_at: None,
            },
        ];
        for sequence in 100..=102 {
            let event = AuthEvent {
                sequence,
                id: Uuid::new_v4(),
                tenant_id: "tenant-a".into(),
                event_type: "session.validated".into(),
                subject: None,
                occurred_at: 1_000,
                data: serde_json::json!({}),
            };
            records.push(StoreRecord {
                key: format!("auth:event:{sequence}"),
                value: serde_json::to_string(&event).unwrap(),
                expires_at: None,
            });
        }
        records.sort_unstable_by(|left, right| left.key.cmp(&right.key));

        let snapshot = BackupSnapshot::from_records("tenant-a", 1_000, records).unwrap();
        snapshot.validate("tenant-a").unwrap();
    }

    #[test]
    fn retained_event_window_rejects_an_internal_gap() {
        let mut records = vec![
            StoreRecord {
                key: "auth:event-min-sequence".into(),
                value: "100".into(),
                expires_at: None,
            },
            StoreRecord {
                key: "auth:event-sequence".into(),
                value: "102".into(),
                expires_at: None,
            },
            StoreRecord {
                key: KEYSET_KEY.into(),
                value: keyset_value(),
                expires_at: None,
            },
        ];
        for sequence in [100, 102] {
            let event = AuthEvent {
                sequence,
                id: Uuid::new_v4(),
                tenant_id: "tenant-a".into(),
                event_type: "session.validated".into(),
                subject: None,
                occurred_at: 1_000,
                data: serde_json::json!({}),
            };
            records.push(StoreRecord {
                key: format!("auth:event:{sequence}"),
                value: serde_json::to_string(&event).unwrap(),
                expires_at: None,
            });
        }
        records.sort_unstable_by(|left, right| left.key.cmp(&right.key));

        let error = BackupSnapshot::from_records("tenant-a", 1_000, records)
            .expect_err("a gap inside the retained event window must fail");
        assert!(error.to_string().contains("retained event sequence"));
    }

    #[test]
    fn manifests_detect_record_tampering_and_duplicates() {
        let keys = KeyRing::new("backup", [11; 32], Vec::new()).unwrap();
        let mut snapshot = minimal_snapshot(&keys);
        snapshot.records[0].value.push(' ');
        assert!(snapshot.validate("tenant-a").is_err());

        let mut duplicate = minimal_snapshot(&keys);
        duplicate.records.push(duplicate.records[0].clone());
        duplicate.manifest.record_count += 1;
        duplicate.manifest.content_sha256 = canonical_records_sha256(&duplicate.records).unwrap();
        duplicate.manifest.key_families.insert("keyset".into(), 2);
        assert!(duplicate.validate("tenant-a").is_err());

        let mut sequence_mismatch = BackupSnapshot::from_records(
            "tenant-a",
            1_000,
            vec![
                StoreRecord {
                    key: "auth:event-sequence".into(),
                    value: "0".into(),
                    expires_at: None,
                },
                StoreRecord {
                    key: KEYSET_KEY.into(),
                    value: keyset_value(),
                    expires_at: None,
                },
            ],
        )
        .unwrap();
        sequence_mismatch.records[0].value = "1".into();
        sequence_mismatch.manifest.content_sha256 =
            canonical_records_sha256(&sequence_mismatch.records).unwrap();
        assert!(sequence_mismatch.validate("tenant-a").is_err());
    }

    #[test]
    fn backup_validation_rejects_reverse_indexes_not_owned_by_the_user() {
        let mut snapshot = identity_snapshot();
        let index = snapshot
            .records
            .iter_mut()
            .find(|record| record.key.starts_with("auth:identifier:"))
            .unwrap();
        index.key = "auth:identifier:phone:+447700900123".into();
        snapshot.manifest.content_sha256 = canonical_records_sha256(&snapshot.records).unwrap();
        assert!(snapshot.validate("tenant-a").is_err());
    }

    #[test]
    fn backup_validation_rejects_a_snapshot_captured_for_another_tenant() {
        let keys = KeyRing::new("backup", [12; 32], Vec::new()).unwrap();
        let snapshot = minimal_snapshot(&keys);
        snapshot.validate("tenant-a").unwrap();
        assert!(snapshot.validate("tenant-b").is_err());

        let identity = identity_snapshot();
        identity.validate("tenant-a").unwrap();
        assert!(identity.validate("").is_err());
    }

    #[test]
    fn fleet_snapshot_requires_owned_slug_audit_and_idempotency_indexes() {
        let snapshot = fleet_snapshot();
        snapshot.validate("fleet-control-plane").unwrap();

        let mut missing_slug = fleet_snapshot();
        missing_slug
            .records
            .retain(|record| !record.key.starts_with("fleet:organization-slug:"));
        missing_slug.manifest.record_count -= 1;
        *missing_slug
            .manifest
            .key_families
            .get_mut("fleet-organization-slug")
            .unwrap() -= 1;
        rehash(&mut missing_slug);
        assert!(missing_slug.validate("fleet-control-plane").is_err());

        let mut mismatched_audit = fleet_snapshot();
        let audit = mismatched_audit
            .records
            .iter_mut()
            .find(|record| record.key.starts_with("fleet:audit:"))
            .unwrap();
        let mut value: FleetAuditRecord = serde_json::from_str(&audit.value).unwrap();
        value.organization_id = Some(Uuid::new_v4());
        audit.value = serde_json::to_string(&value).unwrap();
        rehash(&mut mismatched_audit);
        assert!(mismatched_audit.validate("fleet-control-plane").is_err());

        let mut mismatched_action = fleet_snapshot();
        let audit = mismatched_action
            .records
            .iter_mut()
            .find(|record| record.key.starts_with("fleet:audit:"))
            .unwrap();
        let mut value: FleetAuditRecord = serde_json::from_str(&audit.value).unwrap();
        value.resource_kind = "project".into();
        audit.value = serde_json::to_string(&value).unwrap();
        rehash(&mut mismatched_action);
        assert!(mismatched_action.validate("fleet-control-plane").is_err());
    }
}
