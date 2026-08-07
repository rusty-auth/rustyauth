//! Logical snapshot capture and manifest construction, with fail-closed validation
//! of format, tenant, key families, event continuity and cross-record ownership.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use crate::config::KeyRing;
use crate::{
    jwt::KEYSET_KEY,
    store::{
        AuthEvent, IdentifierKind, OperatorRecord, OrganizationRecord, ServiceAccountRecord,
        ServiceCredentialLocator, Session, Store, StoreRecord, User,
    },
};

const SNAPSHOT_VERSION: u8 = 2;

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
        let content = Zeroizing::new(canonical_records(&records)?);
        let content_sha256 = hex::encode(Sha256::digest(&content));
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

    pub(super) fn validate(&self, expected_tenant: &str) -> Result<()> {
        self.validate_format(expected_tenant)?;
        let index = self.index_records()?;
        self.validate_key_families(&index)?;
        self.validate_event_sequence(&index)?;
        validate_user_indexes(&index)?;
        validate_index_ownership(&index)?;
        validate_record_ownership(&index)
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
        let content = Zeroizing::new(canonical_records(&self.records)?);
        let digest = hex::encode(Sha256::digest(&content));
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
            if family != "session" && record.expires_at.is_some() {
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
        if self.manifest.event_sequence > self.records.len() as u64 {
            bail!("backup event sequence exceeds its bounded record count");
        }
        if index.event_sequence_record.unwrap_or_default() != self.manifest.event_sequence
            || (self.manifest.event_sequence > 0 && index.event_sequence_record.is_none())
        {
            bail!("backup event sequence record does not match its manifest");
        }
        let expected_events: BTreeSet<u64> = (1..=self.manifest.event_sequence).collect();
        if index.event_numbers != expected_events {
            bail!("backup event sequence is not contiguous");
        }
        Ok(())
    }
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
    event_numbers: BTreeSet<u64>,
    event_sequence_record: Option<u64>,
    keyset_count: u8,
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
    Ok(())
}

impl Drop for BackupSnapshot {
    fn drop(&mut self) {
        for record in &mut self.records {
            record.value.zeroize();
        }
    }
}

fn canonical_records(records: &[StoreRecord]) -> Result<Vec<u8>> {
    serde_json::to_vec(records).context("serialize canonical backup records")
}

fn record_family(key: &str) -> Result<String> {
    if key == "auth:event-sequence" {
        return Ok("event-sequence".into());
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
        ("auth:operator:", "operator"),
        ("auth:service-account:", "service-account"),
        ("auth:service-credential:", "service-credential"),
    ] {
        if key.starts_with(prefix) && key.len() > prefix.len() {
            return Ok(family.into());
        }
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
mod tests {
    use super::*;

    #[test]
    fn manifests_detect_record_tampering_and_duplicates() {
        let keys = KeyRing::new("backup", [11; 32], Vec::new()).unwrap();
        let mut snapshot = minimal_snapshot(&keys);
        snapshot.records[0].value.push(' ');
        assert!(snapshot.validate("tenant-a").is_err());

        let mut duplicate = minimal_snapshot(&keys);
        duplicate.records.push(duplicate.records[0].clone());
        duplicate.manifest.record_count += 1;
        duplicate.manifest.content_sha256 = hex::encode(Sha256::digest(
            canonical_records(&duplicate.records).unwrap(),
        ));
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
        sequence_mismatch.manifest.content_sha256 = hex::encode(Sha256::digest(
            canonical_records(&sequence_mismatch.records).unwrap(),
        ));
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
        snapshot.manifest.content_sha256 = hex::encode(Sha256::digest(
            canonical_records(&snapshot.records).unwrap(),
        ));
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
}
