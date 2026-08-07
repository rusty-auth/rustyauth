//! Versioned, authenticated logical backups and S3-compatible object storage.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::{Cursor, Read},
    sync::Arc,
};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, bail};
use aws_credential_types::Credentials;
use aws_sdk_s3::{Client, config::Region, primitives::ByteStream};
use base64::{Engine, engine::general_purpose::STANDARD};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::{Mutex, RwLock, watch};
use tracing::{error, info};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    config::{BackupConfig, KeyRing},
    jwt::{KEYSET_KEY, validate_snapshot_keyset},
    store::{
        AuthEvent, IdentifierKind, OperatorRecord, OrganizationRecord, ServiceAccountRecord,
        ServiceCredentialLocator, Session, Store, StoreRecord, User, now,
    },
};

const MAGIC_V2: &[u8; 8] = b"RAUTHBK2";
const LEGACY_MAGIC: &[u8; 8] = b"PAUTHBK1";
const SNAPSHOT_VERSION: u8 = 2;
const MAX_ENVELOPE_BYTES: usize = 256 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;
const CONTENT_TYPE: &str = "application/vnd.rustyauth.backup.v2";

#[derive(Clone)]
pub struct BackupStore {
    client: Client,
    bucket: String,
    encryption_keys: KeyRing,
    interval_seconds: u64,
    operation: Arc<Mutex<()>>,
    status: Arc<RwLock<BackupStatus>>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupStatus {
    pub running: bool,
    pub last_attempt_at: Option<u64>,
    pub last_success_at: Option<u64>,
    pub last_object_key: Option<String>,
    pub consecutive_failures: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupReceipt {
    pub snapshot_id: Uuid,
    pub object_key: String,
    pub captured_at: u64,
    pub record_count: u64,
    pub envelope_bytes: usize,
    pub encryption_key_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupObject {
    pub key: String,
    pub size: i64,
    pub last_modified: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSnapshot {
    format_version: u8,
    snapshot_id: Uuid,
    tenant_id: String,
    captured_at: u64,
    records: Vec<StoreRecord>,
    manifest: SnapshotManifest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotManifest {
    record_count: u64,
    content_sha256: String,
    key_families: BTreeMap<String, u64>,
    event_sequence: u64,
}

impl BackupStore {
    pub async fn new(config: BackupConfig) -> Result<Self> {
        let credentials = Credentials::new(
            config.access_key_id.expose_secret(),
            config.secret_access_key.expose_secret(),
            None,
            None,
            "rustyauth",
        );
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .credentials_provider(credentials)
            .region(Region::new(config.region))
            .endpoint_url(config.endpoint.to_string())
            .load()
            .await;
        let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
            .force_path_style(config.force_path_style)
            .build();

        Ok(Self {
            client: Client::from_conf(s3_config),
            bucket: config.bucket,
            encryption_keys: config.encryption_keys,
            interval_seconds: config.interval_seconds,
            operation: Arc::new(Mutex::new(())),
            status: Arc::new(RwLock::new(BackupStatus::default())),
        })
    }

    pub async fn status(&self) -> BackupStatus {
        self.status.read().await.clone()
    }

    pub async fn create(
        &self,
        store: &Store,
        tenant_id: &str,
        master_keys: &KeyRing,
    ) -> Result<BackupReceipt> {
        let _operation = self.operation.lock().await;
        let lease = store
            .acquire_backup_lease()
            .await?
            .context("another backup is already running")?;
        {
            let mut status = self.status.write().await;
            status.running = true;
            status.last_attempt_at = Some(now());
        }
        let result = self.create_inner(store, tenant_id, master_keys).await;
        store.release_backup_lease(&lease).await;
        let mut status = self.status.write().await;
        status.running = false;
        match &result {
            Ok(receipt) => {
                status.last_success_at = Some(now());
                status.last_object_key = Some(receipt.object_key.clone());
                status.consecutive_failures = 0;
            }
            Err(_) => {
                status.consecutive_failures = status.consecutive_failures.saturating_add(1);
            }
        }
        result
    }

    async fn create_inner(
        &self,
        store: &Store,
        tenant_id: &str,
        master_keys: &KeyRing,
    ) -> Result<BackupReceipt> {
        let snapshot = BackupSnapshot::capture(store, tenant_id).await?;
        validate_snapshot_keyset(snapshot.signing_keyset()?, master_keys)?;
        let envelope = encode_snapshot(&self.encryption_keys, &snapshot)?;
        if envelope.len() > MAX_ENVELOPE_BYTES {
            bail!("encrypted backup exceeds the 256 MiB object safety limit");
        }
        let checksum = STANDARD.encode(Sha256::digest(&envelope));
        let timestamp = OffsetDateTime::from_unix_timestamp(snapshot.captured_at as i64)?
            .format(&Rfc3339)?
            .replace(':', "-");
        let object_key = format!(
            "rustyauth-backups/v2/{tenant_id}/{timestamp}-{}.rauth",
            snapshot.snapshot_id
        );
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&object_key)
            .content_type(CONTENT_TYPE)
            .checksum_sha256(checksum)
            .metadata("snapshot-id", snapshot.snapshot_id.to_string())
            .metadata("key-id", self.encryption_keys.active().0)
            .body(ByteStream::from(envelope.clone()))
            .send()
            .await
            .context("upload encrypted auth snapshot")?;

        // Read-after-write proves that the provider returned the same decryptable object.
        let downloaded = self.download(&object_key, tenant_id).await?;
        if downloaded.snapshot_id != snapshot.snapshot_id
            || downloaded.manifest.content_sha256 != snapshot.manifest.content_sha256
        {
            bail!("uploaded backup failed read-after-write verification");
        }
        let receipt = BackupReceipt {
            snapshot_id: snapshot.snapshot_id,
            object_key,
            captured_at: snapshot.captured_at,
            record_count: snapshot.manifest.record_count,
            envelope_bytes: envelope.len(),
            encryption_key_id: self.encryption_keys.active().0.to_owned(),
        };
        info!(
            snapshot_id = %receipt.snapshot_id,
            object_key = %receipt.object_key,
            record_count = receipt.record_count,
            envelope_bytes = receipt.envelope_bytes,
            encryption_key_id = %receipt.encryption_key_id,
            "encrypted backup created and verified"
        );
        Ok(receipt)
    }

    pub async fn download(&self, object_key: &str, tenant_id: &str) -> Result<BackupSnapshot> {
        let (snapshot, _, _) = self.download_object(object_key, tenant_id).await?;
        Ok(snapshot)
    }

    async fn download_object(
        &self,
        object_key: &str,
        tenant_id: &str,
    ) -> Result<(BackupSnapshot, String, usize)> {
        validate_object_key(object_key, tenant_id)?;
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(object_key)
            .send()
            .await
            .context("download encrypted auth snapshot")?;
        if output.content_length().unwrap_or_default() < 0
            || output.content_length().unwrap_or_default() as usize > MAX_ENVELOPE_BYTES
        {
            bail!("backup object exceeds the 256 MiB safety limit");
        }
        let bytes = output
            .body
            .collect()
            .await
            .context("read encrypted auth snapshot")?
            .into_bytes();
        if bytes.len() > MAX_ENVELOPE_BYTES {
            bail!("backup object exceeds the 256 MiB safety limit");
        }
        let key_id = envelope_key_id(&bytes)?.to_owned();
        let snapshot = decode_snapshot(&self.encryption_keys, &bytes)?;
        snapshot.validate(tenant_id)?;
        Ok((snapshot, key_id, bytes.len()))
    }

    pub async fn verify(
        &self,
        object_key: &str,
        tenant_id: &str,
    ) -> Result<(BackupReceipt, BackupSnapshot)> {
        let (snapshot, key_id, envelope_bytes) =
            self.download_object(object_key, tenant_id).await?;
        let receipt = BackupReceipt {
            snapshot_id: snapshot.snapshot_id,
            object_key: object_key.to_owned(),
            captured_at: snapshot.captured_at,
            record_count: snapshot.manifest.record_count,
            envelope_bytes,
            encryption_key_id: key_id,
        };
        Ok((receipt, snapshot))
    }

    pub async fn list(&self, tenant_id: &str) -> Result<Vec<BackupObject>> {
        let prefix = format!("rustyauth-backups/v2/{tenant_id}/");
        let mut continuation = None;
        let mut objects = Vec::new();
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix);
            if let Some(token) = continuation.as_deref() {
                request = request.continuation_token(token);
            }
            let output = request.send().await.context("list auth backups")?;
            for object in output.contents() {
                let Some(key) = object.key() else {
                    continue;
                };
                objects.push(BackupObject {
                    key: key.to_owned(),
                    size: object.size().unwrap_or_default(),
                    last_modified: object.last_modified().map(ToString::to_string),
                });
            }
            if !output.is_truncated().unwrap_or(false) {
                break;
            }
            continuation = output.next_continuation_token().map(str::to_owned);
            if continuation.is_none() {
                bail!("backup listing was truncated without a continuation token");
            }
        }
        objects.sort_unstable_by(|left, right| right.key.cmp(&left.key));
        Ok(objects)
    }

    pub async fn run_scheduler(
        self,
        store: Store,
        tenant_id: String,
        master_keys: KeyRing,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(self.interval_seconds));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(error) = self.create(&store, &tenant_id, &master_keys).await {
                        error!(error = %error, "scheduled encrypted backup failed");
                    }
                }
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }
}

impl BackupSnapshot {
    async fn capture(store: &Store, tenant_id: &str) -> Result<Self> {
        let (captured_at, records) = store.export_records().await?;
        Self::from_records(tenant_id, captured_at, records)
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

    fn validate(&self, expected_tenant: &str) -> Result<()> {
        if self.format_version != SNAPSHOT_VERSION {
            bail!(
                "unsupported backup snapshot version {}",
                self.format_version
            );
        }
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

        let mut families = BTreeMap::new();
        let mut users = HashMap::new();
        let mut email_indexes = HashMap::new();
        let mut identifier_indexes = HashMap::new();
        let mut credential_indexes = HashMap::new();
        let mut sessions = Vec::new();
        let mut operators = Vec::new();
        let mut organizations = 0_u8;
        let mut service_accounts = HashMap::new();
        let mut service_credentials = Vec::new();
        let mut event_numbers = BTreeSet::new();
        let mut event_sequence_record = None;
        let mut keyset_count = 0_u8;
        for record in &self.records {
            let family = record_family(&record.key)?;
            *families.entry(family.clone()).or_insert(0) += 1;
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
                    if users.insert(user.id, user).is_some() {
                        bail!("backup contains duplicate records for one user id");
                    }
                }
                "email-index" => {
                    let id = Uuid::parse_str(&record.value)
                        .context("backup email index has an invalid user id")?;
                    email_indexes
                        .insert(record.key.trim_start_matches("auth:email:").to_owned(), id);
                }
                "identifier-index" => {
                    let id = Uuid::parse_str(&record.value)
                        .context("backup identifier index has an invalid user id")?;
                    identifier_indexes.insert(
                        record.key.trim_start_matches("auth:identifier:").to_owned(),
                        id,
                    );
                }
                "credential-index" => {
                    let id = Uuid::parse_str(&record.value)
                        .context("backup credential index has an invalid user id")?;
                    credential_indexes.insert(
                        record.key.trim_start_matches("auth:credential:").to_owned(),
                        id,
                    );
                }
                "session" => {
                    if record.expires_at.is_none() {
                        bail!("backup session {} has no expiry", record.key);
                    }
                    sessions.push(
                        serde_json::from_str::<Session>(&record.value)
                            .with_context(|| format!("decode backup session {}", record.key))?,
                    );
                }
                "organization" => {
                    let _: OrganizationRecord = serde_json::from_str(&record.value)
                        .context("decode backup organization")?;
                    organizations = organizations.saturating_add(1);
                }
                "operator" => {
                    let operator: OperatorRecord = serde_json::from_str(&record.value)
                        .with_context(|| format!("decode backup operator {}", record.key))?;
                    if record.key != format!("auth:operator:{}", operator.user_id) {
                        bail!("backup operator key does not match its user id");
                    }
                    operators.push(operator);
                }
                "service-account" => {
                    let account: ServiceAccountRecord = serde_json::from_str(&record.value)
                        .with_context(|| format!("decode backup service account {}", record.key))?;
                    if record.key != format!("auth:service-account:{}", account.id) {
                        bail!("backup service-account key does not match its id");
                    }
                    service_accounts.insert(account.id, account);
                }
                "service-credential" => {
                    let locator: ServiceCredentialLocator = serde_json::from_str(&record.value)
                        .with_context(|| {
                            format!("decode backup service credential {}", record.key)
                        })?;
                    service_credentials.push(locator);
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
                    event_numbers.insert(sequence);
                }
                "keyset" => keyset_count = keyset_count.saturating_add(1),
                "event-sequence" => {
                    event_sequence_record = Some(
                        record
                            .value
                            .parse::<u64>()
                            .context("backup event sequence record is invalid")?,
                    );
                }
                _ => unreachable!("record_family returns known families"),
            }
        }
        if families != self.manifest.key_families {
            bail!("backup key-family manifest does not match its contents");
        }
        if keyset_count != 1 {
            bail!("backup must contain exactly one signing keyset");
        }
        if self.manifest.event_sequence > self.records.len() as u64 {
            bail!("backup event sequence exceeds its bounded record count");
        }
        if event_sequence_record.unwrap_or_default() != self.manifest.event_sequence
            || (self.manifest.event_sequence > 0 && event_sequence_record.is_none())
        {
            bail!("backup event sequence record does not match its manifest");
        }
        let expected_events: BTreeSet<u64> = (1..=self.manifest.event_sequence).collect();
        if event_numbers != expected_events {
            bail!("backup event sequence is not contiguous");
        }
        for user in users.values() {
            if !user.email.is_empty() && email_indexes.get(&user.email) != Some(&user.id) {
                bail!(
                    "backup email index is missing or inconsistent for {}",
                    user.id
                );
            }
            for identifier in &user.identifiers {
                let index = format!("{}:{}", identifier.kind.as_str(), identifier.value);
                let identifier_matches = identifier_indexes.get(&index) == Some(&user.id);
                let legacy_email_matches = identifier.kind == IdentifierKind::Email
                    && email_indexes.get(&identifier.value) == Some(&user.id);
                if !identifier_matches && !legacy_email_matches {
                    bail!(
                        "backup identifier index is missing or inconsistent for {}",
                        user.id
                    );
                }
            }
            for credential in &user.passkeys {
                if credential_indexes.get(&credential.id) != Some(&user.id) {
                    bail!(
                        "backup credential index is missing or inconsistent for {}",
                        user.id
                    );
                }
            }
        }
        for (email, user_id) in &email_indexes {
            let user = users
                .get(user_id)
                .context("backup email index points to an unknown user")?;
            if !user.identifiers.iter().any(|identifier| {
                identifier.kind == IdentifierKind::Email && identifier.value == *email
            }) {
                bail!("backup email index does not belong to its referenced user");
            }
        }
        for (index, user_id) in &identifier_indexes {
            let (kind, value) = index
                .split_once(':')
                .context("backup identifier index has an invalid key")?;
            let kind = match kind {
                "email" => IdentifierKind::Email,
                "phone" => IdentifierKind::Phone,
                _ => bail!("backup identifier index has an unsupported type"),
            };
            let user = users
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
        for (credential_id, user_id) in &credential_indexes {
            let user = users
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
        if sessions
            .iter()
            .any(|session| !users.contains_key(&session.user_id))
        {
            bail!("backup contains a session for an unknown user");
        }
        if organizations > 1 {
            bail!("backup contains more than one organization");
        }
        if operators
            .iter()
            .any(|operator| !users.contains_key(&operator.user_id))
        {
            bail!("backup contains an operator for an unknown user");
        }
        for locator in service_credentials {
            let account = service_accounts
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
}

impl Drop for BackupSnapshot {
    fn drop(&mut self) {
        for record in &mut self.records {
            record.value.zeroize();
        }
    }
}

fn encode_snapshot(keys: &KeyRing, snapshot: &BackupSnapshot) -> Result<Vec<u8>> {
    let plaintext =
        Zeroizing::new(serde_json::to_vec(snapshot).context("serialize backup snapshot")?);
    if plaintext.len() as u64 > MAX_SNAPSHOT_BYTES {
        bail!("backup snapshot exceeds the 512 MiB plaintext safety limit");
    }
    let compressed = zstd::stream::encode_all(Cursor::new(plaintext.as_slice()), 3)
        .context("compress backup snapshot");
    let compressed = Zeroizing::new(compressed?);
    encrypt_envelope(keys, &compressed)
}

fn decode_snapshot(keys: &KeyRing, envelope: &[u8]) -> Result<BackupSnapshot> {
    let compressed = Zeroizing::new(decrypt_envelope(keys, envelope)?);
    let decoder = zstd::stream::read::Decoder::new(Cursor::new(compressed.as_slice()))
        .context("open compressed backup snapshot")?;
    let mut limited = decoder.take(MAX_SNAPSHOT_BYTES + 1);
    let mut plaintext = Zeroizing::new(Vec::new());
    limited
        .read_to_end(&mut plaintext)
        .context("decompress backup snapshot")?;
    drop(limited);
    if plaintext.len() as u64 > MAX_SNAPSHOT_BYTES {
        bail!("decompressed backup exceeds the 512 MiB safety limit");
    }
    serde_json::from_slice(&plaintext).context("decode backup snapshot")
}

fn encrypt_envelope(keys: &KeyRing, plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::rand_core::{OsRng, RngCore};

    let (key_id, key) = keys.active();
    if key_id.len() > u8::MAX as usize {
        bail!("backup encryption key id is too long");
    }
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut header = Vec::with_capacity(MAGIC_V2.len() + 1 + key_id.len() + nonce.len());
    header.extend_from_slice(MAGIC_V2);
    header.push(key_id.len() as u8);
    header.extend_from_slice(key_id.as_bytes());
    header.extend_from_slice(&nonce);
    let cipher = Aes256Gcm::new_from_slice(key).expect("validated AES-256 key");
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt auth backup"))?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

fn decrypt_envelope(keys: &KeyRing, envelope: &[u8]) -> Result<Vec<u8>> {
    if envelope.starts_with(LEGACY_MAGIC) {
        bail!("legacy PAUTHBK1 payloads predate restorable snapshots and cannot be restored");
    }
    if !envelope.starts_with(MAGIC_V2) || envelope.len() < MAGIC_V2.len() + 1 + 12 + 16 {
        bail!("backup envelope is truncated or has an unsupported format");
    }
    let key_id = envelope_key_id(envelope)?;
    let key_id_start = MAGIC_V2.len() + 1;
    let nonce_start = key_id_start.saturating_add(key_id.len());
    let ciphertext_start = nonce_start.saturating_add(12);
    let key = keys.get(key_id).with_context(|| {
        format!(
            "backup requires encryption key {key_id}; retain it in AUTH_BACKUP_PREVIOUS_KEYS_HEX"
        )
    })?;
    let nonce = &envelope[nonce_start..ciphertext_start];
    let header = &envelope[..ciphertext_start];
    let cipher = Aes256Gcm::new_from_slice(key).expect("validated AES-256 key");
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: &envelope[ciphertext_start..],
                aad: header,
            },
        )
        .map_err(|_| anyhow::anyhow!("backup authentication failed"))
}

fn envelope_key_id(envelope: &[u8]) -> Result<&str> {
    if envelope.starts_with(LEGACY_MAGIC) {
        bail!("legacy PAUTHBK1 payloads predate restorable snapshots and cannot be restored");
    }
    if !envelope.starts_with(MAGIC_V2) || envelope.len() < MAGIC_V2.len() + 1 + 12 + 16 {
        bail!("backup envelope is truncated or has an unsupported format");
    }
    let key_id_length = envelope[MAGIC_V2.len()] as usize;
    let key_id_start = MAGIC_V2.len() + 1;
    let nonce_start = key_id_start.saturating_add(key_id_length);
    let ciphertext_start = nonce_start.saturating_add(12);
    if key_id_length == 0 || ciphertext_start.saturating_add(16) > envelope.len() {
        bail!("backup envelope header is malformed");
    }
    std::str::from_utf8(&envelope[key_id_start..nonce_start])
        .context("backup encryption key id is not UTF-8")
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

fn validate_object_key(object_key: &str, tenant_id: &str) -> Result<()> {
    let prefix = format!("rustyauth-backups/v2/{tenant_id}/");
    if !object_key.starts_with(&prefix)
        || object_key.contains("..")
        || object_key.chars().any(char::is_control)
        || !object_key.ends_with(".rauth")
    {
        bail!("backup object key is outside the configured tenant prefix");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyset_value() -> String {
        // Snapshot validation deliberately treats the keyset as opaque; jwt validates
        // its cryptographic contents before a restore writes anything.
        "{\"version\":1}".into()
    }

    fn minimal_snapshot(keys: &KeyRing) -> BackupSnapshot {
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

    #[test]
    fn backup_envelope_round_trips_and_authenticates_header() {
        let keys = KeyRing::new("backup", [7; 32], Vec::new()).unwrap();
        let snapshot = minimal_snapshot(&keys);
        let one = encode_snapshot(&keys, &snapshot).unwrap();
        let two = encode_snapshot(&keys, &snapshot).unwrap();
        assert!(one.starts_with(MAGIC_V2));
        assert_ne!(one, two);
        assert_eq!(decode_snapshot(&keys, &one).unwrap(), snapshot);

        let mut tampered = one;
        tampered[MAGIC_V2.len() + 2] ^= 1;
        assert!(decode_snapshot(&keys, &tampered).is_err());
    }

    #[test]
    fn backup_key_rollover_keeps_old_snapshots_readable() {
        let old = KeyRing::new("backup", [8; 32], Vec::new()).unwrap();
        let snapshot = minimal_snapshot(&old);
        let envelope = encode_snapshot(&old, &snapshot).unwrap();
        let rolled = KeyRing::new("backup", [9; 32], vec![[8; 32]]).unwrap();
        assert_eq!(decode_snapshot(&rolled, &envelope).unwrap(), snapshot);
        let without_old = KeyRing::new("backup", [9; 32], Vec::new()).unwrap();
        assert!(decode_snapshot(&without_old, &envelope).is_err());
    }

    #[test]
    fn malformed_and_truncated_envelopes_fail_closed() {
        let keys = KeyRing::new("backup", [10; 32], Vec::new()).unwrap();
        for input in [Vec::new(), MAGIC_V2.to_vec(), LEGACY_MAGIC.to_vec()] {
            assert!(decode_snapshot(&keys, &input).is_err());
        }
        let snapshot = minimal_snapshot(&keys);
        let mut envelope = encode_snapshot(&keys, &snapshot).unwrap();
        envelope.truncate(envelope.len() - 1);
        assert!(decode_snapshot(&keys, &envelope).is_err());
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
    fn object_keys_cannot_cross_tenant_boundaries() {
        assert!(
            validate_object_key("rustyauth-backups/v2/tenant-a/2026.rauth", "tenant-a").is_ok()
        );
        assert!(
            validate_object_key("rustyauth-backups/v2/tenant-b/2026.rauth", "tenant-a").is_err()
        );
    }
}
