//! Fail-closed configuration and deployment-policy validation.

mod file;

use std::{
    collections::{HashMap, HashSet},
    env, fmt, fs,
    net::IpAddr,
    path::Path,
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroize;

use crate::store::{IdentifierKind, IdentifierValue};

pub const REALM_CONFIGURATION_EXAMPLE: &str = include_str!("../rustyauth.example.yaml");
pub const FLEET_CONFIGURATION_EXAMPLE: &str = include_str!("../rustyauth.fleet.example.yaml");

const CONFIGURATION_NAMES: &[&str] = &[
    "AUTH_ENV",
    "AUTH_DEPLOYMENT_ROLE",
    "BIND_ADDRESS",
    "PORT",
    "AUTH_ISSUER",
    "WEBAUTHN_RP_ID",
    "WEBAUTHN_RP_ORIGIN",
    "WEBAUTHN_RP_NAME",
    "SABLEDB_URL",
    "AUTH_MASTER_KEY_HEX",
    "AUTH_MASTER_PREVIOUS_KEYS_HEX",
    "AUTH_MASTER_KEY_KMS_CIPHERTEXT_B64",
    "AUTH_MASTER_PREVIOUS_KEYS_KMS_CIPHERTEXT_B64",
    "BOOTSTRAP_TOKEN",
    "AUTH_EVENT_RPC_TOKEN",
    "AUTH_IDENTITY_RPC_TOKEN",
    "AUTH_OPERATOR_EMAILS",
    "SPACETIME_AUDIENCE",
    "AUTH_TENANT_ID",
    "AUTH_REALM_ID",
    "AUTH_ACCESS_TOKEN_SECONDS",
    "AUTH_SESSION_IDLE_SECONDS",
    "AUTH_SESSION_ABSOLUTE_SECONDS",
    "AUTH_EVENT_RETENTION_SECONDS",
    "AUTH_SIGNING_KEY_ROTATION_SECONDS",
    "AUTH_SIGNING_KEY_PREPUBLISH_SECONDS",
    "AUTH_SIGNING_KEY_OVERLAP_SECONDS",
    "AUTH_KEY_MAINTENANCE_SECONDS",
    "AUTH_TRUSTED_PROXY_HOPS",
    "AUTH_BACKUP_ENDPOINT",
    "AUTH_BACKUP_REGION",
    "AUTH_BACKUP_BUCKET",
    "AUTH_BACKUP_ACCESS_KEY_ID",
    "AUTH_BACKUP_SECRET_ACCESS_KEY",
    "AUTH_BACKUP_ENCRYPTION_KEY_HEX",
    "AUTH_BACKUP_PREVIOUS_KEYS_HEX",
    "AUTH_BACKUP_ENCRYPTION_KEY_KMS_CIPHERTEXT_B64",
    "AUTH_BACKUP_PREVIOUS_KEYS_KMS_CIPHERTEXT_B64",
    "AUTH_BACKUP_INTERVAL_SECONDS",
    "AUTH_BACKUP_RPO_SECONDS",
    "AUTH_BACKUP_RETENTION_DAYS",
    "AUTH_BACKUP_ALERT_AFTER_FAILURES",
    "AUTH_BACKUP_SSE",
    "AUTH_BACKUP_SSE_KMS_KEY_ID",
    "AUTH_BACKUP_URL_STYLE",
    "AUTH_ANALYTICS_ENDPOINT",
    "AUTH_ANALYTICS_DATABASE",
    "AUTH_ANALYTICS_USERNAME",
    "AUTH_ANALYTICS_PASSWORD",
];

const SECRET_NAMES: &[&str] = &[
    "SABLEDB_URL",
    "AUTH_MASTER_KEY_HEX",
    "AUTH_MASTER_PREVIOUS_KEYS_HEX",
    "AUTH_MASTER_KEY_KMS_CIPHERTEXT_B64",
    "AUTH_MASTER_PREVIOUS_KEYS_KMS_CIPHERTEXT_B64",
    "BOOTSTRAP_TOKEN",
    "AUTH_EVENT_RPC_TOKEN",
    "AUTH_IDENTITY_RPC_TOKEN",
    "AUTH_BACKUP_ACCESS_KEY_ID",
    "AUTH_BACKUP_SECRET_ACCESS_KEY",
    "AUTH_BACKUP_ENCRYPTION_KEY_HEX",
    "AUTH_BACKUP_PREVIOUS_KEYS_HEX",
    "AUTH_BACKUP_ENCRYPTION_KEY_KMS_CIPHERTEXT_B64",
    "AUTH_BACKUP_PREVIOUS_KEYS_KMS_CIPHERTEXT_B64",
    "AUTH_ANALYTICS_USERNAME",
    "AUTH_ANALYTICS_PASSWORD",
];

const MAX_SECRET_FILE_BYTES: u64 = 64 * 1024;

#[derive(Clone)]
struct SourcedValue {
    value: String,
    origin: String,
}

#[derive(Clone, Default)]
pub(super) struct ConfigValues {
    values: HashMap<String, SourcedValue>,
    webhooks: Vec<WebhookConfig>,
}

impl fmt::Debug for ConfigValues {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigValues")
            .field(
                "values",
                &self
                    .values
                    .iter()
                    .map(|(name, value)| (name, &value.origin))
                    .collect::<HashMap<_, _>>(),
            )
            .field("webhook_count", &self.webhooks.len())
            .finish()
    }
}

impl ConfigValues {
    fn from_environment() -> Result<Self> {
        let mut values = Self::default();
        for name in CONFIGURATION_NAMES {
            if let Some(value) = environment_value(name)? {
                values.insert(*name, value, (*name).to_owned());
            }
        }
        Ok(values)
    }

    fn with_runtime_secrets(mut self) -> Result<Self> {
        for name in SECRET_NAMES {
            if let Some(value) = environment_value(name)? {
                self.insert(*name, value, (*name).to_owned());
            }
        }
        // Railway supplies PORT automatically. Keeping this one documented
        // platform override lets the same YAML document run in Railway without
        // hard-coding a platform-assigned listener port.
        if let Some(value) = environment_value("PORT")? {
            self.insert("PORT", value, "PORT (platform override)".to_owned());
        }
        Ok(self)
    }

    async fn with_kms_envelope_keys(mut self) -> Result<Self> {
        let requests = [
            KmsKeyRequest {
                plaintext_name: "AUTH_MASTER_KEY_HEX",
                ciphertext_name: "AUTH_MASTER_KEY_KMS_CIPHERTEXT_B64",
                purpose: "master",
                list: false,
            },
            KmsKeyRequest {
                plaintext_name: "AUTH_MASTER_PREVIOUS_KEYS_HEX",
                ciphertext_name: "AUTH_MASTER_PREVIOUS_KEYS_KMS_CIPHERTEXT_B64",
                purpose: "master",
                list: true,
            },
            KmsKeyRequest {
                plaintext_name: "AUTH_BACKUP_ENCRYPTION_KEY_HEX",
                ciphertext_name: "AUTH_BACKUP_ENCRYPTION_KEY_KMS_CIPHERTEXT_B64",
                purpose: "backup",
                list: false,
            },
            KmsKeyRequest {
                plaintext_name: "AUTH_BACKUP_PREVIOUS_KEYS_HEX",
                ciphertext_name: "AUTH_BACKUP_PREVIOUS_KEYS_KMS_CIPHERTEXT_B64",
                purpose: "backup",
                list: true,
            },
        ];
        let requested = requests
            .iter()
            .filter_map(|request| {
                self.optional(request.ciphertext_name)
                    .map(|ciphertext| (*request, ciphertext))
            })
            .collect::<Vec<_>>();
        if requested.is_empty() {
            return Ok(self);
        }
        for (request, _) in &requested {
            if self.optional(request.plaintext_name).is_some() {
                bail!(
                    "configure either {} or {}, not both",
                    self.label(request.plaintext_name),
                    self.label(request.ciphertext_name)
                );
            }
        }

        let tenant_id = self.required("AUTH_TENANT_ID")?;
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        let client = aws_sdk_kms::Client::new(&sdk_config);
        for (request, ciphertext) in requested {
            let values = if request.list {
                ciphertext
                    .split(',')
                    .map(str::trim)
                    .enumerate()
                    .map(|(index, value)| (index + 1, value))
                    .collect::<Vec<_>>()
            } else {
                vec![(1, ciphertext.trim())]
            };
            if values.iter().any(|(_, value)| value.is_empty()) {
                bail!(
                    "{} contains an empty ciphertext",
                    self.label(request.ciphertext_name)
                );
            }
            let mut plaintext_keys = Vec::with_capacity(values.len());
            for (index, ciphertext) in values {
                plaintext_keys.push(
                    decrypt_kms_key(
                        &client,
                        ciphertext,
                        request.ciphertext_name,
                        index,
                        request.purpose,
                        &tenant_id,
                    )
                    .await?,
                );
            }
            self.insert(
                request.plaintext_name,
                plaintext_keys.join(","),
                format!(
                    "{} (AWS KMS decrypted)",
                    self.label(request.ciphertext_name)
                ),
            );
        }
        Ok(self)
    }

    fn with_validation_secrets(mut self) -> Self {
        self.insert(
            "AUTH_MASTER_KEY_HEX",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_owned(),
            "validation-only master key".to_owned(),
        );
        self.insert(
            "BOOTSTRAP_TOKEN",
            "validation-only-bootstrap-token-0000000000000001".to_owned(),
            "validation-only bootstrap token".to_owned(),
        );
        self.insert(
            "AUTH_EVENT_RPC_TOKEN",
            "validation-only-event-rpc-token-000000000000001".to_owned(),
            "validation-only event RPC token".to_owned(),
        );
        self.insert(
            "AUTH_IDENTITY_RPC_TOKEN",
            "validation-only-identity-rpc-token-00000000001".to_owned(),
            "validation-only identity RPC token".to_owned(),
        );
        if self.optional("AUTH_BACKUP_ENDPOINT").is_some() {
            self.insert(
                "AUTH_BACKUP_ACCESS_KEY_ID",
                "validation-only-access-key".to_owned(),
                "validation-only backup access key".to_owned(),
            );
            self.insert(
                "AUTH_BACKUP_SECRET_ACCESS_KEY",
                "validation-only-secret-access-key".to_owned(),
                "validation-only backup secret key".to_owned(),
            );
            self.insert(
                "AUTH_BACKUP_ENCRYPTION_KEY_HEX",
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f".to_owned(),
                "validation-only backup encryption key".to_owned(),
            );
        }
        if self.optional("AUTH_ANALYTICS_ENDPOINT").is_some() {
            self.insert(
                "AUTH_ANALYTICS_USERNAME",
                "validation-only-analytics-user".to_owned(),
                "validation-only analytics username".to_owned(),
            );
            self.insert(
                "AUTH_ANALYTICS_PASSWORD",
                "validation-only-analytics-password".to_owned(),
                "validation-only analytics password".to_owned(),
            );
        }
        self
    }

    pub(super) fn insert(&mut self, name: impl Into<String>, value: String, origin: String) {
        let name = name.into();
        let value = value.trim().to_owned();
        if value.is_empty() {
            self.values.remove(&name);
        } else {
            self.values.insert(name, SourcedValue { value, origin });
        }
    }

    fn required(&self, name: &str) -> Result<String> {
        self.optional(name).with_context(|| {
            format!(
                "required configuration value {} is missing",
                self.label(name)
            )
        })
    }

    fn optional(&self, name: &str) -> Option<String> {
        self.values.get(name).map(|value| value.value.clone())
    }

    fn label<'a>(&'a self, name: &'a str) -> &'a str {
        self.values
            .get(name)
            .map(|value| value.origin.as_str())
            .unwrap_or(name)
    }
}

#[derive(Clone, Copy)]
struct KmsKeyRequest {
    plaintext_name: &'static str,
    ciphertext_name: &'static str,
    purpose: &'static str,
    list: bool,
}

async fn decrypt_kms_key(
    client: &aws_sdk_kms::Client,
    ciphertext: &str,
    source_name: &str,
    index: usize,
    purpose: &str,
    tenant_id: &str,
) -> Result<String> {
    let ciphertext = decode_kms_ciphertext(ciphertext, source_name, index)?;
    let response = client
        .decrypt()
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext))
        .encryption_context("rustyauth-purpose", purpose)
        .encryption_context("rustyauth-tenant", tenant_id)
        .send()
        .await
        .with_context(|| format!("decrypt {source_name} item {index} with AWS KMS"))?;
    let plaintext = response
        .plaintext()
        .context("AWS KMS decrypt response omitted plaintext")?
        .as_ref()
        .to_vec();
    encode_kms_plaintext(plaintext, source_name, index)
}

fn decode_kms_ciphertext(value: &str, source_name: &str, index: usize) -> Result<Vec<u8>> {
    let ciphertext = STANDARD
        .decode(value)
        .with_context(|| format!("{source_name} item {index} must be standard base64"))?;
    if ciphertext.is_empty() || ciphertext.len() > MAX_SECRET_FILE_BYTES as usize {
        bail!("{source_name} item {index} has an invalid ciphertext size");
    }
    Ok(ciphertext)
}

fn encode_kms_plaintext(mut plaintext: Vec<u8>, source_name: &str, index: usize) -> Result<String> {
    let encoded = (plaintext.len() == 32).then(|| hex::encode(&plaintext));
    plaintext.zeroize();
    encoded.with_context(|| {
        format!("AWS KMS plaintext for {source_name} item {index} must contain exactly 32 bytes")
    })
}

fn environment_value(name: &str) -> Result<Option<String>> {
    resolve_environment_value(name, env::var_os(name), env::var_os(format!("{name}_FILE")))
}

fn resolve_environment_value(
    name: &str,
    direct: Option<std::ffi::OsString>,
    file_path: Option<std::ffi::OsString>,
) -> Result<Option<String>> {
    let direct = direct
        .map(|value| {
            value
                .into_string()
                .map_err(|_| anyhow::anyhow!("{name} contains non-Unicode data"))
        })
        .transpose()?
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let file_path = file_path
        .map(|value| {
            value
                .into_string()
                .map_err(|_| anyhow::anyhow!("{name}_FILE contains a non-Unicode path"))
        })
        .transpose()?
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if direct.is_some() && file_path.is_some() {
        bail!("configure either {name} or {name}_FILE, not both");
    }
    if let Some(path) = file_path {
        let metadata =
            fs::metadata(&path).with_context(|| format!("inspect {name} secret file {path}"))?;
        if metadata.len() > MAX_SECRET_FILE_BYTES {
            bail!("{name}_FILE exceeds the {MAX_SECRET_FILE_BYTES}-byte secret input limit");
        }
        let value = fs::read_to_string(&path)
            .with_context(|| format!("read {name} from secret file {path}"))?;
        let value = value.trim().to_owned();
        return Ok((!value.is_empty()).then_some(value));
    }
    Ok(direct)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Environment {
    Development,
    Production,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentRole {
    Realm,
    FleetControlPlane,
}

#[derive(Clone, Debug)]
pub struct BackupConfig {
    pub endpoint: Url,
    pub region: String,
    pub bucket: String,
    pub access_key_id: SecretString,
    pub secret_access_key: SecretString,
    pub encryption_keys: KeyRing,
    pub force_path_style: bool,
    pub interval_seconds: u64,
    pub rpo_seconds: u64,
    pub retention_days: u64,
    pub alert_after_failures: u64,
    pub server_side_encryption: BackupServerSideEncryption,
    pub sse_kms_key_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AnalyticsConfig {
    pub endpoint: Url,
    pub database: String,
    pub username: SecretString,
    pub password: SecretString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupServerSideEncryption {
    /// The compatible provider owns its at-rest encryption policy. Application
    /// encryption and Object Lock/versioning are still mandatory.
    Provider,
    Aes256,
    AwsKms,
}

impl BackupServerSideEncryption {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Aes256 => "AES256",
            Self::AwsKms => "aws:kms",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SigningRotationConfig {
    pub rotation_seconds: u64,
    pub prepublish_seconds: u64,
    pub overlap_seconds: u64,
    pub maintenance_seconds: u64,
}

/// A webhook whose desired state comes from the versioned configuration file.
/// Configuration-managed destinations are authoritative: management surfaces
/// may test them and rotate credentials, but must not change or delete them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookConfig {
    pub id: String,
    pub name: String,
    pub endpoint: Url,
    pub enabled: bool,
    pub event_types: Vec<String>,
}

#[derive(Clone)]
pub struct KeyRing(Arc<KeyRingInner>);

struct KeyRingInner {
    active: KeyEntry,
    previous: Vec<KeyEntry>,
}

struct KeyEntry {
    id: String,
    key: [u8; 32],
}

impl Drop for KeyRingInner {
    fn drop(&mut self) {
        self.active.key.zeroize();
        for entry in &mut self.previous {
            entry.key.zeroize();
        }
    }
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyRing")
            .field("active_key_id", &self.0.active.id)
            .field(
                "previous_key_ids",
                &self
                    .0
                    .previous
                    .iter()
                    .map(|entry| entry.id.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl KeyRing {
    pub fn new(purpose: &str, active: [u8; 32], previous: Vec<[u8; 32]>) -> Result<Self> {
        let active = KeyEntry {
            id: derived_key_id(purpose, &active),
            key: active,
        };
        let mut seen = HashSet::from([active.id.clone()]);
        let mut entries = Vec::with_capacity(previous.len());
        for key in previous {
            let id = derived_key_id(purpose, &key);
            if !seen.insert(id.clone()) {
                bail!("{purpose} keyring contains the same key more than once");
            }
            entries.push(KeyEntry { id, key });
        }
        Ok(Self(Arc::new(KeyRingInner {
            active,
            previous: entries,
        })))
    }

    pub fn active(&self) -> (&str, &[u8; 32]) {
        (&self.0.active.id, &self.0.active.key)
    }

    pub fn get(&self, id: &str) -> Option<&[u8; 32]> {
        if self.0.active.id == id {
            return Some(&self.0.active.key);
        }
        self.0
            .previous
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| &entry.key)
    }

    pub fn key_ids(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.0.active.id.as_str())
            .chain(self.0.previous.iter().map(|entry| entry.id.as_str()))
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub environment: Environment,
    pub deployment_role: DeploymentRole,
    pub bind: IpAddr,
    pub port: u16,
    pub issuer: Url,
    pub rp_id: String,
    pub rp_origin: Url,
    pub rp_name: String,
    pub sabledb_url: SecretString,
    pub master_keys: KeyRing,
    pub bootstrap_token: SecretString,
    pub event_rpc_token: SecretString,
    pub identity_rpc_token: SecretString,
    pub operator_emails: Vec<String>,
    pub audience: String,
    pub tenant_id: String,
    pub realm_id: String,
    pub access_token_seconds: u64,
    pub session_idle_seconds: u64,
    pub session_absolute_seconds: u64,
    pub event_retention_seconds: u64,
    pub signing_rotation: SigningRotationConfig,
    pub trusted_proxy_hops: usize,
    pub backup: Option<BackupConfig>,
    pub analytics: Option<AnalyticsConfig>,
    pub webhooks: Vec<WebhookConfig>,
}

/// Safe output returned by `rustyauth config validate`. It intentionally omits
/// all credential material and datastore details.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationSummary {
    pub status: &'static str,
    pub api_version: &'static str,
    pub kind: &'static str,
    pub environment: &'static str,
    pub tenant_id: String,
    pub realm_id: String,
    pub issuer: String,
    pub port: u16,
    pub backups_enabled: bool,
    pub analytics_enabled: bool,
    pub webhook_count: usize,
    pub runtime_secrets: &'static str,
}

impl From<&Config> for ConfigurationSummary {
    fn from(config: &Config) -> Self {
        Self {
            status: "valid",
            api_version: file::API_VERSION,
            kind: match config.deployment_role {
                DeploymentRole::Realm => "Realm",
                DeploymentRole::FleetControlPlane => "FleetControlPlane",
            },
            environment: match config.environment {
                Environment::Development => "development",
                Environment::Production => "production",
            },
            tenant_id: config.tenant_id.clone(),
            realm_id: config.realm_id.clone(),
            issuer: config.issuer.to_string().trim_end_matches('/').to_owned(),
            port: config.port,
            backups_enabled: config.backup.is_some(),
            analytics_enabled: config.analytics.is_some(),
            webhook_count: config.webhooks.len(),
            runtime_secrets: "validated-at-startup",
        }
    }
}

impl Config {
    /// Loads the legacy environment-only contract.
    ///
    /// Every supported value also accepts a `<NAME>_FILE` companion, which is
    /// useful for Docker and Kubernetes secret mounts. Supplying both forms is
    /// rejected so the effective credential is never ambiguous.
    pub fn from_env() -> Result<Self> {
        Self::from_values(&ConfigValues::from_environment()?)
    }

    /// Loads the environment contract and resolves any KMS-enveloped key rings.
    pub async fn from_env_runtime() -> Result<Self> {
        let values = ConfigValues::from_environment()?
            .with_kms_envelope_keys()
            .await?;
        Self::from_values(&values)
    }

    /// Loads the versioned YAML contract from a filesystem path.
    pub fn from_file(path: &Path) -> Result<Self> {
        let values = file::values_from_path(path)?.with_runtime_secrets()?;
        Self::from_values(&values)
    }

    /// Loads YAML plus runtime secrets and resolves KMS-enveloped key rings.
    pub async fn from_file_runtime(path: &Path) -> Result<Self> {
        let values = file::values_from_path(path)?
            .with_runtime_secrets()?
            .with_kms_envelope_keys()
            .await?;
        Self::from_values(&values)
    }

    /// Loads the versioned YAML contract from a multiline environment value.
    pub fn from_yaml(yaml: &str, source_name: &str) -> Result<Self> {
        let values = file::values_from_yaml(yaml, source_name)?.with_runtime_secrets()?;
        Self::from_values(&values)
    }

    /// Loads inline YAML plus runtime secrets and resolves KMS-enveloped key rings.
    pub async fn from_yaml_runtime(yaml: &str, source_name: &str) -> Result<Self> {
        let values = file::values_from_yaml(yaml, source_name)?
            .with_runtime_secrets()?
            .with_kms_envelope_keys()
            .await?;
        Self::from_values(&values)
    }

    /// Validates all non-secret YAML settings with the same runtime parser.
    /// Secret presence and material are checked separately when the service
    /// actually starts, so this command remains useful in pull-request CI.
    pub fn validate_file(path: &Path) -> Result<ConfigurationSummary> {
        let values = file::values_from_path(path)?.with_validation_secrets();
        let config = Self::from_values(&values)?;
        Ok(ConfigurationSummary::from(&config))
    }

    pub fn validate_yaml(yaml: &str, source_name: &str) -> Result<ConfigurationSummary> {
        let values = file::values_from_yaml(yaml, source_name)?.with_validation_secrets();
        let config = Self::from_values(&values)?;
        Ok(ConfigurationSummary::from(&config))
    }

    fn from_values(values: &ConfigValues) -> Result<Self> {
        // AUTH_ENV gates every other fail-closed check, so it must itself fail
        // closed. Defaulting an unset value to development silently drops Secure
        // cookies, HTTPS validation, and identity-verification enforcement.
        let environment = match values.optional("AUTH_ENV").as_deref() {
            Some("development") => Environment::Development,
            Some("production") => Environment::Production,
            Some(other) => bail!(
                "{} must be development or production, got {other}",
                values.label("AUTH_ENV")
            ),
            None => bail!(
                "{} must be set explicitly to development or production",
                values.label("AUTH_ENV")
            ),
        };
        let deployment_role = match values.optional("AUTH_DEPLOYMENT_ROLE").as_deref() {
            None | Some("realm") => DeploymentRole::Realm,
            Some("fleet-control-plane") => DeploymentRole::FleetControlPlane,
            Some(other) => {
                bail!(
                    "{} must be realm or fleet-control-plane, got {other}",
                    values.label("AUTH_DEPLOYMENT_ROLE")
                )
            }
        };

        let bind = IpAddr::from_str(
            values
                .optional("BIND_ADDRESS")
                .as_deref()
                .unwrap_or("0.0.0.0"),
        )
        .with_context(|| format!("{} is invalid", values.label("BIND_ADDRESS")))?;
        let port = values
            .optional("PORT")
            .as_deref()
            .unwrap_or("8080")
            .parse()
            .with_context(|| format!("{} is invalid", values.label("PORT")))?;
        if port == 0 {
            bail!("{} must be between 1 and 65535", values.label("PORT"));
        }
        let issuer = parse_url(values, "AUTH_ISSUER")?;
        let rp_origin = parse_url(values, "WEBAUTHN_RP_ORIGIN")?;
        let rp_id = values.required("WEBAUTHN_RP_ID")?;
        let rp_name = values.required("WEBAUTHN_RP_NAME")?;
        let sabledb_url = SecretString::from(values.required("SABLEDB_URL")?);
        let master_keys = decode_keyring(
            values,
            "AUTH_MASTER_KEY_HEX",
            "AUTH_MASTER_PREVIOUS_KEYS_HEX",
            "master",
        )?;
        let bootstrap_token = SecretString::from(values.required("BOOTSTRAP_TOKEN")?);
        let (event_rpc_token, identity_rpc_token) = match deployment_role {
            DeploymentRole::Realm => (
                SecretString::from(values.required("AUTH_EVENT_RPC_TOKEN")?),
                SecretString::from(values.required("AUTH_IDENTITY_RPC_TOKEN")?),
            ),
            DeploymentRole::FleetControlPlane => (
                disabled_rpc_token("events", &master_keys),
                disabled_rpc_token("identity", &master_keys),
            ),
        };
        let operator_emails = parse_operator_emails(values.optional("AUTH_OPERATOR_EMAILS"))?;
        let audience = match values.optional("SPACETIME_AUDIENCE") {
            Some(value) => value,
            None if deployment_role == DeploymentRole::FleetControlPlane => {
                "rustyauth-fleet-dashboard".to_owned()
            }
            None => bail!("required environment variable SPACETIME_AUDIENCE is missing"),
        };
        let tenant_id = values
            .optional("AUTH_TENANT_ID")
            .unwrap_or_else(|| "vtr".into());
        let realm_id = values
            .optional("AUTH_REALM_ID")
            .unwrap_or_else(|| tenant_id.clone());
        let access_token_seconds = integer(values, "AUTH_ACCESS_TOKEN_SECONDS", 300, 60, 900)?;
        let session_idle_seconds =
            integer(values, "AUTH_SESSION_IDLE_SECONDS", 1_800, 300, 86_400)?;
        let session_absolute_seconds = integer(
            values,
            "AUTH_SESSION_ABSOLUTE_SECONDS",
            604_800,
            3_600,
            2_592_000,
        )?;
        validate_session_lifetimes(
            session_idle_seconds,
            session_absolute_seconds,
            values.label("AUTH_SESSION_IDLE_SECONDS"),
            values.label("AUTH_SESSION_ABSOLUTE_SECONDS"),
        )?;
        let event_retention_seconds = integer(
            values,
            "AUTH_EVENT_RETENTION_SECONDS",
            90 * 86_400,
            86_400,
            3_650 * 86_400,
        )?;
        let rotation_seconds = integer(
            values,
            "AUTH_SIGNING_KEY_ROTATION_SECONDS",
            2_592_000,
            3_600,
            31_536_000,
        )?;
        let prepublish_seconds = integer(
            values,
            "AUTH_SIGNING_KEY_PREPUBLISH_SECONDS",
            600,
            300,
            86_400,
        )?;
        let minimum_overlap = access_token_seconds.saturating_add(300);
        let overlap_seconds = integer(
            values,
            "AUTH_SIGNING_KEY_OVERLAP_SECONDS",
            minimum_overlap,
            minimum_overlap,
            86_400,
        )?;
        let maintenance_seconds = integer(values, "AUTH_KEY_MAINTENANCE_SECONDS", 30, 5, 3_600)?;
        // Zero means X-Forwarded-For is ignored and the TCP peer identifies the
        // client. Trusting the header by default would let any client forge its own
        // rate-limit bucket — but leaving it at zero behind a proxy is just as
        // broken in the other direction: every client then shares the edge's
        // address, so one abuser exhausts the budget for everyone and no attacker
        // can be isolated. Production must state its topology rather than inherit
        // either failure silently.
        let trusted_proxy_hops =
            usize::try_from(integer(values, "AUTH_TRUSTED_PROXY_HOPS", 0, 0, 8)?).unwrap_or(0);
        if environment == Environment::Production
            && values.optional("AUTH_TRUSTED_PROXY_HOPS").is_none()
        {
            bail!(
                "spec.server.trustedProxyHops / AUTH_TRUSTED_PROXY_HOPS must be set explicitly in production: use the number of \
                 reverse proxies in front of this service (1 when the platform terminates TLS), or \
                 0 only when clients connect to this process directly"
            );
        }

        validate_origin(&environment, values.label("AUTH_ISSUER"), &issuer)?;
        validate_origin(&environment, values.label("WEBAUTHN_RP_ORIGIN"), &rp_origin)?;
        validate_rp(
            &rp_id,
            &rp_origin,
            values.label("WEBAUTHN_RP_ID"),
            values.label("WEBAUTHN_RP_ORIGIN"),
        )?;
        validate_sable_url(&environment, &sabledb_url, values.label("SABLEDB_URL"))?;
        validate_tenant_id(&tenant_id, values.label("AUTH_TENANT_ID"))?;
        validate_tenant_id(&realm_id, values.label("AUTH_REALM_ID"))?;
        if prepublish_seconds >= rotation_seconds {
            bail!(
                "{} must be shorter than {}",
                values.label("AUTH_SIGNING_KEY_PREPUBLISH_SECONDS"),
                values.label("AUTH_SIGNING_KEY_ROTATION_SECONDS")
            );
        }
        if environment == Environment::Production && bootstrap_token.expose_secret().len() < 32 {
            bail!("BOOTSTRAP_TOKEN must contain at least 32 characters in production");
        }
        if deployment_role == DeploymentRole::Realm {
            validate_rpc_tokens(&bootstrap_token, &event_rpc_token, &identity_rpc_token)?;
        }

        let backup = BackupConfig::from_values(values, &environment)?;
        let analytics = AnalyticsConfig::from_values(values, deployment_role)?;
        if deployment_role == DeploymentRole::FleetControlPlane && !values.webhooks.is_empty() {
            bail!("spec.webhooks is only valid for kind Realm");
        }

        Ok(Self {
            environment,
            deployment_role,
            bind,
            port,
            issuer,
            rp_id,
            rp_origin,
            rp_name,
            sabledb_url,
            master_keys,
            bootstrap_token,
            event_rpc_token,
            identity_rpc_token,
            operator_emails,
            audience,
            tenant_id,
            realm_id,
            access_token_seconds,
            session_idle_seconds,
            session_absolute_seconds,
            event_retention_seconds,
            signing_rotation: SigningRotationConfig {
                rotation_seconds,
                prepublish_seconds,
                overlap_seconds,
                maintenance_seconds,
            },
            trusted_proxy_hops,
            backup,
            analytics,
            webhooks: values.webhooks.clone(),
        })
    }
}

/// Fleet does not mount the realm event or identity services, so requiring two
/// operational bearer credentials for them adds secret-management work without
/// adding a boundary. The interceptor still needs non-empty digests; derive
/// distinct, non-credential sentinels from the public key identifier.
fn disabled_rpc_token(service: &str, master_keys: &KeyRing) -> SecretString {
    SecretString::from(format!(
        "disabled-for-fleet-{service}-{}",
        master_keys.active().0
    ))
}

fn parse_operator_emails(value: Option<String>) -> Result<Vec<String>> {
    let mut emails = Vec::new();
    let mut seen = HashSet::new();
    for value in value.unwrap_or_default().split(',') {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let email = IdentifierValue::canonical(IdentifierKind::Email, value)
            .context("AUTH_OPERATOR_EMAILS contains an invalid email")?
            .value;
        if !seen.insert(email.clone()) {
            bail!("AUTH_OPERATOR_EMAILS contains a duplicate email");
        }
        emails.push(email);
    }
    Ok(emails)
}

impl AnalyticsConfig {
    fn from_values(values: &ConfigValues, deployment_role: DeploymentRole) -> Result<Option<Self>> {
        let names = [
            "AUTH_ANALYTICS_ENDPOINT",
            "AUTH_ANALYTICS_USERNAME",
            "AUTH_ANALYTICS_PASSWORD",
        ];
        let present = names
            .iter()
            .filter(|name| values.optional(name).is_some())
            .count();
        if present == 0 {
            return Ok(None);
        }
        if present != names.len() {
            bail!(
                "AUTH_ANALYTICS_ENDPOINT, AUTH_ANALYTICS_USERNAME and AUTH_ANALYTICS_PASSWORD must be configured together"
            );
        }
        if deployment_role != DeploymentRole::FleetControlPlane {
            bail!("central analytics configuration is valid only for FleetControlPlane");
        }
        let endpoint = parse_url(values, "AUTH_ANALYTICS_ENDPOINT")?;
        if endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "" | "/")
            || !matches!(endpoint.scheme(), "http" | "https")
        {
            bail!("AUTH_ANALYTICS_ENDPOINT must be an HTTP(S) origin without credentials");
        }
        let database = values
            .optional("AUTH_ANALYTICS_DATABASE")
            .unwrap_or_else(|| "rustyauth".into());
        if database.is_empty()
            || database.len() > 64
            || !database
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            bail!("AUTH_ANALYTICS_DATABASE is invalid");
        }
        let username = values.required("AUTH_ANALYTICS_USERNAME")?;
        let password = values.required("AUTH_ANALYTICS_PASSWORD")?;
        if username.len() > 128 || password.len() < 16 || password.len() > 512 {
            bail!("analytics credentials are invalid");
        }
        Ok(Some(Self {
            endpoint,
            database,
            username: SecretString::from(username),
            password: SecretString::from(password),
        }))
    }
}

impl BackupConfig {
    fn from_values(values: &ConfigValues, environment: &Environment) -> Result<Option<Self>> {
        let names = [
            "AUTH_BACKUP_ENDPOINT",
            "AUTH_BACKUP_REGION",
            "AUTH_BACKUP_BUCKET",
            "AUTH_BACKUP_ACCESS_KEY_ID",
            "AUTH_BACKUP_SECRET_ACCESS_KEY",
            "AUTH_BACKUP_ENCRYPTION_KEY_HEX",
        ];
        let present = names
            .iter()
            .filter(|name| values.optional(name).is_some())
            .count();
        let optional_backup_names = [
            "AUTH_BACKUP_PREVIOUS_KEYS_HEX",
            "AUTH_BACKUP_INTERVAL_SECONDS",
            "AUTH_BACKUP_RPO_SECONDS",
            "AUTH_BACKUP_RETENTION_DAYS",
            "AUTH_BACKUP_ALERT_AFTER_FAILURES",
            "AUTH_BACKUP_SSE",
            "AUTH_BACKUP_SSE_KMS_KEY_ID",
            "AUTH_BACKUP_URL_STYLE",
        ];
        if present == 0 {
            if optional_backup_names
                .iter()
                .any(|name| values.optional(name).is_some())
            {
                bail!(
                    "backup options were provided without the complete required AUTH_BACKUP_* configuration"
                );
            }
            return Ok(None);
        }
        if present != names.len() {
            bail!("backup configuration is partial; provide all AUTH_BACKUP_* variables or none");
        }

        let url_style = values
            .optional("AUTH_BACKUP_URL_STYLE")
            .unwrap_or_else(|| "virtual".into());
        let force_path_style = match url_style.as_str() {
            "virtual" => false,
            "path" => true,
            _ => bail!("AUTH_BACKUP_URL_STYLE must be virtual or path"),
        };

        let endpoint = parse_url(values, "AUTH_BACKUP_ENDPOINT")?;
        // The only URL that was never scheme-checked. Snapshots carry every account
        // and the wrapped signing keys, and the SigV4 Authorization header carries
        // the access key id, so a cleartext endpoint exposes both on the wire — and
        // lets an on-path attacker answer a restore with an older genuine snapshot,
        // rolling identity state back past a revocation.
        validate_backup_endpoint(environment, &endpoint, values.label("AUTH_BACKUP_ENDPOINT"))?;

        let interval_seconds =
            integer(values, "AUTH_BACKUP_INTERVAL_SECONDS", 21_600, 300, 604_800)?;
        let rpo_seconds = integer(
            values,
            "AUTH_BACKUP_RPO_SECONDS",
            interval_seconds,
            interval_seconds,
            2_592_000,
        )?;
        let server_side_encryption = match values
            .optional("AUTH_BACKUP_SSE")
            .as_deref()
            .unwrap_or("aws:kms")
        {
            "provider" => BackupServerSideEncryption::Provider,
            "AES256" | "aes256" => BackupServerSideEncryption::Aes256,
            "aws:kms" => BackupServerSideEncryption::AwsKms,
            other => bail!("AUTH_BACKUP_SSE must be provider, AES256 or aws:kms, got {other}"),
        };
        let sse_kms_key_id = values.optional("AUTH_BACKUP_SSE_KMS_KEY_ID");
        if sse_kms_key_id.is_some() && server_side_encryption != BackupServerSideEncryption::AwsKms
        {
            bail!("AUTH_BACKUP_SSE_KMS_KEY_ID requires AUTH_BACKUP_SSE=aws:kms");
        }

        Ok(Some(Self {
            endpoint,
            region: values.required("AUTH_BACKUP_REGION")?,
            bucket: values.required("AUTH_BACKUP_BUCKET")?,
            access_key_id: SecretString::from(values.required("AUTH_BACKUP_ACCESS_KEY_ID")?),
            secret_access_key: SecretString::from(
                values.required("AUTH_BACKUP_SECRET_ACCESS_KEY")?,
            ),
            encryption_keys: decode_keyring(
                values,
                "AUTH_BACKUP_ENCRYPTION_KEY_HEX",
                "AUTH_BACKUP_PREVIOUS_KEYS_HEX",
                "backup",
            )?,
            force_path_style,
            interval_seconds,
            rpo_seconds,
            retention_days: integer(values, "AUTH_BACKUP_RETENTION_DAYS", 90, 1, 3_650)?,
            alert_after_failures: integer(values, "AUTH_BACKUP_ALERT_AFTER_FAILURES", 2, 1, 100)?,
            server_side_encryption,
            sse_kms_key_id,
        }))
    }
}

fn parse_url(values: &ConfigValues, name: &str) -> Result<Url> {
    Url::parse(&values.required(name)?)
        .with_context(|| format!("{} is not a valid URL", values.label(name)))
}

fn decode_key(values: &ConfigValues, name: &str) -> Result<[u8; 32]> {
    decode_key_value(values.label(name), &values.required(name)?)
}

fn decode_key_value(name: &str, value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("{name} must be hex"))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must contain exactly 32 bytes (64 hex characters)"))?;
    // The all-zero key is published in compose.yaml and .env.example; any key with
    // a single repeated byte is a placeholder rather than generated material.
    // Accepting one would wrap every signing key and backup under a public value.
    if key.iter().all(|byte| *byte == key[0]) {
        bail!("{name} is a placeholder with no entropy; generate one with `openssl rand -hex 32`");
    }
    Ok(key)
}

fn decode_keyring(
    values: &ConfigValues,
    active_name: &str,
    previous_name: &str,
    purpose: &str,
) -> Result<KeyRing> {
    let active = decode_key(values, active_name)?;
    let previous_label = values.label(previous_name).to_owned();
    let previous = values
        .optional(previous_name)
        .map(|raw_values| {
            raw_values
                .split(',')
                .enumerate()
                .map(|(index, value)| {
                    decode_key_value(
                        &format!("{} item {}", previous_label, index + 1),
                        value.trim(),
                    )
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    KeyRing::new(purpose, active, previous)
}

fn derived_key_id(purpose: &str, key: &[u8; 32]) -> String {
    let digest = Sha256::digest(key);
    format!("{purpose}-{}", hex::encode(&digest[..12]))
}

fn integer(
    values: &ConfigValues,
    name: &str,
    fallback: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64> {
    let value = values
        .optional(name)
        .map(|raw| raw.parse::<u64>())
        .transpose()
        .with_context(|| format!("{} must be an integer", values.label(name)))?
        .unwrap_or(fallback);
    if !(minimum..=maximum).contains(&value) {
        bail!(
            "{} must be between {minimum} and {maximum}",
            values.label(name)
        );
    }
    Ok(value)
}

fn validate_origin(environment: &Environment, name: &str, value: &Url) -> Result<()> {
    if value.path() != "/" || value.query().is_some() || value.fragment().is_some() {
        bail!("{name} must be an origin without a path, query or fragment");
    }
    if environment == &Environment::Production && value.scheme() != "https" {
        bail!("{name} must use HTTPS in production");
    }
    if !matches!(value.scheme(), "http" | "https") {
        bail!("{name} must use HTTP or HTTPS");
    }
    Ok(())
}

fn validate_rp(rp_id: &str, origin: &Url, rp_id_name: &str, origin_name: &str) -> Result<()> {
    let host = origin
        .host_str()
        .with_context(|| format!("{origin_name} has no host"))?;
    if rp_id != host {
        bail!(
            "{rp_id_name} must exactly match the host of {origin_name}; subdomain relaxation is disabled"
        );
    }
    Ok(())
}

/// Backups must not cross the network in the clear in production, and the scheme
/// must be one the S3 client can actually speak.
fn validate_backup_endpoint(environment: &Environment, value: &Url, name: &str) -> Result<()> {
    if !matches!(value.scheme(), "http" | "https") {
        bail!("{name} must use HTTP or HTTPS");
    }
    if environment == &Environment::Production && value.scheme() != "https" {
        bail!("{name} must use HTTPS in production");
    }
    Ok(())
}

fn validate_sable_url(environment: &Environment, value: &SecretString, name: &str) -> Result<()> {
    let url = Url::parse(value.expose_secret()).with_context(|| format!("{name} is invalid"))?;
    // `rediss` is accepted so a deployment can encrypt datastore traffic. Rejecting
    // it forced every operator onto plaintext, which no defence-in-depth posture
    // should require of the link carrying sessions and wrapped signing keys.
    if !matches!(url.scheme(), "redis" | "rediss") {
        bail!("{name} must use the redis or rediss scheme");
    }
    let host = url
        .host_str()
        .with_context(|| format!("{name} has no host"))?;
    if environment == &Environment::Production
        && url.scheme() == "redis"
        && !host.ends_with(".railway.internal")
    {
        bail!(
            "production SABLEDB_URL must use Railway private networking (*.railway.internal) or the rediss scheme"
        );
    }
    Ok(())
}

fn validate_tenant_id(value: &str, name: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        bail!("{name} must contain 1-64 ASCII letters, digits, hyphens or underscores");
    }
    Ok(())
}

fn validate_session_lifetimes(
    idle_seconds: u64,
    absolute_seconds: u64,
    idle_name: &str,
    absolute_name: &str,
) -> Result<()> {
    if absolute_seconds <= idle_seconds {
        bail!("{absolute_name} must be greater than {idle_name}");
    }
    Ok(())
}

fn validate_rpc_tokens(
    bootstrap: &SecretString,
    event: &SecretString,
    identity: &SecretString,
) -> Result<()> {
    if event.expose_secret().len() < 32 {
        bail!("AUTH_EVENT_RPC_TOKEN must contain at least 32 characters");
    }
    if identity.expose_secret().len() < 32 {
        bail!("AUTH_IDENTITY_RPC_TOKEN must contain at least 32 characters");
    }
    if event.expose_secret() == bootstrap.expose_secret() {
        bail!("AUTH_EVENT_RPC_TOKEN must not reuse BOOTSTRAP_TOKEN");
    }
    if identity.expose_secret() == bootstrap.expose_secret() {
        bail!("AUTH_IDENTITY_RPC_TOKEN must not reuse BOOTSTRAP_TOKEN");
    }
    if identity.expose_secret() == event.expose_secret() {
        bail!("AUTH_IDENTITY_RPC_TOKEN must not reuse AUTH_EVENT_RPC_TOKEN");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn rp_id_must_match_origin_exactly() {
        let origin = Url::parse("https://auth.example.com").unwrap();
        assert!(validate_rp("auth.example.com", &origin, "rp id", "origin").is_ok());
        assert!(validate_rp("example.com", &origin, "rp id", "origin").is_err());
    }

    #[test]
    fn backup_endpoints_must_be_https_in_production() {
        let plaintext = Url::parse("http://objects.internal:9000").unwrap();
        let secure = Url::parse("https://objects.example.com").unwrap();
        let other = Url::parse("ftp://objects.example.com").unwrap();

        // Snapshots carry every account and the wrapped signing keys, and the
        // SigV4 header carries the access key id, so cleartext exposes both.
        assert!(
            validate_backup_endpoint(&Environment::Production, &plaintext, "endpoint").is_err()
        );
        assert!(validate_backup_endpoint(&Environment::Production, &secure, "endpoint").is_ok());
        // A loopback MinIO is the documented development sink.
        assert!(
            validate_backup_endpoint(&Environment::Development, &plaintext, "endpoint").is_ok()
        );
        // A scheme the client cannot speak should fail at startup, not first upload.
        assert!(validate_backup_endpoint(&Environment::Development, &other, "endpoint").is_err());
    }

    #[test]
    fn production_requires_https() {
        let origin = Url::parse("http://auth.example.com").unwrap();
        assert!(validate_origin(&Environment::Production, "origin", &origin).is_err());
    }

    #[test]
    fn key_ids_are_stable_and_key_material_is_not_debugged() {
        let ring = KeyRing::new("backup", [7; 32], vec![[8; 32]]).unwrap();
        let active_id = ring.active().0.to_owned();
        assert_eq!(ring.get(&active_id), Some(&[7; 32]));
        let debug = format!("{ring:?}");
        assert!(debug.contains(&active_id));
        assert!(!debug.contains("07070707"));
    }

    #[test]
    fn keyrings_reject_duplicate_material() {
        assert!(KeyRing::new("master", [1; 32], vec![[1; 32]]).is_err());
    }

    #[test]
    fn tenant_ids_are_safe_for_object_prefixes() {
        assert!(validate_tenant_id("tenant_01-prod", "tenant").is_ok());
        assert!(validate_tenant_id("../another-tenant", "tenant").is_err());
        assert!(validate_tenant_id("", "tenant").is_err());
    }

    #[test]
    fn absolute_session_expiry_must_exceed_idle_expiry() {
        assert!(validate_session_lifetimes(1_800, 86_400, "idle", "absolute").is_ok());
        assert!(validate_session_lifetimes(1_800, 1_800, "idle", "absolute").is_err());
        assert!(validate_session_lifetimes(1_801, 1_800, "idle", "absolute").is_err());

        let invalid_yaml = REALM_CONFIGURATION_EXAMPLE
            .replace("idleTimeout: 30m", "idleTimeout: 2h")
            .replace("absoluteTimeout: 7d", "absoluteTimeout: 1h");
        let error = Config::validate_yaml(&invalid_yaml, "invalid session policy")
            .unwrap_err()
            .to_string();
        assert!(error.contains(
            "spec.sessions.absoluteTimeout must be greater than spec.sessions.idleTimeout"
        ));
    }

    #[test]
    fn rpc_tokens_are_long_and_separately_scoped() {
        let bootstrap = SecretString::from("bootstrap-token-longer-than-32-characters");
        let event = SecretString::from("event-token-longer-than-32-characters");
        let identity = SecretString::from("identity-token-longer-than-32-characters");
        assert!(validate_rpc_tokens(&bootstrap, &event, &identity).is_ok());
        assert!(validate_rpc_tokens(&bootstrap, &event, &event).is_err());
        assert!(validate_rpc_tokens(&bootstrap, &SecretString::from("short"), &identity).is_err());
    }

    #[test]
    fn checked_in_examples_pass_the_runtime_validation_rules() {
        let realm = Config::validate_yaml(REALM_CONFIGURATION_EXAMPLE, "realm example").unwrap();
        assert_eq!(realm.kind, "Realm");
        assert!(!realm.backups_enabled);

        let fleet = Config::validate_yaml(FLEET_CONFIGURATION_EXAMPLE, "fleet example").unwrap();
        assert_eq!(fleet.kind, "FleetControlPlane");
    }

    #[test]
    fn direct_and_file_values_are_mutually_exclusive() {
        let error = resolve_environment_value(
            "EXAMPLE_SECRET",
            Some(OsString::from("direct")),
            Some(OsString::from("/run/secrets/example")),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not both"));
    }

    #[test]
    fn docker_secret_files_ignore_their_trailing_newline() {
        let path = std::env::temp_dir().join(format!("rustyauth-secret-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"secret-from-file\n").unwrap();
        let value =
            resolve_environment_value("EXAMPLE_SECRET", None, Some(path.as_os_str().to_owned()))
                .unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(value.as_deref(), Some("secret-from-file"));
    }

    #[test]
    fn raw_configuration_values_never_debug_secret_material() {
        let mut values = ConfigValues::default();
        values.insert(
            "AUTH_MASTER_KEY_HEX",
            "do-not-print-this-value".to_owned(),
            "AUTH_MASTER_KEY_HEX".to_owned(),
        );
        let debug = format!("{values:?}");
        assert!(debug.contains("AUTH_MASTER_KEY_HEX"));
        assert!(!debug.contains("do-not-print-this-value"));
    }

    #[tokio::test]
    async fn plaintext_and_kms_enveloped_key_inputs_are_mutually_exclusive() {
        let mut values = ConfigValues::default();
        values.insert("AUTH_TENANT_ID", "tenant-a".to_owned(), "tenant".to_owned());
        values.insert(
            "AUTH_MASTER_KEY_HEX",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_owned(),
            "plaintext master key".to_owned(),
        );
        values.insert(
            "AUTH_MASTER_KEY_KMS_CIPHERTEXT_B64",
            STANDARD.encode([1_u8; 64]),
            "KMS master key".to_owned(),
        );
        let error = values
            .with_kms_envelope_keys()
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("not both"));
        assert!(!error.contains(&STANDARD.encode([1_u8; 64])));
    }

    #[test]
    fn kms_key_material_has_bounded_strict_encodings_and_is_zeroizable() {
        assert!(decode_kms_ciphertext("not base64!", "ciphertext", 1).is_err());
        assert!(decode_kms_ciphertext("", "ciphertext", 1).is_err());
        assert!(encode_kms_plaintext(vec![9_u8; 31], "ciphertext", 1).is_err());
        assert_eq!(
            encode_kms_plaintext((0_u8..32).collect(), "ciphertext", 1).unwrap(),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
    }
}
