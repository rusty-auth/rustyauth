//! Fail-closed environment configuration and deployment-policy validation.

use std::{collections::HashSet, env, fmt, net::IpAddr, path::PathBuf, str::FromStr, sync::Arc};

use anyhow::{Context, Result, bail};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroize;

use crate::store::{IdentifierKind, IdentifierValue};

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
    pub dashboard_dir: PathBuf,
    pub audience: String,
    pub tenant_id: String,
    pub access_token_seconds: u64,
    pub session_idle_seconds: u64,
    pub session_absolute_seconds: u64,
    pub signing_rotation: SigningRotationConfig,
    pub trusted_proxy_hops: usize,
    pub backup: Option<BackupConfig>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        // AUTH_ENV gates every other fail-closed check, so it must itself fail
        // closed. Defaulting an unset value to development silently drops Secure
        // cookies, HTTPS validation, and identity-verification enforcement.
        let environment = match optional("AUTH_ENV").as_deref() {
            Some("development") => Environment::Development,
            Some("production") => Environment::Production,
            Some(other) => bail!("AUTH_ENV must be development or production, got {other}"),
            None => bail!("AUTH_ENV must be set explicitly to development or production"),
        };
        let deployment_role = match optional("AUTH_DEPLOYMENT_ROLE").as_deref() {
            None | Some("realm") => DeploymentRole::Realm,
            Some("fleet-control-plane") => DeploymentRole::FleetControlPlane,
            Some(other) => {
                bail!("AUTH_DEPLOYMENT_ROLE must be realm or fleet-control-plane, got {other}")
            }
        };

        let bind = IpAddr::from_str(optional("BIND_ADDRESS").as_deref().unwrap_or("0.0.0.0"))
            .context("BIND_ADDRESS is invalid")?;
        let port = optional("PORT")
            .as_deref()
            .unwrap_or("8080")
            .parse()
            .context("PORT is invalid")?;
        let issuer = parse_url("AUTH_ISSUER")?;
        let rp_origin = parse_url("WEBAUTHN_RP_ORIGIN")?;
        let rp_id = required("WEBAUTHN_RP_ID")?;
        let rp_name = required("WEBAUTHN_RP_NAME")?;
        let sabledb_url = SecretString::from(required("SABLEDB_URL")?);
        let master_keys = decode_keyring(
            "AUTH_MASTER_KEY_HEX",
            "AUTH_MASTER_PREVIOUS_KEYS_HEX",
            "master",
        )?;
        let bootstrap_token = SecretString::from(required("BOOTSTRAP_TOKEN")?);
        let event_rpc_token = SecretString::from(required("AUTH_EVENT_RPC_TOKEN")?);
        let identity_rpc_token = SecretString::from(required("AUTH_IDENTITY_RPC_TOKEN")?);
        let operator_emails = parse_operator_emails(optional("AUTH_OPERATOR_EMAILS"))?;
        let dashboard_dir = PathBuf::from(
            optional("AUTH_DASHBOARD_DIR")
                .unwrap_or_else(|| "/usr/share/rustyauth/dashboard".to_owned()),
        );
        let audience = required("SPACETIME_AUDIENCE")?;
        let tenant_id = optional("AUTH_TENANT_ID").unwrap_or_else(|| "vtr".into());
        let access_token_seconds = integer("AUTH_ACCESS_TOKEN_SECONDS", 300, 60, 900)?;
        let session_idle_seconds = integer("AUTH_SESSION_IDLE_SECONDS", 1_800, 300, 86_400)?;
        let session_absolute_seconds =
            integer("AUTH_SESSION_ABSOLUTE_SECONDS", 604_800, 3_600, 2_592_000)?;
        let rotation_seconds = integer(
            "AUTH_SIGNING_KEY_ROTATION_SECONDS",
            2_592_000,
            3_600,
            31_536_000,
        )?;
        let prepublish_seconds = integer("AUTH_SIGNING_KEY_PREPUBLISH_SECONDS", 600, 300, 86_400)?;
        let minimum_overlap = access_token_seconds.saturating_add(300);
        let overlap_seconds = integer(
            "AUTH_SIGNING_KEY_OVERLAP_SECONDS",
            minimum_overlap,
            minimum_overlap,
            86_400,
        )?;
        let maintenance_seconds = integer("AUTH_KEY_MAINTENANCE_SECONDS", 30, 5, 3_600)?;
        // Zero means X-Forwarded-For is ignored and the TCP peer identifies the
        // client. Trusting the header by default would let any client forge its own
        // rate-limit bucket — but leaving it at zero behind a proxy is just as
        // broken in the other direction: every client then shares the edge's
        // address, so one abuser exhausts the budget for everyone and no attacker
        // can be isolated. Production must state its topology rather than inherit
        // either failure silently.
        let trusted_proxy_hops =
            usize::try_from(integer("AUTH_TRUSTED_PROXY_HOPS", 0, 0, 8)?).unwrap_or(0);
        if environment == Environment::Production && optional("AUTH_TRUSTED_PROXY_HOPS").is_none() {
            bail!(
                "AUTH_TRUSTED_PROXY_HOPS must be set explicitly in production: use the number of \
                 reverse proxies in front of this service (1 when the platform terminates TLS), or \
                 0 only when clients connect to this process directly"
            );
        }

        validate_origin(&environment, "AUTH_ISSUER", &issuer)?;
        validate_origin(&environment, "WEBAUTHN_RP_ORIGIN", &rp_origin)?;
        validate_rp(&rp_id, &rp_origin)?;
        validate_sable_url(&environment, &sabledb_url)?;
        validate_tenant_id(&tenant_id)?;
        if prepublish_seconds >= rotation_seconds {
            bail!("AUTH_SIGNING_KEY_PREPUBLISH_SECONDS must be shorter than the rotation period");
        }
        if environment == Environment::Production && bootstrap_token.expose_secret().len() < 32 {
            bail!("BOOTSTRAP_TOKEN must contain at least 32 characters in production");
        }
        validate_rpc_tokens(&bootstrap_token, &event_rpc_token, &identity_rpc_token)?;

        let backup = BackupConfig::from_env(&environment)?;

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
            dashboard_dir,
            audience,
            tenant_id,
            access_token_seconds,
            session_idle_seconds,
            session_absolute_seconds,
            signing_rotation: SigningRotationConfig {
                rotation_seconds,
                prepublish_seconds,
                overlap_seconds,
                maintenance_seconds,
            },
            trusted_proxy_hops,
            backup,
        })
    }
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

impl BackupConfig {
    fn from_env(environment: &Environment) -> Result<Option<Self>> {
        let names = [
            "AUTH_BACKUP_ENDPOINT",
            "AUTH_BACKUP_REGION",
            "AUTH_BACKUP_BUCKET",
            "AUTH_BACKUP_ACCESS_KEY_ID",
            "AUTH_BACKUP_SECRET_ACCESS_KEY",
            "AUTH_BACKUP_ENCRYPTION_KEY_HEX",
        ];
        let present = names.iter().filter(|name| optional(name).is_some()).count();
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
                .any(|name| optional(name).is_some())
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

        let url_style = optional("AUTH_BACKUP_URL_STYLE").unwrap_or_else(|| "virtual".into());
        let force_path_style = match url_style.as_str() {
            "virtual" => false,
            "path" => true,
            _ => bail!("AUTH_BACKUP_URL_STYLE must be virtual or path"),
        };

        let endpoint = parse_url("AUTH_BACKUP_ENDPOINT")?;
        // The only URL that was never scheme-checked. Snapshots carry every account
        // and the wrapped signing keys, and the SigV4 Authorization header carries
        // the access key id, so a cleartext endpoint exposes both on the wire — and
        // lets an on-path attacker answer a restore with an older genuine snapshot,
        // rolling identity state back past a revocation.
        validate_backup_endpoint(environment, &endpoint)?;

        let interval_seconds = integer("AUTH_BACKUP_INTERVAL_SECONDS", 21_600, 300, 604_800)?;
        let rpo_seconds = integer(
            "AUTH_BACKUP_RPO_SECONDS",
            interval_seconds,
            interval_seconds,
            2_592_000,
        )?;
        let server_side_encryption =
            match optional("AUTH_BACKUP_SSE").as_deref().unwrap_or("aws:kms") {
                "provider" => BackupServerSideEncryption::Provider,
                "AES256" | "aes256" => BackupServerSideEncryption::Aes256,
                "aws:kms" => BackupServerSideEncryption::AwsKms,
                other => bail!("AUTH_BACKUP_SSE must be provider, AES256 or aws:kms, got {other}"),
            };
        let sse_kms_key_id = optional("AUTH_BACKUP_SSE_KMS_KEY_ID");
        if sse_kms_key_id.is_some() && server_side_encryption != BackupServerSideEncryption::AwsKms
        {
            bail!("AUTH_BACKUP_SSE_KMS_KEY_ID requires AUTH_BACKUP_SSE=aws:kms");
        }

        Ok(Some(Self {
            endpoint,
            region: required("AUTH_BACKUP_REGION")?,
            bucket: required("AUTH_BACKUP_BUCKET")?,
            access_key_id: SecretString::from(required("AUTH_BACKUP_ACCESS_KEY_ID")?),
            secret_access_key: SecretString::from(required("AUTH_BACKUP_SECRET_ACCESS_KEY")?),
            encryption_keys: decode_keyring(
                "AUTH_BACKUP_ENCRYPTION_KEY_HEX",
                "AUTH_BACKUP_PREVIOUS_KEYS_HEX",
                "backup",
            )?,
            force_path_style,
            interval_seconds,
            rpo_seconds,
            retention_days: integer("AUTH_BACKUP_RETENTION_DAYS", 90, 1, 3_650)?,
            alert_after_failures: integer("AUTH_BACKUP_ALERT_AFTER_FAILURES", 2, 1, 100)?,
            server_side_encryption,
            sse_kms_key_id,
        }))
    }
}

fn required(name: &str) -> Result<String> {
    optional(name).with_context(|| format!("required environment variable {name} is missing"))
}

fn optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn parse_url(name: &str) -> Result<Url> {
    Url::parse(&required(name)?).with_context(|| format!("{name} is not a valid URL"))
}

fn decode_key(name: &str) -> Result<[u8; 32]> {
    decode_key_value(name, &required(name)?)
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

fn decode_keyring(active_name: &str, previous_name: &str, purpose: &str) -> Result<KeyRing> {
    let active = decode_key(active_name)?;
    let previous = optional(previous_name)
        .map(|values| {
            values
                .split(',')
                .enumerate()
                .map(|(index, value)| {
                    decode_key_value(&format!("{previous_name} item {}", index + 1), value.trim())
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

fn integer(name: &str, fallback: u64, minimum: u64, maximum: u64) -> Result<u64> {
    let value = optional(name)
        .map(|raw| raw.parse::<u64>())
        .transpose()
        .with_context(|| format!("{name} must be an integer"))?
        .unwrap_or(fallback);
    if !(minimum..=maximum).contains(&value) {
        bail!("{name} must be between {minimum} and {maximum}");
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

fn validate_rp(rp_id: &str, origin: &Url) -> Result<()> {
    let host = origin
        .host_str()
        .context("WEBAUTHN_RP_ORIGIN has no host")?;
    if rp_id != host {
        bail!(
            "WEBAUTHN_RP_ID must exactly match WEBAUTHN_RP_ORIGIN host; subdomain relaxation is disabled"
        );
    }
    Ok(())
}

/// Backups must not cross the network in the clear in production, and the scheme
/// must be one the S3 client can actually speak.
fn validate_backup_endpoint(environment: &Environment, value: &Url) -> Result<()> {
    if !matches!(value.scheme(), "http" | "https") {
        bail!("AUTH_BACKUP_ENDPOINT must use HTTP or HTTPS");
    }
    if environment == &Environment::Production && value.scheme() != "https" {
        bail!("AUTH_BACKUP_ENDPOINT must use HTTPS in production");
    }
    Ok(())
}

fn validate_sable_url(environment: &Environment, value: &SecretString) -> Result<()> {
    let url = Url::parse(value.expose_secret()).context("SABLEDB_URL is invalid")?;
    // `rediss` is accepted so a deployment can encrypt datastore traffic. Rejecting
    // it forced every operator onto plaintext, which no defence-in-depth posture
    // should require of the link carrying sessions and wrapped signing keys.
    if !matches!(url.scheme(), "redis" | "rediss") {
        bail!("SABLEDB_URL must use the redis or rediss scheme");
    }
    let host = url.host_str().context("SABLEDB_URL has no host")?;
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

fn validate_tenant_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        bail!("AUTH_TENANT_ID must contain 1-64 ASCII letters, digits, hyphens or underscores");
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

    #[test]
    fn rp_id_must_match_origin_exactly() {
        let origin = Url::parse("https://auth.example.com").unwrap();
        assert!(validate_rp("auth.example.com", &origin).is_ok());
        assert!(validate_rp("example.com", &origin).is_err());
    }

    #[test]
    fn backup_endpoints_must_be_https_in_production() {
        let plaintext = Url::parse("http://objects.internal:9000").unwrap();
        let secure = Url::parse("https://objects.example.com").unwrap();
        let other = Url::parse("ftp://objects.example.com").unwrap();

        // Snapshots carry every account and the wrapped signing keys, and the
        // SigV4 header carries the access key id, so cleartext exposes both.
        assert!(validate_backup_endpoint(&Environment::Production, &plaintext).is_err());
        assert!(validate_backup_endpoint(&Environment::Production, &secure).is_ok());
        // A loopback MinIO is the documented development sink.
        assert!(validate_backup_endpoint(&Environment::Development, &plaintext).is_ok());
        // A scheme the client cannot speak should fail at startup, not first upload.
        assert!(validate_backup_endpoint(&Environment::Development, &other).is_err());
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
        assert!(validate_tenant_id("tenant_01-prod").is_ok());
        assert!(validate_tenant_id("../another-tenant").is_err());
        assert!(validate_tenant_id("").is_err());
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
}
