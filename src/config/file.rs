//! Versioned, non-secret YAML configuration contract.

use std::{collections::HashSet, fs, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer};

use super::{ConfigValues, WebhookConfig};

pub(super) const API_VERSION: &str = "rustyauth.dev/v1alpha1";
const MAX_CONFIGURATION_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationDocument {
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: Spec,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Metadata {
    tenant_id: String,
    #[serde(default)]
    realm_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Spec {
    environment: String,
    server: Server,
    datastore: Datastore,
    relying_party: RelyingParty,
    tokens: Tokens,
    #[serde(default)]
    sessions: Sessions,
    #[serde(default)]
    events: Events,
    #[serde(default)]
    signing_keys: SigningKeys,
    #[serde(default)]
    operators: Operators,
    #[serde(default)]
    backups: Option<Backups>,
    #[serde(default)]
    analytics: Option<Analytics>,
    #[serde(default)]
    webhooks: Vec<Webhook>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Webhook {
    id: String,
    name: String,
    endpoint: String,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    event_types: Vec<String>,
}

const fn enabled_by_default() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Server {
    #[serde(default)]
    bind: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    public_issuer: String,
    #[serde(default)]
    trusted_proxy_hops: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Datastore {
    endpoint: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RelyingParty {
    id: String,
    origin: String,
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Tokens {
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    access_ttl: Option<HumanDuration>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Sessions {
    #[serde(default)]
    idle_timeout: Option<HumanDuration>,
    #[serde(default)]
    absolute_timeout: Option<HumanDuration>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Events {
    #[serde(default)]
    retention: Option<HumanDuration>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SigningKeys {
    #[serde(default)]
    rotate_every: Option<HumanDuration>,
    #[serde(default)]
    prepublish_for: Option<HumanDuration>,
    #[serde(default)]
    overlap_for: Option<HumanDuration>,
    #[serde(default)]
    maintenance_interval: Option<HumanDuration>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Operators {
    #[serde(default)]
    bootstrap_emails: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Backups {
    enabled: bool,
    #[serde(default)]
    destination: Option<BackupDestination>,
    #[serde(default)]
    schedule: Option<BackupSchedule>,
    #[serde(default)]
    retention: Option<HumanDuration>,
    #[serde(default)]
    alert_after_failures: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Analytics {
    enabled: bool,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    database: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackupDestination {
    endpoint: String,
    region: String,
    bucket: String,
    #[serde(default)]
    url_style: Option<String>,
    #[serde(default)]
    storage_profile: Option<String>,
    #[serde(default)]
    server_side_encryption: Option<ServerSideEncryption>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServerSideEncryption {
    mode: String,
    #[serde(default)]
    kms_key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackupSchedule {
    #[serde(default)]
    interval: Option<HumanDuration>,
    #[serde(default)]
    recovery_point_objective: Option<HumanDuration>,
}

#[derive(Clone, Copy, Debug)]
struct HumanDuration(u64);

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let duration = humantime::parse_duration(&value).map_err(serde::de::Error::custom)?;
        let seconds = duration.as_secs();
        if duration != Duration::from_secs(seconds) {
            return Err(serde::de::Error::custom(
                "duration must resolve to a whole number of seconds",
            ));
        }
        Ok(Self(seconds))
    }
}

pub(super) fn values_from_path(path: &Path) -> Result<ConfigValues> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("inspect configuration file {}", path.display()))?;
    if metadata.len() > MAX_CONFIGURATION_BYTES {
        bail!(
            "configuration file {} exceeds the {MAX_CONFIGURATION_BYTES}-byte limit",
            path.display()
        );
    }
    let yaml = fs::read_to_string(path)
        .with_context(|| format!("read configuration file {}", path.display()))?;
    values_from_yaml(&yaml, &path.display().to_string())
}

pub(super) fn values_from_yaml(yaml: &str, source_name: &str) -> Result<ConfigValues> {
    if yaml.len() as u64 > MAX_CONFIGURATION_BYTES {
        bail!("{source_name} exceeds the {MAX_CONFIGURATION_BYTES}-byte configuration limit");
    }
    let document: ConfigurationDocument = serde_yaml_ng::from_str(yaml)
        .with_context(|| format!("parse YAML configuration from {source_name}"))?;
    document.into_values(source_name)
}

impl ConfigurationDocument {
    fn into_values(self, source_name: &str) -> Result<ConfigValues> {
        if self.api_version != API_VERSION {
            bail!(
                "{source_name}: apiVersion must be {API_VERSION}, got {}",
                self.api_version
            );
        }
        let deployment_role = match self.kind.as_str() {
            "Realm" => "realm",
            "FleetControlPlane" => "fleet-control-plane",
            other => bail!("{source_name}: kind must be Realm or FleetControlPlane, got {other}"),
        };
        if self.kind == "Realm" && self.metadata.realm_id.is_none() {
            bail!("{source_name}: metadata.realmId is required for kind Realm");
        }
        if self.kind == "FleetControlPlane" && self.metadata.realm_id.is_some() {
            bail!("{source_name}: metadata.realmId is not valid for kind FleetControlPlane");
        }
        if self.kind == "Realm" && self.spec.tokens.audience.is_none() {
            bail!("{source_name}: spec.tokens.audience is required for kind Realm");
        }
        if self.kind == "FleetControlPlane" && !self.spec.webhooks.is_empty() {
            bail!("{source_name}: spec.webhooks is only valid for kind Realm");
        }
        if self.kind == "Realm" && self.spec.analytics.is_some() {
            bail!("{source_name}: spec.analytics is only valid for kind FleetControlPlane");
        }

        let mut values = ConfigValues {
            webhooks: validated_webhooks(self.spec.webhooks, source_name)?,
            ..ConfigValues::default()
        };
        insert(
            &mut values,
            "AUTH_ENV",
            self.spec.environment,
            "spec.environment",
        );
        insert(&mut values, "AUTH_DEPLOYMENT_ROLE", deployment_role, "kind");
        insert(
            &mut values,
            "AUTH_TENANT_ID",
            self.metadata.tenant_id,
            "metadata.tenantId",
        );
        if let Some(realm_id) = self.metadata.realm_id {
            insert(&mut values, "AUTH_REALM_ID", realm_id, "metadata.realmId");
        }
        insert(
            &mut values,
            "AUTH_ISSUER",
            self.spec.server.public_issuer,
            "spec.server.publicIssuer",
        );
        if let Some(bind) = self.spec.server.bind {
            insert(&mut values, "BIND_ADDRESS", bind, "spec.server.bind");
        }
        if let Some(port) = self.spec.server.port {
            insert(&mut values, "PORT", port.to_string(), "spec.server.port");
        }
        if let Some(hops) = self.spec.server.trusted_proxy_hops {
            insert(
                &mut values,
                "AUTH_TRUSTED_PROXY_HOPS",
                hops.to_string(),
                "spec.server.trustedProxyHops",
            );
        }
        insert(
            &mut values,
            "SABLEDB_URL",
            self.spec.datastore.endpoint,
            "spec.datastore.endpoint",
        );
        insert(
            &mut values,
            "WEBAUTHN_RP_ID",
            self.spec.relying_party.id,
            "spec.relyingParty.id",
        );
        insert(
            &mut values,
            "WEBAUTHN_RP_ORIGIN",
            self.spec.relying_party.origin,
            "spec.relyingParty.origin",
        );
        insert(
            &mut values,
            "WEBAUTHN_RP_NAME",
            self.spec.relying_party.name,
            "spec.relyingParty.name",
        );
        if let Some(audience) = self.spec.tokens.audience {
            insert(
                &mut values,
                "SPACETIME_AUDIENCE",
                audience,
                "spec.tokens.audience",
            );
        }
        insert_duration(
            &mut values,
            "AUTH_ACCESS_TOKEN_SECONDS",
            self.spec.tokens.access_ttl,
            "spec.tokens.accessTtl",
        );
        insert_duration(
            &mut values,
            "AUTH_SESSION_IDLE_SECONDS",
            self.spec.sessions.idle_timeout,
            "spec.sessions.idleTimeout",
        );
        insert_duration(
            &mut values,
            "AUTH_SESSION_ABSOLUTE_SECONDS",
            self.spec.sessions.absolute_timeout,
            "spec.sessions.absoluteTimeout",
        );
        insert_duration(
            &mut values,
            "AUTH_EVENT_RETENTION_SECONDS",
            self.spec.events.retention,
            "spec.events.retention",
        );
        insert_duration(
            &mut values,
            "AUTH_SIGNING_KEY_ROTATION_SECONDS",
            self.spec.signing_keys.rotate_every,
            "spec.signingKeys.rotateEvery",
        );
        insert_duration(
            &mut values,
            "AUTH_SIGNING_KEY_PREPUBLISH_SECONDS",
            self.spec.signing_keys.prepublish_for,
            "spec.signingKeys.prepublishFor",
        );
        insert_duration(
            &mut values,
            "AUTH_SIGNING_KEY_OVERLAP_SECONDS",
            self.spec.signing_keys.overlap_for,
            "spec.signingKeys.overlapFor",
        );
        insert_duration(
            &mut values,
            "AUTH_KEY_MAINTENANCE_SECONDS",
            self.spec.signing_keys.maintenance_interval,
            "spec.signingKeys.maintenanceInterval",
        );
        if !self.spec.operators.bootstrap_emails.is_empty() {
            insert(
                &mut values,
                "AUTH_OPERATOR_EMAILS",
                self.spec.operators.bootstrap_emails.join(","),
                "spec.operators.bootstrapEmails",
            );
        }

        if let Some(backups) = self.spec.backups {
            backups.insert_values(&mut values, source_name)?;
        }
        if let Some(analytics) = self.spec.analytics {
            analytics.insert_values(&mut values, source_name)?;
        }
        Ok(values)
    }
}

impl Analytics {
    fn insert_values(self, values: &mut ConfigValues, source_name: &str) -> Result<()> {
        if !self.enabled {
            if self.endpoint.is_some() || self.database.is_some() {
                bail!("{source_name}: disabled analytics cannot contain endpoint or database");
            }
            return Ok(());
        }
        insert(
            values,
            "AUTH_ANALYTICS_ENDPOINT",
            self.endpoint
                .with_context(|| format!("{source_name}: analytics.endpoint is required"))?,
            "spec.analytics.endpoint",
        );
        if let Some(database) = self.database {
            insert(
                values,
                "AUTH_ANALYTICS_DATABASE",
                database,
                "spec.analytics.database",
            );
        }
        Ok(())
    }
}

fn validated_webhooks(webhooks: Vec<Webhook>, source_name: &str) -> Result<Vec<WebhookConfig>> {
    const MAX_WEBHOOKS: usize = 50;
    const MAX_EVENTS: usize = 50;
    if webhooks.len() > MAX_WEBHOOKS {
        bail!("{source_name}: spec.webhooks may contain at most {MAX_WEBHOOKS} destinations");
    }

    let mut ids = HashSet::with_capacity(webhooks.len());
    let mut validated = Vec::with_capacity(webhooks.len());
    for (index, webhook) in webhooks.into_iter().enumerate() {
        let path = format!("spec.webhooks[{index}]");
        if webhook.id.is_empty()
            || webhook.id.len() > 64
            || !webhook
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!(
                "{source_name}: {path}.id must contain 1-64 ASCII letters, digits, hyphens or underscores"
            );
        }
        if !ids.insert(webhook.id.clone()) {
            bail!(
                "{source_name}: {path}.id duplicates webhook id {}",
                webhook.id
            );
        }

        let name = webhook.name.trim().to_owned();
        if name.is_empty() || name.len() > 100 || name.chars().any(char::is_control) {
            bail!("{source_name}: {path}.name must contain 1-100 printable characters");
        }

        let endpoint = url::Url::parse(webhook.endpoint.trim())
            .with_context(|| format!("{source_name}: {path}.endpoint is not a valid URL"))?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
        {
            bail!(
                "{source_name}: {path}.endpoint must be an HTTPS URL without credentials or a fragment"
            );
        }

        if webhook.event_types.is_empty() || webhook.event_types.len() > MAX_EVENTS {
            bail!("{source_name}: {path}.eventTypes must contain 1-{MAX_EVENTS} values");
        }
        let mut events = HashSet::with_capacity(webhook.event_types.len());
        for event_type in &webhook.event_types {
            if !valid_event_type(event_type) {
                bail!("{source_name}: {path}.eventTypes contains an invalid event type");
            }
            if !events.insert(event_type.as_str()) {
                bail!("{source_name}: {path}.eventTypes contains duplicate {event_type}");
            }
        }

        validated.push(WebhookConfig {
            id: webhook.id,
            name,
            endpoint,
            enabled: webhook.enabled,
            event_types: webhook.event_types,
        });
    }
    Ok(validated)
}

fn valid_event_type(value: &str) -> bool {
    let bytes = value.as_bytes();
    let boundary = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    !bytes.is_empty()
        && bytes.len() <= 128
        && boundary(bytes[0])
        && boundary(bytes[bytes.len() - 1])
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

impl Backups {
    fn insert_values(self, values: &mut ConfigValues, source_name: &str) -> Result<()> {
        if !self.enabled {
            if self.destination.is_some()
                || self.schedule.is_some()
                || self.retention.is_some()
                || self.alert_after_failures.is_some()
            {
                bail!(
                    "{source_name}: spec.backups is disabled, so no destination, schedule, retention or alert settings may be supplied"
                );
            }
            return Ok(());
        }
        let destination = self.destination.with_context(|| {
            format!("{source_name}: spec.backups.destination is required when backups are enabled")
        })?;
        insert(
            values,
            "AUTH_BACKUP_ENDPOINT",
            destination.endpoint,
            "spec.backups.destination.endpoint",
        );
        insert(
            values,
            "AUTH_BACKUP_REGION",
            destination.region,
            "spec.backups.destination.region",
        );
        insert(
            values,
            "AUTH_BACKUP_BUCKET",
            destination.bucket,
            "spec.backups.destination.bucket",
        );
        if let Some(style) = destination.url_style {
            insert(
                values,
                "AUTH_BACKUP_URL_STYLE",
                style,
                "spec.backups.destination.urlStyle",
            );
        }
        if let Some(profile) = destination.storage_profile {
            if !matches!(profile.as_str(), "immutable" | "portable") {
                bail!(
                    "{source_name}: spec.backups.destination.storageProfile must be immutable or portable, got {profile}"
                );
            }
            insert(
                values,
                "AUTH_BACKUP_STORAGE_PROFILE",
                profile,
                "spec.backups.destination.storageProfile",
            );
        }
        if let Some(encryption) = destination.server_side_encryption {
            let mode = match encryption.mode.as_str() {
                "provider" => "provider",
                "aes256" => "AES256",
                "aws-kms" => "aws:kms",
                other => bail!(
                    "{source_name}: spec.backups.destination.serverSideEncryption.mode must be provider, aes256 or aws-kms, got {other}"
                ),
            };
            insert(
                values,
                "AUTH_BACKUP_SSE",
                mode,
                "spec.backups.destination.serverSideEncryption.mode",
            );
            if let Some(key_id) = encryption.kms_key_id {
                insert(
                    values,
                    "AUTH_BACKUP_SSE_KMS_KEY_ID",
                    key_id,
                    "spec.backups.destination.serverSideEncryption.kmsKeyId",
                );
            }
        }
        if let Some(schedule) = self.schedule {
            insert_duration(
                values,
                "AUTH_BACKUP_INTERVAL_SECONDS",
                schedule.interval,
                "spec.backups.schedule.interval",
            );
            insert_duration(
                values,
                "AUTH_BACKUP_RPO_SECONDS",
                schedule.recovery_point_objective,
                "spec.backups.schedule.recoveryPointObjective",
            );
        }
        if let Some(retention) = self.retention {
            const DAY_SECONDS: u64 = 86_400;
            if retention.0 % DAY_SECONDS != 0 {
                bail!("{source_name}: spec.backups.retention must be a whole number of days");
            }
            insert(
                values,
                "AUTH_BACKUP_RETENTION_DAYS",
                (retention.0 / DAY_SECONDS).to_string(),
                "spec.backups.retention",
            );
        }
        if let Some(failures) = self.alert_after_failures {
            insert(
                values,
                "AUTH_BACKUP_ALERT_AFTER_FAILURES",
                failures.to_string(),
                "spec.backups.alertAfterFailures",
            );
        }
        Ok(())
    }
}

fn insert(values: &mut ConfigValues, name: &str, value: impl Into<String>, yaml_path: &str) {
    values.insert(name, value.into(), yaml_path.to_owned());
}

fn insert_duration(
    values: &mut ConfigValues,
    name: &str,
    duration: Option<HumanDuration>,
    yaml_path: &str,
) {
    if let Some(duration) = duration {
        insert(values, name, duration.0.to_string(), yaml_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_REALM: &str = r#"
apiVersion: rustyauth.dev/v1alpha1
kind: Realm
metadata:
  tenantId: example
  realmId: example-development
spec:
  environment: development
  server:
    publicIssuer: http://localhost:8081
    trustedProxyHops: 0
  datastore:
    endpoint: redis://sabledb:6379
  relyingParty:
    id: localhost
    origin: http://localhost:8081
    name: Example Local
  tokens:
    audience: example-api
    accessTtl: 5m
  sessions:
    idleTimeout: 30m
    absoluteTimeout: 7d
  signingKeys:
    rotateEvery: 30d
    prepublishFor: 10m
    overlapFor: 10m
    maintenanceInterval: 30s
"#;

    #[test]
    fn valid_realm_maps_human_durations_to_runtime_seconds() {
        let values = values_from_yaml(VALID_REALM, "test configuration").unwrap();
        assert_eq!(
            values.optional("AUTH_SESSION_ABSOLUTE_SECONDS").as_deref(),
            Some("604800")
        );
        assert_eq!(values.label("AUTH_ISSUER"), "spec.server.publicIssuer");
    }

    #[test]
    fn unknown_fields_are_rejected_with_location() {
        let invalid = VALID_REALM.replace("accessTtl: 5m", "accessTTL: 5m");
        let error = format!(
            "{:#}",
            values_from_yaml(&invalid, "test configuration").unwrap_err()
        );
        assert!(error.contains("parse YAML configuration"));
        assert!(error.contains("unknown field `accessTTL`"));
    }

    #[test]
    fn disabled_backups_cannot_hide_stale_settings() {
        let invalid =
            format!("{VALID_REALM}\n  backups:\n    enabled: false\n    retention: 90d\n");
        let error = values_from_yaml(&invalid, "test configuration")
            .unwrap_err()
            .to_string();
        assert!(error.contains("spec.backups is disabled"));
    }

    #[test]
    fn portable_backup_storage_profile_maps_to_runtime_policy() {
        let yaml = format!(
            "{VALID_REALM}\n  backups:\n    enabled: true\n    destination:\n      endpoint: http://localhost:9000\n      region: local\n      bucket: backups\n      urlStyle: path\n      storageProfile: portable\n      serverSideEncryption:\n        mode: provider\n"
        );
        let values = values_from_yaml(&yaml, "test configuration").unwrap();
        assert_eq!(
            values.optional("AUTH_BACKUP_STORAGE_PROFILE").as_deref(),
            Some("portable")
        );
    }

    #[test]
    fn realm_requires_stable_realm_id_and_audience() {
        let missing_realm = VALID_REALM.replace("  realmId: example-development\n", "");
        assert!(
            values_from_yaml(&missing_realm, "test configuration")
                .unwrap_err()
                .to_string()
                .contains("metadata.realmId")
        );
    }

    #[test]
    fn durations_require_readable_units() {
        let invalid = VALID_REALM.replace("accessTtl: 5m", "accessTtl: 300");
        let error = format!(
            "{:#}",
            values_from_yaml(&invalid, "test configuration").unwrap_err()
        );
        assert!(error.contains("time unit needed"));
    }

    #[test]
    fn declarative_webhooks_are_strict_unique_https_resources() {
        let yaml = format!(
            "{VALID_REALM}\n  webhooks:\n    - id: lifecycle\n      name: Lifecycle\n      endpoint: https://api.example.com/rustyauth\n      eventTypes: [identity.created, session.created]\n"
        );
        let values = values_from_yaml(&yaml, "test configuration").unwrap();
        assert_eq!(values.webhooks.len(), 1);
        assert!(values.webhooks[0].enabled);

        let duplicate = yaml.replace(
            "eventTypes: [identity.created, session.created]",
            "eventTypes: [identity.created, identity.created]",
        );
        assert!(
            values_from_yaml(&duplicate, "test configuration")
                .unwrap_err()
                .to_string()
                .contains("duplicate identity.created")
        );
        let insecure = yaml.replace("https://api.example.com", "http://api.example.com");
        assert!(
            values_from_yaml(&insecure, "test configuration")
                .unwrap_err()
                .to_string()
                .contains("must be an HTTPS URL")
        );
    }
}
