//! Fail-closed environment configuration and deployment-policy validation.

use std::{env, net::IpAddr, str::FromStr};

use anyhow::{Context, Result, bail};
use secrecy::{ExposeSecret, SecretString};
use url::Url;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Environment {
    Development,
    Production,
}

#[derive(Clone, Debug)]
pub struct BackupConfig {
    pub endpoint: Url,
    pub region: String,
    pub bucket: String,
    pub access_key_id: SecretString,
    pub secret_access_key: SecretString,
    pub encryption_key: [u8; 32],
    pub force_path_style: bool,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub environment: Environment,
    pub bind: IpAddr,
    pub port: u16,
    pub issuer: Url,
    pub rp_id: String,
    pub rp_origin: Url,
    pub rp_name: String,
    pub sabledb_url: SecretString,
    pub master_key: [u8; 32],
    pub bootstrap_token: SecretString,
    pub event_rpc_token: SecretString,
    pub identity_rpc_token: SecretString,
    pub audience: String,
    pub tenant_id: String,
    pub access_token_seconds: u64,
    pub session_idle_seconds: u64,
    pub session_absolute_seconds: u64,
    pub backup: Option<BackupConfig>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let environment = match optional("AUTH_ENV").as_deref() {
            Some("development") | None => Environment::Development,
            Some("production") => Environment::Production,
            Some(other) => bail!("AUTH_ENV must be development or production, got {other}"),
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
        let master_key = decode_key("AUTH_MASTER_KEY_HEX")?;
        let bootstrap_token = SecretString::from(required("BOOTSTRAP_TOKEN")?);
        let event_rpc_token = SecretString::from(required("AUTH_EVENT_RPC_TOKEN")?);
        let identity_rpc_token = SecretString::from(required("AUTH_IDENTITY_RPC_TOKEN")?);
        let audience = required("SPACETIME_AUDIENCE")?;
        let tenant_id = optional("AUTH_TENANT_ID").unwrap_or_else(|| "vtr".into());
        let access_token_seconds = integer("AUTH_ACCESS_TOKEN_SECONDS", 300, 60, 900)?;
        let session_idle_seconds = integer("AUTH_SESSION_IDLE_SECONDS", 1_800, 300, 86_400)?;
        let session_absolute_seconds =
            integer("AUTH_SESSION_ABSOLUTE_SECONDS", 604_800, 3_600, 2_592_000)?;

        validate_origin(&environment, "AUTH_ISSUER", &issuer)?;
        validate_origin(&environment, "WEBAUTHN_RP_ORIGIN", &rp_origin)?;
        validate_rp(&rp_id, &rp_origin)?;
        validate_sable_url(&environment, &sabledb_url)?;
        if environment == Environment::Production && bootstrap_token.expose_secret().len() < 32 {
            bail!("BOOTSTRAP_TOKEN must contain at least 32 characters in production");
        }
        if event_rpc_token.expose_secret().len() < 32 {
            bail!("AUTH_EVENT_RPC_TOKEN must contain at least 32 characters");
        }
        if event_rpc_token.expose_secret() == bootstrap_token.expose_secret() {
            bail!("AUTH_EVENT_RPC_TOKEN must not reuse BOOTSTRAP_TOKEN");
        }
        if identity_rpc_token.expose_secret().len() < 32 {
            bail!("AUTH_IDENTITY_RPC_TOKEN must contain at least 32 characters");
        }
        if identity_rpc_token.expose_secret() == bootstrap_token.expose_secret() {
            bail!("AUTH_IDENTITY_RPC_TOKEN must not reuse BOOTSTRAP_TOKEN");
        }
        if identity_rpc_token.expose_secret() == event_rpc_token.expose_secret() {
            bail!("AUTH_IDENTITY_RPC_TOKEN must not reuse AUTH_EVENT_RPC_TOKEN");
        }

        Ok(Self {
            environment,
            bind,
            port,
            issuer,
            rp_id,
            rp_origin,
            rp_name,
            sabledb_url,
            master_key,
            bootstrap_token,
            event_rpc_token,
            identity_rpc_token,
            audience,
            tenant_id,
            access_token_seconds,
            session_idle_seconds,
            session_absolute_seconds,
            backup: BackupConfig::from_env()?,
        })
    }
}

impl BackupConfig {
    fn from_env() -> Result<Option<Self>> {
        let names = [
            "AUTH_BACKUP_ENDPOINT",
            "AUTH_BACKUP_REGION",
            "AUTH_BACKUP_BUCKET",
            "AUTH_BACKUP_ACCESS_KEY_ID",
            "AUTH_BACKUP_SECRET_ACCESS_KEY",
            "AUTH_BACKUP_ENCRYPTION_KEY_HEX",
        ];
        let present = names.iter().filter(|name| optional(name).is_some()).count();
        if present == 0 {
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

        Ok(Some(Self {
            endpoint: parse_url("AUTH_BACKUP_ENDPOINT")?,
            region: required("AUTH_BACKUP_REGION")?,
            bucket: required("AUTH_BACKUP_BUCKET")?,
            access_key_id: SecretString::from(required("AUTH_BACKUP_ACCESS_KEY_ID")?),
            secret_access_key: SecretString::from(required("AUTH_BACKUP_SECRET_ACCESS_KEY")?),
            encryption_key: decode_key("AUTH_BACKUP_ENCRYPTION_KEY_HEX")?,
            force_path_style,
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
    let bytes = hex::decode(required(name)?).with_context(|| format!("{name} must be hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must contain exactly 32 bytes (64 hex characters)"))
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

fn validate_sable_url(environment: &Environment, value: &SecretString) -> Result<()> {
    let url = Url::parse(value.expose_secret()).context("SABLEDB_URL is invalid")?;
    if url.scheme() != "redis" {
        bail!("SABLEDB_URL must use the redis scheme");
    }
    let host = url.host_str().context("SABLEDB_URL has no host")?;
    if environment == &Environment::Production && !host.ends_with(".railway.internal") {
        bail!("production SABLEDB_URL must use Railway private networking (*.railway.internal)");
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
    fn production_requires_https() {
        let origin = Url::parse("http://auth.example.com").unwrap();
        assert!(validate_origin(&Environment::Production, "origin", &origin).is_err());
    }
}
