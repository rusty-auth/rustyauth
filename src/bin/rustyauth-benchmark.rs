//! Synthetic fixture generator for the isolated RustyAuth benchmark project.
//!
//! This binary is excluded from ordinary builds and requires the explicit
//! `benchmark-tools` feature. It never ships in the server, dashboard or public
//! Railway template.

use std::{
    env,
    fs::{self, File},
    io::{BufWriter, Write},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;
use webauthn_rs::WebauthnBuilder;

use rustyauth::{
    store::{AccountProfile, IdentifierKind, IdentifierValue, SessionOrigin, Store},
    webauthn_soft::SoftAuthenticator,
};

const EXPECTED_PROJECT_ID: &str = "3da0030b-006f-4198-a8e7-f8f18da4a8e0";
const DEFAULT_ACCOUNTS: u64 = 10_000;
const SESSION_SECONDS: u64 = 86_400;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Fixture<'a> {
    index: u64,
    email: &'a str,
    session_token: String,
    credential_id: String,
    private_jwk: serde_json::Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SeedSummary {
    project_id: String,
    accounts: u64,
    valid_sessions: u64,
    fixture_path: String,
    fixture_sha256: String,
    rp_id: String,
    origin: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let command = env::args().nth(1).unwrap_or_else(|| "seed".to_owned());
    match command.as_str() {
        "seed" => seed().await,
        "count" => count().await,
        other => bail!("unknown benchmark command {other:?}; expected seed or count"),
    }
}

async fn connection() -> Result<redis::aio::ConnectionManager> {
    let url = required("SABLEDB_URL")?;
    let client = redis::Client::open(url).context("create benchmark SableDB client")?;
    redis::aio::ConnectionManager::new_with_config(
        client,
        redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(Duration::from_secs(5)))
            // Dataset preparation performs durable write batches and can overlap
            // an LSM compaction pause on the smallest supported SableDB tier.
            // This timeout is outside the measured workload; k6 owns the actual
            // latency gates once the prepared realm is online.
            .set_response_timeout(Some(Duration::from_secs(30))),
    )
    .await
    .context("connect to isolated benchmark SableDB")
}

async fn seed() -> Result<()> {
    require_isolated_project()?;
    let account_count = optional_u64("BENCHMARK_ACCOUNTS", DEFAULT_ACCOUNTS)?;
    if account_count == 0 || account_count > 1_000_000 {
        bail!("BENCHMARK_ACCOUNTS must be between 1 and 1,000,000");
    }
    let seed = required("BENCHMARK_SEED")?;
    let rp_id = required("WEBAUTHN_RP_ID")?;
    let origin = required("WEBAUTHN_RP_ORIGIN")?;
    let origin_url = Url::parse(&origin).context("parse WEBAUTHN_RP_ORIGIN")?;
    let output = PathBuf::from(
        env::var("BENCHMARK_FIXTURES_PATH").unwrap_or_else(|_| "/data/fixtures.jsonl".to_owned()),
    );
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).context("create benchmark fixture directory")?;
    }

    let redis = connection().await?;
    let mut raw = redis.clone();
    let identity_patterns = [
        "auth:user:*",
        "auth:session:*",
        "auth:credential:*",
        "auth:identifier:*",
        "auth:email:*",
    ];
    let mut existing = 0_u64;
    for pattern in identity_patterns {
        existing = existing.saturating_add(scan_count(&mut raw, pattern).await?);
    }
    if existing != 0 {
        bail!(
            "benchmark SableDB already contains {existing} identity records; reset it through the reviewed benchmark control before reseeding"
        );
    }

    let store = Store::new(redis, required("AUTH_TENANT_ID")?);
    let webauthn = WebauthnBuilder::new(&rp_id, &origin_url)
        .context("create benchmark WebAuthn relying party")?
        .rp_name("RustyAuth synthetic benchmark")
        .build()
        .context("build benchmark WebAuthn relying party")?;
    let mut writer =
        BufWriter::new(File::create(&output).context("create benchmark fixture file")?);

    for index in 0..account_count {
        let email = format!("realm-{index:06}@benchmark.invalid");
        let user_id = deterministic_uuid(&seed, index);
        let authenticator = SoftAuthenticator::from_seed(&seed, index);
        let (options, registration_state) = webauthn
            .start_passkey_registration(user_id, &email, &email, None)
            .context("start synthetic passkey registration")?;
        let options = serde_json::to_value(options).context("serialize registration options")?;
        let response = serde_json::from_value(authenticator.register(&options, &origin))
            .context("decode synthetic passkey registration")?;
        let passkey = webauthn
            .finish_passkey_registration(&response, &registration_state)
            .context("verify synthetic passkey registration")?;
        let user = store
            .create_user_with_passkey(
                user_id,
                IdentifierValue::canonical(IdentifierKind::Email, &email)
                    .context("canonicalize synthetic identifier")?,
                AccountProfile::default(),
                passkey,
                true,
                None,
            )
            .await
            .with_context(|| format!("persist synthetic account {index}"))?;
        let credential_id = user
            .passkeys
            .first()
            .context("seeded account has no passkey")?
            .id
            .clone();
        let (session_token, _) = store
            .create_session(
                &user,
                SessionOrigin::Passkey {
                    credential_id: credential_id.clone(),
                },
                SESSION_SECONDS,
            )
            .await
            .with_context(|| format!("persist synthetic session {index}"))?;
        serde_json::to_writer(
            &mut writer,
            &Fixture {
                index,
                email: &email,
                session_token,
                credential_id,
                private_jwk: authenticator.private_jwk(),
            },
        )
        .context("serialize benchmark fixture")?;
        writer.write_all(b"\n").context("write benchmark fixture")?;

        if (index + 1) % 1_000 == 0 || index + 1 == account_count {
            eprintln!(
                "seeded {} of {account_count} synthetic accounts and sessions",
                index + 1
            );
        }
    }
    writer.flush().context("flush benchmark fixtures")?;
    let bytes = fs::read(&output).context("hash benchmark fixtures")?;
    let summary = SeedSummary {
        project_id: EXPECTED_PROJECT_ID.to_owned(),
        accounts: account_count,
        valid_sessions: account_count,
        fixture_path: output.display().to_string(),
        fixture_sha256: hex::encode(Sha256::digest(&bytes)),
        rp_id,
        origin,
    };
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

async fn count() -> Result<()> {
    require_isolated_project()?;
    let mut redis = connection().await?;
    let accounts = scan_count(&mut redis, "auth:user:*").await?;
    let sessions = scan_count(&mut redis, "auth:session:*").await?;
    println!("{{\"registeredAccounts\":{accounts},\"validSessions\":{sessions}}}");
    Ok(())
}

async fn scan_count(redis: &mut redis::aio::ConnectionManager, pattern: &str) -> Result<u64> {
    let mut cursor = 0_u64;
    let mut count = 0_u64;
    loop {
        let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(1_000_u16)
            .query_async(redis)
            .await
            .with_context(|| format!("scan {pattern}"))?;
        count = count.saturating_add(keys.len() as u64);
        cursor = next;
        if cursor == 0 {
            return Ok(count);
        }
    }
}

fn require_isolated_project() -> Result<()> {
    let actual = required("BENCHMARK_PROJECT_ID")?;
    if actual != EXPECTED_PROJECT_ID {
        bail!(
            "refusing benchmark data mutation outside the dedicated project {EXPECTED_PROJECT_ID}"
        );
    }
    Ok(())
}

fn required(name: &str) -> Result<String> {
    let value = env::var(name).with_context(|| format!("{name} is required"))?;
    if value.trim().is_empty() {
        bail!("{name} must not be empty");
    }
    Ok(value)
}

fn optional_u64(name: &str, default: u64) -> Result<u64> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .with_context(|| format!("{name} must be an unsigned integer")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("read {name}")),
    }
}

fn deterministic_uuid(seed: &str, index: u64) -> Uuid {
    let digest = Sha256::digest(format!("rustyauth-benchmark-user\0{seed}\0{index}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}
