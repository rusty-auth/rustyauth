//! Synthetic fixture generator for the isolated RustyAuth benchmark project.
//!
//! This binary is excluded from ordinary builds and requires the explicit
//! `benchmark-tools` feature. It never ships in the server, dashboard or public
//! Railway template.

use std::{
    collections::HashSet,
    env,
    fs::{self, File},
    io::{BufWriter, Write},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;
use webauthn_rs::WebauthnBuilder;

use rustyauth::{
    store::{
        AccountIdentifier, AccountProfile, AuthEvent, IdentifierKind, IdentifierValue, Session,
        Store, StoredPasskey, User, now,
    },
    webauthn_soft::SoftAuthenticator,
};

const EXPECTED_PROJECT_ID: &str = "3da0030b-006f-4198-a8e7-f8f18da4a8e0";
const RESET_CONFIRMATION: &str = "reset-synthetic-benchmark-data";
const DEFAULT_ACCOUNTS: u64 = 10_000;
const SESSION_SECONDS: u64 = 86_400;
const SEED_BATCH_SIZE: u64 = 25;
const DELETE_BATCH_SIZE: usize = 25;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    index: u64,
    email: String,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionRefreshSummary {
    refreshed_sessions: u64,
    recreated_sessions: u64,
    pruned_sessions: u64,
    refreshed_at: u64,
    idle_seconds: u64,
    absolute_seconds: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let command = env::args().nth(1).unwrap_or_else(|| "seed".to_owned());
    match command.as_str() {
        "seed" => seed().await,
        "refresh-sessions" => refresh_sessions().await,
        "count" => count().await,
        "reset" => reset().await,
        other => bail!(
            "unknown benchmark command {other:?}; expected seed, refresh-sessions, count, or reset"
        ),
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
    let tenant_id = required("AUTH_TENANT_ID")?;
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
        "auth:event*",
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
    let active_writer: bool = redis::cmd("EXISTS")
        .arg("auth:writer-lease")
        .query_async(&mut raw)
        .await
        .context("check benchmark writer lease")?;
    if active_writer {
        bail!(
            "benchmark SableDB still has an active RustyAuth writer lease; stop the realm before seeding"
        );
    }

    let webauthn = WebauthnBuilder::new(&rp_id, &origin_url)
        .context("create benchmark WebAuthn relying party")?
        .rp_name("RustyAuth synthetic benchmark")
        .build()
        .context("build benchmark WebAuthn relying party")?;
    let mut writer =
        BufWriter::new(File::create(&output).context("create benchmark fixture file")?);
    let mut event_sequence = 0_u64;

    for batch_start in (0..account_count).step_by(SEED_BATCH_SIZE as usize) {
        let batch_end = account_count.min(batch_start.saturating_add(SEED_BATCH_SIZE));
        let mut pipeline = redis::pipe();
        pipeline.atomic();
        let mut fixtures = Vec::with_capacity((batch_end - batch_start) as usize);

        for index in batch_start..batch_end {
            let email = format!("realm-{index:06}@benchmark.invalid");
            let identifier = IdentifierValue::canonical(IdentifierKind::Email, &email)
                .context("canonicalize synthetic identifier")?;
            let user_id = deterministic_uuid("user", &seed, index);
            let authenticator = SoftAuthenticator::from_seed(&seed, index);
            let (options, registration_state) = webauthn
                .start_passkey_registration(user_id, &email, &email, None)
                .context("start synthetic passkey registration")?;
            let options =
                serde_json::to_value(options).context("serialize registration options")?;
            let response = serde_json::from_value(authenticator.register(&options, &origin))
                .context("decode synthetic passkey registration")?;
            let passkey = webauthn
                .finish_passkey_registration(&response, &registration_state)
                .context("verify synthetic passkey registration")?;
            let credential_id = URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());
            let credential: webauthn_rs::prelude::Credential = passkey.clone().into();
            let current = now();
            let user = User {
                id: user_id,
                email: identifier.value.clone(),
                email_verified: true,
                profile: AccountProfile::default(),
                identifiers: vec![AccountIdentifier {
                    kind: identifier.kind,
                    value: identifier.value.clone(),
                    verified: true,
                    verified_at: Some(current),
                    primary: true,
                    created_at: current,
                }],
                session_version: 1,
                recovery_codes: Vec::new(),
                created_at: current,
                passkeys: vec![StoredPasskey {
                    id: credential_id.clone(),
                    label: "Primary passkey".to_owned(),
                    counter: credential.counter,
                    created_at: current,
                    last_used_at: None,
                    passkey,
                }],
            };
            let session_token = deterministic_session_token(&seed, index);
            let session = Session {
                id: deterministic_uuid("session", &seed, index),
                user_id,
                auth_method: "passkey".to_owned(),
                current_credential_id: Some(credential_id.clone()),
                session_version: user.session_version,
                created_at: current,
                step_up_at: Some(current),
                last_seen_at: current,
                absolute_expires_at: current.saturating_add(SESSION_SECONDS),
            };
            let identity_event = next_event(
                &mut event_sequence,
                &tenant_id,
                "identity.created",
                user_id,
                current,
            )?;
            let session_event = next_event(
                &mut event_sequence,
                &tenant_id,
                "session.created",
                user_id,
                current,
            )?;

            pipeline
                .cmd("SET")
                .arg(format!("auth:user:{user_id}"))
                .arg(serde_json::to_string(&user)?)
                .ignore()
                .cmd("SET")
                .arg(format!(
                    "auth:identifier:{}:{}",
                    identifier.kind.as_str(),
                    identifier.value
                ))
                .arg(user_id.to_string())
                .ignore()
                .cmd("SET")
                .arg(format!("auth:email:{}", identifier.value))
                .arg(user_id.to_string())
                .ignore()
                .cmd("SET")
                .arg(format!("auth:credential:{credential_id}"))
                .arg(user_id.to_string())
                .ignore()
                .cmd("SETEX")
                .arg(session_key(&session_token))
                .arg(SESSION_SECONDS)
                .arg(serde_json::to_string(&session)?)
                .ignore();
            queue_event(&mut pipeline, &identity_event)?;
            queue_event(&mut pipeline, &session_event)?;
            fixtures.push(Fixture {
                index,
                email,
                session_token,
                credential_id,
                private_jwk: authenticator.private_jwk(),
            });
        }
        pipeline
            .cmd("SET")
            .arg("auth:event-sequence")
            .arg(event_sequence)
            .ignore();
        let _: () = pipeline.query_async(&mut raw).await.with_context(|| {
            format!("persist synthetic account batch {batch_start}..{batch_end}")
        })?;
        for fixture in fixtures {
            serde_json::to_writer(&mut writer, &fixture).context("serialize benchmark fixture")?;
            writer.write_all(b"\n").context("write benchmark fixture")?;
        }
        writer.flush().context("checkpoint benchmark fixtures")?;

        if batch_end % 1_000 == 0 || batch_end == account_count {
            eprintln!(
                "seeded {} of {account_count} synthetic accounts and sessions",
                batch_end
            );
        }
    }
    writer.flush().context("flush benchmark fixtures")?;
    let accounts = scan_count(&mut raw, "auth:user:*").await?;
    let sessions = scan_count(&mut raw, "auth:session:*").await?;
    if accounts != account_count || sessions != account_count {
        bail!(
            "benchmark seed cardinality mismatch: expected {account_count}, found {accounts} accounts and {sessions} sessions"
        );
    }
    validate_seeded_realm(redis, &tenant_id, &seed, account_count).await?;
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

async fn validate_seeded_realm(
    redis: redis::aio::ConnectionManager,
    tenant_id: &str,
    seed: &str,
    account_count: u64,
) -> Result<()> {
    let store = Store::new(redis, tenant_id.to_owned());
    for index in [0, account_count - 1] {
        let expected_id = deterministic_uuid("user", seed, index);
        let expected_email = format!("realm-{index:06}@benchmark.invalid");
        let user = store
            .user(expected_id)
            .await
            .with_context(|| format!("hydrate synthetic account {index}"))?
            .with_context(|| format!("synthetic account {index} is missing"))?;
        if user.email != expected_email || user.passkeys.len() != 1 {
            bail!("synthetic account {index} failed production-model validation");
        }
        let session_token = deterministic_session_token(seed, index);
        let (_, session_user) = store
            .session(&session_token, SESSION_SECONDS)
            .await
            .with_context(|| format!("hydrate synthetic session {index}"))?
            .with_context(|| format!("synthetic session {index} is invalid"))?;
        if session_user.id != expected_id {
            bail!("synthetic session {index} resolved to the wrong account");
        }
    }

    let expected_events = account_count
        .checked_mul(2)
        .context("benchmark event count overflow")?;
    if store.latest_event_sequence().await? != expected_events {
        bail!("synthetic event sequence does not match the seeded realm");
    }
    let mut verified_events = 0_u64;
    while verified_events < expected_events {
        let events = store.events(verified_events, 500).await?;
        if events.is_empty() {
            bail!("synthetic event log ended before sequence {expected_events}");
        }
        verified_events = verified_events.saturating_add(events.len() as u64);
    }
    if verified_events != expected_events {
        bail!("synthetic event log exceeds the expected sequence");
    }
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

async fn refresh_sessions() -> Result<()> {
    require_isolated_project()?;
    let account_count = optional_u64("BENCHMARK_ACCOUNTS", DEFAULT_ACCOUNTS)?;
    let idle_seconds = required_u64("BENCHMARK_SESSION_IDLE_SECONDS")?;
    if account_count == 0 || account_count > 1_000_000 {
        bail!("BENCHMARK_ACCOUNTS must be between 1 and 1,000,000");
    }
    if idle_seconds == 0 || idle_seconds >= SESSION_SECONDS {
        bail!(
            "BENCHMARK_SESSION_IDLE_SECONDS must be positive and shorter than the benchmark absolute session lifetime"
        );
    }
    let seed = required("BENCHMARK_SEED")?;
    let tenant_id = required("AUTH_TENANT_ID")?;
    let redis = connection().await?;
    let mut raw = redis.clone();
    let accounts = scan_count(&mut raw, "auth:user:*").await?;
    let sessions_before = scan_count(&mut raw, "auth:session:*").await?;
    if accounts != account_count {
        bail!(
            "benchmark refresh requires exactly {account_count} accounts; found {accounts} accounts and {sessions_before} sessions"
        );
    }
    let pruned_sessions = prune_extra_synthetic_sessions(&mut raw, &seed, account_count).await?;

    let current = now();
    let mut recreated_sessions = 0_u64;
    for batch_start in (0..account_count).step_by(SEED_BATCH_SIZE as usize) {
        let batch_end = account_count.min(batch_start.saturating_add(SEED_BATCH_SIZE));
        let keys: Vec<_> = (batch_start..batch_end)
            .map(|index| session_key(&deterministic_session_token(&seed, index)))
            .collect();
        let mut read_pipeline = redis::pipe();
        for key in &keys {
            read_pipeline.cmd("GET").arg(key);
        }
        let values: Vec<Option<String>> = read_pipeline
            .query_async(&mut raw)
            .await
            .with_context(|| format!("read synthetic session batch {batch_start}..{batch_end}"))?;
        if values.len() != keys.len() {
            bail!("SableDB returned an incomplete synthetic session batch");
        }

        let mut write_pipeline = redis::pipe();
        write_pipeline.atomic();
        for (offset, (key, value)) in keys.iter().zip(values).enumerate() {
            let index = batch_start.saturating_add(offset as u64);
            let mut session = match value {
                Some(value) => serde_json::from_str(&value)
                    .with_context(|| format!("decode synthetic session {index}"))?,
                None => {
                    recreated_sessions = recreated_sessions.saturating_add(1);
                    recreate_session(&mut raw, &seed, index, current).await?
                }
            };
            if session.id != deterministic_uuid("session", &seed, index)
                || session.user_id != deterministic_uuid("user", &seed, index)
            {
                bail!("synthetic session {index} does not match its deterministic fixture");
            }
            refresh_session(&mut session, current);
            write_pipeline
                .cmd("SETEX")
                .arg(key)
                .arg(SESSION_SECONDS)
                .arg(serde_json::to_string(&session)?)
                .ignore();
        }
        write_pipeline
            .query_async::<()>(&mut raw)
            .await
            .with_context(|| {
                format!("refresh synthetic session batch {batch_start}..{batch_end}")
            })?;
    }

    let final_sessions = scan_count(&mut raw, "auth:session:*").await?;
    if final_sessions != account_count {
        bail!(
            "benchmark refresh cardinality mismatch: expected {account_count} sessions, found {final_sessions}"
        );
    }

    // Hydrate boundary fixtures through the production session model so the
    // refresh cannot report success with a missing account, revoked passkey or
    // mismatched session version.
    let store = Store::new(redis, tenant_id);
    for index in [0, account_count - 1] {
        let token = deterministic_session_token(&seed, index);
        store
            .session(&token, idle_seconds)
            .await
            .with_context(|| format!("validate refreshed synthetic session {index}"))?
            .with_context(|| format!("refreshed synthetic session {index} is invalid"))?;
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&SessionRefreshSummary {
            refreshed_sessions: account_count,
            recreated_sessions,
            pruned_sessions,
            refreshed_at: current,
            idle_seconds,
            absolute_seconds: SESSION_SECONDS,
        })?
    );
    Ok(())
}

/// Removes superseded login sessions created by earlier benchmark journeys.
///
/// This remains fail-closed: the command is already restricted to the one
/// dedicated Railway project, and every extra session must belong to one of
/// the deterministic synthetic accounts before any deletion begins. A session
/// for any other account aborts the refresh without deleting the validated set.
async fn prune_extra_synthetic_sessions(
    redis: &mut redis::aio::ConnectionManager,
    seed: &str,
    account_count: u64,
) -> Result<u64> {
    let expected_keys: HashSet<_> = (0..account_count)
        .map(|index| session_key(&deterministic_session_token(seed, index)))
        .collect();
    let expected_users: HashSet<_> = (0..account_count)
        .map(|index| deterministic_uuid("user", seed, index))
        .collect();
    let session_keys = scan_keys(redis, "auth:session:*").await?;
    let extra_keys: Vec<_> = session_keys
        .into_iter()
        .filter(|key| !expected_keys.contains(key))
        .collect();

    let mut present_extra_keys = Vec::with_capacity(extra_keys.len());
    for chunk in extra_keys.chunks(DELETE_BATCH_SIZE) {
        let mut pipeline = redis::pipe();
        for key in chunk {
            pipeline.cmd("GET").arg(key);
        }
        let values: Vec<Option<String>> = pipeline
            .query_async(&mut *redis)
            .await
            .context("read superseded synthetic benchmark sessions")?;
        if values.len() != chunk.len() {
            bail!("SableDB returned an incomplete superseded session batch");
        }
        for (key, value) in chunk.iter().zip(values) {
            let Some(value) = value else {
                continue;
            };
            let session: Session = serde_json::from_str(&value)
                .with_context(|| format!("decode superseded benchmark session {key}"))?;
            if !is_synthetic_session(&session, &expected_users) {
                bail!(
                    "refusing to prune session {key} because it is not owned by a deterministic benchmark account"
                );
            }
            present_extra_keys.push(key.clone());
        }
    }

    let mut deleted = 0_u64;
    for chunk in present_extra_keys.chunks(DELETE_BATCH_SIZE) {
        let removed: u64 = redis::cmd("DEL")
            .arg(chunk)
            .query_async(&mut *redis)
            .await
            .context("prune superseded synthetic benchmark sessions")?;
        deleted = deleted.saturating_add(removed);
    }
    Ok(deleted)
}

fn is_synthetic_session(session: &Session, expected_users: &HashSet<Uuid>) -> bool {
    expected_users.contains(&session.user_id)
}

async fn recreate_session(
    redis: &mut redis::aio::ConnectionManager,
    seed: &str,
    index: u64,
    current: u64,
) -> Result<Session> {
    let user_id = deterministic_uuid("user", seed, index);
    let value: Option<String> = redis::cmd("GET")
        .arg(format!("auth:user:{user_id}"))
        .query_async(redis)
        .await
        .with_context(|| format!("read synthetic account {index} for session recovery"))?;
    let user: User = serde_json::from_str(
        &value.with_context(|| format!("synthetic account {index} is missing"))?,
    )
    .with_context(|| format!("decode synthetic account {index}"))?;
    if user.id != user_id || user.passkeys.len() != 1 {
        bail!("synthetic account {index} cannot reconstruct its passkey session");
    }
    Ok(Session {
        id: deterministic_uuid("session", seed, index),
        user_id,
        auth_method: "passkey".to_owned(),
        current_credential_id: Some(user.passkeys[0].id.clone()),
        session_version: user.session_version,
        created_at: current,
        step_up_at: Some(current),
        last_seen_at: current,
        absolute_expires_at: current.saturating_add(SESSION_SECONDS),
    })
}

fn refresh_session(session: &mut Session, current: u64) {
    session.last_seen_at = current;
    session.absolute_expires_at = current.saturating_add(SESSION_SECONDS);
}

async fn reset() -> Result<()> {
    require_isolated_project()?;
    if required("BENCHMARK_RESET_CONFIRM")? != RESET_CONFIRMATION {
        bail!("BENCHMARK_RESET_CONFIRM does not authorize the synthetic benchmark reset");
    }

    let mut redis = connection().await?;
    let mut deleted = 0_u64;
    for _ in 0..20 {
        deleted = deleted.saturating_add(delete_scan_pass(&mut redis).await?);
        let remaining: u64 = redis::cmd("DBSIZE")
            .query_async(&mut redis)
            .await
            .context("verify benchmark reset")?;
        if remaining == 0 {
            println!("{{\"deletedKeys\":{deleted},\"remainingKeys\":0}}");
            return Ok(());
        }
    }
    bail!("benchmark reset did not converge after 20 bounded passes");
}

async fn delete_scan_pass(redis: &mut redis::aio::ConnectionManager) -> Result<u64> {
    let mut cursor = 0_u64;
    let mut deleted = 0_u64;
    loop {
        let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("COUNT")
            .arg(500_u16)
            .query_async(&mut *redis)
            .await
            .context("scan isolated benchmark keys for reset")?;
        if !keys.is_empty() {
            for chunk in keys.chunks(DELETE_BATCH_SIZE) {
                let removed: u64 = redis::cmd("DEL")
                    .arg(chunk)
                    .query_async(&mut *redis)
                    .await
                    .context("delete isolated benchmark key batch")?;
                deleted = deleted.saturating_add(removed);
            }
        }
        cursor = next;
        if cursor == 0 {
            return Ok(deleted);
        }
    }
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

async fn scan_keys(
    redis: &mut redis::aio::ConnectionManager,
    pattern: &str,
) -> Result<Vec<String>> {
    let mut cursor = 0_u64;
    let mut found = Vec::new();
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
        found.extend(keys);
        cursor = next;
        if cursor == 0 {
            return Ok(found);
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

fn required_u64(name: &str) -> Result<u64> {
    required(name)?
        .parse()
        .with_context(|| format!("{name} must be an unsigned integer"))
}

fn deterministic_uuid(domain: &str, seed: &str, index: u64) -> Uuid {
    let digest =
        Sha256::digest(format!("rustyauth-benchmark-{domain}\0{seed}\0{index}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn deterministic_session_token(seed: &str, index: u64) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(
        format!("rustyauth-benchmark-session-token\0{seed}\0{index}").as_bytes(),
    ))
}

fn session_key(token: &str) -> String {
    format!(
        "auth:session:{}",
        hex::encode(Sha256::digest(token.as_bytes()))
    )
}

fn next_event(
    sequence: &mut u64,
    tenant_id: &str,
    event_type: &str,
    subject: Uuid,
    occurred_at: u64,
) -> Result<AuthEvent> {
    *sequence = sequence
        .checked_add(1)
        .context("auth event sequence exhausted")?;
    Ok(AuthEvent {
        sequence: *sequence,
        id: Uuid::new_v4(),
        tenant_id: tenant_id.to_owned(),
        event_type: event_type.to_owned(),
        subject: Some(subject),
        occurred_at,
        data: serde_json::json!({}),
    })
}

fn queue_event(pipeline: &mut redis::Pipeline, event: &AuthEvent) -> Result<()> {
    pipeline
        .cmd("SET")
        .arg(format!("auth:event:{}", event.sequence))
        .arg(serde_json::to_string(event)?)
        .ignore();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_id_domains_do_not_overlap() {
        assert_eq!(
            deterministic_uuid("user", "seed", 7),
            deterministic_uuid("user", "seed", 7)
        );
        assert_ne!(
            deterministic_uuid("user", "seed", 7),
            deterministic_uuid("session", "seed", 7)
        );
    }

    #[test]
    fn deterministic_session_tokens_are_stable_and_distinct() {
        let first = deterministic_session_token("seed", 7);
        assert_eq!(first, deterministic_session_token("seed", 7));
        assert_ne!(first, deterministic_session_token("seed", 8));
        assert_eq!(first.len(), 43);
    }

    #[test]
    fn session_refresh_renews_idle_and_absolute_boundaries_only() {
        let credential_id = "credential-a".to_owned();
        let mut session = Session {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            auth_method: "passkey".to_owned(),
            current_credential_id: Some(credential_id.clone()),
            session_version: 7,
            created_at: 100,
            step_up_at: Some(100),
            last_seen_at: 100,
            absolute_expires_at: 200,
        };
        refresh_session(&mut session, 1_000);
        assert_eq!(session.last_seen_at, 1_000);
        assert_eq!(session.absolute_expires_at, 1_000 + SESSION_SECONDS);
        assert_eq!(session.created_at, 100);
        assert_eq!(session.step_up_at, Some(100));
        assert_eq!(session.current_credential_id, Some(credential_id));
        assert_eq!(session.session_version, 7);
    }

    #[test]
    fn superseded_session_pruning_is_scoped_to_deterministic_accounts() {
        let synthetic_user = deterministic_uuid("user", "seed", 7);
        let expected = HashSet::from([synthetic_user]);
        let mut session = Session {
            id: Uuid::new_v4(),
            user_id: synthetic_user,
            auth_method: "passkey".to_owned(),
            current_credential_id: None,
            session_version: 1,
            created_at: 1,
            step_up_at: Some(1),
            last_seen_at: 1,
            absolute_expires_at: 2,
        };
        assert!(is_synthetic_session(&session, &expected));
        session.user_id = Uuid::new_v4();
        assert!(!is_synthetic_session(&session, &expected));
    }
}
