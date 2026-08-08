//! Operator command line: argument parsing, usage text and the host-side
//! doctor, backup, keys, operator and local-agent subcommands.

use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

use anyhow::{Context, Result};
use redis::AsyncCommands;
use serde_json::json;
use uuid::Uuid;

use crate::{
    backup::BackupStore,
    config::{Config, DeploymentRole, Environment},
    jwt::{JwtIssuer, validate_snapshot_keyset},
    store::{IdentifierKind, IdentifierValue, OperatorRoleRecord, Store},
};

#[derive(Debug, Eq, PartialEq)]
pub struct LocalAgentRequest {
    email: String,
    redirect_url: Option<url::Url>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProcessMode {
    Help,
    Serve,
    Healthcheck,
    LocalAgent(LocalAgentRequest),
    BackupCreate,
    BackupList,
    BackupStatus,
    BackupVerify {
        object_key: String,
    },
    BackupRestore {
        object_key: String,
        preserve_sessions: bool,
    },
    KeysStatus,
    KeysRotate,
    OperatorPromote {
        user_id: String,
        role: String,
    },
    OperatorDemote {
        user_id: String,
    },
    OperatorFind {
        email: String,
    },
    OperatorList,
    FleetPairingCode {
        control_plane_origin: String,
        operator_user_id: String,
    },
    Doctor,
}

pub fn parse_process_arguments(arguments: Vec<String>) -> Result<ProcessMode> {
    match arguments.as_slice() {
        [] => return Ok(ProcessMode::Serve),
        [value] if value == "--help" || value == "-h" || value == "help" => {
            return Ok(ProcessMode::Help);
        }
        [value] if value == "--healthcheck" => return Ok(ProcessMode::Healthcheck),
        [group, command] if group == "backup" && command == "create" => {
            return Ok(ProcessMode::BackupCreate);
        }
        [group, command] if group == "backup" && command == "list" => {
            return Ok(ProcessMode::BackupList);
        }
        [group, command] if group == "backup" && command == "status" => {
            return Ok(ProcessMode::BackupStatus);
        }
        [group, command, object_key] if group == "backup" && command == "verify" => {
            return Ok(ProcessMode::BackupVerify {
                object_key: object_key.clone(),
            });
        }
        [group, command, object_key] if group == "backup" && command == "restore" => {
            return Ok(ProcessMode::BackupRestore {
                object_key: object_key.clone(),
                preserve_sessions: false,
            });
        }
        [group, command, object_key, flag]
            if group == "backup" && command == "restore" && flag == "--preserve-sessions" =>
        {
            return Ok(ProcessMode::BackupRestore {
                object_key: object_key.clone(),
                preserve_sessions: true,
            });
        }
        [group, command] if group == "keys" && command == "status" => {
            return Ok(ProcessMode::KeysStatus);
        }
        [group, command] if group == "keys" && command == "rotate" => {
            return Ok(ProcessMode::KeysRotate);
        }
        [group, command, user_id, role] if group == "operator" && command == "promote" => {
            return Ok(ProcessMode::OperatorPromote {
                user_id: user_id.clone(),
                role: role.clone(),
            });
        }
        [group, command, user_id] if group == "operator" && command == "demote" => {
            return Ok(ProcessMode::OperatorDemote {
                user_id: user_id.clone(),
            });
        }
        [group, command, email] if group == "operator" && command == "find" => {
            return Ok(ProcessMode::OperatorFind {
                email: email.clone(),
            });
        }
        [group, command] if group == "operator" && command == "list" => {
            return Ok(ProcessMode::OperatorList);
        }
        [group, command, control_plane_origin, operator_user_id]
            if group == "fleet" && command == "pairing-code" =>
        {
            return Ok(ProcessMode::FleetPairingCode {
                control_plane_origin: control_plane_origin.clone(),
                operator_user_id: operator_user_id.clone(),
            });
        }
        [command] if command == "doctor" => return Ok(ProcessMode::Doctor),
        _ => {}
    }
    if arguments.first().map(String::as_str) != Some("--local-agent-session")
        || !matches!(arguments.len(), 3 | 5)
        || arguments[1] != "--email"
        || (arguments.len() == 5 && arguments[3] != "--redirect")
    {
        anyhow::bail!("invalid command\n\n{CLI_HELP}");
    }
    let email = arguments[2].trim().to_ascii_lowercase();
    if email.len() > 320 || !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
        anyhow::bail!("valid existing account email required");
    }
    let redirect_url = arguments
        .get(4)
        .map(|value| url::Url::parse(value).context("agent redirect is not a valid URL"))
        .transpose()?;
    Ok(ProcessMode::LocalAgent(LocalAgentRequest {
        email,
        redirect_url,
    }))
}

pub const CLI_HELP: &str = "RustyAuth authentication and recovery service

Usage:
  rustyauth
  rustyauth doctor
  rustyauth backup create
  rustyauth backup list
  rustyauth backup status
  rustyauth backup verify <object-key>
  rustyauth backup restore <object-key> [--preserve-sessions]
  rustyauth keys status
  rustyauth keys rotate
  rustyauth operator list
  rustyauth operator find <email>
  rustyauth operator promote <user-id> <owner|administrator|support|auditor>
  rustyauth operator demote <user-id>
  rustyauth fleet pairing-code <control-plane-origin> <operator-user-id>

Running without a command starts the HTTP service. Restore requires an empty SableDB namespace and
invalidates existing sessions unless --preserve-sessions is explicitly supplied.

In development, the dashboard setup flow can create the first local Owner with the bootstrap token.
Production keeps that route closed: operator promotion is the supported first-Owner path and requires
shell access to the deployment.

Promotion takes a user id, not an address. Any enrolled account can attach an unclaimed address to
itself, so resolving an address here would promote whoever claimed it first. Run `operator find
<email>` to see which accounts hold the address and when they claimed it, then promote the id you
recognise.";

/// Executes one operator subcommand against the already-initialized store.
///
/// `Serve` belongs to the process entry point, and `Help`/`Healthcheck` exit
/// before configuration is loaded, so none of the three can reach this dispatch.
pub async fn run(
    mode: ProcessMode,
    config: Config,
    redis: redis::aio::ConnectionManager,
    store: Store,
) -> Result<()> {
    match mode {
        ProcessMode::LocalAgent(request) => {
            create_local_agent_handoff(&config, store, request).await
        }
        ProcessMode::BackupCreate => {
            let _jwt = initialize_jwt(&config, redis, &store).await?;
            let backup = configured_backup(&config).await?;
            let receipt = backup
                .create(&store, &config.tenant_id, &config.master_keys)
                .await?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
            Ok(())
        }
        ProcessMode::BackupList => {
            let backup = configured_backup(&config).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&backup.list(&config.tenant_id).await?)?
            );
            Ok(())
        }
        ProcessMode::BackupStatus => {
            let backup = configured_backup(&config).await?;
            let status = backup.persisted_status(&store).await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            if status.alerting {
                anyhow::bail!(
                    "backup health is alerting: recovery point overdue or failure threshold reached"
                );
            }
            Ok(())
        }
        ProcessMode::BackupVerify { object_key } => {
            let backup = configured_backup(&config).await?;
            let (receipt, snapshot) = backup.verify(&object_key, &config.tenant_id).await?;
            validate_snapshot_keyset(snapshot.signing_keyset()?, &config.master_keys)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
            Ok(())
        }
        ProcessMode::BackupRestore {
            object_key,
            preserve_sessions,
        } => {
            let backup = configured_backup(&config).await?;
            let snapshot = backup.download(&object_key, &config.tenant_id).await?;
            validate_snapshot_keyset(snapshot.signing_keyset()?, &config.master_keys)?;
            let snapshot_id = snapshot.snapshot_id();
            let captured_at = snapshot.captured_at();
            let record_count = snapshot.record_count();
            let restored = store
                .restore_records(snapshot.records(), preserve_sessions)
                .await?;
            let jwt = initialize_jwt(&config, redis, &store).await?;
            let key_status = jwt.force_rotate(true).await?;
            store.append_event("recovery.restored", None).await?;
            store.complete_restore().await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "snapshotId": snapshot_id,
                    "capturedAt": captured_at,
                    "snapshotRecordCount": record_count,
                    "restoredRecordCount": restored,
                    "sessionsPreserved": preserve_sessions,
                    "activeSigningKey": key_status.active_kid,
                }))?
            );
            Ok(())
        }
        ProcessMode::KeysStatus => {
            let jwt = initialize_jwt(&config, redis, &store).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&jwt.stored_status().await?)?
            );
            Ok(())
        }
        ProcessMode::KeysRotate => {
            let jwt = initialize_jwt(&config, redis, &store).await?;
            let status = jwt.force_rotate(false).await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        ProcessMode::OperatorPromote { user_id, role } => {
            promote_operator(&store, &user_id, &role).await
        }
        ProcessMode::OperatorDemote { user_id } => demote_operator(&store, &user_id).await,
        ProcessMode::OperatorFind { email } => find_operator_candidates(&store, &email).await,
        ProcessMode::OperatorList => {
            let operators = store
                .operators()
                .await?
                .into_iter()
                .map(|listing| {
                    json!({
                        "userId": listing.operator.user_id,
                        "role": listing.operator.role,
                        "email": listing.user.primary_email().map(|value| value.value.clone()),
                        "createdAt": listing.operator.created_at,
                        "lastAuthenticatedAt": listing.last_authenticated_at,
                        "revokedAt": listing.operator.revoked_at,
                    })
                })
                .collect::<Vec<_>>();
            println!("{}", serde_json::to_string_pretty(&operators)?);
            Ok(())
        }
        ProcessMode::FleetPairingCode {
            control_plane_origin,
            operator_user_id,
        } => {
            create_fleet_pairing_code(&config, &store, &control_plane_origin, &operator_user_id)
                .await
        }
        ProcessMode::Doctor => doctor(&config, redis, &store).await,
        ProcessMode::Serve => unreachable!("serve is dispatched by the process entry point"),
        ProcessMode::Help => unreachable!("help exits before configuration"),
        ProcessMode::Healthcheck => unreachable!("healthcheck exits before configuration"),
    }
}

async fn create_fleet_pairing_code(
    config: &Config,
    store: &Store,
    control_plane_origin: &str,
    operator_user_id: &str,
) -> Result<()> {
    if config.deployment_role != DeploymentRole::Realm {
        anyhow::bail!(
            "Fleet pairing codes are created by realm deployments, not the control plane"
        );
    }
    let origin =
        url::Url::parse(control_plane_origin).context("control-plane origin is not a valid URL")?;
    if origin.path() != "/" || origin.query().is_some() || origin.fragment().is_some() {
        anyhow::bail!("control-plane origin must not contain a path, query or fragment");
    }
    if !matches!(origin.scheme(), "http" | "https")
        || (config.environment == Environment::Production && origin.scheme() != "https")
    {
        anyhow::bail!("control-plane origin must use HTTPS in production");
    }
    let operator_user_id = Uuid::parse_str(operator_user_id)
        .context("operator-user-id must be an existing operator UUID")?;
    let operator = store
        .operator(operator_user_id)
        .await?
        .filter(|record| {
            record.revoked_at.is_none()
                && matches!(
                    record.role,
                    OperatorRoleRecord::Owner | OperatorRoleRecord::Administrator
                )
        })
        .context("an active owner or administrator must authorize realm pairing")?;
    let (record, code) = store
        .create_realm_pairing(
            config.realm_id.clone(),
            origin.to_string().trim_end_matches('/').to_owned(),
            vec![
                "realm.summary.read".into(),
                "realm.connection.revoke".into(),
            ],
            operator.user_id,
        )
        .await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "pairingCode": code,
            "realmId": record.realm_id,
            "controlPlaneOrigin": record.control_plane_origin,
            "expiresAt": record.expires_at,
            "requestedScopes": record.requested_scopes,
        }))?
    );
    Ok(())
}

/// Composes the JWT issuer from configuration and the stored keyset.
///
/// Shared by the serving entry point and the subcommands that act on signing
/// keys, so both operate on the same stored keyset with the same policy.
pub async fn initialize_jwt(
    config: &Config,
    redis: redis::aio::ConnectionManager,
    store: &Store,
) -> Result<JwtIssuer> {
    JwtIssuer::load_or_create(
        redis,
        config.master_keys.clone(),
        config.signing_rotation.clone(),
        store.snapshot_gate(),
        config.issuer.as_str().trim_end_matches('/').to_owned(),
        config.audience.clone(),
        config.tenant_id.clone(),
        config.access_token_seconds,
    )
    .await
    .context("initialize JWT signing keyset")
}

async fn configured_backup(config: &Config) -> Result<BackupStore> {
    let backup = config
        .backup
        .clone()
        .context("backups are not configured; provide the complete AUTH_BACKUP_* environment")?;
    BackupStore::new(backup).await
}

async fn doctor(
    config: &Config,
    redis: redis::aio::ConnectionManager,
    store: &Store,
) -> Result<()> {
    let mut connection = store.connection();
    let pong: String = connection.ping().await.context("SableDB readiness check")?;
    if pong != "PONG" {
        anyhow::bail!("SableDB returned an unexpected readiness response");
    }
    let jwt = initialize_jwt(config, redis, store).await?;
    // Backup posture is reported here rather than on the public metadata endpoint:
    // whether backups exist and whether they are currently failing tells an
    // attacker how recoverable the deployment is before they try anything
    // destructive. `doctor` runs on the host, for an operator who already knows.
    let mut backup_alerting = false;
    let backup = match &config.backup {
        Some(_) => {
            let backup = configured_backup(config).await?;
            let count = backup.list(&config.tenant_id).await?.len();
            let status = backup.persisted_status(store).await?;
            backup_alerting = status.alerting;
            json!({
                "configured": true,
                "reachable": true,
                "objects": count,
                "lastAttemptAt": status.last_attempt_at,
                "lastSuccessAt": status.last_success_at,
                "consecutiveFailures": status.consecutive_failures,
                "rpoSeconds": status.rpo_seconds,
                "retentionDays": status.retention_days,
                "overdue": status.overdue,
                "alerting": status.alerting,
            })
        }
        None => json!({ "configured": false }),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": if backup_alerting { "degraded" } else { "ok" },
            "sabledb": "ready",
            "signingKeys": jwt.stored_status().await?,
            "backups": backup,
        }))?
    );
    if backup_alerting {
        anyhow::bail!(
            "backup health is alerting: recovery point overdue or failure threshold reached"
        );
    }
    Ok(())
}

/// Grants an operator role from the host.
///
/// Browser bootstrap requires an already-verified operator email, and nothing can
/// verify one until an operator exists to do it. This command breaks that cycle,
/// and deliberately costs shell access to the deployment rather than merely
/// control of an inbox.
///
/// It takes a user id, not an address. Resolving an address here would grant the
/// role to whichever account currently holds it, and any enrolled user can attach
/// an unclaimed address to themselves through the self-service API — so an
/// attacker who claims the allowlisted address first would receive Owner the
/// moment an administrator ran the promotion they were always going to run.
/// `operator find` exists so the administrator can see which account they are
/// about to promote, and when that account claimed the address.
async fn promote_operator(store: &Store, user_id: &str, role: &str) -> Result<()> {
    let role = match role {
        "owner" => OperatorRoleRecord::Owner,
        "administrator" => OperatorRoleRecord::Administrator,
        "support" => OperatorRoleRecord::Support,
        "auditor" => OperatorRoleRecord::Auditor,
        other => {
            anyhow::bail!("role must be owner, administrator, support or auditor, got {other}")
        }
    };
    let user_id = Uuid::parse_str(user_id.trim())
        .context("expected a user id; run `rustyauth operator find <email>` to look one up")?;
    let (operator, user) = store
        .promote_operator(user_id, role)
        .await
        .context("promote operator")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "userId": operator.user_id,
            "role": operator.role,
            "identifiers": identifier_summary(&user),
        }))?
    );
    Ok(())
}

/// Shows the accounts holding an address, so a promotion names an account the
/// administrator has actually looked at.
///
/// `claimedAt` and `verified` are the fields that matter: an operator address
/// claimed recently by an account nobody recognises is someone trying to be
/// promoted by the administrator's own hand.
async fn find_operator_candidates(store: &Store, email: &str) -> Result<()> {
    let identifier = IdentifierValue::canonical(IdentifierKind::Email, email)
        .context("operator email is not a valid address")?;
    let found = store
        .user_by_identifier(&identifier)
        .await
        .context("look up the address")?;
    let candidates = found
        .iter()
        .map(|user| {
            json!({
                "userId": user.id,
                "createdAt": user.created_at,
                "identifiers": identifier_summary(user),
            })
        })
        .collect::<Vec<_>>();
    println!("{}", serde_json::to_string_pretty(&candidates)?);
    Ok(())
}

fn identifier_summary(user: &crate::store::User) -> Vec<serde_json::Value> {
    user.identifiers
        .iter()
        .map(|identifier| {
            json!({
                "type": identifier.kind,
                "value": identifier.value,
                "verified": identifier.verified,
                "primary": identifier.primary,
                "claimedAt": identifier.created_at,
            })
        })
        .collect()
}

/// Removes an operator record.
async fn demote_operator(store: &Store, user_id: &str) -> Result<()> {
    let user_id = Uuid::parse_str(user_id.trim()).context("expected a user id")?;
    let removed = store
        .demote_operator(user_id)
        .await
        .context("remove operator")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({ "userId": user_id, "removed": removed }))?
    );
    Ok(())
}

async fn create_local_agent_handoff(
    config: &Config,
    store: Store,
    request: LocalAgentRequest,
) -> Result<()> {
    if config.environment != Environment::Development
        || config.issuer.host_str() != Some("localhost")
        || config.rp_origin.host_str() != Some("localhost")
    {
        anyhow::bail!("local agent handoff is disabled outside loopback development");
    }
    let redirect_url = validated_local_redirect(&config.rp_origin, request.redirect_url)?;
    let code = store
        .create_local_agent_handoff(&request.email, redirect_url, 60)
        .await
        .context("create one-use local agent handoff")?;
    let mut url = config
        .issuer
        .join("/v1/local-agent-handoff")
        .context("construct local handoff URL")?;
    url.query_pairs_mut().append_pair("code", &code);
    println!("{url}");
    Ok(())
}

fn validated_local_redirect(rp_origin: &url::Url, requested: Option<url::Url>) -> Result<String> {
    let requested = requested.unwrap_or_else(|| {
        let mut value = rp_origin.clone();
        value.set_fragment(Some("/dashboard"));
        value
    });
    if requested.origin() != rp_origin.origin()
        || requested.path() != "/"
        || requested.query().is_some()
        || requested.username() != ""
        || requested.password().is_some()
        || requested
            .fragment()
            .is_none_or(|fragment| !fragment.starts_with('/'))
    {
        anyhow::bail!("agent redirect must be a hash route on the configured loopback app origin");
    }
    Ok(requested.to_string())
}

pub fn container_healthcheck() -> Result<()> {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .context("connect to local health endpoint")?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut response = [0_u8; 128];
    let count = stream.read(&mut response)?;
    let status = std::str::from_utf8(&response[..count]).context("health response is not UTF-8")?;
    if !status.starts_with("HTTP/1.1 200") {
        anyhow::bail!("health endpoint returned a non-200 status");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_agent_cli_requires_an_existing_email_and_accepts_a_route() {
        let mode = parse_process_arguments(vec![
            "--local-agent-session".into(),
            "--email".into(),
            "Agent@Example.com".into(),
            "--redirect".into(),
            "http://localhost:5174/#/ownership".into(),
        ])
        .unwrap();
        let ProcessMode::LocalAgent(request) = mode else {
            panic!("expected local-agent mode");
        };
        assert_eq!(request.email, "agent@example.com");
        assert_eq!(
            request.redirect_url.unwrap().as_str(),
            "http://localhost:5174/#/ownership"
        );
    }

    #[test]
    fn operational_commands_are_explicit_and_restore_is_safe_by_default() {
        assert_eq!(
            parse_process_arguments(vec![
                "backup".into(),
                "restore".into(),
                "rustyauth-backups/v2/vtr/example.rauth".into(),
            ])
            .unwrap(),
            ProcessMode::BackupRestore {
                object_key: "rustyauth-backups/v2/vtr/example.rauth".into(),
                preserve_sessions: false,
            }
        );
        assert_eq!(
            parse_process_arguments(vec!["keys".into(), "rotate".into()]).unwrap(),
            ProcessMode::KeysRotate
        );
        assert_eq!(
            parse_process_arguments(vec![
                "fleet".into(),
                "pairing-code".into(),
                "https://fleet.example.com".into(),
                "5c9f24a2-9c62-4ff7-a2af-2adcf904cdf8".into(),
            ])
            .unwrap(),
            ProcessMode::FleetPairingCode {
                control_plane_origin: "https://fleet.example.com".into(),
                operator_user_id: "5c9f24a2-9c62-4ff7-a2af-2adcf904cdf8".into(),
            }
        );
    }

    #[test]
    fn local_agent_redirect_cannot_escape_the_configured_app() {
        let origin = url::Url::parse("http://localhost:5174").unwrap();
        let accepted = url::Url::parse("http://localhost:5174/#/tax").unwrap();
        assert_eq!(
            validated_local_redirect(&origin, Some(accepted)).unwrap(),
            "http://localhost:5174/#/tax"
        );
        let escaped = url::Url::parse("http://localhost:9999/#/tax").unwrap();
        assert!(validated_local_redirect(&origin, Some(escaped)).is_err());
    }
}
