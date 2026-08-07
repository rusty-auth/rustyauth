//! RustyAuth process entry point and dependency composition root.
//!
//! Protocol handlers live in `auth`; durable state belongs to `store`; key
//! material and token issuance belong to `jwt`. This module only initializes
//! those capabilities, applies transport middleware, and owns process lifetime.

mod app_state;
mod auth;
mod backup;
mod config;
mod event_rpc;
mod identity_rpc;
#[cfg(test)]
mod integration_tests;
mod jwt;
mod operator_auth;
mod organization_rpc;
mod rpc;
mod service_account_rpc;
mod store;

mod proto {
    connectrpc::include_generated!();
}

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use redis::AsyncCommands;
use secrecy::ExposeSecret;
use serde::Serialize;
use serde_json::json;
use tokio::{net::TcpListener, sync::watch};
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};
use tracing::{info, warn};
use webauthn_rs::WebauthnBuilder;
use zeroize::Zeroize;

use crate::{
    app_state::AppState,
    backup::BackupStore,
    config::{Config, Environment},
    jwt::{JwtIssuer, validate_snapshot_keyset},
    store::Store,
};

#[derive(Serialize)]
struct Health<'a> {
    status: &'a str,
}

#[derive(Serialize)]
struct Metadata<'a> {
    issuer: String,
    passkeys: bool,
    event_protocols: [&'a str; 4],
    identity_protocols: [&'a str; 3],
    backup_sink_configured: bool,
    scheduled_backups: bool,
    last_backup_at: Option<u64>,
    backup_healthy: Option<bool>,
}

#[derive(Debug, Eq, PartialEq)]
struct LocalAgentRequest {
    email: String,
    redirect_url: Option<url::Url>,
}

#[derive(Debug, Eq, PartialEq)]
enum ProcessMode {
    Help,
    Serve,
    Healthcheck,
    LocalAgent(LocalAgentRequest),
    BackupCreate,
    BackupList,
    BackupVerify {
        object_key: String,
    },
    BackupRestore {
        object_key: String,
        preserve_sessions: bool,
    },
    KeysStatus,
    KeysRotate,
    Doctor,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mode = parse_process_arguments(std::env::args().skip(1).collect())?;
    if mode == ProcessMode::Help {
        println!("{CLI_HELP}");
        return Ok(());
    }
    if mode == ProcessMode::Healthcheck {
        return container_healthcheck();
    }
    init_tracing();
    let config = Config::from_env().context("invalid auth service configuration")?;
    info!(environment = ?config.environment, issuer = %config.issuer, "configuration accepted");

    let redis_client = redis::Client::open(config.sabledb_url.expose_secret().to_owned())
        .context("create SableDB client")?;
    let redis = redis::aio::ConnectionManager::new_with_config(
        redis_client,
        redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(Duration::from_secs(3)))
            .set_response_timeout(Some(Duration::from_secs(3))),
    )
    .await
    .context("connect to SableDB")?;
    let store = Store::new(redis.clone(), config.tenant_id.clone());
    store.ensure_restore_complete().await?;

    match mode {
        ProcessMode::Serve => serve(config, redis, store).await,
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
        ProcessMode::Doctor => doctor(&config, redis, &store).await,
        ProcessMode::Help => unreachable!("help exits before configuration"),
        ProcessMode::Healthcheck => unreachable!("healthcheck exits before configuration"),
    }
}

async fn serve(
    mut config: Config,
    redis: redis::aio::ConnectionManager,
    store: Store,
) -> Result<()> {
    let webauthn = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)
        .context("create WebAuthn relying-party configuration")?
        .rp_name(&config.rp_name)
        .build()
        .context("build WebAuthn relying party")?;
    let issuer = config.issuer.as_str().trim_end_matches('/').to_owned();
    let jwt = initialize_jwt(&config, redis, &store).await?;
    store.ensure_organization(&config.rp_name).await?;
    let backup = match config.backup.clone() {
        Some(value) => Some(BackupStore::new(value).await?),
        None => {
            warn!("encrypted auth backups are disabled");
            None
        }
    };
    let rpc_service = rpc::service(
        store.clone(),
        &config.event_rpc_token,
        &config.identity_rpc_token,
        config.rp_origin.as_str(),
        config.session_idle_seconds,
        config.operator_emails.clone(),
        jwt.clone(),
    );
    config.event_rpc_token.zeroize();
    config.identity_rpc_token.zeroize();

    let bind = (config.bind, config.port);
    let cors_origin = HeaderValue::from_str(config.rp_origin.as_str().trim_end_matches('/'))
        .context("WEBAUTHN_RP_ORIGIN cannot be represented as an Origin header")?;
    let state = AppState {
        store: store.clone(),
        webauthn: Arc::new(webauthn),
        jwt,
        issuer,
        rp_origin: config.rp_origin.to_string(),
        bootstrap_token: config.bootstrap_token,
        session_idle_seconds: config.session_idle_seconds,
        session_absolute_seconds: config.session_absolute_seconds,
        secure_cookie: config.environment == Environment::Production,
        identity_verification_required: config.environment == Environment::Production,
        local_agent_handoffs_enabled: config.environment == Environment::Development,
        backup,
    };
    let signing_worker = state.jwt.clone();
    let backup_worker = state.backup.clone();

    let request_id = HeaderName::from_static("x-request-id");
    let dashboard_index = config.dashboard_dir.join("index.html");
    let dashboard_assets = config.dashboard_dir.join("assets");
    let dashboard_brand = config.dashboard_dir.join("brand");
    let dashboard_favicon = config.dashboard_dir.join("favicon.svg");
    let app = Router::new()
        .route("/healthz", get(live))
        .route("/readyz", get(ready))
        .route("/.well-known/passkey-auth", get(metadata))
        .route_service("/", ServeFile::new(dashboard_index.clone()))
        .route_service("/dashboard", ServeFile::new(dashboard_index))
        .nest_service("/assets", ServeDir::new(dashboard_assets))
        .nest_service("/brand", ServeDir::new(dashboard_brand))
        .route_service("/favicon.svg", ServeFile::new(dashboard_favicon))
        .merge(auth::routes())
        .with_state(state)
        .fallback_service(rpc_service)
        .layer(
            CorsLayer::new()
                .allow_origin(cors_origin)
                .allow_credentials(true)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    HeaderName::from_static("connect-protocol-version"),
                    HeaderName::from_static("connect-timeout-ms"),
                    HeaderName::from_static("grpc-accept-encoding"),
                    HeaderName::from_static("grpc-encoding"),
                    HeaderName::from_static("grpc-timeout"),
                    HeaderName::from_static("x-bootstrap-token"),
                    HeaderName::from_static("x-grpc-web"),
                    HeaderName::from_static("x-request-id"),
                    HeaderName::from_static("x-user-agent"),
                ]),
        )
        .layer(SetSensitiveRequestHeadersLayer::new(std::iter::once(
            header::AUTHORIZATION,
        )))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(PropagateRequestIdLayer::new(request_id.clone()))
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind(bind)
        .await
        .context("bind auth listener")?;
    info!(address = %listener.local_addr()?, "passkey auth service listening");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let signing_task = tokio::spawn(signing_worker.run_maintenance(shutdown_rx.clone()));
    let backup_task = backup_worker.map(|backup| {
        tokio::spawn(backup.run_scheduler(
            store,
            config.tenant_id.clone(),
            config.master_keys.clone(),
            shutdown_rx,
        ))
    });
    let signal = shutdown_tx.clone();
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            let _ = signal.send(true);
        })
        .await
        .context("serve auth HTTP");
    let _ = shutdown_tx.send(true);
    signing_task.abort();
    if let Some(task) = backup_task {
        task.abort();
    }
    result
}

async fn initialize_jwt(
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
    let backup = match &config.backup {
        Some(_) => {
            let backup = configured_backup(config).await?;
            let count = backup.list(&config.tenant_id).await?.len();
            json!({ "configured": true, "reachable": true, "objects": count })
        }
        None => json!({ "configured": false }),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "ok",
            "sabledb": "ready",
            "signingKeys": jwt.stored_status().await?,
            "backups": backup,
        }))?
    );
    Ok(())
}

fn parse_process_arguments(arguments: Vec<String>) -> Result<ProcessMode> {
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

const CLI_HELP: &str = "RustyAuth authentication and recovery service

Usage:
  passkey-auth-service
  passkey-auth-service doctor
  passkey-auth-service backup create
  passkey-auth-service backup list
  passkey-auth-service backup verify <object-key>
  passkey-auth-service backup restore <object-key> [--preserve-sessions]
  passkey-auth-service keys status
  passkey-auth-service keys rotate

Running without a command starts the HTTP service. Restore requires an empty SableDB namespace and
invalidates existing sessions unless --preserve-sessions is explicitly supplied.";

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

fn container_healthcheck() -> Result<()> {
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

async fn live() -> Json<Health<'static>> {
    Json(Health { status: "ok" })
}

async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    let mut connection = state.store.connection();
    let result: redis::RedisResult<String> = connection.ping().await;
    match result {
        Ok(value) if value == "PONG" => (StatusCode::OK, Json(Health { status: "ready" })),
        Ok(_) | Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Health {
                status: "not_ready",
            }),
        ),
    }
}

async fn metadata(State(state): State<AppState>) -> Json<Metadata<'static>> {
    let _ = &state.webauthn;
    let backup_status = match &state.backup {
        Some(backup) => Some(backup.status().await),
        None => None,
    };
    Json(Metadata {
        issuer: state.issuer.to_string(),
        passkeys: true,
        event_protocols: ["http-poll", "connect", "grpc-web", "grpc"],
        identity_protocols: ["connect", "grpc-web", "grpc"],
        backup_sink_configured: state.backup.is_some(),
        scheduled_backups: state.backup.is_some(),
        last_backup_at: backup_status
            .as_ref()
            .and_then(|status| status.last_success_at),
        backup_healthy: backup_status.as_ref().and_then(|status| {
            status
                .last_attempt_at
                .map(|_| status.last_success_at.is_some() && status.consecutive_failures == 0)
        }),
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "passkey_auth_service=info,tower_http=info".into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();
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
