//! RustyAuth process entry point and dependency composition root.
//!
//! Protocol handlers live in `auth`; durable state belongs to `store`; key
//! material and token issuance belong to `jwt`; the operator command line
//! lives in `cli`. This module only initializes those capabilities, applies
//! transport middleware, and owns process lifetime.

use std::{
    future::{Future, IntoFuture},
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    middleware,
    response::IntoResponse,
    routing::get,
};
use redis::AsyncCommands;
use secrecy::ExposeSecret;
use serde::Serialize;
use tokio::{net::TcpListener, sync::watch};
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::{SetSensitiveRequestHeadersLayer, SetSensitiveResponseHeadersLayer},
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{info, warn};
use webauthn_rs::WebauthnBuilder;
use zeroize::Zeroize;

use rustyauth::{
    analytics_store::GreptimeAnalyticsStore,
    app_state::AppState,
    auth,
    backup::BackupStore,
    cli::{self, CLI_HELP, ProcessMode},
    config::{
        Config, ConfigurationSummary, Environment, FLEET_CONFIGURATION_EXAMPLE,
        REALM_CONFIGURATION_EXAMPLE,
    },
    rate_limit::RateLimiter,
    request_timing::{BENCHMARK_TIMING_HEADER, benchmark_server_timing, benchmark_timing_digest},
    rpc,
    store::{Store, WriterLease},
    telemetry::run_telemetry_exporter,
    webhook::WebhookRuntime,
};

/// Ceiling on any single request. Long-lived RPC streams are served by the
/// fallback service, which applies its own deadline.
const REQUEST_TIMEOUT_SECONDS: u64 = 30;
/// Ceiling on a request body. The RPC layer applies a tighter 64 KiB limit; this
/// bounds the REST handlers, which otherwise inherit axum's 2 MiB default.
const MAX_REQUEST_BODY_BYTES: usize = 256 * 1024;
/// How long in-flight work may finish after a shutdown signal before the process
/// exits anyway. Without a bound, a single open event stream blocks every deploy.
const SHUTDOWN_GRACE_SECONDS: u64 = 20;
/// Distinct rate-limit subjects tracked at once. Bounds the memory a flood of
/// unique addresses or identifiers can cause the limiter itself to consume.
const RATE_LIMIT_TRACKING_CAPACITY: usize = 65_536;
/// Independent multiplexed connections let SableDB distribute request work
/// across its worker threads. Cloning one manager does not create a new TCP
/// connection and would leave every authenticated request behind one queue.
const STORE_CONNECTION_POOL_SIZE: usize = 4;

#[derive(Serialize)]
struct Health<'a> {
    status: &'a str,
}

/// Answers a panicking request without disclosing the panic message, which can
/// carry internal state, and records it for operators.
fn panic_response(panic: Box<dyn std::any::Any + Send + 'static>) -> http::Response<String> {
    let detail = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&'static str>().copied())
        .unwrap_or("unknown panic");
    tracing::error!(detail, "request handler panicked");
    http::Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"error":"authentication service failed closed"}"#.to_owned())
        .unwrap_or_else(|_| http::Response::new(String::new()))
}

/// HSTS is only meaningful over TLS, and pinning it from a development origin
/// would poison the browser for `http://localhost` well past the session.
fn hsts_layer(production: bool) -> SetResponseHeaderLayer<Option<HeaderValue>> {
    SetResponseHeaderLayer::if_not_present(
        header::STRICT_TRANSPORT_SECURITY,
        production
            .then(|| HeaderValue::from_static("max-age=63072000; includeSubDomains; preload")),
    )
}

#[derive(Serialize)]
struct Metadata<'a> {
    issuer: String,
    deployment_role: &'a str,
    passkeys: bool,
    event_protocols: [&'a str; 4],
    identity_protocols: [&'a str; 3],
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut arguments = std::env::args().skip(1).collect();
    let config_path = cli::extract_config_path(&mut arguments)?;
    let mode = cli::parse_process_arguments(arguments)?;
    if mode == ProcessMode::Help {
        println!("{CLI_HELP}");
        return Ok(());
    }
    if mode == ProcessMode::Healthcheck {
        return cli::container_healthcheck(healthcheck_port(config_path.as_deref())?);
    }
    if let ProcessMode::ConfigExample { kind } = &mode {
        print!(
            "{}",
            if kind == "fleet" {
                FLEET_CONFIGURATION_EXAMPLE
            } else {
                REALM_CONFIGURATION_EXAMPLE
            }
        );
        return Ok(());
    }
    if let ProcessMode::ConfigValidate { path } = &mode {
        let summary = validate_configuration(config_path.as_deref(), path.as_deref())?;
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }
    init_tracing();
    let config = load_configuration(config_path.as_deref())
        .await
        .context("invalid auth service configuration")?;
    info!(
        environment = ?config.environment,
        deployment_role = ?config.deployment_role,
        issuer = %config.issuer,
        "configuration accepted"
    );

    let redis_client = redis::Client::open(config.sabledb_url.expose_secret().to_owned())
        .context("create SableDB client")?;
    let redis = redis::aio::ConnectionManager::new_with_config(
        redis_client.clone(),
        redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(Duration::from_secs(3)))
            .set_response_timeout(Some(Duration::from_secs(3))),
    )
    .await
    .context("connect to SableDB")?;
    let mut store_connections = vec![redis.clone()];
    if mode == ProcessMode::Serve {
        for _ in 1..STORE_CONNECTION_POOL_SIZE {
            store_connections.push(
                redis::aio::ConnectionManager::new_with_config(
                    redis_client.clone(),
                    redis::aio::ConnectionManagerConfig::new()
                        .set_connection_timeout(Some(Duration::from_secs(3)))
                        .set_response_timeout(Some(Duration::from_secs(3))),
                )
                .await
                .context("connect SableDB request pool")?,
            );
        }
    }
    let store = Store::new_with_connections(store_connections, config.tenant_id.clone());
    store.ensure_restore_complete().await?;

    match mode {
        ProcessMode::Serve => {
            let writer_lease = store.acquire_writer_lease().await?;
            serve(config, redis, store, writer_lease).await
        }
        mode => {
            let writer_lease = if mode.requires_writer_lease() {
                Some(store.acquire_writer_lease().await?)
            } else {
                None
            };
            let result = cli::run(mode, config, redis, store).await;
            if let Some(lease) = writer_lease
                && let Err(error) = lease.release().await
            {
                warn!(error = %error, "release one-shot writer lease");
            }
            result
        }
    }
}

const DEFAULT_CONFIG_PATH: &str = "/etc/rustyauth/config.yaml";

/// Runtime precedence is explicit and deliberately short:
/// CLI path, inline platform YAML, platform file path, conventional container
/// mount, then the backwards-compatible environment-only contract.
async fn load_configuration(explicit_path: Option<&Path>) -> Result<Config> {
    if let Some(path) = explicit_path {
        return Config::from_file_runtime(path)
            .await
            .with_context(|| format!("load --config {}", path.display()));
    }
    let inline = nonempty_environment("RUSTYAUTH_CONFIG_YAML")?;
    let configured_path = nonempty_environment("RUSTYAUTH_CONFIG_FILE")?;
    if inline.is_some() && configured_path.is_some() {
        anyhow::bail!("configure either RUSTYAUTH_CONFIG_YAML or RUSTYAUTH_CONFIG_FILE, not both");
    }
    if let Some(yaml) = inline {
        return Config::from_yaml_runtime(&yaml, "RUSTYAUTH_CONFIG_YAML").await;
    }
    if let Some(path) = configured_path {
        return Config::from_file_runtime(Path::new(&path))
            .await
            .with_context(|| format!("load RUSTYAUTH_CONFIG_FILE {path}"));
    }
    if Path::new(DEFAULT_CONFIG_PATH).is_file() {
        return Config::from_file_runtime(Path::new(DEFAULT_CONFIG_PATH)).await;
    }
    Config::from_env_runtime().await
}

fn validate_configuration(
    explicit_path: Option<&Path>,
    positional_path: Option<&str>,
) -> Result<ConfigurationSummary> {
    if explicit_path.is_some() && positional_path.is_some() {
        anyhow::bail!("choose either --config <path> or config validate <path>, not both");
    }
    if positional_path == Some("-") {
        let mut yaml = String::new();
        std::io::stdin()
            .read_to_string(&mut yaml)
            .context("read YAML configuration from standard input")?;
        return Config::validate_yaml(&yaml, "standard input");
    }
    if let Some(path) = positional_path
        .map(PathBuf::from)
        .or_else(|| explicit_path.map(PathBuf::from))
    {
        return Config::validate_file(&path);
    }
    let inline = nonempty_environment("RUSTYAUTH_CONFIG_YAML")?;
    let configured_path = nonempty_environment("RUSTYAUTH_CONFIG_FILE")?;
    if inline.is_some() && configured_path.is_some() {
        anyhow::bail!("configure either RUSTYAUTH_CONFIG_YAML or RUSTYAUTH_CONFIG_FILE, not both");
    }
    if let Some(yaml) = inline {
        return Config::validate_yaml(&yaml, "RUSTYAUTH_CONFIG_YAML");
    }
    if let Some(path) = configured_path {
        return Config::validate_file(Path::new(&path));
    }
    if Path::new(DEFAULT_CONFIG_PATH).is_file() {
        return Config::validate_file(Path::new(DEFAULT_CONFIG_PATH));
    }
    anyhow::bail!(
        "no YAML configuration selected; pass a path, pipe YAML to `config validate -`, or set RUSTYAUTH_CONFIG_YAML/RUSTYAUTH_CONFIG_FILE"
    )
}

fn nonempty_environment(name: &str) -> Result<Option<String>> {
    std::env::var_os(name)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| anyhow::anyhow!("{name} contains non-Unicode data"))
        })
        .transpose()
        .map(|value| {
            value
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
}

fn healthcheck_port(explicit_path: Option<&Path>) -> Result<Option<u16>> {
    if let Some(port) = nonempty_environment("PORT")? {
        return port.parse::<u16>().context("PORT is invalid").map(Some);
    }
    let declarative_source_selected = explicit_path.is_some()
        || nonempty_environment("RUSTYAUTH_CONFIG_YAML")?.is_some()
        || nonempty_environment("RUSTYAUTH_CONFIG_FILE")?.is_some()
        || Path::new(DEFAULT_CONFIG_PATH).is_file();
    if !declarative_source_selected {
        return Ok(None);
    }
    Ok(Some(validate_configuration(explicit_path, None)?.port))
}

async fn serve(
    mut config: Config,
    redis: redis::aio::ConnectionManager,
    store: Store,
    writer_lease: WriterLease,
) -> Result<()> {
    let webauthn = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)
        .context("create WebAuthn relying-party configuration")?
        .rp_name(&config.rp_name)
        .build()
        .context("build WebAuthn relying party")?;
    let issuer = config.issuer.as_str().trim_end_matches('/').to_owned();
    let jwt = cli::initialize_jwt(&config, redis.clone(), &store).await?;
    store.ensure_organization(&config.rp_name).await?;
    let backup = match config.backup.clone() {
        Some(value) => Some(BackupStore::new(value).await?),
        None => {
            warn!("encrypted auth backups are disabled");
            None
        }
    };
    let analytics = match config.analytics.clone() {
        Some(value) => {
            let store = GreptimeAnalyticsStore::new(value)?;
            store.initialize().await?;
            Some(store)
        }
        None => None,
    };
    // Shared with the HTTP handlers so a client cannot spend one budget by
    // switching protocols.
    let rate_limiter = Arc::new(RateLimiter::distributed(
        redis.clone(),
        &config.tenant_id,
        RATE_LIMIT_TRACKING_CAPACITY,
    ));
    let service_instance_id = match config.deployment_role {
        rustyauth::config::DeploymentRole::Realm => config.realm_id.clone(),
        rustyauth::config::DeploymentRole::FleetControlPlane => config.tenant_id.clone(),
    };
    let webhook_runtime = if config.deployment_role == rustyauth::config::DeploymentRole::Realm {
        let runtime = WebhookRuntime::new(store.clone(), config.master_keys.clone())?;
        runtime.reconcile_configuration(&config.webhooks).await?;
        Some(runtime)
    } else {
        None
    };
    if config.deployment_role == rustyauth::config::DeploymentRole::Realm
        && let Err(error) = store
            .project_analytics_events(&config.realm_id, 10_000)
            .await
    {
        // Analytics is deliberately fail-open with respect to authentication.
        // The background worker retries from the last atomic source cursor.
        warn!(error = %error, "initial local analytics projection failed");
    }
    let rpc_service = rpc::service(rpc::RpcServiceConfig {
        store: store.clone(),
        event_token: &config.event_rpc_token,
        identity_token: &config.identity_rpc_token,
        rp_origin: config.rp_origin.as_str(),
        session_idle_seconds: config.session_idle_seconds,
        operator_emails: config.operator_emails.clone(),
        jwt: jwt.clone(),
        rate_limiter: Arc::clone(&rate_limiter),
        deployment_role: config.deployment_role,
        environment: config.environment.clone(),
        master_keys: config.master_keys.clone(),
        control_plane_instance_id: service_instance_id,
        issuer: config.issuer.to_string().trim_end_matches('/').to_owned(),
        rp_id: config.rp_id.clone(),
        webhook_runtime: webhook_runtime.clone(),
        backup: backup.clone(),
        analytics,
    });
    config.event_rpc_token.zeroize();
    config.identity_rpc_token.zeroize();

    let bind = (config.bind, config.port);
    let cors_origin = HeaderValue::from_str(config.rp_origin.as_str().trim_end_matches('/'))
        .context("WEBAUTHN_RP_ORIGIN cannot be represented as an Origin header")?;
    let state = AppState {
        rate_limiter,
        trusted_proxy_hops: config.trusted_proxy_hops,
        store: store.clone(),
        auth_telemetry: auth::AuthTelemetry::new(store.clone()),
        webauthn: Arc::new(webauthn),
        jwt,
        issuer,
        deployment_role: config.deployment_role,
        rp_origin: config.rp_origin.to_string(),
        bootstrap_token: config.bootstrap_token,
        session_idle_seconds: config.session_idle_seconds,
        session_absolute_seconds: config.session_absolute_seconds,
        secure_cookie: config.environment == Environment::Production,
        identity_verification_required: config.environment == Environment::Production,
        local_agent_handoffs_enabled: config.environment == Environment::Development,
        backup,
        webhook_runtime: webhook_runtime.clone(),
    };
    let benchmark_timing_digest = benchmark_timing_digest(state.bootstrap_token.expose_secret());
    let signing_worker = state.jwt.clone();
    let backup_worker = state.backup.clone();
    let connector_jwt = state.jwt.clone();
    let connector_backup = state.backup.clone();
    let webhook_worker = webhook_runtime;
    let analytics_realm_id = (config.deployment_role == rustyauth::config::DeploymentRole::Realm)
        .then(|| config.realm_id.clone());

    let request_id = HeaderName::from_static("x-request-id");
    let app = Router::new()
        .route("/healthz", get(live))
        .route("/readyz", get(ready))
        .route("/.well-known/passkey-auth", get(metadata))
        .merge(auth::routes())
        .with_state(state)
        .fallback_service(rpc_service);
    let app = apply_transport_policy(
        app,
        cors_origin,
        request_id,
        config.environment == Environment::Production,
        benchmark_timing_digest,
    );

    let listener = TcpListener::bind(bind)
        .await
        .context("bind auth listener")?;
    info!(address = %listener.local_addr()?, "passkey auth service listening");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let writer_task = tokio::spawn(run_writer_lease(
        writer_lease,
        shutdown_rx.clone(),
        shutdown_tx.clone(),
    ));
    let signing_task = tokio::spawn(signing_worker.run_maintenance(shutdown_rx.clone()));
    let webhook_task = webhook_worker.map(|runtime| tokio::spawn(runtime.run(shutdown_rx.clone())));
    let analytics_task = analytics_realm_id.map(|realm_id| {
        tokio::spawn(run_analytics_projector(
            store.clone(),
            realm_id,
            shutdown_rx.clone(),
        ))
    });
    let telemetry_export_task =
        (config.deployment_role == rustyauth::config::DeploymentRole::Realm).then(|| {
            tokio::spawn(run_telemetry_exporter(
                store.clone(),
                config.realm_id.clone(),
                connector_jwt,
                connector_backup,
                shutdown_rx.clone(),
            ))
        });
    let event_retention_task = tokio::spawn(run_event_retention(
        store.clone(),
        config.event_retention_seconds,
        shutdown_rx.clone(),
    ));
    let backup_task = backup_worker.map(|backup| {
        tokio::spawn(backup.run_scheduler(
            store.clone(),
            config.tenant_id.clone(),
            config.master_keys.clone(),
            shutdown_rx.clone(),
        ))
    });
    // ConnectInfo carries the peer address, which the rate limiter needs to
    // identify a client when no trusted proxy is configured.
    let server_shutdown = shutdown_rx.clone();
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_shutdown(server_shutdown))
    .into_future();
    tokio::pin!(server);
    let mut internal_shutdown = shutdown_rx.clone();
    let result = tokio::select! {
        result = &mut server => result.context("serve auth HTTP"),
        _ = shutdown_signal() => {
            let _ = shutdown_tx.send(true);
            bounded_server_shutdown(&mut server).await
        }
        _ = wait_for_shutdown_ref(&mut internal_shutdown) => {
            bounded_server_shutdown(&mut server).await
        }
    };
    let _ = shutdown_tx.send(true);

    // Both workers watch the shutdown channel and exit on their own. Give them a
    // bounded window to finish — a backup mid-upload should checkpoint rather than
    // die mid-write — then stop waiting so a stuck worker cannot block the deploy.
    let workers = async {
        let _ = writer_task.await;
        let _ = signing_task.await;
        if let Some(task) = backup_task {
            let _ = task.await;
        }
        if let Some(task) = webhook_task {
            let _ = task.await;
        }
        if let Some(task) = analytics_task {
            let _ = task.await;
        }
        if let Some(task) = telemetry_export_task {
            let _ = task.await;
        }
        let _ = event_retention_task.await;
    };
    if tokio::time::timeout(Duration::from_secs(SHUTDOWN_GRACE_SECONDS), workers)
        .await
        .is_err()
    {
        warn!(
            grace_seconds = SHUTDOWN_GRACE_SECONDS,
            "background workers did not stop within the shutdown grace period"
        );
    }
    result
}

async fn bounded_server_shutdown(
    server: &mut std::pin::Pin<&mut impl Future<Output = std::io::Result<()>>>,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(SHUTDOWN_GRACE_SECONDS), server)
        .await
        .context("HTTP server did not drain before the shutdown deadline")?
        .context("serve auth HTTP")
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    wait_for_shutdown_ref(&mut shutdown).await;
}

async fn wait_for_shutdown_ref(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

async fn run_writer_lease(
    lease: WriterLease,
    mut shutdown: watch::Receiver<bool>,
    shutdown_tx: watch::Sender<bool>,
) {
    const RENEW_INTERVAL_SECONDS: u64 = 10;
    let mut owns_lease = true;
    let mut interval = tokio::time::interval(Duration::from_secs(RENEW_INTERVAL_SECONDS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = interval.tick() => match lease.renew().await {
                Ok(true) => {}
                Ok(false) => {
                    owns_lease = false;
                    tracing::error!("RustyAuth writer lease was lost; stopping the server before another writer can overlap");
                    let _ = shutdown_tx.send(true);
                    break;
                }
                Err(error) => {
                    tracing::error!(error = %error, "RustyAuth writer lease could not be renewed; stopping the server");
                    let _ = shutdown_tx.send(true);
                    break;
                }
            },
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    if owns_lease && let Err(error) = lease.release().await {
        tracing::error!(error = %error, "release RustyAuth writer lease");
    }
}

async fn run_analytics_projector(
    store: Store,
    realm_id: String,
    mut shutdown: watch::Receiver<bool>,
) {
    const PROJECTION_BATCH: u64 = 10_000;
    const MAX_BATCHES_PER_TICK: usize = 5;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                for _ in 0..MAX_BATCHES_PER_TICK {
                    match store.project_analytics_events(&realm_id, PROJECTION_BATCH).await {
                        Ok(result) if result.events_scanned == PROJECTION_BATCH as usize => continue,
                        Ok(_) => break,
                        Err(error) => {
                            tracing::error!(error = %error, "local analytics projection failed");
                            break;
                        }
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

async fn run_event_retention(
    store: Store,
    retention_seconds: u64,
    mut shutdown: watch::Receiver<bool>,
) {
    const RETENTION_BATCH: usize = 10_000;
    let mut interval = tokio::time::interval(Duration::from_secs(3_600));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let cutoff = rustyauth::store::now().saturating_sub(retention_seconds);
                loop {
                    match store.prune_events_older_than(cutoff, RETENTION_BATCH).await {
                        Ok(removed) if removed == RETENTION_BATCH => continue,
                        Ok(_) => break,
                        Err(error) => {
                            tracing::error!(error = %error, "auth event retention pass failed");
                            break;
                        }
                    }
                }
                loop {
                    match store
                        .prune_webhook_deliveries_older_than(cutoff, RETENTION_BATCH)
                        .await
                    {
                        Ok(removed) if removed == RETENTION_BATCH => continue,
                        Ok(_) => break,
                        Err(error) => {
                            tracing::error!(error = %error, "webhook delivery retention pass failed");
                            break;
                        }
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

/// Applies transport policy: timeouts, limits, panic capture, tracing, CORS and
/// response security headers.
///
/// Extracted so the ordering can be exercised by a test. Ordering is the whole
/// point of this function and it is not verifiable by reading, because
/// `Router::layer` inverts the order these are written in.
fn apply_transport_policy(
    router: Router,
    cors_origin: HeaderValue,
    request_id: HeaderName,
    production: bool,
    benchmark_timing_digest: [u8; 32],
) -> Router {
    router
        // Layer order matters and is not the order these read in. `Router::layer`
        // makes each newly added layer the OUTERMOST one, so this list runs from
        // innermost to outermost. The layers that answer on their own — the timeout
        // and the panic capture — must sit INSIDE the header and CORS layers, or the
        // 408 and 500 they generate leave without CSP, nosniff, HSTS or
        // Access-Control-Allow-Origin, and a browser sees an opaque network error
        // instead of the status. The body limit only wraps the body, so its 413
        // surfaces from the extractor and is already inside these layers.
        //
        // Slow-body clients would otherwise hold a connection open indefinitely:
        // the RPC limits cap request size, never duration.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(REQUEST_TIMEOUT_SECONDS),
        ))
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
        // A panicking handler must cost one request, not the process.
        .layer(CatchPanicLayer::custom(panic_response))
        // Outside the panic layer, so a caught panic is still recorded against its
        // request span rather than after the span has been left.
        .layer(TraceLayer::new_for_http())
        // The timing layer is inert unless the caller presents the exact
        // benchmark capability. It sits inside request-id propagation so measured
        // responses retain the same correlation contract as ordinary traffic.
        .layer(middleware::from_fn(move |request, next| {
            benchmark_server_timing(request, next, benchmark_timing_digest)
        }))
        .layer(PropagateRequestIdLayer::new(request_id.clone()))
        // Outside the trace layer, so the span carries the id.
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
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
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        // Authentication, identity and Fleet responses can carry bearer or
        // operator-visible state. Public artifacts such as JWKS set their own
        // explicit cache policy, which `if_not_present` preserves.
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        // The dashboard is an admin surface served from this origin. It loads no
        // third-party code, so the policy can be strict enough that an injected
        // script has nowhere to run and nowhere to exfiltrate to.
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self'; \
                 img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; \
                 form-action 'self'; base-uri 'none'; object-src 'none'",
            ),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("cross-origin-resource-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("geolocation=(), camera=(), microphone=(), payment=()"),
        ))
        .layer(hsts_layer(production))
        // Outermost, so nothing below observes the raw values. Cookie carries the
        // operator session; x-bootstrap-token gates enrolment.
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
            header::COOKIE,
            HeaderName::from_static("x-bootstrap-token"),
            HeaderName::from_static(BENCHMARK_TIMING_HEADER),
        ]))
        .layer(SetSensitiveResponseHeadersLayer::new(std::iter::once(
            header::SET_COOKIE,
        )))
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

/// Public protocol discovery.
///
/// Deliberately says nothing about backups. Reporting whether backups exist, when
/// the last one succeeded, or whether they are currently failing tells an attacker
/// how recoverable the deployment is before they attempt anything destructive.
/// `doctor` and the operator dashboard carry that detail to authorized callers.
async fn metadata(State(state): State<AppState>) -> Json<Metadata<'static>> {
    let _ = &state.webauthn;
    Json(Metadata {
        issuer: state.issuer.to_string(),
        deployment_role: match state.deployment_role {
            rustyauth::config::DeploymentRole::Realm => "realm",
            rustyauth::config::DeploymentRole::FleetControlPlane => "fleetControlPlane",
        },
        passkeys: true,
        event_protocols: ["http-poll", "connect", "grpc-web", "grpc"],
        identity_protocols: ["connect", "grpc-web", "grpc"],
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
        .unwrap_or_else(|_| "rustyauth=info,tower_http=info".into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::routing::post;
    use http::Request;
    use tower::ServiceExt;

    /// Applies the real transport policy to a trivial router.
    ///
    /// The routes exist only to trigger each short-circuiting layer: a body limit
    /// rejection, a caught panic, and an ordinary success.
    fn policy_router(production: bool) -> Router {
        let router = Router::new()
            .route("/ok", get(|| async { "ok" }))
            .route(
                "/timed",
                get(|| async {
                    rustyauth::request_timing::record_sabledb_round_trip(Duration::from_millis(3));
                    "timed"
                }),
            )
            .route("/sink", post(|_: String| async { "accepted" }))
            .route(
                "/panic",
                get(|| async {
                    panic!("deliberate panic for the transport policy test");
                    #[allow(unreachable_code)]
                    ""
                }),
            );
        apply_transport_policy(
            router,
            HeaderValue::from_static("https://app.example.test"),
            HeaderName::from_static("x-request-id"),
            production,
            benchmark_timing_digest("benchmark-secret"),
        )
    }

    async fn response_for(request: Request<Body>, production: bool) -> http::Response<Body> {
        policy_router(production)
            .oneshot(request)
            .await
            .expect("the transport policy is infallible")
    }

    #[tokio::test]
    async fn internal_server_timing_is_secret_gated_and_splits_store_time() {
        let ordinary = response_for(
            Request::builder()
                .uri("/timed")
                .body(Body::empty())
                .unwrap(),
            true,
        )
        .await;
        assert!(ordinary.headers().get("server-timing").is_none());

        let measured = response_for(
            Request::builder()
                .uri("/timed")
                .header(
                    BENCHMARK_TIMING_HEADER,
                    hex::encode(benchmark_timing_digest("benchmark-secret")),
                )
                .body(Body::empty())
                .unwrap(),
            true,
        )
        .await;
        let timing = measured
            .headers()
            .get("server-timing")
            .and_then(|value| value.to_str().ok())
            .expect("authorized benchmark response has server timing");
        assert!(timing.contains("app;dur="), "{timing}");
        assert!(timing.contains("sabledb;dur=3."), "{timing}");
        assert!(timing.contains("1 round trips"), "{timing}");
        assert!(timing.contains("nonstore;dur="), "{timing}");
    }

    /// Every response leaves with the security headers, including the ones the
    /// middleware itself generates.
    ///
    /// This is ordering, not configuration: `Router::layer` makes the last-added
    /// layer outermost, so a timeout, body-limit or panic layer added after the
    /// header layers would short-circuit outside them and answer without any of
    /// these headers. Reading the chain does not reveal that; this does.
    #[tokio::test]
    async fn short_circuited_responses_still_carry_the_security_headers() {
        let oversized = Request::builder()
            .method(Method::POST)
            .uri("/sink")
            .body(Body::from("x".repeat(MAX_REQUEST_BODY_BYTES + 1)))
            .expect("request builds");

        let cases: Vec<(&str, http::Response<Body>)> = vec![
            (
                "success",
                response_for(
                    Request::builder().uri("/ok").body(Body::empty()).unwrap(),
                    true,
                )
                .await,
            ),
            ("body limit", response_for(oversized, true).await),
            (
                "caught panic",
                response_for(
                    Request::builder()
                        .uri("/panic")
                        .body(Body::empty())
                        .unwrap(),
                    true,
                )
                .await,
            ),
        ];

        for (label, response) in cases {
            let headers = response.headers();
            for name in [
                header::X_CONTENT_TYPE_OPTIONS,
                header::CACHE_CONTROL,
                header::CONTENT_SECURITY_POLICY,
                header::X_FRAME_OPTIONS,
                header::REFERRER_POLICY,
                header::STRICT_TRANSPORT_SECURITY,
            ] {
                assert!(
                    headers.contains_key(&name),
                    "{label} response is missing {name}"
                );
            }
        }
    }

    /// A panicking handler costs one request, not the process, and the response
    /// says nothing about the panic.
    #[tokio::test]
    async fn a_panicking_handler_returns_a_generic_error() {
        let response = response_for(
            Request::builder()
                .uri("/panic")
                .body(Body::empty())
                .unwrap(),
            true,
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body reads");
        let body = String::from_utf8_lossy(&body);
        assert!(
            !body.contains("deliberate panic"),
            "the panic message must not reach the client: {body}"
        );
    }

    /// HSTS instructs a browser to refuse plain HTTP to this host for two years.
    /// Emitting it from a loopback development origin would strand the developer.
    #[tokio::test]
    async fn hsts_is_production_only() {
        let request = || Request::builder().uri("/ok").body(Body::empty()).unwrap();
        assert!(
            response_for(request(), true)
                .await
                .headers()
                .contains_key(header::STRICT_TRANSPORT_SECURITY)
        );
        assert!(
            !response_for(request(), false)
                .await
                .headers()
                .contains_key(header::STRICT_TRANSPORT_SECURITY)
        );
    }
}
