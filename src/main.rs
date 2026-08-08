//! RustyAuth process entry point and dependency composition root.
//!
//! Protocol handlers live in `auth`; durable state belongs to `store`; key
//! material and token issuance belong to `jwt`; the operator command line
//! lives in `cli`. This module only initializes those capabilities, applies
//! transport middleware, and owns process lifetime.

use std::{sync::Arc, time::Duration};

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
use tokio::{net::TcpListener, sync::watch};
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::{SetSensitiveRequestHeadersLayer, SetSensitiveResponseHeadersLayer},
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{info, warn};
use webauthn_rs::WebauthnBuilder;
use zeroize::Zeroize;

use rustyauth::{
    app_state::AppState,
    auth,
    backup::BackupStore,
    cli::{self, CLI_HELP, ProcessMode},
    config::{Config, Environment},
    rate_limit::RateLimiter,
    rpc,
    store::Store,
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
    passkeys: bool,
    event_protocols: [&'a str; 4],
    identity_protocols: [&'a str; 3],
}

#[tokio::main]
async fn main() -> Result<()> {
    let mode = cli::parse_process_arguments(std::env::args().skip(1).collect())?;
    if mode == ProcessMode::Help {
        println!("{CLI_HELP}");
        return Ok(());
    }
    if mode == ProcessMode::Healthcheck {
        return cli::container_healthcheck();
    }
    init_tracing();
    let config = Config::from_env().context("invalid auth service configuration")?;
    info!(
        environment = ?config.environment,
        deployment_role = ?config.deployment_role,
        issuer = %config.issuer,
        "configuration accepted"
    );

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
        mode => cli::run(mode, config, redis, store).await,
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
    let jwt = cli::initialize_jwt(&config, redis, &store).await?;
    store.ensure_organization(&config.rp_name).await?;
    let backup = match config.backup.clone() {
        Some(value) => Some(BackupStore::new(value).await?),
        None => {
            warn!("encrypted auth backups are disabled");
            None
        }
    };
    // Shared with the HTTP handlers so a client cannot spend one budget by
    // switching protocols.
    let rate_limiter = Arc::new(RateLimiter::new(RATE_LIMIT_TRACKING_CAPACITY));
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
        .fallback_service(rpc_service);
    let app = apply_transport_policy(
        app,
        cors_origin,
        request_id,
        config.environment == Environment::Production,
    );

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
    // ConnectInfo carries the peer address, which the rate limiter needs to
    // identify a client when no trusted proxy is configured.
    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        let _ = signal.send(true);
    })
    .await
    .context("serve auth HTTP");
    let _ = shutdown_tx.send(true);

    // Both workers watch the shutdown channel and exit on their own. Give them a
    // bounded window to finish — a backup mid-upload should checkpoint rather than
    // die mid-write — then stop waiting so a stuck worker cannot block the deploy.
    let workers = async {
        let _ = signing_task.await;
        if let Some(task) = backup_task {
            let _ = task.await;
        }
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
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
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
        )
    }

    async fn response_for(request: Request<Body>, production: bool) -> http::Response<Body> {
        policy_router(production)
            .oneshot(request)
            .await
            .expect("the transport policy is infallible")
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
