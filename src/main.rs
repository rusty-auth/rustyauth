mod auth;
mod backup;
mod config;
mod jwt;
mod store;

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
use secrecy::SecretString;
use serde::Serialize;
use tokio::net::TcpListener;
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};
use tracing::{info, warn};
use webauthn_rs::{Webauthn, WebauthnBuilder};
use zeroize::Zeroize;

use crate::{
    backup::BackupStore,
    config::{Config, Environment},
    jwt::JwtIssuer,
    store::Store,
};

#[derive(Clone)]
pub(crate) struct AppState {
    store: Store,
    webauthn: Arc<Webauthn>,
    jwt: JwtIssuer,
    issuer: String,
    rp_origin: String,
    bootstrap_token: SecretString,
    session_idle_seconds: u64,
    session_absolute_seconds: u64,
    secure_cookie: bool,
    email_verification_required: bool,
    local_agent_handoffs_enabled: bool,
    backup: Option<BackupStore>,
}

#[derive(Serialize)]
struct Health<'a> {
    status: &'a str,
}

#[derive(Serialize)]
struct Metadata<'a> {
    issuer: String,
    passkeys: bool,
    event_protocols: [&'a str; 1],
    backup_sink_configured: bool,
    scheduled_backups: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct LocalAgentRequest {
    email: String,
    redirect_url: Option<url::Url>,
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--healthcheck") {
        return container_healthcheck();
    }
    init_tracing();
    let mut config = Config::from_env().context("invalid auth service configuration")?;
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

    if let Some(request) = local_agent_request()? {
        return create_local_agent_handoff(&config, redis, request).await;
    }

    let webauthn = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)
        .context("create WebAuthn relying-party configuration")?
        .rp_name(&config.rp_name)
        .build()
        .context("build WebAuthn relying party")?;
    let issuer = config.issuer.as_str().trim_end_matches('/').to_owned();
    let jwt = JwtIssuer::load_or_create(
        redis.clone(),
        &config.master_key,
        issuer.clone(),
        config.audience.clone(),
        config.tenant_id.clone(),
        config.access_token_seconds,
    )
    .await
    .context("initialize JWT signing key")?;
    let backup = match config.backup.take() {
        Some(value) => Some(BackupStore::new(value).await?),
        None => {
            warn!("encrypted auth backups are disabled");
            None
        }
    };

    let bind = (config.bind, config.port);
    let cors_origin = HeaderValue::from_str(config.rp_origin.as_str().trim_end_matches('/'))
        .context("WEBAUTHN_RP_ORIGIN cannot be represented as an Origin header")?;
    let state = AppState {
        store: Store::new(redis, config.tenant_id),
        webauthn: Arc::new(webauthn),
        jwt,
        issuer,
        rp_origin: config.rp_origin.to_string(),
        bootstrap_token: config.bootstrap_token,
        session_idle_seconds: config.session_idle_seconds,
        session_absolute_seconds: config.session_absolute_seconds,
        secure_cookie: config.environment == Environment::Production,
        email_verification_required: config.environment == Environment::Production,
        local_agent_handoffs_enabled: config.environment == Environment::Development,
        backup,
    };
    config.master_key.zeroize();

    let request_id = HeaderName::from_static("x-request-id");
    let app = Router::new()
        .route("/healthz", get(live))
        .route("/readyz", get(ready))
        .route("/.well-known/passkey-auth", get(metadata))
        .merge(auth::routes())
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(cors_origin)
                .allow_credentials(true)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([
                    header::CONTENT_TYPE,
                    HeaderName::from_static("x-bootstrap-token"),
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
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve auth HTTP")?;
    Ok(())
}

fn local_agent_request() -> Result<Option<LocalAgentRequest>> {
    parse_local_agent_arguments(std::env::args().skip(1).collect())
}

fn parse_local_agent_arguments(arguments: Vec<String>) -> Result<Option<LocalAgentRequest>> {
    if arguments.first().map(String::as_str) != Some("--local-agent-session") {
        return Ok(None);
    }
    if !matches!(arguments.len(), 3 | 5)
        || arguments[1] != "--email"
        || (arguments.len() == 5 && arguments[3] != "--redirect")
    {
        anyhow::bail!(
            "usage: passkey-auth-service --local-agent-session --email <existing-email> [--redirect <loopback-spa-url>]"
        );
    }
    let email = arguments[2].trim().to_ascii_lowercase();
    if email.len() > 320 || !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
        anyhow::bail!("valid existing account email required");
    }
    let redirect_url = arguments
        .get(4)
        .map(|value| url::Url::parse(value).context("agent redirect is not a valid URL"))
        .transpose()?;
    Ok(Some(LocalAgentRequest {
        email,
        redirect_url,
    }))
}

async fn create_local_agent_handoff(
    config: &Config,
    redis: redis::aio::ConnectionManager,
    request: LocalAgentRequest,
) -> Result<()> {
    if config.environment != Environment::Development
        || config.issuer.host_str() != Some("localhost")
        || config.rp_origin.host_str() != Some("localhost")
    {
        anyhow::bail!("local agent handoff is disabled outside loopback development");
    }
    let store = Store::new(redis, config.tenant_id.clone());
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
    Json(Metadata {
        issuer: state.issuer.to_string(),
        passkeys: true,
        event_protocols: ["http-poll"],
        backup_sink_configured: state.backup.is_some(),
        scheduled_backups: false,
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
        let request = parse_local_agent_arguments(vec![
            "--local-agent-session".into(),
            "--email".into(),
            "Agent@Example.com".into(),
            "--redirect".into(),
            "http://localhost:5174/#/ownership".into(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(request.email, "agent@example.com");
        assert_eq!(
            request.redirect_url.unwrap().as_str(),
            "http://localhost:5174/#/ownership"
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
