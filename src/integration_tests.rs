//! HTTP-boundary and clean-room recovery coverage against real SableDB and S3 services.

use std::{env, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use redis::AsyncCommands;
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;
use webauthn_rs::WebauthnBuilder;

use crate::{
    app_state::AppState,
    auth,
    backup::BackupStore,
    config::{BackupConfig, KeyRing, SigningRotationConfig},
    jwt::{JwtIssuer, validate_snapshot_keyset},
    store::{
        AccountIdentifier, AccountProfile, IdentifierKind, IdentifierValue, Session, Store, User,
        now,
    },
};

#[tokio::test]
#[ignore = "requires the compose.integration.yaml services"]
async fn clean_room_backup_restore_and_rotation() -> Result<()> {
    let source_url = required("RUSTYAUTH_TEST_SOURCE_SABLEDB_URL")?;
    let destination_url = required("RUSTYAUTH_TEST_DESTINATION_SABLEDB_URL")?;
    let source_redis = connection(&source_url).await?;
    let destination_redis = connection(&destination_url).await?;
    flush(source_redis.clone()).await?;
    flush(destination_redis.clone()).await?;

    let tenant_id = format!("integration-{}", Uuid::new_v4());
    let source = Store::new(source_redis.clone(), tenant_id.clone());
    let destination = Store::new(destination_redis.clone(), tenant_id.clone());
    let master_keys = KeyRing::new("master", [31; 32], Vec::new())?;
    let rotation = rotation_config();
    let source_jwt = JwtIssuer::load_or_create(
        source_redis.clone(),
        master_keys.clone(),
        rotation.clone(),
        source.snapshot_gate(),
        "https://auth.integration.invalid".into(),
        "integration".into(),
        tenant_id.clone(),
        300,
    )
    .await?;
    let source_key = source_jwt.stored_status().await?.active_kid;

    let user_id = Uuid::new_v4();
    let email = "backup-integration@example.invalid";
    let current = now();
    let user = User {
        id: user_id,
        email: email.into(),
        email_verified: true,
        profile: AccountProfile::default(),
        identifiers: vec![AccountIdentifier {
            kind: IdentifierKind::Email,
            value: email.into(),
            verified: true,
            verified_at: Some(current),
            primary: true,
            created_at: current,
        }],
        session_version: 7,
        created_at: current,
        passkeys: Vec::new(),
    };
    let passkey_token = "integration-recent-passkey-session-token";
    let other_passkey_token = "integration-other-passkey-session-token";
    let agent_token = "integration-agent-session-token-0001";
    let stale_token = "integration-stale-passkey-session-token";
    let passkey_session = session(user_id, user.session_version, "passkey", current);
    let other_passkey_session = session(user_id, user.session_version, "passkey", current);
    let agent_session = session(user_id, user.session_version, "agent", current);
    let stale_session = session(
        user_id,
        user.session_version,
        "passkey",
        current.saturating_sub(301),
    );
    let mut source_connection = source_redis.clone();
    let mut seed = redis::pipe();
    seed.atomic()
        .set(
            format!("auth:user:{user_id}"),
            serde_json::to_string(&user)?,
        )
        .set(format!("auth:email:{email}"), user_id.to_string())
        .set(
            format!("auth:identifier:email:{email}"),
            user_id.to_string(),
        );
    for (token, value) in [
        (passkey_token, &passkey_session),
        (other_passkey_token, &other_passkey_session),
        (agent_token, &agent_session),
        (stale_token, &stale_session),
    ] {
        seed.set(session_key(token), serde_json::to_string(value)?)
            .arg("EX")
            .arg(3_600_u16);
    }
    let _: () = seed.query_async(&mut source_connection).await?;
    source
        .append_event("integration.seeded", Some(user_id))
        .await?;

    let origin = "http://localhost:3000";
    let webauthn_origin = Url::parse(origin)?;
    let webauthn = WebauthnBuilder::new("localhost", &webauthn_origin)?
        .rp_name("RustyAuth integration")
        .build()?;
    let app = auth::routes().with_state(AppState {
        store: source.clone(),
        webauthn: Arc::new(webauthn),
        jwt: source_jwt.clone(),
        issuer: "https://auth.integration.invalid".into(),
        rp_origin: origin.into(),
        bootstrap_token: SecretString::from("integration-bootstrap-token"),
        session_idle_seconds: 1_800,
        session_absolute_seconds: 3_600,
        secure_cookie: true,
        identity_verification_required: true,
        local_agent_handoffs_enabled: false,
        backup: None,
    });

    assert_status(
        request(
            &app,
            Method::GET,
            "/v1/account",
            passkey_token,
            Some(origin),
            None,
        )
        .await?,
        StatusCode::OK,
    );
    assert_status(
        request(&app, Method::GET, "/v1/account", passkey_token, None, None).await?,
        StatusCode::UNAUTHORIZED,
    );
    assert_status(
        request(
            &app,
            Method::GET,
            "/v1/account",
            passkey_token,
            Some("https://attacker.invalid"),
            None,
        )
        .await?,
        StatusCode::UNAUTHORIZED,
    );
    assert_status(
        request(
            &app,
            Method::GET,
            "/v1/account",
            agent_token,
            Some(origin),
            None,
        )
        .await?,
        StatusCode::OK,
    );

    let phone_input = json!({ "type": "phone", "value": "+44 (7700) 900-123" });
    for token in [agent_token, stale_token] {
        assert_status(
            request(
                &app,
                Method::POST,
                "/v1/account/identifiers",
                token,
                Some(origin),
                Some(phone_input.clone()),
            )
            .await?,
            StatusCode::UNAUTHORIZED,
        );
    }
    assert_status(
        request(
            &app,
            Method::POST,
            "/v1/account/identifiers",
            passkey_token,
            Some(origin),
            Some(json!({ "type": "phone", "value": "07700 900123" })),
        )
        .await?,
        StatusCode::BAD_REQUEST,
    );
    let added = request(
        &app,
        Method::POST,
        "/v1/account/identifiers",
        passkey_token,
        Some(origin),
        Some(phone_input),
    )
    .await?;
    assert_eq!(added.0, StatusCode::CREATED, "unexpected body: {}", added.1);
    assert!(added.1["identifiers"].as_array().is_some_and(|values| {
        values.iter().any(|value| {
            value["type"] == "phone"
                && value["value"] == "+447700900123"
                && value["verified"] == false
        })
    }));

    let phone = IdentifierValue {
        kind: IdentifierKind::Phone,
        value: "+447700900123".into(),
    };
    let primary = request(
        &app,
        Method::POST,
        "/v1/account/identifiers/primary",
        passkey_token,
        Some(origin),
        Some(json!({ "type": "phone", "value": "+447700900123" })),
    )
    .await?;
    assert_eq!(primary.0, StatusCode::OK, "unexpected body: {}", primary.1);
    let primary_user = source
        .user(user_id)
        .await?
        .context("source user vanished")?;
    assert_eq!(
        primary_user
            .primary_identifier()
            .map(|value| value.value.as_str()),
        Some(phone.value.as_str())
    );
    let phone_user = source
        .user_by_identifier(&phone)
        .await?
        .context("phone identifier did not resolve its account")?;
    assert_eq!(phone_user.id, user_id);
    assert_eq!(
        phone_user
            .primary_identifier()
            .map(|value| value.value.as_str()),
        Some(phone.value.as_str())
    );

    assert_status(
        request(
            &app,
            Method::POST,
            "/v1/account/profile",
            agent_token,
            Some(origin),
            Some(json!({ "givenName": "Mallory" })),
        )
        .await?,
        StatusCode::UNAUTHORIZED,
    );
    assert_status(
        request(
            &app,
            Method::POST,
            "/v1/account/profile",
            passkey_token,
            Some(origin),
            Some(json!({ "displayName": "safe\u{202e}name" })),
        )
        .await?,
        StatusCode::BAD_REQUEST,
    );
    let profile = request(
        &app,
        Method::POST,
        "/v1/account/profile",
        passkey_token,
        Some(origin),
        Some(json!({
            "givenName": " Ada ",
            "familyName": " Lovelace ",
            "displayName": " Countess of Lovelace "
        })),
    )
    .await?;
    assert_eq!(profile.0, StatusCode::OK, "unexpected body: {}", profile.1);
    assert_eq!(profile.1["profile"]["givenName"], "Ada");
    assert_eq!(profile.1["profile"]["familyName"], "Lovelace");

    for token in [agent_token, stale_token] {
        assert_status(
            request(
                &app,
                Method::POST,
                "/v1/passkeys/registration/add/options",
                token,
                Some(origin),
                Some(json!({ "label": "Recovery key" })),
            )
            .await?,
            StatusCode::UNAUTHORIZED,
        );
    }
    let add_passkey = request(
        &app,
        Method::POST,
        "/v1/passkeys/registration/add/options",
        passkey_token,
        Some(origin),
        Some(json!({ "label": "Recovery key" })),
    )
    .await?;
    assert_eq!(
        add_passkey.0,
        StatusCode::OK,
        "unexpected body: {}",
        add_passkey.1
    );
    let ceremony_id = add_passkey.1["ceremonyId"]
        .as_str()
        .context("add-passkey response omitted ceremonyId")?;
    assert_status(
        request(
            &app,
            Method::POST,
            "/v1/passkeys/registration/add/verify",
            other_passkey_token,
            Some(origin),
            Some(json!({
                "ceremonyId": ceremony_id,
                "response": {
                    "id": "synthetic",
                    "rawId": "AA",
                    "response": {
                        "attestationObject": "AA",
                        "clientDataJSON": "AA"
                    },
                    "type": "public-key"
                }
            })),
        )
        .await?,
        StatusCode::UNAUTHORIZED,
    );
    assert_status(
        request(
            &app,
            Method::POST,
            "/v1/credentials/rename",
            agent_token,
            Some(origin),
            Some(json!({ "credentialId": "synthetic", "label": "Owned" })),
        )
        .await?,
        StatusCode::UNAUTHORIZED,
    );

    let backup = BackupStore::new(backup_config([41; 32], Vec::new())?).await?;
    let receipt = backup.create(&source, &tenant_id, &master_keys).await?;
    let snapshot = backup.download(&receipt.object_key, &tenant_id).await?;
    validate_snapshot_keyset(snapshot.signing_keyset()?, &master_keys)?;
    assert_eq!(snapshot.snapshot_id(), receipt.snapshot_id);
    assert!(
        backup
            .list(&tenant_id)
            .await?
            .iter()
            .any(|object| object.key == receipt.object_key)
    );

    let rolled_backup = BackupStore::new(backup_config([42; 32], vec![[41; 32]])?).await?;
    assert_eq!(
        rolled_backup
            .download(&receipt.object_key, &tenant_id)
            .await?
            .snapshot_id(),
        receipt.snapshot_id
    );

    let restored = destination
        .restore_records(snapshot.records(), false)
        .await?;
    assert!(restored > 0);
    assert!(destination.ensure_restore_complete().await.is_err());
    let destination_jwt = JwtIssuer::load_or_create(
        destination_redis.clone(),
        master_keys,
        rotation,
        destination.snapshot_gate(),
        "https://auth.integration.invalid".into(),
        "integration".into(),
        tenant_id.clone(),
        300,
    )
    .await?;
    let restored_status = destination_jwt.force_rotate(true).await?;
    assert_ne!(restored_status.active_kid, source_key);
    destination.append_event("recovery.restored", None).await?;
    destination.complete_restore().await?;
    destination.ensure_restore_complete().await?;

    let restored_user = destination
        .user(user_id)
        .await?
        .context("restored user is missing")?;
    assert_eq!(restored_user.session_version, 8);
    assert_eq!(restored_user.identifiers.len(), 2);
    assert_eq!(
        restored_user
            .primary_identifier()
            .map(|identifier| identifier.value.as_str()),
        Some(phone.value.as_str())
    );
    assert_eq!(restored_user.profile.given_name.as_deref(), Some("Ada"));
    assert_eq!(
        restored_user.profile.display_name.as_deref(),
        Some("Countess of Lovelace")
    );
    let email_identifier = IdentifierValue {
        kind: IdentifierKind::Email,
        value: email.into(),
    };
    let remaining = destination
        .remove_identifier(user_id, &email_identifier)
        .await?;
    assert_eq!(remaining.identifiers.len(), 1);
    assert!(destination.user_by_email(email).await?.is_none());
    assert!(
        destination
            .remove_identifier(user_id, &phone)
            .await
            .is_err()
    );
    let mut destination_connection = destination_redis.clone();
    let restored_session: Option<String> = destination_connection
        .get(session_key(passkey_token))
        .await?;
    assert!(restored_session.is_none());
    let event_sequence: u64 = destination_connection.get("auth:event-sequence").await?;
    assert_eq!(event_sequence, 7);
    assert!(
        destination
            .restore_records(snapshot.records(), false)
            .await
            .is_err()
    );

    flush(source_redis).await?;
    flush(destination_redis).await?;
    Ok(())
}

fn session(user_id: Uuid, session_version: u64, auth_method: &str, created_at: u64) -> Session {
    Session {
        id: Uuid::new_v4(),
        user_id,
        auth_method: auth_method.into(),
        current_credential_id: None,
        session_version,
        created_at,
        last_seen_at: now(),
        absolute_expires_at: now() + 3_600,
    }
}

fn session_key(token: &str) -> String {
    format!("auth:session:{:x}", Sha256::digest(token.as_bytes()))
}

async fn request(
    app: &Router,
    method: Method,
    uri: &str,
    token: &str,
    origin: Option<&str>,
    body: Option<Value>,
) -> Result<(StatusCode, Value)> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    builder = builder.header(header::COOKIE, format!("passkey_auth_session={token}"));
    let body = if let Some(value) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(serde_json::to_vec(&value)?)
    } else {
        Body::empty()
    };
    let response = app.clone().oneshot(builder.body(body)?).await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_048_576).await?;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).context("decode integration HTTP response")?
    };
    Ok((status, body))
}

fn assert_status(response: (StatusCode, Value), expected: StatusCode) {
    assert_eq!(response.0, expected, "unexpected body: {}", response.1);
}

fn rotation_config() -> SigningRotationConfig {
    SigningRotationConfig {
        rotation_seconds: 2_592_000,
        prepublish_seconds: 600,
        overlap_seconds: 600,
        maintenance_seconds: 30,
    }
}

fn backup_config(active: [u8; 32], previous: Vec<[u8; 32]>) -> Result<BackupConfig> {
    Ok(BackupConfig {
        endpoint: Url::parse(&required("RUSTYAUTH_TEST_S3_ENDPOINT")?)?,
        region: "us-east-1".into(),
        bucket: required("RUSTYAUTH_TEST_S3_BUCKET")?,
        access_key_id: SecretString::from(required("RUSTYAUTH_TEST_S3_ACCESS_KEY")?),
        secret_access_key: SecretString::from(required("RUSTYAUTH_TEST_S3_SECRET_KEY")?),
        encryption_keys: KeyRing::new("backup", active, previous)?,
        force_path_style: true,
        interval_seconds: 21_600,
    })
}

async fn connection(value: &str) -> Result<redis::aio::ConnectionManager> {
    let client = redis::Client::open(value).context("create integration SableDB client")?;
    redis::aio::ConnectionManager::new(client)
        .await
        .context("connect to integration SableDB")
}

async fn flush(mut connection: redis::aio::ConnectionManager) -> Result<()> {
    redis::cmd("FLUSHDB")
        .arg("ASYNC")
        .query_async::<()>(&mut connection)
        .await
        .context("flush dedicated integration SableDB")
}

fn required(name: &str) -> Result<String> {
    env::var(name).with_context(|| format!("integration environment variable {name} is missing"))
}
