//! HTTP-boundary and clean-room recovery coverage against real SableDB and S3 services.

use std::{env, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Method, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use buffa::Message;
use redis::AsyncCommands;
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;
use webauthn_rs::WebauthnBuilder;

use rustyauth::{
    app_state::AppState,
    auth,
    backup::BackupStore,
    config::{BackupConfig, BackupServerSideEncryption, KeyRing, SigningRotationConfig},
    jwt::{JwtIssuer, validate_snapshot_keyset},
    proto::rustyauth::analytics::v1::{
        BucketAcknowledgementStatus, MetricSchemaVersion, SessionTokenMetrics, TelemetryBucket,
        TelemetryBucketBatch,
    },
    rate_limit::RateLimiter,
    store::{
        AccountIdentifier, AccountProfile, EncryptedFleetCredential, FleetAnalyticsPolicyRecord,
        FleetAnalyticsResidencyRecord, FleetConnectionModeRecord, FleetConnectionRecord,
        FleetConnectionStateRecord, FleetEnvironmentKindRecord, FleetResourceKindRecord,
        FleetRoleRecord, IdentifierKind, IdentifierValue, RemoteMutationClaim, Session, Store,
        TelemetryOutboxRecord, User, now,
    },
};

const PRODUCTION_SESSION_COOKIE: &str = "__Host-Http-rustyauth_session";

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
        recovery_codes: Vec::new(),
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
        rate_limiter: Arc::new(RateLimiter::new(1_024)),
        trusted_proxy_hops: 0,
        store: source.clone(),
        webauthn: Arc::new(webauthn),
        jwt: source_jwt.clone(),
        issuer: "https://auth.integration.invalid".into(),
        deployment_role: rustyauth::config::DeploymentRole::Realm,
        rp_origin: origin.into(),
        bootstrap_token: SecretString::from("integration-bootstrap-token"),
        session_idle_seconds: 1_800,
        session_absolute_seconds: 3_600,
        secure_cookie: true,
        identity_verification_required: true,
        local_agent_handoffs_enabled: false,
        backup: None,
        webhook_runtime: None,
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

/// M10 exit gate: a realm can be disconnected for one complete retention
/// window, restart on the same durable outbox, retry ambiguously, and converge
/// to one logical central revision without touching the authentication log.
#[tokio::test]
#[ignore = "requires the compose.integration.yaml SableDB service"]
async fn telemetry_survives_24_hour_outage_restart_and_exact_replay() -> Result<()> {
    let database_url = required("RUSTYAUTH_TEST_SOURCE_SABLEDB_URL")?;
    let redis = connection(&database_url).await?;
    flush(redis.clone()).await?;
    let realm_id = "qualification-realm";
    let realm = Store::new(redis.clone(), "qualification-realm-store".into());
    let fleet = Store::new(redis.clone(), "qualification-fleet-store".into());
    let connection_id = Uuid::new_v4();
    let connection = FleetConnectionRecord {
        id: connection_id,
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        environment_id: Uuid::new_v4(),
        realm_id: realm_id.into(),
        assignment_epoch: 1,
        display_name: "Qualification realm".into(),
        mode: FleetConnectionModeRecord::OutboundConnector,
        management_endpoint: "http://127.0.0.1:1".into(),
        credential: EncryptedFleetCredential {
            wrapping_key_id: "unused-in-ledger-test".into(),
            nonce: String::new(),
            ciphertext: String::new(),
        },
        credential_hint: String::new(),
        staged_credential: None,
        staged_credential_hint: None,
        credential_rotation_request_id: None,
        deployment_version: env!("CARGO_PKG_VERSION").into(),
        protocol_version: "1".into(),
        capabilities: vec![("telemetry.rollups.v1".into(), 1)],
        granted_scopes: vec!["realm.read".into(), "telemetry.export".into()],
        issuer: "https://qualification.invalid".into(),
        rp_id: "qualification.invalid".into(),
        state: FleetConnectionStateRecord::Healthy,
        last_seen_at: None,
        created_at: now(),
        updated_at: now(),
        revoked_at: None,
    };
    let mut policy_database = redis.clone();
    let _: () = policy_database
        .set(
            format!("fleet:analytics-policy:{}", connection.organization_id),
            serde_json::to_string(&FleetAnalyticsPolicyRecord {
                organization_id: connection.organization_id,
                enabled: true,
                canonical_retention_days: 35,
                residency: FleetAnalyticsResidencyRecord::RollupsOnly,
                max_buckets_per_minute_per_realm: 2_880,
                updated_at: now(),
                updated_by: None,
            })?,
        )
        .await?;

    // Five-minute snapshots for exactly 24 hours accumulate while Fleet is
    // unreachable. Authentication continues to append to its own durable log.
    let mut database = redis.clone();
    let first_bucket_start = now().saturating_sub(24 * 60 * 60 + 600) / 300 * 300;
    for index in 0_u64..288 {
        let start_seconds = first_bucket_start + index * 300;
        let batch_id = Uuid::new_v4();
        let batch = TelemetryBucketBatch {
            transport_schema_version: 1,
            batch_id: batch_id.to_string(),
            realm_id: realm_id.into(),
            buckets: vec![TelemetryBucket {
                realm_id: realm_id.into(),
                assignment_epoch: 1,
                bucket_start_unix_milliseconds: (start_seconds * 1_000) as i64,
                bucket_width_seconds: 300,
                revision: 1,
                first_event_sequence: index + 1,
                last_event_sequence: index + 1,
                metric_schema_version: MetricSchemaVersion::V1.into(),
                closed: true,
                sessions_and_tokens: SessionTokenMetrics::default().into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        rustyauth::analytics::validate_batch(&batch)?;
        let record = TelemetryOutboxRecord {
            bucket_start: start_seconds,
            revision: 1,
            batch_id,
            payload_base64url: URL_SAFE_NO_PAD.encode(batch.encode_to_vec()),
            first_queued_at: now(),
            attempts: 12,
            next_attempt_at: 0,
        };
        let _: () = database
            .set(
                format!("analytics:outbox:{start_seconds:020}:{:020}", 1),
                serde_json::to_string(&record)?,
            )
            .await?;
    }
    let auth_event = realm
        .append_event("qualification.authentication.completed", None)
        .await?;
    assert_eq!(realm.telemetry_outbox(289).await?.len(), 288);

    // A process restart reconstructs no in-memory queue; the same 288 records
    // are read from SableDB. Sending each twice models a lost first ACK.
    let restarted = Store::new(redis.clone(), "qualification-realm-store".into());
    let queued = restarted.telemetry_outbox(288).await?;
    assert_eq!(queued.len(), 288);
    for record in queued {
        let batch = rustyauth::analytics::decode_and_validate_batch(&record.payload()?)?;
        let accepted = fleet
            .accept_fleet_telemetry_batch(&connection, &batch)
            .await?;
        assert_eq!(
            accepted.buckets[0].status.as_known(),
            Some(BucketAcknowledgementStatus::Accepted)
        );
        let retried = fleet
            .accept_fleet_telemetry_batch(&connection, &batch)
            .await?;
        assert_eq!(
            retried.buckets[0].status.as_known(),
            Some(BucketAcknowledgementStatus::AlreadyAccepted)
        );
        assert!(
            restarted
                .acknowledge_telemetry_bucket(record.bucket_start, record.revision)
                .await?
        );
    }
    assert!(restarted.telemetry_outbox(288).await?.is_empty());
    assert_eq!(
        realm
            .events(auth_event.sequence.saturating_sub(1), 1)
            .await?[0]
            .id,
        auth_event.id,
        "telemetry outage and replay must not alter authentication durability"
    );

    // An old acknowledgement can remove only its exact old revision.
    let old_start = 1_900_000_000_u64;
    for revision in [1_u64, 2] {
        let record = TelemetryOutboxRecord {
            bucket_start: old_start,
            revision,
            batch_id: Uuid::new_v4(),
            payload_base64url: String::new(),
            first_queued_at: now(),
            attempts: 0,
            next_attempt_at: 0,
        };
        let _: () = database
            .set(
                format!("analytics:outbox:{old_start:020}:{revision:020}"),
                serde_json::to_string(&record)?,
            )
            .await?;
    }
    assert!(restarted.acknowledge_telemetry_bucket(old_start, 1).await?);
    let remaining = restarted.telemetry_outbox(2).await?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].revision, 2);

    flush(redis).await?;
    Ok(())
}

/// M2 exit gate: hierarchy IDs do not grant access or let a caller cross an
/// organization boundary, while inherited roles stay inside their ancestors.
#[tokio::test]
#[ignore = "requires the compose.integration.yaml SableDB service"]
async fn fleet_hierarchy_rejects_cross_organization_and_project_access() -> Result<()> {
    let database_url = required("RUSTYAUTH_TEST_SOURCE_SABLEDB_URL")?;
    let redis = connection(&database_url).await?;
    flush(redis.clone()).await?;
    let store = Store::new(redis.clone(), "fleet-isolation-qualification".into());
    let owner = Uuid::new_v4();
    let delegated_operator = Uuid::new_v4();

    let organization_a = store
        .create_fleet_organization(
            "organization-a".into(),
            "Organization A".into(),
            Uuid::new_v4(),
            owner,
            "isolation qualification".into(),
        )
        .await?;
    let organization_b = store
        .create_fleet_organization(
            "organization-b".into(),
            "Organization B".into(),
            Uuid::new_v4(),
            owner,
            "isolation qualification".into(),
        )
        .await?;
    let project_a = store
        .create_fleet_project(
            organization_a.id,
            "project-a".into(),
            "Project A".into(),
            String::new(),
            Uuid::new_v4(),
            owner,
            "isolation qualification".into(),
        )
        .await?;
    let project_b = store
        .create_fleet_project(
            organization_b.id,
            "project-b".into(),
            "Project B".into(),
            String::new(),
            Uuid::new_v4(),
            owner,
            "isolation qualification".into(),
        )
        .await?;
    let production_a = store
        .create_fleet_environment(
            organization_a.id,
            project_a.id,
            "production".into(),
            "Production A".into(),
            FleetEnvironmentKindRecord::Production,
            "qualification".into(),
            "eu-west".into(),
            Uuid::new_v4(),
            owner,
            "isolation qualification".into(),
        )
        .await?;
    let production_b = store
        .create_fleet_environment(
            organization_b.id,
            project_b.id,
            "production".into(),
            "Production B".into(),
            FleetEnvironmentKindRecord::Production,
            "qualification".into(),
            "us-east".into(),
            Uuid::new_v4(),
            owner,
            "isolation qualification".into(),
        )
        .await?;

    assert!(
        store
            .create_fleet_environment(
                organization_a.id,
                project_b.id,
                "cross-boundary".into(),
                "Must fail".into(),
                FleetEnvironmentKindRecord::Production,
                String::new(),
                String::new(),
                Uuid::new_v4(),
                owner,
                "negative isolation case".into(),
            )
            .await
            .is_err(),
        "a project from another organization must not be accepted as a parent"
    );
    assert!(
        store
            .update_fleet_environment(
                organization_a.id,
                project_a.id,
                production_b.id,
                "Must fail".into(),
                FleetEnvironmentKindRecord::Production,
                String::new(),
                String::new(),
                Uuid::new_v4(),
                owner,
                "negative isolation case".into(),
            )
            .await
            .is_err(),
        "knowing another organization's environment ID must not authorize a mutation"
    );

    store
        .upsert_fleet_role_binding(
            delegated_operator,
            FleetResourceKindRecord::Organization,
            organization_a.id,
            FleetRoleRecord::Administrator,
            Uuid::new_v4(),
            owner,
            "delegated isolation qualification".into(),
        )
        .await?;
    assert_eq!(
        store
            .fleet_effective_role(
                delegated_operator,
                FleetResourceKindRecord::Environment,
                production_a.id,
            )
            .await?,
        Some(FleetRoleRecord::Administrator)
    );
    assert_eq!(
        store
            .fleet_effective_role(
                delegated_operator,
                FleetResourceKindRecord::Environment,
                production_b.id,
            )
            .await?,
        None,
        "an organization-level role must never leak into a sibling organization"
    );
    assert!(
        store
            .fleet_projects(organization_a.id, false)
            .await?
            .iter()
            .all(|project| project.organization_id == organization_a.id)
    );
    assert!(
        store
            .fleet_environments(organization_a.id, project_a.id, false)
            .await?
            .iter()
            .all(
                |environment| environment.organization_id == organization_a.id
                    && environment.project_id == project_a.id
            )
    );

    flush(redis).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires the compose.integration.yaml SableDB service"]
async fn remote_mutation_replay_fencing_survives_restart() -> Result<()> {
    let database_url = required("RUSTYAUTH_TEST_SOURCE_SABLEDB_URL")?;
    let redis = connection(&database_url).await?;
    flush(redis.clone()).await?;
    let request_id = Uuid::new_v4();
    let first = Store::new(redis.clone(), "remote-mutation-qualification".into());
    assert_eq!(
        first.claim_remote_mutation(request_id, "digest-a").await?,
        RemoteMutationClaim::Claimed
    );
    assert!(
        first
            .claim_remote_mutation(request_id, "digest-a")
            .await
            .is_err(),
        "an in-flight duplicate must not execute concurrently"
    );
    let completed_at = first
        .complete_remote_mutation(request_id, "digest-a", true, "passkey revoked".into())
        .await?;

    let restarted = Store::new(redis.clone(), "remote-mutation-qualification".into());
    assert_eq!(
        restarted
            .claim_remote_mutation(request_id, "digest-a")
            .await?,
        RemoteMutationClaim::Completed {
            completed_at,
            succeeded: true,
            summary: "passkey revoked".into(),
        }
    );
    assert!(
        restarted
            .claim_remote_mutation(request_id, "digest-b")
            .await
            .is_err(),
        "a request id must never be retargeted after restart"
    );
    flush(redis).await?;
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
        step_up_at: (auth_method == "passkey").then_some(created_at),
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
    builder = builder.header(
        header::COOKIE,
        format!("{PRODUCTION_SESSION_COOKIE}={token}"),
    );
    let body = if let Some(value) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(serde_json::to_vec(&value)?)
    } else {
        Body::empty()
    };
    // `axum::serve` supplies this from the accepted socket; a tower oneshot has no
    // socket, so the rate limiter's peer address has to be injected here.
    let mut request = builder.body(body)?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_000))));
    let response = app.clone().oneshot(request).await?;
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
        rpo_seconds: 21_600,
        retention_days: 90,
        alert_after_failures: 2,
        server_side_encryption: BackupServerSideEncryption::Provider,
        sse_kms_key_id: None,
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
