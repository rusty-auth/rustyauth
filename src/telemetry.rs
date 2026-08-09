//! Realm-initiated Fleet telemetry connector and exporter.
//!
//! Realms send only closed, identity-free aggregate snapshots. Authentication
//! never waits for this module: projection and delivery are independent
//! restart-safe workers backed by the local SableDB outbox.

use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use buffa::{Message, MessageView};
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
    ServiceStream,
    client::{CallOptions, ClientConfig, HttpClient},
};
use futures::StreamExt;
use hmac::{Hmac, Mac};
use http::header;
use rand::RngCore;
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use url::Url;
use uuid::Uuid;

use crate::{
    analytics::{
        CAPABILITY_TELEMETRY_ROLLUPS_V1, decode_and_validate_batch, validate_acknowledgement,
    },
    analytics_store::GreptimeAnalyticsStore,
    config::KeyRing,
    fleet_rpc::{open_fleet_credential, seal_fleet_credential},
    jwt::JwtIssuer,
    management_rpc::RealmCommandExecutor,
    proto::rustyauth::{
        analytics::v1::{BucketAcknowledgementStatus, TelemetryBatchAcknowledgement},
        management::v1::{
            ConnectorFrame, ConnectorFrameKind, OutboundPairingRequest, PairingGrant,
            RealmConnectorService, RealmConnectorServiceClient, RealmDiscovery,
        },
    },
    rate_limit::{RateLimitClass, RateLimiter},
    store::{
        FleetConnectionRecord, FleetConnectionStateRecord, RealmFleetGrantRecord, Store,
        TelemetryOutboxRecord, now,
    },
};

const TELEMETRY_BATCH_TYPE: &str = "rustyauth.analytics.v1.TelemetryBucketBatch";
const TELEMETRY_ACK_TYPE: &str = "rustyauth.analytics.v1.TelemetryBatchAcknowledgement";
const EXPORT_BATCH_LIMIT: usize = 16;
const CONNECTOR_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RETRY_SECONDS: u64 = 300;
const CONNECTOR_COMMAND_QUEUE: usize = 32;
const CONNECTOR_SIGNATURE_DOMAIN: &[u8] = b"rustyauth-connector-frame-v1\0";

struct QueuedConnectorCommand {
    frame: ConnectorFrame,
    response: oneshot::Sender<ConnectorFrame>,
}

/// Live rendezvous for realm-initiated streams. Delivery remains deliberately
/// bounded and ephemeral: after a Fleet restart a realm reconnects, while the
/// realm's mutation ledger provides the durable idempotency/replay boundary.
#[derive(Clone, Default)]
pub(crate) struct ConnectorHub {
    sessions: Arc<Mutex<HashMap<Uuid, mpsc::Sender<QueuedConnectorCommand>>>>,
}

impl ConnectorHub {
    async fn register(&self, connection_id: Uuid) -> mpsc::Receiver<QueuedConnectorCommand> {
        let (sender, receiver) = mpsc::channel(CONNECTOR_COMMAND_QUEUE);
        self.sessions.lock().await.insert(connection_id, sender);
        receiver
    }

    pub(crate) async fn command(
        &self,
        connection_id: Uuid,
        frame: ConnectorFrame,
    ) -> Result<ConnectorFrame, ConnectError> {
        if frame.kind.as_known() != Some(ConnectorFrameKind::Command)
            || frame.connection_id != connection_id.to_string()
            || Uuid::parse_str(&frame.request_id).is_err()
        {
            return Err(invalid_connector("invalid outbound connector command"));
        }
        let sender = self
            .sessions
            .lock()
            .await
            .get(&connection_id)
            .cloned()
            .ok_or_else(connector_offline)?;
        let (response_sender, response_receiver) = oneshot::channel();
        tokio::time::timeout(
            CONNECTOR_TIMEOUT,
            sender.send(QueuedConnectorCommand {
                frame,
                response: response_sender,
            }),
        )
        .await
        .map_err(|_| {
            ConnectError::new(
                ErrorCode::ResourceExhausted,
                "realm connector command queue is full",
            )
        })?
        .map_err(|_| connector_offline())?;
        tokio::time::timeout(CONNECTOR_TIMEOUT, response_receiver)
            .await
            .map_err(|_| {
                ConnectError::new(
                    ErrorCode::DeadlineExceeded,
                    "realm connector command timed out",
                )
            })?
            .map_err(|_| connector_offline())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TelemetryExportResult {
    pub attempted: usize,
    pub acknowledged: usize,
    pub terminally_rejected: usize,
}

pub(crate) struct ConnectorRpc {
    store: Store,
    credential_keys: KeyRing,
    hub: ConnectorHub,
    rate_limiter: Arc<RateLimiter>,
    control_plane_instance_id: String,
    analytics: Option<GreptimeAnalyticsStore>,
}

impl ConnectorRpc {
    pub(crate) fn new(
        store: Store,
        credential_keys: KeyRing,
        hub: ConnectorHub,
        rate_limiter: Arc<RateLimiter>,
        control_plane_instance_id: String,
        analytics: Option<GreptimeAnalyticsStore>,
    ) -> Self {
        Self {
            store,
            credential_keys,
            hub,
            rate_limiter,
            control_plane_instance_id,
            analytics,
        }
    }
}

#[allow(refining_impl_trait)]
impl RealmConnectorService for ConnectorRpc {
    async fn pair_outbound(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, OutboundPairingRequest>,
    ) -> ServiceResult<PairingGrant> {
        if !self
            .rate_limiter
            .check(
                RateLimitClass::PairingExchange,
                "fleet-outbound-pairing-global",
            )
            .await
            .allowed
        {
            return Err(ConnectError::new(
                ErrorCode::ResourceExhausted,
                "outbound pairing rate limit exceeded",
            ));
        }
        let attempt_id = Uuid::parse_str(request.attempt_id)
            .map_err(|_| invalid_connector("outbound pairing attempt is invalid"))?;
        let pairing_code = safe_outbound_pairing_code(request.pairing_code)?;
        let attempt = self
            .store
            .authenticated_outbound_connection_attempt(attempt_id, &pairing_code)
            .await
            .map_err(connector_source)?
            .ok_or_else(|| {
                ConnectError::new(ErrorCode::Unauthenticated, "outbound pairing is invalid")
            })?;
        let discovery = request
            .discovery
            .as_option()
            .ok_or_else(|| invalid_connector("realm discovery is required"))?
            .to_owned_message()
            .map_err(|_| invalid_connector("realm discovery is invalid"))?;
        validate_management_discovery(&discovery, true)?;
        let scopes = safe_connector_scopes(&request.requested_scopes)?;
        if let Some(existing) = self
            .store
            .fleet_connection_for_completion_request(attempt_id)
            .await
            .map_err(connector_source)?
        {
            if existing.mode != crate::store::FleetConnectionModeRecord::OutboundConnector
                || existing.realm_id != discovery.realm_id
                || existing.granted_scopes != scopes
            {
                return Err(ConnectError::new(
                    ErrorCode::AlreadyExists,
                    "outbound pairing attempt was completed with different data",
                ));
            }
            let credential =
                open_fleet_credential(&self.credential_keys, existing.id, &existing.credential)?;
            return Response::ok(pairing_grant_from_connection(
                existing,
                credential.expose_secret().to_owned(),
                self.control_plane_instance_id.clone(),
            )?);
        }
        let assignment_epoch = self
            .store
            .reserve_fleet_assignment_epoch(&discovery.realm_id)
            .await
            .map_err(connector_source)?;
        let connection_id = Uuid::new_v4();
        let mut random = [0_u8; 32];
        rand::rng().fill_bytes(&mut random);
        let credential = format!("rfg_{}", URL_SAFE_NO_PAD.encode(random));
        let credential_secret = secrecy::SecretString::from(credential.clone());
        let encrypted =
            seal_fleet_credential(&self.credential_keys, connection_id, &credential_secret)?;
        let credential_hint = credential
            .chars()
            .rev()
            .take(6)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();
        let record = FleetConnectionRecord {
            id: connection_id,
            organization_id: attempt.organization_id,
            project_id: attempt.project_id,
            environment_id: attempt.environment_id,
            realm_id: discovery.realm_id.clone(),
            assignment_epoch,
            display_name: discovery.realm_id.clone(),
            mode: crate::store::FleetConnectionModeRecord::OutboundConnector,
            management_endpoint: attempt.management_endpoint,
            credential: encrypted,
            credential_hint: credential_hint.clone(),
            staged_credential: None,
            staged_credential_hint: None,
            credential_rotation_request_id: None,
            deployment_version: discovery.deployment_version,
            protocol_version: discovery.management_protocol_version,
            capabilities: discovery
                .capabilities
                .into_iter()
                .map(|capability| (capability.name, capability.version))
                .collect(),
            granted_scopes: scopes.clone(),
            issuer: discovery.issuer,
            rp_id: discovery.rp_id,
            state: FleetConnectionStateRecord::Offline,
            last_seen_at: None,
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
        };
        let record = self
            .store
            .complete_fleet_connection(
                attempt_id,
                record,
                attempt_id,
                attempt.created_by,
                "private realm completed outbound pairing".into(),
            )
            .await
            .map_err(connector_source)?;
        Response::ok(pairing_grant_from_connection(
            record,
            credential,
            self.control_plane_instance_id.clone(),
        )?)
    }

    async fn connect(
        &self,
        ctx: RequestContext,
        mut requests: connectrpc::InboundStream<ConnectorFrame>,
    ) -> ServiceResult<ServiceStream<ConnectorFrame>> {
        let supplied_proof = bearer(ctx.headers())
            .ok_or_else(|| {
                ConnectError::new(ErrorCode::Unauthenticated, "connector proof required")
            })?
            .to_owned();
        let store = self.store.clone();
        let credential_keys = self.credential_keys.clone();
        let hub = self.hub.clone();
        let analytics = self.analytics.clone();
        let output = async_stream::try_stream! {
            let hello = next_frame(&mut requests).await?;
            if hello.kind.as_known() != Some(ConnectorFrameKind::Hello) {
                Err(invalid_connector("first connector frame must be HELLO"))?;
            }
            let connection_id = Uuid::parse_str(&hello.connection_id)
                .map_err(|_| invalid_connector("connection_id must be a canonical UUID"))?;
            let connection = store
                .fleet_connection(connection_id)
                .await
                .map_err(connector_source)?
                .filter(connector_connection_active)
                .ok_or_else(|| ConnectError::new(ErrorCode::Unauthenticated, "connector identity is invalid"))?;
            let signing_key = authenticate_connector(&connection, &credential_keys, &supplied_proof)?;
            validate_hello(&hello, &connection)?;
            let mut commands = hub.register(connection.id).await;
            let mut pending = HashMap::<Uuid, oneshot::Sender<ConnectorFrame>>::new();

            loop {
                pending.retain(|_, response| !response.is_closed());
                let event = tokio::select! {
                    inbound = requests.next() => futures::future::Either::Left(
                        inbound.map(|frame| frame.map(|frame| frame.to_owned_message()))
                    ),
                    command = commands.recv() => futures::future::Either::Right(command),
                };
                match event {
                    futures::future::Either::Left(inbound) => {
                        let Some(frame) = inbound else { break };
                        let frame = frame?;
                        match frame.kind.as_known() {
                            Some(ConnectorFrameKind::TelemetryBatch) => {
                                validate_telemetry_frame(&frame, &connection)?;
                                let batch = decode_and_validate_batch(&frame.payload)
                                    .map_err(|error| ConnectError::new(ErrorCode::InvalidArgument, error.to_string()))?;
                                if batch.realm_id != connection.realm_id
                                    || batch.buckets.iter().any(|bucket| bucket.assignment_epoch != connection.assignment_epoch)
                                {
                                    Err(ConnectError::new(
                                        ErrorCode::PermissionDenied,
                                        "telemetry hierarchy assignment does not match the authenticated connection",
                                    ))?;
                                }
                                let accepted = store
                                    .accept_fleet_telemetry_batch_with_records(&connection, &batch)
                                    .await
                                    .map_err(connector_source)?;
                                if let Some(analytics) = &analytics {
                                    analytics
                                        .upsert(&accepted.records)
                                        .await
                                        .map_err(connector_source)?;
                                }
                                let acknowledgement = accepted.acknowledgement;
                                validate_acknowledgement(&acknowledgement)
                                    .map_err(|error| ConnectError::new(ErrorCode::Internal, error.to_string()))?;
                                yield ConnectorFrame {
                                    realm_id: connection.realm_id.clone(),
                                    connection_id: connection.id.to_string(),
                                    request_id: frame.request_id,
                                    kind: ConnectorFrameKind::TelemetryAck.into(),
                                    capability: CAPABILITY_TELEMETRY_ROLLUPS_V1.into(),
                                    payload: acknowledgement.encode_to_vec(),
                                    payload_type: TELEMETRY_ACK_TYPE.into(),
                                    ..Default::default()
                                };
                            }
                            Some(ConnectorFrameKind::Result | ConnectorFrameKind::Error) => {
                                validate_command_response(&frame, &connection, &signing_key)?;
                                let request_id = Uuid::parse_str(&frame.request_id)
                                    .map_err(|_| invalid_connector("connector response request id is invalid"))?;
                                let response = pending.remove(&request_id)
                                    .ok_or_else(|| invalid_connector("unsolicited or replayed connector response"))?;
                                let _ = response.send(frame);
                            }
                            Some(ConnectorFrameKind::Heartbeat) => {
                                validate_heartbeat(&frame, &connection, &signing_key)?;
                                store
                                    .observe_fleet_connection(
                                        connection.id,
                                        FleetConnectionStateRecord::Healthy,
                                    )
                                    .await
                                    .map_err(connector_source)?;
                            }
                            _ => Err(invalid_connector("connector frame kind is not valid in this direction"))?,
                        }
                    }
                    futures::future::Either::Right(command) => {
                        let Some(command) = command else { break };
                        if pending.len() >= CONNECTOR_COMMAND_QUEUE {
                            drop(command.response);
                            continue;
                        }
                        let request_id = Uuid::parse_str(&command.frame.request_id)
                            .map_err(|_| invalid_connector("connector command request id is invalid"))?;
                        if pending.contains_key(&request_id) {
                            Err(invalid_connector("duplicate in-flight connector request id"))?;
                        }
                        pending.insert(request_id, command.response);
                        yield command.frame;
                    }
                }
            }
        };
        Response::stream_ok(Box::pin(output))
    }
}

async fn next_frame(
    requests: &mut connectrpc::InboundStream<ConnectorFrame>,
) -> Result<ConnectorFrame, ConnectError> {
    requests
        .next()
        .await
        .ok_or_else(|| invalid_connector("connector stream ended before HELLO"))?
        .map(|frame| frame.to_owned_message())
}

fn safe_outbound_pairing_code(value: &str) -> Result<String, ConnectError> {
    let value = value.trim();
    if !value.starts_with("rpair_")
        || !(32..=128).contains(&value.len())
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ConnectError::new(
            ErrorCode::Unauthenticated,
            "outbound pairing is invalid",
        ));
    }
    Ok(value.to_owned())
}

fn safe_connector_scopes(values: &[&str]) -> Result<Vec<String>, ConnectError> {
    let scopes = if values.is_empty() {
        vec!["realm.read".to_owned(), "telemetry.export".to_owned()]
    } else {
        values.iter().map(|scope| (*scope).to_owned()).collect()
    };
    if scopes.len() > 3
        || scopes.iter().any(|scope| {
            !matches!(
                scope.as_str(),
                "realm.read" | "realm.support" | "telemetry.export"
            )
        })
    {
        return Err(invalid_connector("outbound pairing scope is invalid"));
    }
    if scopes
        .iter()
        .enumerate()
        .any(|(index, scope)| scopes[..index].contains(scope))
    {
        return Err(invalid_connector("outbound pairing scope is duplicated"));
    }
    Ok(scopes)
}

#[doc(hidden)]
pub fn validate_management_discovery(
    discovery: &RealmDiscovery,
    require_outbound_connector: bool,
) -> Result<(), ConnectError> {
    if discovery.realm_id.is_empty()
        || discovery.realm_id.len() > 128
        || !discovery
            .realm_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || discovery.management_protocol_version != "1"
        || !discovery.pairing_supported
        || (require_outbound_connector && !discovery.outbound_connector_supported)
        || discovery.capabilities.is_empty()
        || discovery.capabilities.len() > 32
        || discovery.capabilities.iter().any(|capability| {
            capability.name.is_empty()
                || capability.name.len() > 128
                || capability.version == 0
                || !capability
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        })
    {
        return Err(invalid_connector("realm discovery is invalid"));
    }
    for value in [
        discovery.deployment_version.as_str(),
        discovery.issuer.as_str(),
        discovery.rp_id.as_str(),
    ] {
        if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
            return Err(invalid_connector("realm discovery is invalid"));
        }
    }
    let issuer = Url::parse(&discovery.issuer)
        .map_err(|_| invalid_connector("realm discovery issuer is invalid"))?;
    let issuer_host = issuer
        .host_str()
        .ok_or_else(|| invalid_connector("realm discovery issuer is invalid"))?;
    if issuer.username() != ""
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
        || !matches!(issuer.path(), "" | "/")
        || !(issuer.scheme() == "https"
            || (issuer.scheme() == "http"
                && matches!(issuer_host, "localhost" | "127.0.0.1" | "::1")))
    {
        return Err(invalid_connector("realm discovery issuer is invalid"));
    }
    Ok(())
}

fn format_connector_timestamp(value: u64) -> Result<String, ConnectError> {
    let value = i64::try_from(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "timestamp is invalid"))?;
    OffsetDateTime::from_unix_timestamp(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "timestamp is invalid"))?
        .format(&Rfc3339)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "format connector timestamp"))
}

fn pairing_grant_from_connection(
    record: FleetConnectionRecord,
    credential: String,
    control_plane_instance_id: String,
) -> Result<PairingGrant, ConnectError> {
    Ok(PairingGrant {
        connection_id: record.id.to_string(),
        realm_id: record.realm_id,
        credential,
        credential_hint: record.credential_hint,
        granted_scopes: record.granted_scopes,
        created_at: format_connector_timestamp(record.created_at)?,
        expires_at: format_connector_timestamp(record.created_at.saturating_add(31_536_000))?,
        assignment_epoch: record.assignment_epoch,
        control_plane_instance_id,
        ..Default::default()
    })
}

fn validate_hello(
    frame: &ConnectorFrame,
    connection: &FleetConnectionRecord,
) -> Result<(), ConnectError> {
    if frame.realm_id != connection.realm_id
        || frame.connection_id != connection.id.to_string()
        || frame.capability != CAPABILITY_TELEMETRY_ROLLUPS_V1
        || !frame.payload.is_empty()
        || !frame.payload_type.is_empty()
    {
        return Err(ConnectError::new(
            ErrorCode::PermissionDenied,
            "connector HELLO does not match the authenticated connection",
        ));
    }
    if !connection
        .capabilities
        .iter()
        .any(|(name, version)| name == CAPABILITY_TELEMETRY_ROLLUPS_V1 && *version == 1)
    {
        return Err(ConnectError::new(
            ErrorCode::FailedPrecondition,
            "connection was paired without telemetry.rollups.v1",
        ));
    }
    Ok(())
}

fn validate_telemetry_frame(
    frame: &ConnectorFrame,
    connection: &FleetConnectionRecord,
) -> Result<(), ConnectError> {
    if frame.kind.as_known() != Some(ConnectorFrameKind::TelemetryBatch)
        || frame.realm_id != connection.realm_id
        || frame.connection_id != connection.id.to_string()
        || frame.capability != CAPABILITY_TELEMETRY_ROLLUPS_V1
        || frame.payload_type != TELEMETRY_BATCH_TYPE
        || Uuid::parse_str(&frame.request_id).is_err()
    {
        return Err(invalid_connector("invalid telemetry connector frame"));
    }
    Ok(())
}

fn connector_connection_active(connection: &FleetConnectionRecord) -> bool {
    matches!(
        connection.state,
        FleetConnectionStateRecord::Healthy
            | FleetConnectionStateRecord::Degraded
            | FleetConnectionStateRecord::Offline
    ) && connection.revoked_at.is_none()
}

fn authenticate_connector(
    connection: &FleetConnectionRecord,
    keys: &KeyRing,
    supplied: &str,
) -> Result<[u8; 32], ConnectError> {
    let supplied_digest: [u8; 32] = Sha256::digest(supplied.as_bytes()).into();
    for encrypted in
        std::iter::once(&connection.credential).chain(connection.staged_credential.as_ref())
    {
        let credential = open_fleet_credential(keys, connection.id, encrypted)?;
        let expected = connector_proof_from_credential(credential.expose_secret());
        let expected_digest: [u8; 32] = Sha256::digest(expected.as_bytes()).into();
        if bool::from(expected_digest.ct_eq(&supplied_digest)) {
            return Ok(connector_signing_key_from_credential(
                credential.expose_secret(),
            ));
        }
    }
    Err(ConnectError::new(
        ErrorCode::Unauthenticated,
        "connector identity is invalid",
    ))
}

/// Completes a Fleet-created outbound attempt from the realm side. The
/// plaintext grant credential exists only for this call and is immediately
/// reduced to the realm's one-way digest after the local one-time pairing code
/// is consumed.
#[allow(clippy::too_many_arguments)]
pub async fn pair_outbound_realm(
    store: &Store,
    control_plane_origin: &str,
    attempt_id: Uuid,
    pairing_code: &str,
    realm_id: &str,
    issuer: &str,
    rp_id: &str,
    requested_scopes: Vec<String>,
) -> Result<RealmFleetGrantRecord> {
    let endpoint =
        Url::parse(control_plane_origin).context("Fleet control-plane origin is invalid")?;
    let host = endpoint
        .host_str()
        .context("Fleet control-plane origin has no host")?;
    if endpoint.username() != ""
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !matches!(endpoint.path(), "" | "/")
        || !(endpoint.scheme() == "https"
            || (endpoint.scheme() == "http" && matches!(host, "localhost" | "127.0.0.1" | "::1")))
    {
        bail!("Fleet control-plane origin must use HTTPS (or loopback HTTP)");
    }
    safe_outbound_pairing_code(pairing_code).map_err(|error| anyhow!(error.to_string()))?;
    let discovery = RealmDiscovery {
        realm_id: realm_id.into(),
        deployment_version: env!("CARGO_PKG_VERSION").into(),
        management_protocol_version: "1".into(),
        issuer: issuer.trim_end_matches('/').into(),
        rp_id: rp_id.into(),
        rpc_protocols: vec!["connect+protobuf".into(), "grpc+protobuf".into()],
        capabilities: vec![
            crate::proto::rustyauth::management::v1::ManagementCapability {
                name: "realm.health".into(),
                version: 1,
                ..Default::default()
            },
            crate::proto::rustyauth::management::v1::ManagementCapability {
                name: "realm.summary".into(),
                version: 1,
                ..Default::default()
            },
            crate::proto::rustyauth::management::v1::ManagementCapability {
                name: "realm.operations".into(),
                version: 1,
                ..Default::default()
            },
            crate::proto::rustyauth::management::v1::ManagementCapability {
                name: "realm.remote-admin".into(),
                version: 1,
                ..Default::default()
            },
            crate::proto::rustyauth::management::v1::ManagementCapability {
                name: CAPABILITY_TELEMETRY_ROLLUPS_V1.into(),
                version: 1,
                ..Default::default()
            },
        ],
        pairing_supported: true,
        outbound_connector_supported: true,
        ..Default::default()
    };
    validate_management_discovery(&discovery, true).map_err(|error| anyhow!(error.to_string()))?;
    let client = connector_pairing_client(control_plane_origin)?;
    let mut response = client
        .pair_outbound_with_options(
            OutboundPairingRequest {
                attempt_id: attempt_id.to_string(),
                pairing_code: pairing_code.into(),
                discovery: discovery.into(),
                requested_scopes: requested_scopes.clone(),
                ..Default::default()
            },
            CallOptions::default().with_timeout(CONNECTOR_TIMEOUT),
        )
        .await
        .context("complete outbound Fleet pairing")?
        .into_owned();
    if response.realm_id != realm_id
        || response.assignment_epoch == 0
        || response.granted_scopes != requested_scopes
        || response.control_plane_instance_id.is_empty()
    {
        bail!("Fleet returned an inconsistent outbound pairing grant");
    }
    let connection_id = Uuid::parse_str(&response.connection_id)
        .context("Fleet returned an invalid outbound connection id")?;
    let credential = secrecy::SecretString::from(std::mem::take(&mut response.credential));
    store
        .consume_outbound_realm_pairing(
            pairing_code,
            control_plane_origin.trim_end_matches('/'),
            response.control_plane_instance_id,
            response.assignment_epoch,
            connection_id,
            credential.expose_secret(),
            &response.granted_scopes,
        )
        .await
}

pub(crate) fn sign_connector_frame(
    frame: &mut ConnectorFrame,
    signing_key: &[u8; 32],
) -> Result<(), ConnectError> {
    frame.signature.clear();
    let mut mac = Hmac::<Sha256>::new_from_slice(signing_key)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "initialize connector signature"))?;
    mac.update(&connector_frame_signing_bytes(frame));
    frame.signature = mac.finalize().into_bytes().to_vec();
    Ok(())
}

pub(crate) fn connector_signing_key_from_credential(credential: &str) -> [u8; 32] {
    Sha256::digest(credential.as_bytes()).into()
}

fn connector_signing_key_from_digest(digest: &str) -> Result<[u8; 32], ConnectError> {
    hex::decode(digest)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ConnectError::new(ErrorCode::DataLoss, "stored connector key is invalid"))
}

fn verify_connector_frame(
    frame: &ConnectorFrame,
    signing_key: &[u8; 32],
) -> Result<(), ConnectError> {
    if frame.signature.len() != 32 {
        return Err(ConnectError::new(
            ErrorCode::Unauthenticated,
            "connector frame signature is invalid",
        ));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(signing_key)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "initialize connector signature"))?;
    mac.update(&connector_frame_signing_bytes(frame));
    mac.verify_slice(&frame.signature).map_err(|_| {
        ConnectError::new(
            ErrorCode::Unauthenticated,
            "connector frame signature is invalid",
        )
    })
}

fn connector_frame_signing_bytes(frame: &ConnectorFrame) -> Vec<u8> {
    let mut output = Vec::with_capacity(
        CONNECTOR_SIGNATURE_DOMAIN.len()
            + frame.realm_id.len()
            + frame.connection_id.len()
            + frame.request_id.len()
            + frame.capability.len()
            + frame.expires_at.len()
            + frame.payload_type.len()
            + frame.payload.len()
            + 64,
    );
    output.extend_from_slice(CONNECTOR_SIGNATURE_DOMAIN);
    for value in [
        frame.realm_id.as_bytes(),
        frame.connection_id.as_bytes(),
        frame.request_id.as_bytes(),
        &frame.kind.to_i32().to_be_bytes(),
        frame.capability.as_bytes(),
        frame.expires_at.as_bytes(),
        frame.payload_type.as_bytes(),
        &frame.payload,
    ] {
        output.extend_from_slice(&(value.len() as u64).to_be_bytes());
        output.extend_from_slice(value);
    }
    output
}

fn validate_command_response(
    frame: &ConnectorFrame,
    connection: &FleetConnectionRecord,
    signing_key: &[u8; 32],
) -> Result<(), ConnectError> {
    validate_bound_signed_frame(frame, connection, signing_key)?;
    if frame.capability != "realm.operations"
        && frame.capability != "realm.remote-admin"
        && frame.capability != "realm.connection.revoke"
        && frame.capability != "realm.connection.rotate"
    {
        return Err(invalid_connector(
            "connector response capability is invalid",
        ));
    }
    Ok(())
}

fn validate_heartbeat(
    frame: &ConnectorFrame,
    connection: &FleetConnectionRecord,
    signing_key: &[u8; 32],
) -> Result<(), ConnectError> {
    validate_bound_signed_frame(frame, connection, signing_key)?;
    if !frame.payload.is_empty() || !frame.payload_type.is_empty() {
        return Err(invalid_connector("connector heartbeat payload is invalid"));
    }
    Ok(())
}

fn validate_bound_signed_frame(
    frame: &ConnectorFrame,
    connection: &FleetConnectionRecord,
    signing_key: &[u8; 32],
) -> Result<(), ConnectError> {
    if frame.realm_id != connection.realm_id
        || frame.connection_id != connection.id.to_string()
        || Uuid::parse_str(&frame.request_id).is_err()
    {
        return Err(ConnectError::new(
            ErrorCode::PermissionDenied,
            "connector frame does not match its authenticated connection",
        ));
    }
    validate_connector_expiry(&frame.expires_at)?;
    verify_connector_frame(frame, signing_key)
}

pub(crate) fn connector_expiry_after(duration: Duration) -> Result<String, ConnectError> {
    let seconds = i64::try_from(duration.as_secs())
        .map_err(|_| invalid_connector("connector expiry duration is invalid"))?;
    (OffsetDateTime::now_utc() + time::Duration::seconds(seconds))
        .format(&Rfc3339)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "format connector expiry"))
}

fn validate_connector_expiry(value: &str) -> Result<(), ConnectError> {
    let expiry = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| invalid_connector("connector frame expiry is invalid"))?;
    let current = OffsetDateTime::now_utc();
    if expiry <= current || expiry > current + time::Duration::minutes(5) {
        return Err(invalid_connector(
            "connector frame expiry must be in the next five minutes",
        ));
    }
    Ok(())
}

/// Runs one bounded delivery pass. Failure leaves the exact snapshot in the
/// outbox; only an accepted/already-accepted exact acknowledgement removes it.
pub async fn export_telemetry_once(store: &Store, realm_id: &str) -> Result<TelemetryExportResult> {
    let Some(grant) = store
        .realm_telemetry_export_grants()
        .await?
        .into_iter()
        .next()
    else {
        return Ok(TelemetryExportResult::default());
    };
    if grant.realm_id != realm_id {
        bail!("Fleet grant realm does not match configured realm");
    }
    let due = store
        .telemetry_outbox(EXPORT_BATCH_LIMIT)
        .await?
        .into_iter()
        .filter(|record| record.next_attempt_at <= now())
        .collect::<Vec<_>>();
    let mut result = TelemetryExportResult::default();
    for record in due {
        result.attempted += 1;
        let (record_realm_id, record_assignment_epoch) = outbox_identity(&record)?;
        if record_realm_id != grant.realm_id || record_assignment_epoch > grant.assignment_epoch {
            bail!("outbox snapshot does not match the current Fleet assignment");
        }
        if record_assignment_epoch < grant.assignment_epoch {
            // A revoked assignment must never be replayed into a newer
            // hierarchy epoch. It is terminal locally and remains available in
            // the encrypted realm backup that captured the old relationship.
            store
                .acknowledge_telemetry_bucket(record.bucket_start, record.revision)
                .await?;
            result.terminally_rejected += 1;
            continue;
        }
        match export_record(&grant, &record).await {
            Ok(acknowledgement) => {
                let outcome = apply_acknowledgement(store, &record, &acknowledgement).await?;
                result.acknowledged += usize::from(outcome == AckOutcome::Acknowledged);
                result.terminally_rejected +=
                    usize::from(outcome == AckOutcome::TerminallyRejected);
                if outcome == AckOutcome::Retained {
                    let delay = retry_delay_seconds(record.attempts);
                    let _ = store
                        .defer_telemetry_bucket(
                            record.bucket_start,
                            record.revision,
                            now().saturating_add(delay),
                        )
                        .await?;
                }
            }
            Err(error) => {
                let delay = retry_delay_seconds(record.attempts);
                let _ = store
                    .defer_telemetry_bucket(
                        record.bucket_start,
                        record.revision,
                        now().saturating_add(delay),
                    )
                    .await?;
                return Err(error);
            }
        }
    }
    Ok(result)
}

fn outbox_identity(record: &TelemetryOutboxRecord) -> Result<(String, u64)> {
    let batch = decode_and_validate_batch(&record.payload()?).map_err(|error| anyhow!(error))?;
    let bucket = batch
        .buckets
        .first()
        .ok_or_else(|| anyhow!("outbox batch does not contain a bucket"))?;
    if batch.buckets.len() != 1 {
        bail!("outbox record must contain exactly one bucket");
    }
    Ok((batch.realm_id, bucket.assignment_epoch))
}

async fn export_record(
    grant: &RealmFleetGrantRecord,
    record: &TelemetryOutboxRecord,
) -> Result<TelemetryBatchAcknowledgement> {
    let bytes = record.payload()?;
    let batch = decode_and_validate_batch(&bytes).map_err(|error| anyhow!(error))?;
    if batch.realm_id != grant.realm_id
        || batch
            .buckets
            .iter()
            .any(|bucket| bucket.assignment_epoch != grant.assignment_epoch)
    {
        bail!("outbox snapshot does not match the current Fleet assignment");
    }
    let client = connector_client(
        &grant.control_plane_origin,
        &connector_proof_from_digest(&grant.credential_digest),
    )?;
    let mut stream = client
        .connect()
        .await
        .context("open Fleet telemetry connector")?;
    stream
        .send(ConnectorFrame {
            realm_id: grant.realm_id.clone(),
            connection_id: grant.connection_id.to_string(),
            request_id: Uuid::new_v4().to_string(),
            kind: ConnectorFrameKind::Hello.into(),
            capability: CAPABILITY_TELEMETRY_ROLLUPS_V1.into(),
            ..Default::default()
        })
        .await
        .context("send Fleet connector HELLO")?;
    let request_id = Uuid::new_v4().to_string();
    stream
        .send(ConnectorFrame {
            realm_id: grant.realm_id.clone(),
            connection_id: grant.connection_id.to_string(),
            request_id: request_id.clone(),
            kind: ConnectorFrameKind::TelemetryBatch.into(),
            capability: CAPABILITY_TELEMETRY_ROLLUPS_V1.into(),
            payload: bytes,
            payload_type: TELEMETRY_BATCH_TYPE.into(),
            ..Default::default()
        })
        .await
        .context("send Fleet telemetry snapshot")?;
    stream.close_send();
    let response = tokio::time::timeout(CONNECTOR_TIMEOUT, stream.message::<ConnectorFrame>())
        .await
        .context("Fleet telemetry acknowledgement timed out")??
        .ok_or_else(|| anyhow!("Fleet connector closed without an acknowledgement"))?
        .to_owned_message();
    if response.kind.as_known() != Some(ConnectorFrameKind::TelemetryAck)
        || response.realm_id != grant.realm_id
        || response.connection_id != grant.connection_id.to_string()
        || response.request_id != request_id
        || response.capability != CAPABILITY_TELEMETRY_ROLLUPS_V1
        || response.payload_type != TELEMETRY_ACK_TYPE
    {
        bail!("Fleet connector returned a mismatched acknowledgement frame");
    }
    let acknowledgement = TelemetryBatchAcknowledgement::decode_from_slice(&response.payload)
        .context("decode Fleet telemetry acknowledgement")?;
    validate_acknowledgement(&acknowledgement).map_err(|error| anyhow!(error))?;
    if acknowledgement.batch_id != batch.batch_id {
        bail!("Fleet acknowledgement batch id does not match the outbox batch");
    }
    Ok(acknowledgement)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AckOutcome {
    Acknowledged,
    TerminallyRejected,
    Retained,
}

async fn apply_acknowledgement(
    store: &Store,
    record: &TelemetryOutboxRecord,
    acknowledgement: &TelemetryBatchAcknowledgement,
) -> Result<AckOutcome> {
    let Some(bucket) = acknowledgement.buckets.first() else {
        bail!("Fleet acknowledgement did not contain a bucket result");
    };
    let source = decode_and_validate_batch(&record.payload()?).map_err(|error| anyhow!(error))?;
    let source_bucket = source
        .buckets
        .first()
        .ok_or_else(|| anyhow!("outbox batch does not contain a bucket"))?;
    let key = bucket
        .key
        .as_option()
        .ok_or_else(|| anyhow!("Fleet acknowledgement does not contain a bucket key"))?;
    if acknowledgement.batch_id != record.batch_id.to_string()
        || acknowledgement.buckets.len() != 1
        || bucket.revision != record.revision
        || key.realm_id != source_bucket.realm_id
        || key.assignment_epoch != source_bucket.assignment_epoch
        || key.bucket_start_unix_milliseconds != source_bucket.bucket_start_unix_milliseconds
        || key.bucket_width_seconds != source_bucket.bucket_width_seconds
        || key.metric_schema_version != source_bucket.metric_schema_version
    {
        bail!("Fleet acknowledgement does not match the exact outbox revision");
    }
    match bucket.status.as_known() {
        Some(
            BucketAcknowledgementStatus::Accepted | BucketAcknowledgementStatus::AlreadyAccepted,
        ) => {
            store
                .acknowledge_telemetry_bucket(record.bucket_start, record.revision)
                .await?;
            Ok(AckOutcome::Acknowledged)
        }
        // Stale means Fleet already durably holds a newer revision. Dropping
        // this exact older record is safe and prevents a restore from looping.
        Some(BucketAcknowledgementStatus::Rejected)
            if bucket.rejection_reason.as_known()
                == Some(
                    crate::proto::rustyauth::analytics::v1::BucketRejectionReason::StaleRevision,
                ) =>
        {
            store
                .acknowledge_telemetry_bucket(record.bucket_start, record.revision)
                .await?;
            Ok(AckOutcome::TerminallyRejected)
        }
        _ => Ok(AckOutcome::Retained),
    }
}

fn connector_client(
    endpoint: &str,
    proof: &str,
) -> Result<RealmConnectorServiceClient<HttpClient>> {
    let url = Url::parse(endpoint).context("Fleet connector endpoint is invalid")?;
    let transport = match url.scheme() {
        "http" => HttpClient::plaintext_http2_only(),
        "https" => {
            let roots = connectrpc::rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            );
            let tls = connectrpc::rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            HttpClient::with_tls(Arc::new(tls))
        }
        _ => bail!("Fleet connector endpoint must use HTTP or HTTPS"),
    };
    let config = ClientConfig::new(
        endpoint
            .parse()
            .context("Fleet connector endpoint is invalid")?,
    )
    .with_protocol(connectrpc::Protocol::Grpc)
    .with_default_timeout(CONNECTOR_TIMEOUT)
    .with_default_header(header::AUTHORIZATION, format!("Bearer {proof}"));
    Ok(RealmConnectorServiceClient::new(transport, config))
}

fn connector_pairing_client(endpoint: &str) -> Result<RealmConnectorServiceClient<HttpClient>> {
    let url = Url::parse(endpoint).context("Fleet connector endpoint is invalid")?;
    let transport = match url.scheme() {
        "http" => HttpClient::plaintext_http2_only(),
        "https" => {
            let roots = connectrpc::rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            );
            let tls = connectrpc::rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            HttpClient::with_tls(Arc::new(tls))
        }
        _ => bail!("Fleet connector endpoint must use HTTP or HTTPS"),
    };
    let config = ClientConfig::new(
        endpoint
            .parse()
            .context("Fleet connector endpoint is invalid")?,
    )
    .with_protocol(connectrpc::Protocol::Grpc)
    .with_default_timeout(CONNECTOR_TIMEOUT);
    Ok(RealmConnectorServiceClient::new(transport, config))
}

pub async fn run_telemetry_exporter(
    store: Store,
    realm_id: String,
    jwt: JwtIssuer,
    backup: Option<crate::backup::BackupStore>,
    mut shutdown: watch::Receiver<bool>,
) {
    let executor = RealmCommandExecutor::new(store.clone(), realm_id.clone(), jwt, backup);
    loop {
        if *shutdown.borrow() {
            break;
        }
        let grant = match store.realm_telemetry_export_grants().await {
            Ok(grants) => grants.into_iter().find(|grant| grant.realm_id == realm_id),
            Err(error) => {
                tracing::warn!(error = %error, "Fleet connector grant lookup failed");
                None
            }
        };
        if let Some(grant) = grant
            && let Err(error) =
                run_connector_session(&store, &executor, &grant, shutdown.clone()).await
        {
            tracing::warn!(error = %error, "Fleet connector session disconnected");
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            changed = shutdown.changed() => if changed.is_err() || *shutdown.borrow() { break },
        }
    }
}

async fn run_connector_session(
    store: &Store,
    executor: &RealmCommandExecutor,
    grant: &RealmFleetGrantRecord,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let client = connector_client(
        &grant.control_plane_origin,
        &connector_proof_from_digest(&grant.credential_digest),
    )?;
    let mut stream = client.connect().await.context("open Fleet connector")?;
    stream
        .send(ConnectorFrame {
            realm_id: grant.realm_id.clone(),
            connection_id: grant.connection_id.to_string(),
            request_id: Uuid::new_v4().to_string(),
            kind: ConnectorFrameKind::Hello.into(),
            capability: CAPABILITY_TELEMETRY_ROLLUPS_V1.into(),
            ..Default::default()
        })
        .await
        .context("send Fleet connector HELLO")?;

    let signing_key = connector_signing_key_from_digest(&grant.credential_digest)
        .map_err(|error| anyhow!(error.to_string()))?;
    let mut pending_telemetry: Option<(TelemetryOutboxRecord, String)> = None;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut heartbeat_at = now();
    loop {
        let event = tokio::select! {
            message = stream.message::<ConnectorFrame>() => futures::future::Either::Left(
                message.map(|message| message.map(|frame| frame.to_owned_message()))
            ),
            _ = interval.tick() => futures::future::Either::Right(false),
            changed = shutdown.changed() => futures::future::Either::Right(
                changed.is_err() || *shutdown.borrow()
            ),
        };
        match event {
            futures::future::Either::Left(message) => {
                let message = match message {
                    Ok(Some(message)) => message,
                    Ok(None) => {
                        defer_pending_telemetry(store, pending_telemetry.take()).await;
                        bail!("Fleet connector closed the stream");
                    }
                    Err(error) => {
                        defer_pending_telemetry(store, pending_telemetry.take()).await;
                        return Err(error).context("receive Fleet connector frame");
                    }
                };
                match message.kind.as_known() {
                    Some(ConnectorFrameKind::TelemetryAck) => {
                        let (record, request_id) = pending_telemetry.take().ok_or_else(|| {
                            anyhow!("unsolicited Fleet telemetry acknowledgement")
                        })?;
                        if message.realm_id != grant.realm_id
                            || message.connection_id != grant.connection_id.to_string()
                            || message.request_id != request_id
                            || message.capability != CAPABILITY_TELEMETRY_ROLLUPS_V1
                            || message.payload_type != TELEMETRY_ACK_TYPE
                        {
                            defer_pending_telemetry(store, Some((record, request_id))).await;
                            bail!("Fleet returned a mismatched telemetry acknowledgement frame");
                        }
                        let acknowledgement =
                            TelemetryBatchAcknowledgement::decode_from_slice(&message.payload)
                                .context("decode Fleet telemetry acknowledgement")?;
                        let outcome =
                            apply_acknowledgement(store, &record, &acknowledgement).await?;
                        if outcome == AckOutcome::Retained {
                            let _ = store
                                .defer_telemetry_bucket(
                                    record.bucket_start,
                                    record.revision,
                                    now().saturating_add(retry_delay_seconds(record.attempts)),
                                )
                                .await;
                        }
                    }
                    Some(ConnectorFrameKind::Command) => {
                        let closes_for_rotation = message.capability == "realm.connection.rotate";
                        let response =
                            execute_connector_command(executor, grant, message, &signing_key).await;
                        stream
                            .send(response)
                            .await
                            .context("send Fleet connector command response")?;
                        if closes_for_rotation {
                            defer_pending_telemetry(store, pending_telemetry.take()).await;
                            stream.close_send();
                            return Ok(());
                        }
                    }
                    _ => bail!("Fleet sent an invalid connector frame kind"),
                }
            }
            futures::future::Either::Right(true) => {
                stream.close_send();
                return Ok(());
            }
            futures::future::Either::Right(false) => {
                if pending_telemetry.is_none()
                    && let Some(record) = next_telemetry_record(store, grant).await?
                {
                    let request_id = Uuid::new_v4().to_string();
                    let payload = record.payload()?;
                    if let Err(error) = stream
                        .send(ConnectorFrame {
                            realm_id: grant.realm_id.clone(),
                            connection_id: grant.connection_id.to_string(),
                            request_id: request_id.clone(),
                            kind: ConnectorFrameKind::TelemetryBatch.into(),
                            capability: CAPABILITY_TELEMETRY_ROLLUPS_V1.into(),
                            payload,
                            payload_type: TELEMETRY_BATCH_TYPE.into(),
                            ..Default::default()
                        })
                        .await
                    {
                        defer_pending_telemetry(store, Some((record, request_id))).await;
                        return Err(error).context("send Fleet telemetry snapshot");
                    }
                    pending_telemetry = Some((record, request_id));
                }
                if now() >= heartbeat_at {
                    let mut heartbeat = ConnectorFrame {
                        realm_id: grant.realm_id.clone(),
                        connection_id: grant.connection_id.to_string(),
                        request_id: Uuid::new_v4().to_string(),
                        kind: ConnectorFrameKind::Heartbeat.into(),
                        capability: "connector.lifecycle".into(),
                        expires_at: connector_expiry_after(Duration::from_secs(30))
                            .map_err(|error| anyhow!(error.to_string()))?,
                        ..Default::default()
                    };
                    sign_connector_frame(&mut heartbeat, &signing_key)
                        .map_err(|error| anyhow!(error.to_string()))?;
                    stream
                        .send(heartbeat)
                        .await
                        .context("send Fleet connector heartbeat")?;
                    heartbeat_at = now().saturating_add(15);
                }
            }
        }
    }
}

async fn next_telemetry_record(
    store: &Store,
    grant: &RealmFleetGrantRecord,
) -> Result<Option<TelemetryOutboxRecord>> {
    for record in store.telemetry_outbox(1).await? {
        if record.next_attempt_at > now() {
            return Ok(None);
        }
        let (realm_id, assignment_epoch) = outbox_identity(&record)?;
        if realm_id != grant.realm_id || assignment_epoch > grant.assignment_epoch {
            bail!("outbox snapshot does not match the current Fleet assignment");
        }
        if assignment_epoch < grant.assignment_epoch {
            store
                .acknowledge_telemetry_bucket(record.bucket_start, record.revision)
                .await?;
            continue;
        }
        return Ok(Some(record));
    }
    Ok(None)
}

async fn defer_pending_telemetry(store: &Store, pending: Option<(TelemetryOutboxRecord, String)>) {
    if let Some((record, _)) = pending {
        let _ = store
            .defer_telemetry_bucket(
                record.bucket_start,
                record.revision,
                now().saturating_add(retry_delay_seconds(record.attempts)),
            )
            .await;
    }
}

async fn execute_connector_command(
    executor: &RealmCommandExecutor,
    grant: &RealmFleetGrantRecord,
    command: ConnectorFrame,
    signing_key: &[u8; 32],
) -> ConnectorFrame {
    let result = validate_realm_command(&command, grant, signing_key).and_then(|()| {
        let required_scope = match command.capability.as_str() {
            "realm.operations" => Some("realm.read"),
            "realm.remote-admin" => Some("realm.support"),
            "realm.connection.revoke" => Some("realm.read"),
            "realm.connection.rotate" => Some("realm.read"),
            _ => None,
        };
        if required_scope
            .is_some_and(|required| !grant.granted_scopes.iter().any(|scope| scope == required))
        {
            Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "realm grant does not allow this operation",
            ))
        } else {
            Ok(())
        }
    });
    let outcome = match result {
        Ok(()) if command.capability == "realm.operations"
            && command.payload_type
                == "rustyauth.management.v1.GetOperationalSnapshotRequest" =>
        {
            match crate::proto::rustyauth::management::v1::GetOperationalSnapshotRequest::decode_from_slice(
                &command.payload,
            ) {
                Ok(request) => executor
                    .operational_snapshot(grant.connection_id, request)
                    .await
                    .map(|response| (
                        "rustyauth.management.v1.RealmOperationalSnapshot",
                        response.encode_to_vec(),
                    )),
                Err(_) => Err(invalid_connector("connector command payload is invalid")),
            }
        }
        Ok(()) if command.capability == "realm.remote-admin"
            && command.payload_type == "rustyauth.management.v1.RemoteMutationRequest" =>
        {
            match crate::proto::rustyauth::management::v1::RemoteMutationRequest::decode_from_slice(
                &command.payload,
            ) {
                Ok(request) => executor
                    .remote_mutation(grant.connection_id, request)
                    .await
                    .map(|response| (
                        "rustyauth.management.v1.RemoteMutationResult",
                        response.encode_to_vec(),
                    )),
                Err(_) => Err(invalid_connector("connector command payload is invalid")),
            }
        }
        Ok(())
            if command.capability == "realm.connection.revoke"
                && command.payload_type
                    == "rustyauth.management.v1.RevokeFleetConnectionRequest" =>
        {
            match crate::proto::rustyauth::management::v1::RevokeFleetConnectionRequest::decode_from_slice(
                &command.payload,
            ) {
                Ok(request) => executor
                    .revoke_connection(grant.connection_id, request)
                    .await
                    .map(|response| (
                        "rustyauth.management.v1.FleetConnectionState",
                        response.encode_to_vec(),
                    )),
                Err(_) => Err(invalid_connector("connector command payload is invalid")),
            }
        }
        Ok(())
            if command.capability == "realm.connection.rotate"
                && command.payload_type
                    == "rustyauth.management.v1.RotateFleetCredentialRequest" =>
        {
            match crate::proto::rustyauth::management::v1::RotateFleetCredentialRequest::decode_from_slice(
                &command.payload,
            ) {
                Ok(request) => executor
                    .rotate_connection_credential(grant.connection_id, request)
                    .await
                    .map(|response| (
                        "rustyauth.management.v1.PairingGrant",
                        response.encode_to_vec(),
                    )),
                Err(_) => Err(invalid_connector("connector command payload is invalid")),
            }
        }
        Ok(()) => Err(invalid_connector("connector command capability or type is invalid")),
        Err(error) => Err(error),
    };
    let (kind, payload_type, payload) = match outcome {
        Ok((payload_type, payload)) => (ConnectorFrameKind::Result, payload_type, payload),
        Err(error) => {
            tracing::warn!(
                connection_id = %grant.connection_id,
                request_id = %command.request_id,
                code = ?error.code,
                "realm rejected Fleet connector command"
            );
            (
                ConnectorFrameKind::Error,
                "rustyauth.connector.v1.CommandError",
                Vec::new(),
            )
        }
    };
    let mut response = ConnectorFrame {
        realm_id: grant.realm_id.clone(),
        connection_id: grant.connection_id.to_string(),
        request_id: command.request_id,
        kind: kind.into(),
        capability: command.capability,
        expires_at: command.expires_at,
        payload,
        payload_type: payload_type.into(),
        ..Default::default()
    };
    if let Err(error) = sign_connector_frame(&mut response, signing_key) {
        tracing::error!(error = %error, "could not sign connector command response");
        response.kind = ConnectorFrameKind::Error.into();
        response.payload.clear();
        response.payload_type = "rustyauth.connector.v1.CommandError".into();
        response.signature.clear();
    }
    response
}

fn validate_realm_command(
    command: &ConnectorFrame,
    grant: &RealmFleetGrantRecord,
    signing_key: &[u8; 32],
) -> Result<(), ConnectError> {
    if command.kind.as_known() != Some(ConnectorFrameKind::Command)
        || command.realm_id != grant.realm_id
        || command.connection_id != grant.connection_id.to_string()
        || Uuid::parse_str(&command.request_id).is_err()
    {
        return Err(ConnectError::new(
            ErrorCode::PermissionDenied,
            "connector command does not match the authenticated grant",
        ));
    }
    validate_connector_expiry(&command.expires_at)?;
    verify_connector_frame(command, signing_key)
}

fn connector_proof_from_credential(credential: &str) -> String {
    connector_proof_from_digest(&hex::encode(Sha256::digest(credential.as_bytes())))
}

fn connector_proof_from_digest(digest: &str) -> String {
    format!("rfc1_{digest}")
}

fn retry_delay_seconds(attempts: u32) -> u64 {
    1_u64
        .checked_shl(attempts.min(9))
        .unwrap_or(MAX_RETRY_SECONDS)
        .min(MAX_RETRY_SECONDS)
}

fn bearer(headers: &http::HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn invalid_connector(message: &'static str) -> ConnectError {
    ConnectError::new(ErrorCode::InvalidArgument, message)
}

fn connector_offline() -> ConnectError {
    ConnectError::new(
        ErrorCode::Unavailable,
        "realm outbound connector is offline",
    )
}

fn connector_source(error: anyhow::Error) -> ConnectError {
    tracing::error!(error = %error, "Fleet telemetry connector persistence failed");
    ConnectError::new(
        ErrorCode::Unavailable,
        "Fleet telemetry persistence unavailable",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::rustyauth::management::v1::ManagementCapability;

    fn discovery_fixture() -> RealmDiscovery {
        RealmDiscovery {
            realm_id: "realm-a".into(),
            deployment_version: "1.0.0".into(),
            management_protocol_version: "1".into(),
            issuer: "https://realm.example.com".into(),
            rp_id: "app.example.com".into(),
            rpc_protocols: vec!["connect+protobuf".into()],
            capabilities: vec![ManagementCapability {
                name: "realm.health".into(),
                version: 1,
                ..Default::default()
            }],
            pairing_supported: true,
            outbound_connector_supported: true,
            ..Default::default()
        }
    }

    #[test]
    fn protocol_version_skew_is_explicit_and_additive_capabilities_are_safe() {
        let mut current = discovery_fixture();
        current.capabilities.push(ManagementCapability {
            name: "future.additive-capability".into(),
            version: 2,
            ..Default::default()
        });
        assert!(validate_management_discovery(&current, false).is_ok());
        assert!(validate_management_discovery(&current, true).is_ok());

        let mut without_outbound = current.clone();
        without_outbound.outbound_connector_supported = false;
        assert!(validate_management_discovery(&without_outbound, false).is_ok());
        assert!(validate_management_discovery(&without_outbound, true).is_err());

        for unsupported in ["0", "2", "1.1", ""] {
            let mut skewed = current.clone();
            skewed.management_protocol_version = unsupported.into();
            assert!(
                validate_management_discovery(&skewed, false).is_err(),
                "unsupported protocol {unsupported:?} must fail before pairing"
            );
        }
    }

    #[test]
    fn realm_and_fleet_derive_the_same_directional_connector_proof() {
        let credential = "rfg_example-secret";
        let digest = hex::encode(Sha256::digest(credential.as_bytes()));
        assert_eq!(
            connector_proof_from_credential(credential),
            connector_proof_from_digest(&digest)
        );
        assert!(!connector_proof_from_credential(credential).contains(credential));
    }

    #[test]
    fn retry_backoff_is_bounded() {
        assert_eq!(retry_delay_seconds(0), 1);
        assert_eq!(retry_delay_seconds(8), 256);
        assert_eq!(retry_delay_seconds(32), MAX_RETRY_SECONDS);
    }

    #[test]
    fn connector_frame_signatures_bind_every_command_field() {
        let key = connector_signing_key_from_credential("rfg_test-secret");
        let mut frame = ConnectorFrame {
            realm_id: "realm-a".into(),
            connection_id: Uuid::new_v4().to_string(),
            request_id: Uuid::new_v4().to_string(),
            kind: ConnectorFrameKind::Command.into(),
            capability: "realm.operations".into(),
            expires_at: connector_expiry_after(Duration::from_secs(30)).unwrap(),
            payload: vec![1, 2, 3],
            payload_type: "example.Request".into(),
            ..Default::default()
        };
        sign_connector_frame(&mut frame, &key).unwrap();
        verify_connector_frame(&frame, &key).unwrap();

        frame.payload.push(4);
        let error = verify_connector_frame(&frame, &key).unwrap_err();
        assert_eq!(error.code, ErrorCode::Unauthenticated);
    }

    #[tokio::test]
    async fn connector_hub_exactly_correlates_a_live_response() {
        let hub = ConnectorHub::default();
        let connection_id = Uuid::new_v4();
        let request_id = Uuid::new_v4();
        let mut commands = hub.register(connection_id).await;
        let requester = {
            let hub = hub.clone();
            tokio::spawn(async move {
                hub.command(
                    connection_id,
                    ConnectorFrame {
                        connection_id: connection_id.to_string(),
                        request_id: request_id.to_string(),
                        kind: ConnectorFrameKind::Command.into(),
                        ..Default::default()
                    },
                )
                .await
            })
        };
        let queued = commands.recv().await.unwrap();
        assert_eq!(queued.frame.request_id, request_id.to_string());
        queued
            .response
            .send(ConnectorFrame {
                connection_id: connection_id.to_string(),
                request_id: request_id.to_string(),
                kind: ConnectorFrameKind::Result.into(),
                ..Default::default()
            })
            .unwrap();
        let response = requester.await.unwrap().unwrap();
        assert_eq!(response.request_id, request_id.to_string());
    }

    #[tokio::test]
    async fn an_exporter_panic_is_confined_to_its_background_task() {
        let task = tokio::spawn(async { panic!("qualification exporter panic") });
        assert!(task.await.unwrap_err().is_panic());
        assert_eq!(tokio::spawn(async { 42 }).await.unwrap(), 42);
    }
}

#[cfg(test)]
mod live_tests {
    use std::env;

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use connectrpc::ConnectRpcService;
    use redis::AsyncCommands;
    use secrecy::SecretString;

    use super::*;
    use crate::{
        analytics::{TRANSPORT_SCHEMA_VERSION_V1, validate_batch},
        analytics_store::GreptimeAnalyticsStore,
        config::AnalyticsConfig,
        fleet_rpc::seal_fleet_credential,
        proto::rustyauth::{
            analytics::v1::{
                MetricSchemaVersion, SessionTokenMetrics, TelemetryBucket, TelemetryBucketBatch,
            },
            management::v1::{
                GetOperationalSnapshotRequest, RealmConnectorServiceServer,
                RealmOperationalSnapshot,
            },
        },
        store::{
            FleetAnalyticsPolicyRecord, FleetAnalyticsResidencyRecord,
            FleetConnectionAttemptRecord, FleetConnectionModeRecord,
        },
    };

    #[tokio::test]
    #[ignore = "requires the compose.integration.yaml SableDB service"]
    async fn grpc_connector_authenticates_persists_and_exactly_acknowledges() -> Result<()> {
        let database_url = env::var("RUSTYAUTH_TEST_SOURCE_SABLEDB_URL")
            .context("RUSTYAUTH_TEST_SOURCE_SABLEDB_URL is missing")?;
        let client = redis::Client::open(database_url)?;
        let redis = redis::aio::ConnectionManager::new(client).await?;
        let mut database = redis.clone();
        redis::cmd("FLUSHDB")
            .arg("ASYNC")
            .query_async::<()>(&mut database)
            .await?;
        let realm = Store::new(redis.clone(), "connector-realm-store".into());
        let fleet = Store::new(redis.clone(), "connector-fleet-store".into());
        let keys = KeyRing::new("connector-test", [73; 32], Vec::new())?;
        let analytics = match env::var("RUSTYAUTH_TEST_GREPTIME_URL") {
            Ok(endpoint) => {
                let analytics = GreptimeAnalyticsStore::new(AnalyticsConfig {
                    endpoint: Url::parse(&endpoint)?,
                    database: format!("rustyauth_connector_test_{}", Uuid::new_v4().simple()),
                    username: SecretString::from("rustyauth"),
                    password: SecretString::from("rustyauth-test-password"),
                })?;
                analytics.initialize().await?;
                Some(analytics)
            }
            Err(_) => None,
        };

        let hub = ConnectorHub::default();
        let service = ConnectRpcService::new(RealmConnectorServiceServer::new(ConnectorRpc::new(
            fleet.clone(),
            keys.clone(),
            hub.clone(),
            Arc::new(RateLimiter::new(1_024)),
            "connector-test-fleet".into(),
            analytics.clone(),
        )));
        let app = axum::Router::new().fallback_service(service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        // Pair a second, private realm without exposing an inbound realm
        // endpoint. Fleet knows only the digest of the realm-generated code.
        let private_realm_id = "private-outbound-qualification-realm";
        let private_scopes = vec!["realm.read".into(), "telemetry.export".into()];
        let (_, private_code) = realm
            .create_realm_pairing(
                private_realm_id.into(),
                endpoint.clone(),
                private_scopes.clone(),
                Uuid::new_v4(),
            )
            .await?;
        let outbound_attempt_id = Uuid::new_v4();
        let outbound_attempt = FleetConnectionAttemptRecord {
            id: outbound_attempt_id,
            organization_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            environment_id: Uuid::new_v4(),
            mode: FleetConnectionModeRecord::OutboundConnector,
            management_endpoint: endpoint.clone(),
            pairing_code_digest: Some(hex::encode(Sha256::digest(private_code.as_bytes()))),
            created_by: Uuid::new_v4(),
            created_at: now(),
            expires_at: now().saturating_add(600),
        };
        let _: () = database
            .set(
                format!("fleet:connection-attempt:{outbound_attempt_id}"),
                serde_json::to_string(&outbound_attempt)?,
            )
            .await?;
        let pairing_client = connector_pairing_client(&endpoint)?;
        let outbound_request = OutboundPairingRequest {
            attempt_id: outbound_attempt_id.to_string(),
            pairing_code: private_code.clone(),
            discovery: RealmDiscovery {
                realm_id: private_realm_id.into(),
                deployment_version: env!("CARGO_PKG_VERSION").into(),
                management_protocol_version: "1".into(),
                issuer: "http://localhost".into(),
                rp_id: "localhost".into(),
                capabilities: vec![
                    crate::proto::rustyauth::management::v1::ManagementCapability {
                        name: "realm.operations".into(),
                        version: 1,
                        ..Default::default()
                    },
                    crate::proto::rustyauth::management::v1::ManagementCapability {
                        name: CAPABILITY_TELEMETRY_ROLLUPS_V1.into(),
                        version: 1,
                        ..Default::default()
                    },
                ],
                pairing_supported: true,
                outbound_connector_supported: true,
                ..Default::default()
            }
            .into(),
            requested_scopes: private_scopes.clone(),
            ..Default::default()
        };
        let mut outbound_grant = pairing_client
            .pair_outbound(outbound_request.clone())
            .await?
            .into_owned();
        let replayed_grant = pairing_client
            .pair_outbound(outbound_request)
            .await?
            .into_owned();
        assert_eq!(replayed_grant.connection_id, outbound_grant.connection_id);
        assert_eq!(replayed_grant.credential, outbound_grant.credential);
        assert_eq!(
            replayed_grant.assignment_epoch,
            outbound_grant.assignment_epoch
        );
        let private_connection_id = Uuid::parse_str(&outbound_grant.connection_id)?;
        let private_credential = SecretString::from(std::mem::take(&mut outbound_grant.credential));
        let stored_private_grant = realm
            .consume_outbound_realm_pairing(
                &private_code,
                &endpoint,
                outbound_grant.control_plane_instance_id,
                outbound_grant.assignment_epoch,
                private_connection_id,
                private_credential.expose_secret(),
                &outbound_grant.granted_scopes,
            )
            .await?;
        assert_eq!(stored_private_grant.realm_id, private_realm_id);
        assert_eq!(
            fleet
                .fleet_connection(private_connection_id)
                .await?
                .context("outbound Fleet connection was not persisted")?
                .mode,
            FleetConnectionModeRecord::OutboundConnector
        );
        realm
            .revoke_realm_fleet_grant(private_connection_id)
            .await?;

        let realm_id = "grpc-qualification-realm";
        let connection_id = Uuid::new_v4();
        let credential = SecretString::from("rfg_grpc-qualification-secret".to_owned());
        let encrypted = seal_fleet_credential(&keys, connection_id, &credential)?;
        let connection = FleetConnectionRecord {
            id: connection_id,
            organization_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            environment_id: Uuid::new_v4(),
            realm_id: realm_id.into(),
            assignment_epoch: 1,
            display_name: "gRPC qualification realm".into(),
            mode: FleetConnectionModeRecord::OutboundConnector,
            management_endpoint: endpoint.clone(),
            credential: encrypted,
            credential_hint: "secret".into(),
            staged_credential: None,
            staged_credential_hint: None,
            credential_rotation_request_id: None,
            deployment_version: env!("CARGO_PKG_VERSION").into(),
            protocol_version: "1".into(),
            capabilities: vec![(CAPABILITY_TELEMETRY_ROLLUPS_V1.into(), 1)],
            granted_scopes: vec!["realm.read".into(), "telemetry.export".into()],
            issuer: "https://grpc-qualification.invalid".into(),
            rp_id: "grpc-qualification.invalid".into(),
            state: FleetConnectionStateRecord::Healthy,
            last_seen_at: None,
            created_at: now(),
            updated_at: now(),
            revoked_at: None,
        };
        let _: () = database
            .set(
                format!("fleet:connection:{connection_id}"),
                serde_json::to_string(&connection)?,
            )
            .await?;
        let _: () = database
            .set(
                format!("fleet:analytics-policy:{}", connection.organization_id),
                serde_json::to_string(&FleetAnalyticsPolicyRecord {
                    organization_id: connection.organization_id,
                    enabled: true,
                    canonical_retention_days: 35,
                    residency: FleetAnalyticsResidencyRecord::RollupsOnly,
                    max_buckets_per_minute_per_realm: 288,
                    updated_at: now(),
                    updated_by: None,
                })?,
            )
            .await?;
        let digest = hex::encode(Sha256::digest(credential.expose_secret().as_bytes()));
        let mut grant = RealmFleetGrantRecord {
            connection_id,
            realm_id: realm_id.into(),
            control_plane_origin: "http://127.0.0.1:9".into(),
            control_plane_instance_id: "grpc-qualification-fleet".into(),
            assignment_epoch: 1,
            credential_digest: digest,
            credential_hint: "secret".into(),
            granted_scopes: vec!["realm.read".into(), "telemetry.export".into()],
            created_at: now(),
            expires_at: now().saturating_add(3_600),
            revoked_at: None,
        };
        let _: () = database
            .set(
                format!("auth:fleet-grant:{connection_id}"),
                serde_json::to_string(&grant)?,
            )
            .await?;

        let bucket_start = now().saturating_sub(600) / 300 * 300;
        let batch_id = Uuid::new_v4();
        let batch = TelemetryBucketBatch {
            transport_schema_version: TRANSPORT_SCHEMA_VERSION_V1,
            batch_id: batch_id.to_string(),
            realm_id: realm_id.into(),
            buckets: vec![TelemetryBucket {
                realm_id: realm_id.into(),
                assignment_epoch: 1,
                bucket_start_unix_milliseconds: (bucket_start * 1_000) as i64,
                bucket_width_seconds: 300,
                revision: 1,
                first_event_sequence: 1,
                last_event_sequence: 1,
                metric_schema_version: MetricSchemaVersion::V1.into(),
                closed: true,
                sessions_and_tokens: SessionTokenMetrics::default().into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        validate_batch(&batch)?;
        let outbox = TelemetryOutboxRecord {
            bucket_start,
            revision: 1,
            batch_id,
            payload_base64url: URL_SAFE_NO_PAD.encode(batch.encode_to_vec()),
            first_queued_at: now(),
            attempts: 0,
            next_attempt_at: 0,
        };
        let _: () = database
            .set(
                format!("analytics:outbox:{bucket_start:020}:{:020}", 1),
                serde_json::to_string(&outbox)?,
            )
            .await?;

        // A real connection refusal changes only retry metadata. An auth event
        // remains independently durable while Fleet is unavailable.
        assert!(export_telemetry_once(&realm, realm_id).await.is_err());
        let mut retained = realm
            .telemetry_outbox(1)
            .await?
            .pop()
            .context("outbox record was lost during central outage")?;
        assert_eq!(retained.attempts, 1);
        let auth_event = realm
            .append_event("qualification.authentication.completed", None)
            .await?;
        assert_eq!(
            realm
                .events(auth_event.sequence.saturating_sub(1), 1)
                .await?[0]
                .id,
            auth_event.id
        );

        grant.control_plane_origin = endpoint;
        retained.next_attempt_at = 0;
        let _: () = database
            .set(
                format!("auth:fleet-grant:{connection_id}"),
                serde_json::to_string(&grant)?,
            )
            .await?;
        let _: () = database
            .set(
                format!("analytics:outbox:{bucket_start:020}:{:020}", 1),
                serde_json::to_string(&retained)?,
            )
            .await?;

        let exported = export_telemetry_once(&realm, realm_id).await?;
        assert_eq!(exported.attempted, 1);
        assert_eq!(exported.acknowledged, 1);
        assert!(realm.telemetry_outbox(1).await?.is_empty());
        let accepted = fleet
            .fleet_telemetry_bucket(realm_id, 1, (bucket_start * 1_000) as i64)
            .await?
            .context("central acceptance record is missing")?;
        assert_eq!(accepted.revision, 1);
        assert_eq!(accepted.connection_id, connection_id);
        assert_eq!(accepted.organization_id, connection.organization_id);
        assert_eq!(accepted.project_id, connection.project_id);
        assert_eq!(accepted.environment_id, connection.environment_id);
        if let Some(analytics) = &analytics {
            assert_eq!(
                analytics
                    .query(
                        Some(connection.organization_id),
                        Some(connection.project_id),
                        Some(connection.environment_id),
                        Some(connection.id),
                        Some(realm_id),
                        (bucket_start * 1_000) as i64,
                        (bucket_start.saturating_add(300) * 1_000) as i64,
                    )
                    .await?
                    .len(),
                1
            );
        }
        assert_eq!(
            fleet
                .fleet_telemetry_buckets(
                    Some(connection.organization_id),
                    Some(connection.project_id),
                    Some(connection.environment_id),
                    Some(connection.id),
                    Some(realm_id),
                    (bucket_start * 1_000) as i64,
                    (bucket_start.saturating_add(300) * 1_000) as i64,
                )
                .await?
                .len(),
            1
        );
        assert!(
            fleet
                .fleet_telemetry_buckets(
                    Some(Uuid::new_v4()),
                    None,
                    None,
                    None,
                    None,
                    (bucket_start * 1_000) as i64,
                    (bucket_start.saturating_add(300) * 1_000) as i64,
                )
                .await?
                .is_empty()
        );
        assert_eq!(export_telemetry_once(&realm, realm_id).await?.attempted, 0);

        // The same authenticated gRPC service carries a signed, exact-bound
        // management command over a new realm-initiated session.
        let client = connector_client(
            &grant.control_plane_origin,
            &connector_proof_from_digest(&grant.credential_digest),
        )?;
        let mut command_stream = client.connect().await?;
        command_stream
            .send(ConnectorFrame {
                realm_id: realm_id.into(),
                connection_id: connection_id.to_string(),
                request_id: Uuid::new_v4().to_string(),
                kind: ConnectorFrameKind::Hello.into(),
                capability: CAPABILITY_TELEMETRY_ROLLUPS_V1.into(),
                ..Default::default()
            })
            .await?;
        // Drive the server-side output stream through HELLO registration
        // before enqueuing the command. No frame is expected yet.
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                command_stream.message::<ConnectorFrame>(),
            )
            .await
            .is_err()
        );
        let command_id = Uuid::new_v4();
        let signing_key = connector_signing_key_from_credential(credential.expose_secret());
        let expires_at = connector_expiry_after(Duration::from_secs(30))?;
        let mut command = ConnectorFrame {
            realm_id: realm_id.into(),
            connection_id: connection_id.to_string(),
            request_id: command_id.to_string(),
            kind: ConnectorFrameKind::Command.into(),
            capability: "realm.operations".into(),
            expires_at: expires_at.clone(),
            payload: GetOperationalSnapshotRequest {
                connection_id: connection_id.to_string(),
                ..Default::default()
            }
            .encode_to_vec(),
            payload_type: "rustyauth.management.v1.GetOperationalSnapshotRequest".into(),
            ..Default::default()
        };
        sign_connector_frame(&mut command, &signing_key)?;
        let command_task = {
            let hub = hub.clone();
            tokio::spawn(async move { hub.command(connection_id, command).await })
        };
        let received = tokio::time::timeout(
            Duration::from_secs(2),
            command_stream.message::<ConnectorFrame>(),
        )
        .await??
        .context("Fleet did not deliver the connector command")?
        .to_owned_message();
        validate_realm_command(&received, &grant, &signing_key)?;
        let mut response = ConnectorFrame {
            realm_id: realm_id.into(),
            connection_id: connection_id.to_string(),
            request_id: command_id.to_string(),
            kind: ConnectorFrameKind::Result.into(),
            capability: "realm.operations".into(),
            expires_at,
            payload: RealmOperationalSnapshot {
                realm_id: realm_id.into(),
                source: "live-realm".into(),
                ..Default::default()
            }
            .encode_to_vec(),
            payload_type: "rustyauth.management.v1.RealmOperationalSnapshot".into(),
            ..Default::default()
        };
        sign_connector_frame(&mut response, &signing_key)?;
        command_stream.send(response).await?;
        let delivered = command_task.await??;
        assert_eq!(delivered.request_id, command_id.to_string());
        assert_eq!(
            RealmOperationalSnapshot::decode_from_slice(&delivered.payload)?.realm_id,
            realm_id
        );

        // Rotation is staged durably at Fleet before the realm swaps digests.
        // Exact retries succeed, changed-data replays fail, and promotion
        // removes the old encrypted credential only after realm confirmation.
        let rotation_id = Uuid::new_v4();
        let rotated_credential =
            SecretString::from("rfg_grpc-qualification-rotated-secret-000000000000".to_owned());
        let rotated_hint = "000000".to_owned();
        let rotated_encrypted = seal_fleet_credential(&keys, connection_id, &rotated_credential)?;
        fleet
            .stage_fleet_connection_credential(
                connection_id,
                rotated_encrypted,
                rotated_hint.clone(),
                rotation_id,
            )
            .await?;
        let rotated_grant = realm
            .rotate_realm_fleet_grant(
                connection_id,
                rotation_id,
                rotated_credential.expose_secret(),
                &rotated_hint,
            )
            .await?;
        assert_eq!(
            realm
                .rotate_realm_fleet_grant(
                    connection_id,
                    rotation_id,
                    rotated_credential.expose_secret(),
                    &rotated_hint,
                )
                .await?,
            rotated_grant
        );
        assert!(
            realm
                .realm_fleet_grant_by_credential(credential.expose_secret())
                .await?
                .is_none()
        );
        assert!(
            realm
                .realm_fleet_grant_by_credential(rotated_credential.expose_secret())
                .await?
                .is_some()
        );
        let promoted = fleet
            .rotate_fleet_connection_credential(
                connection.organization_id,
                connection.project_id,
                connection.environment_id,
                connection_id,
                rotation_id,
                Uuid::new_v4(),
                "qualification credential rotation".into(),
            )
            .await?;
        assert!(promoted.staged_credential.is_none());
        assert_eq!(
            open_fleet_credential(&keys, connection_id, &promoted.credential)?.expose_secret(),
            rotated_credential.expose_secret()
        );

        server.abort();
        let _ = server.await;
        redis::cmd("FLUSHDB")
            .arg("ASYNC")
            .query_async::<()>(&mut database)
            .await?;
        Ok(())
    }
}
