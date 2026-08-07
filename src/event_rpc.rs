use std::{collections::HashSet, sync::Arc, time::Duration};

use anyhow::Result;
use connectrpc::interceptor::{StreamRequest, StreamResponse};
use connectrpc::{
    ConnectError, ConnectRpcService, ErrorCode, Interceptor, Limits, NextStream, PayloadStream,
    RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{
    proto::rustyauth::events::v1::{
        AuthEvent as ProtoAuthEvent, AuthEventCheckpoint, AuthEventService, AuthEventServiceServer,
        SubscribeRequest, SubscribeResponse,
    },
    store::{AuthEvent, EventLogIntegrityError, Store},
};

const EVENT_BATCH_SIZE: u64 = 100;
const DEFAULT_CHECKPOINT_SECONDS: u32 = 15;
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_FILTER_VALUES: usize = 50;
const MAX_CONCURRENT_STREAMS: usize = 32;

type Dispatcher = AuthEventServiceServer<EventService<Store>>;
pub(crate) type EventRpcService = ConnectRpcService<Dispatcher>;

pub(crate) fn service(store: Store, token: &SecretString) -> EventRpcService {
    let dispatcher = AuthEventServiceServer::new(EventService::new(
        store,
        DEFAULT_POLL_INTERVAL,
        MAX_CONCURRENT_STREAMS,
    ));
    ConnectRpcService::new(dispatcher)
        .with_limits(
            Limits::default()
                .max_request_body_size(16 * 1024)
                .max_message_size(64 * 1024),
        )
        .with_interceptor(EventRpcAuth::new(token))
}

trait EventSource: Clone + Send + Sync + 'static {
    fn events(&self, after: u64, limit: u64)
    -> impl Future<Output = Result<Vec<AuthEvent>>> + Send;

    fn latest_event_sequence(&self) -> impl Future<Output = Result<u64>> + Send;
}

impl EventSource for Store {
    async fn events(&self, after: u64, limit: u64) -> Result<Vec<AuthEvent>> {
        Store::events(self, after, limit).await
    }

    async fn latest_event_sequence(&self) -> Result<u64> {
        Store::latest_event_sequence(self).await
    }
}

pub(crate) struct EventService<S> {
    source: S,
    poll_interval: Duration,
    streams: Arc<Semaphore>,
}

impl<S> EventService<S> {
    fn new(source: S, poll_interval: Duration, max_streams: usize) -> Self {
        Self {
            source,
            poll_interval,
            streams: Arc::new(Semaphore::new(max_streams)),
        }
    }
}

impl<S: EventSource> AuthEventService for EventService<S> {
    #[allow(refining_impl_trait)]
    async fn subscribe(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, SubscribeRequest>,
    ) -> ServiceResult<ServiceStream<SubscribeResponse>> {
        let after_sequence = request.after_sequence;
        let event_types = validated_event_types(request.event_types.iter().copied())?;
        let tenant_ids = validated_tenant_ids(request.tenant_ids.iter().copied())?;
        let checkpoint_interval = checkpoint_interval(request.checkpoint_interval_seconds)?;
        let permit = Arc::clone(&self.streams).try_acquire_owned().map_err(|_| {
            ConnectError::new(ErrorCode::ResourceExhausted, "too many event streams")
        })?;
        let initial_latest = self
            .source
            .latest_event_sequence()
            .await
            .map_err(source_error)?;
        if after_sequence > initial_latest {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "after_sequence {after_sequence} is ahead of latest sequence {initial_latest}"
                ),
            ));
        }

        let source = self.source.clone();
        let poll_interval = self.poll_interval;
        let stream = event_stream(
            source,
            after_sequence,
            event_types,
            tenant_ids,
            checkpoint_interval,
            poll_interval,
            permit,
        );
        Response::stream_ok(stream)
    }
}

fn event_stream<S: EventSource>(
    source: S,
    after_sequence: u64,
    event_types: HashSet<String>,
    tenant_ids: HashSet<String>,
    checkpoint_interval: Duration,
    poll_interval: Duration,
    permit: OwnedSemaphorePermit,
) -> impl futures::Stream<Item = Result<SubscribeResponse, ConnectError>> + Send {
    async_stream::try_stream! {
        let _permit = permit;
        let mut scan_cursor = after_sequence;
        let mut checkpoint_at = tokio::time::Instant::now() + checkpoint_interval;
        loop {
            let batch = source
                .events(scan_cursor, EVENT_BATCH_SIZE)
                .await
                .map_err(source_error)?;
            let batch_is_full = batch.len() == EVENT_BATCH_SIZE as usize;
            for event in batch {
                let expected = scan_cursor.checked_add(1).ok_or_else(sequence_exhausted)?;
                if event.sequence != expected {
                    Err(ConnectError::new(
                        ErrorCode::DataLoss,
                        format!("auth event log is missing sequence {expected}"),
                    ))?;
                }
                scan_cursor = event.sequence;
                if (event_types.is_empty() || event_types.contains(&event.event_type))
                    && (tenant_ids.is_empty() || tenant_ids.contains(&event.tenant_id))
                {
                    yield event_response(event)?;
                }
            }

            if batch_is_full {
                continue;
            }
            if tokio::time::Instant::now() >= checkpoint_at {
                let latest_sequence = source
                    .latest_event_sequence()
                    .await
                    .map_err(source_error)?;
                if latest_sequence < scan_cursor {
                    Err(ConnectError::new(
                        ErrorCode::DataLoss,
                        "auth event sequence moved backwards",
                    ))?;
                }
                yield checkpoint_response(latest_sequence)?;
                checkpoint_at = tokio::time::Instant::now() + checkpoint_interval;
            }
            tokio::time::sleep(poll_interval).await;
        }
    }
}

fn event_response(event: AuthEvent) -> Result<SubscribeResponse, ConnectError> {
    let occurred_at = format_timestamp(event.occurred_at)?;
    let data_json = serde_json::to_vec(&event.data)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "auth event data is invalid"))?;
    Ok(SubscribeResponse {
        payload: ProtoAuthEvent {
            sequence: event.sequence,
            id: event.id.to_string(),
            r#type: event.event_type,
            subject: event
                .subject
                .map(|value| value.to_string())
                .unwrap_or_default(),
            occurred_at,
            data_json,
            tenant_id: event.tenant_id,
            ..Default::default()
        }
        .into(),
        ..Default::default()
    })
}

fn checkpoint_response(latest_sequence: u64) -> Result<SubscribeResponse, ConnectError> {
    let occurred_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "format event checkpoint"))?;
    Ok(SubscribeResponse {
        payload: AuthEventCheckpoint {
            latest_sequence,
            occurred_at,
            ..Default::default()
        }
        .into(),
        ..Default::default()
    })
}

fn format_timestamp(timestamp: u64) -> Result<String, ConnectError> {
    let timestamp = i64::try_from(timestamp)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "auth event timestamp is invalid"))?;
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "auth event timestamp is invalid"))?
        .format(&Rfc3339)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "auth event timestamp is invalid"))
}

fn validated_event_types<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<HashSet<String>, ConnectError> {
    validate_filters(values, "event_types", valid_event_type)
}

fn validated_tenant_ids<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<HashSet<String>, ConnectError> {
    validate_filters(values, "tenant_ids", valid_tenant_id)
}

fn validate_filters<'a>(
    values: impl Iterator<Item = &'a str>,
    name: &str,
    valid: impl Fn(&str) -> bool,
) -> Result<HashSet<String>, ConnectError> {
    let values = values.collect::<Vec<_>>();
    if values.len() > MAX_FILTER_VALUES {
        return Err(ConnectError::new(
            ErrorCode::InvalidArgument,
            format!("at most {MAX_FILTER_VALUES} {name} may be subscribed"),
        ));
    }
    let mut unique = HashSet::with_capacity(values.len());
    for value in values {
        if !valid(value) {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                format!("invalid {name} value"),
            ));
        }
        unique.insert(value.to_owned());
    }
    Ok(unique)
}

fn valid_event_type(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_lowercase_or_digit()
        && bytes[bytes.len() - 1].is_ascii_lowercase_or_digit()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase_or_digit() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_tenant_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_lowercase_or_digit()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase_or_digit() || *byte == b'-')
}

trait AsciiLowercaseOrDigit {
    fn is_ascii_lowercase_or_digit(&self) -> bool;
}

impl AsciiLowercaseOrDigit for u8 {
    fn is_ascii_lowercase_or_digit(&self) -> bool {
        self.is_ascii_lowercase() || self.is_ascii_digit()
    }
}

fn checkpoint_interval(value: u32) -> Result<Duration, ConnectError> {
    match value {
        0 => Ok(Duration::from_secs(DEFAULT_CHECKPOINT_SECONDS.into())),
        5..=60 => Ok(Duration::from_secs(value.into())),
        _ => Err(ConnectError::new(
            ErrorCode::InvalidArgument,
            "checkpoint_interval_seconds must be between 5 and 60",
        )),
    }
}

fn source_error(error: anyhow::Error) -> ConnectError {
    if error.downcast_ref::<EventLogIntegrityError>().is_some() {
        tracing::error!(error = %error, "auth event log integrity failure");
        ConnectError::new(ErrorCode::DataLoss, "auth event log integrity failure")
    } else {
        tracing::error!(error = %error, "auth event source failed");
        ConnectError::new(ErrorCode::Unavailable, "auth event source unavailable")
    }
}

fn sequence_exhausted() -> ConnectError {
    ConnectError::new(ErrorCode::DataLoss, "auth event sequence is exhausted")
}

#[derive(Clone)]
struct EventRpcAuth {
    expected_digest: [u8; 32],
}

impl EventRpcAuth {
    fn new(token: &SecretString) -> Self {
        Self {
            expected_digest: Sha256::digest(token.expose_secret().as_bytes()).into(),
        }
    }

    fn authorized(&self, headers: &http::HeaderMap) -> bool {
        let supplied = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        let supplied_digest: [u8; 32] = Sha256::digest(supplied.as_bytes()).into();
        bool::from(self.expected_digest.ct_eq(&supplied_digest))
    }
}

#[connectrpc::async_trait]
impl Interceptor for EventRpcAuth {
    async fn intercept_streaming(
        &self,
        request: StreamRequest,
        inbound: PayloadStream,
        next: NextStream<'_>,
    ) -> Result<StreamResponse, ConnectError> {
        if !self.authorized(request.ctx.headers()) {
            return Err(ConnectError::new(
                ErrorCode::Unauthenticated,
                "authentication required",
            ));
        }
        next.run(request, inbound).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use connectrpc::{
        Protocol,
        client::{ClientConfig, HttpClient},
    };
    use serde_json::json;
    use tokio::time::timeout;
    use uuid::Uuid;

    use super::*;
    use crate::proto::rustyauth::events::v1::{AuthEventServiceClient, subscribe_response};

    const TEST_TOKEN: &str = "event-rpc-test-token-longer-than-32-characters";

    #[derive(Clone)]
    struct MemoryEventSource {
        events: Arc<Vec<AuthEvent>>,
    }

    impl MemoryEventSource {
        fn new(events: Vec<AuthEvent>) -> Self {
            Self {
                events: Arc::new(events),
            }
        }
    }

    impl EventSource for MemoryEventSource {
        async fn events(&self, after: u64, limit: u64) -> Result<Vec<AuthEvent>> {
            Ok(self
                .events
                .iter()
                .filter(|event| event.sequence > after)
                .take(limit as usize)
                .cloned()
                .collect())
        }

        async fn latest_event_sequence(&self) -> Result<u64> {
            Ok(self
                .events
                .last()
                .map(|event| event.sequence)
                .unwrap_or_default())
        }
    }

    fn test_event(sequence: u64) -> AuthEvent {
        AuthEvent {
            sequence,
            id: Uuid::new_v4(),
            tenant_id: "default".to_owned(),
            event_type: "identity.created".to_owned(),
            subject: Some(Uuid::new_v4()),
            occurred_at: 1_700_000_000,
            data: json!({"source": "wire-test"}),
        }
    }

    async fn spawn_test_service(
        source: MemoryEventSource,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let dispatcher =
            AuthEventServiceServer::new(EventService::new(source, Duration::from_millis(10), 4));
        let token = SecretString::from(TEST_TOKEN);
        let service =
            ConnectRpcService::new(dispatcher).with_interceptor(EventRpcAuth::new(&token));
        let app = axum::Router::new().fallback_service(service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test RPC server");
        let address = listener.local_addr().expect("test RPC server address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve test RPC server");
        });
        (format!("http://{address}"), server)
    }

    fn client(
        base_url: &str,
        protocol: Protocol,
        authorized: bool,
    ) -> AuthEventServiceClient<HttpClient> {
        let transport = if protocol == Protocol::Grpc {
            HttpClient::plaintext_http2_only()
        } else {
            HttpClient::plaintext()
        };
        let mut config = ClientConfig::new(base_url.parse().expect("valid test RPC URL"))
            .with_protocol(protocol)
            .with_default_timeout(Duration::from_secs(2));
        if authorized {
            config = config
                .with_default_header(http::header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"));
        }
        AuthEventServiceClient::new(transport, config)
    }

    fn subscribe_request() -> SubscribeRequest {
        SubscribeRequest {
            after_sequence: 0,
            checkpoint_interval_seconds: 5,
            ..Default::default()
        }
    }

    #[test]
    fn event_and_tenant_filters_are_narrowly_validated() {
        assert!(valid_event_type("identity.created"));
        assert!(valid_event_type("a"));
        assert!(!valid_event_type("Identity.Created"));
        assert!(!valid_event_type("identity."));
        assert!(valid_tenant_id("tenant-1"));
        assert!(!valid_tenant_id("Tenant-1"));
        assert!(!valid_tenant_id("tenant_name"));
    }

    #[test]
    fn checkpoint_interval_is_bounded() {
        assert_eq!(checkpoint_interval(0).unwrap(), Duration::from_secs(15));
        assert!(checkpoint_interval(5).is_ok());
        assert!(checkpoint_interval(60).is_ok());
        assert!(checkpoint_interval(4).is_err());
        assert!(checkpoint_interval(61).is_err());
    }

    #[test]
    fn event_rpc_bearer_authentication_fails_closed() {
        let token = SecretString::from(TEST_TOKEN);
        let auth = EventRpcAuth::new(&token);
        let mut headers = http::HeaderMap::new();
        assert!(!auth.authorized(&headers));
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer wrong-token"),
        );
        assert!(!auth.authorized(&headers));
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer event-rpc-test-token-longer-than-32-characters"),
        );
        assert!(auth.authorized(&headers));
    }

    #[tokio::test]
    async fn subscription_works_over_connect_grpc_web_and_grpc() {
        for protocol in [Protocol::Connect, Protocol::GrpcWeb, Protocol::Grpc] {
            let expected = test_event(1);
            let (base_url, server) =
                spawn_test_service(MemoryEventSource::new(vec![expected.clone()])).await;
            let client = client(&base_url, protocol, true);
            let mut stream = client
                .subscribe(subscribe_request())
                .await
                .unwrap_or_else(|error| panic!("{protocol:?} subscription failed: {error}"));
            let message = timeout(
                Duration::from_secs(2),
                stream.message::<SubscribeResponse>(),
            )
            .await
            .unwrap_or_else(|_| panic!("{protocol:?} response timed out"))
            .unwrap_or_else(|error| panic!("{protocol:?} response failed: {error}"))
            .unwrap_or_else(|| panic!("{protocol:?} stream ended without an event"))
            .to_owned_message();

            let subscribe_response::Payload::Event(event) =
                message.payload.expect("event response payload")
            else {
                panic!("{protocol:?} returned a checkpoint before the first event");
            };
            assert_eq!(event.sequence, expected.sequence);
            assert_eq!(event.r#type, expected.event_type);
            assert_eq!(event.tenant_id, expected.tenant_id);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&event.data_json)
                    .expect("valid event JSON"),
                expected.data
            );
            server.abort();
        }
    }

    #[tokio::test]
    async fn subscription_rejects_missing_bearer_token() {
        let (base_url, server) =
            spawn_test_service(MemoryEventSource::new(vec![test_event(1)])).await;
        let client = client(&base_url, Protocol::Connect, false);
        let error = match client.subscribe(subscribe_request()).await {
            Err(error) => error,
            Ok(mut stream) => timeout(
                Duration::from_secs(2),
                stream.message::<SubscribeResponse>(),
            )
            .await
            .expect("unauthenticated response timed out")
            .expect_err("unauthenticated stream returned a message"),
        };
        assert_eq!(error.code, ErrorCode::Unauthenticated);
        server.abort();
    }

    #[tokio::test]
    async fn subscription_reports_event_sequence_gaps_as_data_loss() {
        let (base_url, server) =
            spawn_test_service(MemoryEventSource::new(vec![test_event(1), test_event(3)])).await;
        let client = client(&base_url, Protocol::Connect, true);
        let mut stream = client
            .subscribe(subscribe_request())
            .await
            .expect("subscribe to gapped event source");
        stream
            .message::<SubscribeResponse>()
            .await
            .expect("read first event")
            .expect("first event exists");
        let error = stream
            .message::<SubscribeResponse>()
            .await
            .expect_err("gapped event source must fail");
        assert_eq!(error.code, ErrorCode::DataLoss);
        server.abort();
    }
}
