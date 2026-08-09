//! Operator-authorized webhook administration and delivery history RPCs.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use secrecy::ExposeSecret;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use uuid::Uuid;

use crate::{
    operator_auth::{OperatorAuthorizer, OperatorCapability},
    proto::rustyauth::webhooks::v1::*,
    rpc::RpcPrincipal,
    store::{
        Store, WebhookDeliveryRecord, WebhookDeliveryStatusRecord, WebhookManagementSourceRecord,
        WebhookRecord, WebhookStatusRecord, now,
    },
    webhook::WebhookRuntime,
};

const DEFAULT_PAGE_SIZE: usize = 25;
const MAX_PAGE_SIZE: u32 = 100;

pub(crate) struct WebhookRpc {
    store: Store,
    authorizer: OperatorAuthorizer,
    runtime: WebhookRuntime,
}

impl WebhookRpc {
    pub(crate) fn new(
        store: Store,
        authorizer: OperatorAuthorizer,
        runtime: WebhookRuntime,
    ) -> Self {
        Self {
            store,
            authorizer,
            runtime,
        }
    }

    async fn authorize(
        &self,
        ctx: &RequestContext,
        capability: OperatorCapability,
    ) -> Result<(), ConnectError> {
        if ctx.extensions().get::<RpcPrincipal>() == Some(&RpcPrincipal::Machine) {
            return Ok(());
        }
        self.authorizer
            .authorize(ctx.headers(), capability)
            .await
            .map(|_| ())
    }
}

#[allow(refining_impl_trait)]
impl WebhookService for WebhookRpc {
    async fn list_webhooks(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListWebhooksRequest>,
    ) -> ServiceResult<ListWebhooksResponse> {
        self.authorize(&ctx, OperatorCapability::Read).await?;
        let after = decode_page_token(request.page_token)?;
        let page_size = page_size(request.page_size)?;
        let status = webhook_status_filter(request.status.as_known())?;
        let mut records = self.store.webhooks().await.map_err(internal)?;
        records.retain(|record| {
            after.as_ref().is_none_or(|after| record.id > *after)
                && status.is_none_or(|status| record.status == status)
        });
        let next_page_token =
            (records.len() > page_size).then(|| encode_page_token(&records[page_size - 1].id));
        records.truncate(page_size);
        Response::ok(ListWebhooksResponse {
            webhooks: records
                .into_iter()
                .map(webhook_to_proto)
                .collect::<Result<_, _>>()?,
            next_page_token: next_page_token.unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn get_webhook(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetWebhookRequest>,
    ) -> ServiceResult<Webhook> {
        self.authorize(&ctx, OperatorCapability::Read).await?;
        let id = safe_id(request.webhook_id)?;
        let record = self
            .store
            .webhook(id)
            .await
            .map_err(internal)?
            .ok_or_else(not_found)?;
        Response::ok(webhook_to_proto(record)?)
    }

    async fn create_webhook(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateWebhookRequest>,
    ) -> ServiceResult<CreateWebhookResponse> {
        self.authorize(&ctx, OperatorCapability::Administer).await?;
        let (record, secret) = self
            .runtime
            .create_dashboard_webhook(
                safe_text(request.name, "name", 100)?,
                safe_url(request.url)?,
                safe_event_types(&request.event_types)?,
            )
            .await
            .map_err(internal)?;
        Response::ok(CreateWebhookResponse {
            webhook: Some(webhook_to_proto(record)?).into(),
            signing_secret: secret.expose_secret().to_owned(),
            ..Default::default()
        })
    }

    async fn update_webhook(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateWebhookRequest>,
    ) -> ServiceResult<Webhook> {
        self.authorize(&ctx, OperatorCapability::Administer).await?;
        require_reason(request.reason)?;
        let id = safe_id(request.webhook_id)?;
        let mut record = self
            .store
            .webhook(id)
            .await
            .map_err(internal)?
            .ok_or_else(not_found)?;
        if record.management_source == WebhookManagementSourceRecord::Configuration {
            return Err(ConnectError::new(
                ErrorCode::FailedPrecondition,
                "configuration-managed webhooks must be changed in deployment configuration",
            ));
        }
        record.name = safe_text(request.name, "name", 100)?;
        record.url = safe_url(request.url)?;
        record.status = webhook_status_required(request.status.as_known())?;
        record.event_types = safe_event_types(&request.event_types)?;
        record.updated_at = now();
        self.store
            .put_webhook(&record, "webhook.updated")
            .await
            .map_err(internal)?;
        Response::ok(webhook_to_proto(record)?)
    }

    async fn rotate_signing_secret(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RotateSigningSecretRequest>,
    ) -> ServiceResult<RotateSigningSecretResponse> {
        self.authorize(&ctx, OperatorCapability::Administer).await?;
        require_reason(request.reason)?;
        let (record, secret) = self
            .runtime
            .rotate_secret(safe_id(request.webhook_id)?)
            .await
            .map_err(source_error)?;
        Response::ok(RotateSigningSecretResponse {
            webhook: Some(webhook_to_proto(record)?).into(),
            signing_secret: secret.expose_secret().to_owned(),
            ..Default::default()
        })
    }

    async fn test_webhook(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, TestWebhookRequest>,
    ) -> ServiceResult<WebhookDelivery> {
        self.authorize(&ctx, OperatorCapability::Administer).await?;
        let delivery = self
            .runtime
            .test_delivery(safe_id(request.webhook_id)?)
            .await
            .map_err(source_error)?;
        Response::ok(delivery_to_proto(delivery)?)
    }

    async fn list_deliveries(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListDeliveriesRequest>,
    ) -> ServiceResult<ListDeliveriesResponse> {
        self.authorize(&ctx, OperatorCapability::Read).await?;
        let webhook_id = safe_id(request.webhook_id)?;
        let after = decode_uuid_page_token(request.page_token)?;
        let page_size = page_size(request.page_size)?;
        let status = delivery_status_filter(request.status.as_known())?;
        let mut records = self.store.webhook_deliveries().await.map_err(internal)?;
        records.retain(|record| {
            record.webhook_id == webhook_id
                && after.is_none_or(|after| record.id > after)
                && status.is_none_or(|status| record.status == status)
        });
        records.sort_unstable_by_key(|record| record.id);
        let next_page_token =
            (records.len() > page_size).then(|| encode_uuid_page_token(records[page_size - 1].id));
        records.truncate(page_size);
        Response::ok(ListDeliveriesResponse {
            deliveries: records
                .into_iter()
                .map(delivery_to_proto)
                .collect::<Result<_, _>>()?,
            next_page_token: next_page_token.unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn replay_delivery(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ReplayDeliveryRequest>,
    ) -> ServiceResult<WebhookDelivery> {
        self.authorize(&ctx, OperatorCapability::Administer).await?;
        require_reason(request.reason)?;
        let delivery = self
            .runtime
            .replay_delivery(required_uuid(request.delivery_id, "delivery_id")?)
            .await
            .map_err(source_error)?;
        Response::ok(delivery_to_proto(delivery)?)
    }

    async fn delete_webhook(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteWebhookRequest>,
    ) -> ServiceResult<DeleteWebhookResponse> {
        self.authorize(&ctx, OperatorCapability::Administer).await?;
        require_reason(request.reason)?;
        let id = safe_id(request.webhook_id)?;
        let record = self
            .store
            .webhook(id)
            .await
            .map_err(internal)?
            .ok_or_else(not_found)?;
        if record.management_source == WebhookManagementSourceRecord::Configuration {
            return Err(ConnectError::new(
                ErrorCode::FailedPrecondition,
                "configuration-managed webhooks must be removed from deployment configuration",
            ));
        }
        self.store.remove_webhook(id).await.map_err(internal)?;
        Response::ok(DeleteWebhookResponse::default())
    }
}

pub(crate) fn webhook_to_proto(record: WebhookRecord) -> Result<Webhook, ConnectError> {
    Ok(Webhook {
        id: record.id,
        name: record.name,
        url: record.url,
        status: match record.status {
            WebhookStatusRecord::Active => WebhookStatus::Active,
            WebhookStatusRecord::Paused => WebhookStatus::Paused,
            WebhookStatusRecord::Failing => WebhookStatus::Failing,
        }
        .into(),
        event_types: record.event_types,
        secret_hint: record.secret_hint,
        created_at: format_timestamp(record.created_at)?,
        updated_at: format_timestamp(record.updated_at)?,
        last_delivery_at: format_optional_timestamp(record.last_delivery_at)?,
        management_source: match record.management_source {
            WebhookManagementSourceRecord::Dashboard => WebhookManagementSource::Dashboard,
            WebhookManagementSourceRecord::Configuration => WebhookManagementSource::Configuration,
        }
        .into(),
        ..Default::default()
    })
}

fn delivery_to_proto(record: WebhookDeliveryRecord) -> Result<WebhookDelivery, ConnectError> {
    Ok(WebhookDelivery {
        id: record.id.to_string(),
        webhook_id: record.webhook_id,
        event_id: record.event_id.to_string(),
        event_type: record.event_type,
        status: match record.status {
            WebhookDeliveryStatusRecord::Pending => DeliveryStatus::Pending,
            WebhookDeliveryStatusRecord::Succeeded => DeliveryStatus::Succeeded,
            WebhookDeliveryStatusRecord::Retrying => DeliveryStatus::Retrying,
            WebhookDeliveryStatusRecord::Failed => DeliveryStatus::Failed,
        }
        .into(),
        attempt_count: record.attempt_count,
        response_status: record.response_status.unwrap_or_default().into(),
        latency_milliseconds: record.latency_milliseconds,
        created_at: format_timestamp(record.created_at)?,
        next_attempt_at: format_optional_timestamp(record.next_attempt_at)?,
        completed_at: format_optional_timestamp(record.completed_at)?,
        error_class: record.error_class,
        ..Default::default()
    })
}

fn safe_id(value: &str) -> Result<&str, ConnectError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid("webhook_id is invalid"));
    }
    Ok(value)
}

fn safe_text(value: &str, field: &'static str, maximum: usize) -> Result<String, ConnectError> {
    let value = value.trim();
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(invalid(format!("{field} is invalid")));
    }
    Ok(value.to_owned())
}

fn safe_url(value: &str) -> Result<String, ConnectError> {
    let url = Url::parse(value.trim()).map_err(|_| invalid("url is invalid"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "url must be HTTPS without credentials or a fragment",
        ));
    }
    Ok(url.to_string())
}

fn safe_event_types(values: &[&str]) -> Result<Vec<String>, ConnectError> {
    if values.is_empty() || values.len() > 50 {
        return Err(invalid("event_types must contain 1-50 values"));
    }
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        if !valid_event_type(value) || result.iter().any(|existing| existing == value) {
            return Err(invalid(
                "event_types contains an invalid or duplicate value",
            ));
        }
        result.push((*value).to_owned());
    }
    Ok(result)
}

fn valid_event_type(value: &str) -> bool {
    let bytes = value.as_bytes();
    let boundary = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    value == "*"
        || (!bytes.is_empty()
            && bytes.len() <= 128
            && boundary(bytes[0])
            && boundary(bytes[bytes.len() - 1])
            && bytes.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            }))
}

fn require_reason(value: &str) -> Result<String, ConnectError> {
    safe_text(value, "reason", 500)
}

fn webhook_status_filter(
    status: Option<WebhookStatus>,
) -> Result<Option<WebhookStatusRecord>, ConnectError> {
    match status {
        None | Some(WebhookStatus::Unspecified) => Ok(None),
        Some(status) => webhook_status_required(Some(status)).map(Some),
    }
}

fn webhook_status_required(
    status: Option<WebhookStatus>,
) -> Result<WebhookStatusRecord, ConnectError> {
    match status {
        Some(WebhookStatus::Active) => Ok(WebhookStatusRecord::Active),
        Some(WebhookStatus::Paused) => Ok(WebhookStatusRecord::Paused),
        Some(WebhookStatus::Failing) => Ok(WebhookStatusRecord::Failing),
        None | Some(WebhookStatus::Unspecified) => Err(invalid("status is required")),
    }
}

fn delivery_status_filter(
    status: Option<DeliveryStatus>,
) -> Result<Option<WebhookDeliveryStatusRecord>, ConnectError> {
    match status {
        None | Some(DeliveryStatus::Unspecified) => Ok(None),
        Some(DeliveryStatus::Pending) => Ok(Some(WebhookDeliveryStatusRecord::Pending)),
        Some(DeliveryStatus::Succeeded) => Ok(Some(WebhookDeliveryStatusRecord::Succeeded)),
        Some(DeliveryStatus::Retrying) => Ok(Some(WebhookDeliveryStatusRecord::Retrying)),
        Some(DeliveryStatus::Failed) => Ok(Some(WebhookDeliveryStatusRecord::Failed)),
    }
}

fn page_size(value: u32) -> Result<usize, ConnectError> {
    match value {
        0 => Ok(DEFAULT_PAGE_SIZE),
        value if value <= MAX_PAGE_SIZE => Ok(value as usize),
        _ => Err(invalid("page_size must not exceed 100")),
    }
}

fn encode_page_token(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

fn decode_page_token(value: &str) -> Result<Option<String>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid("page_token is invalid"))?;
    let decoded = String::from_utf8(decoded).map_err(|_| invalid("page_token is invalid"))?;
    safe_id(&decoded)?;
    Ok(Some(decoded))
}

fn encode_uuid_page_token(value: Uuid) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

fn decode_uuid_page_token(value: &str) -> Result<Option<Uuid>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid("page_token is invalid"))?;
    Uuid::from_slice(&bytes)
        .map(Some)
        .map_err(|_| invalid("page_token is invalid"))
}

fn required_uuid(value: &str, field: &'static str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(value).map_err(|_| invalid(format!("{field} must be a UUID")))
}

fn format_timestamp(timestamp: u64) -> Result<String, ConnectError> {
    let timestamp = i64::try_from(timestamp).map_err(|_| internal("timestamp is out of range"))?;
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|_| internal("timestamp is out of range"))?
        .format(&Rfc3339)
        .map_err(internal)
}

fn format_optional_timestamp(timestamp: Option<u64>) -> Result<String, ConnectError> {
    timestamp
        .map(format_timestamp)
        .transpose()
        .map(|value| value.unwrap_or_default())
}

fn invalid(message: impl Into<String>) -> ConnectError {
    ConnectError::new(ErrorCode::InvalidArgument, message)
}

fn not_found() -> ConnectError {
    ConnectError::new(ErrorCode::NotFound, "webhook resource was not found")
}

fn source_error(error: impl std::fmt::Display) -> ConnectError {
    let message = error.to_string();
    if message.contains("missing") || message.contains("no longer retained") {
        return not_found();
    }
    internal(error)
}

fn internal(error: impl std::fmt::Display) -> ConnectError {
    tracing::error!(error = %error, "webhook RPC failed");
    ConnectError::new(ErrorCode::Internal, "webhook operation failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_inputs_are_bounded_and_https_only() {
        assert_eq!(
            safe_url("https://example.com/hook").unwrap(),
            "https://example.com/hook"
        );
        assert!(safe_url("http://example.com/hook").is_err());
        assert!(safe_url("https://user@example.com/hook").is_err());
        assert!(safe_event_types(&["identity.created", "session.created"]).is_ok());
        assert!(safe_event_types(&["identity.created", "identity.created"]).is_err());
        assert!(safe_event_types(&["Bad Event"]).is_err());
    }

    #[test]
    fn pagination_tokens_are_opaque_and_validated() {
        let id = "application-lifecycle";
        assert_eq!(
            decode_page_token(&encode_page_token(id))
                .unwrap()
                .as_deref(),
            Some(id)
        );
        assert!(decode_page_token("not+base64").is_err());
        let uuid = Uuid::new_v4();
        assert_eq!(
            decode_uuid_page_token(&encode_uuid_page_token(uuid)).unwrap(),
            Some(uuid)
        );
    }
}
