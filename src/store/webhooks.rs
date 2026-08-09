//! Durable webhook destinations, delivery attempts, and per-destination cursors.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Store, events::queue_events};

const WEBHOOK_PREFIX: &str = "auth:webhook:";
const DELIVERY_PREFIX: &str = "auth:webhook-delivery:";
const DELIVERY_EVENT_PREFIX: &str = "auth:webhook-delivery-event:";
const CURSOR_PREFIX: &str = "auth:webhook-cursor:";
const DELIVERY_BACKLOG_KEY: &str = "auth:webhook-delivery-backlog";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WebhookStatusRecord {
    Active,
    Paused,
    Failing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WebhookManagementSourceRecord {
    Dashboard,
    Configuration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WebhookDeliveryStatusRecord {
    Pending,
    Succeeded,
    Retrying,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedWebhookSecret {
    pub wrapping_key_id: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookRecord {
    pub id: String,
    pub name: String,
    pub url: String,
    pub status: WebhookStatusRecord,
    pub event_types: Vec<String>,
    pub secret: EncryptedWebhookSecret,
    pub secret_hint: String,
    pub management_source: WebhookManagementSourceRecord,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_delivery_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookDeliveryRecord {
    pub id: Uuid,
    pub webhook_id: String,
    pub event_sequence: u64,
    pub event_id: Uuid,
    pub event_type: String,
    pub status: WebhookDeliveryStatusRecord,
    pub attempt_count: u32,
    pub response_status: Option<u16>,
    pub latency_milliseconds: u64,
    pub created_at: u64,
    pub next_attempt_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub error_class: String,
}

impl Store {
    pub async fn webhooks(&self) -> Result<Vec<WebhookRecord>> {
        let mut cursor = 0_u64;
        let mut keys = BTreeSet::new();
        loop {
            let mut connection = self.redis.clone();
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{WEBHOOK_PREFIX}*"))
                .arg("COUNT")
                .arg(100_u16)
                .query_async(&mut connection)
                .await
                .context("scan webhook destinations")?;
            keys.extend(batch);
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(record) = self.get_json(&key).await? {
                records.push(record);
            }
        }
        records.sort_unstable_by(|left: &WebhookRecord, right| left.id.cmp(&right.id));
        Ok(records)
    }

    pub async fn webhook(&self, id: &str) -> Result<Option<WebhookRecord>> {
        self.get_json(&webhook_key(id)).await
    }

    pub async fn put_webhook(&self, record: &WebhookRecord, event_type: &str) -> Result<()> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut connection = self.redis.clone();
        let _: () = connection
            .set(webhook_key(&record.id), serde_json::to_string(record)?)
            .await
            .context("persist webhook destination")?;
        self.append_event_locked(event_type, None).await?;
        Ok(())
    }

    pub async fn update_webhook_runtime(&self, record: &WebhookRecord) -> Result<()> {
        let mut connection = self.redis.clone();
        let _: () = connection
            .set(webhook_key(&record.id), serde_json::to_string(record)?)
            .await
            .context("update webhook runtime state")?;
        Ok(())
    }

    pub async fn remove_webhook(&self, id: &str) -> Result<()> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut connection = self.redis.clone();
        let _: () = redis::pipe()
            .atomic()
            .del(webhook_key(id))
            .del(cursor_key(id))
            .query_async(&mut connection)
            .await
            .context("remove webhook destination")?;
        self.append_event_locked("webhook.deleted", None).await?;
        Ok(())
    }

    pub async fn webhook_cursor(&self, id: &str) -> Result<u64> {
        Ok(self.get::<u64>(&cursor_key(id)).await?.unwrap_or(0))
    }

    pub async fn set_webhook_cursor(&self, id: &str, sequence: u64) -> Result<()> {
        let mut connection = self.redis.clone();
        let _: () = connection
            .set(cursor_key(id), sequence)
            .await
            .context("advance webhook cursor")?;
        Ok(())
    }

    pub async fn webhook_delivery_for_event(
        &self,
        webhook_id: &str,
        event_sequence: u64,
    ) -> Result<Option<WebhookDeliveryRecord>> {
        let Some(id) = self
            .get::<String>(&delivery_event_key(webhook_id, event_sequence))
            .await?
        else {
            return Ok(None);
        };
        let id = Uuid::parse_str(&id).context("stored webhook delivery id is invalid")?;
        self.webhook_delivery(id).await
    }

    pub async fn webhook_delivery(&self, id: Uuid) -> Result<Option<WebhookDeliveryRecord>> {
        self.get_json(&delivery_key(id)).await
    }

    pub async fn webhook_deliveries(&self) -> Result<Vec<WebhookDeliveryRecord>> {
        let ids = self
            .record_ids(DELIVERY_PREFIX, "scan webhook deliveries")
            .await?;
        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(record) = self.webhook_delivery(id).await? {
                records.push(record);
            }
        }
        records.sort_unstable_by_key(|record| (record.created_at, record.id));
        Ok(records)
    }

    pub async fn webhook_delivery_backlog(&self) -> Result<u64> {
        Ok(self.get::<u64>(DELIVERY_BACKLOG_KEY).await?.unwrap_or(0))
    }

    pub async fn put_webhook_delivery(&self, record: &WebhookDeliveryRecord) -> Result<()> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let previous = self.webhook_delivery(record.id).await?;
        if previous.as_ref().is_some_and(|previous| {
            is_terminal_delivery(previous.status) && !is_terminal_delivery(record.status)
        }) {
            bail!("a terminal webhook delivery cannot return to a pending state");
        }
        let was_open = previous
            .as_ref()
            .is_some_and(|previous| is_open_delivery(previous.status));
        let is_open = is_open_delivery(record.status);
        let backlog = self.webhook_delivery_backlog().await?;
        let backlog = match (was_open, is_open) {
            (false, true) => backlog
                .checked_add(1)
                .context("webhook delivery backlog exhausted")?,
            (true, false) => backlog
                .checked_sub(1)
                .context("webhook delivery backlog is inconsistent")?,
            _ => backlog,
        };
        let transition_event = delivery_transition_event(previous.as_ref(), record);
        let mut event = if let Some(event_type) = transition_event {
            let mut events = self
                .pending_events(vec![(event_type.to_owned(), None)])
                .await?;
            let mut event = events.pop().expect("one event input produces one event");
            event.data = serde_json::json!({
                "latencyMilliseconds": record.latency_milliseconds,
                "backlog": backlog,
            });
            Some(event)
        } else {
            None
        };
        let mut connection = self.redis.clone();
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(delivery_key(record.id), serde_json::to_string(record)?)
            .set(
                delivery_event_key(&record.webhook_id, record.event_sequence),
                record.id.to_string(),
            )
            .set(DELIVERY_BACKLOG_KEY, backlog);
        if let Some(event) = event.take() {
            queue_events(&mut pipeline, std::slice::from_ref(&event))?;
        }
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("persist webhook delivery")?;
        Ok(())
    }

    pub async fn prune_webhook_deliveries_older_than(
        &self,
        cutoff: u64,
        limit: usize,
    ) -> Result<usize> {
        if limit == 0 {
            return Ok(0);
        }
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut expired = Vec::new();
        for id in self
            .record_ids(DELIVERY_PREFIX, "scan webhook deliveries for retention")
            .await?
        {
            let Some(record) = self.webhook_delivery(id).await? else {
                continue;
            };
            if is_terminal_delivery(record.status)
                && record
                    .completed_at
                    .is_some_and(|completed| completed < cutoff)
            {
                expired.push(record);
                if expired.len() == limit {
                    break;
                }
            }
        }
        if expired.is_empty() {
            return Ok(0);
        }
        let mut pipeline = redis::pipe();
        pipeline.atomic();
        for record in &expired {
            pipeline
                .del(delivery_key(record.id))
                .del(delivery_event_key(
                    &record.webhook_id,
                    record.event_sequence,
                ));
        }
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("prune webhook delivery retention")?;
        Ok(expired.len())
    }
}

fn is_open_delivery(status: WebhookDeliveryStatusRecord) -> bool {
    matches!(
        status,
        WebhookDeliveryStatusRecord::Pending | WebhookDeliveryStatusRecord::Retrying
    )
}

fn is_terminal_delivery(status: WebhookDeliveryStatusRecord) -> bool {
    matches!(
        status,
        WebhookDeliveryStatusRecord::Succeeded | WebhookDeliveryStatusRecord::Failed
    )
}

fn delivery_transition_event<'a>(
    previous: Option<&WebhookDeliveryRecord>,
    record: &'a WebhookDeliveryRecord,
) -> Option<&'a str> {
    let changed = previous.is_none_or(|previous| previous.status != record.status);
    if !changed {
        return None;
    }
    match record.status {
        WebhookDeliveryStatusRecord::Pending if previous.is_none() => {
            Some("analytics.webhook.delivery.queued")
        }
        WebhookDeliveryStatusRecord::Succeeded => Some("analytics.webhook.delivery.succeeded"),
        WebhookDeliveryStatusRecord::Failed => Some("analytics.webhook.delivery.failed"),
        WebhookDeliveryStatusRecord::Pending | WebhookDeliveryStatusRecord::Retrying => None,
    }
}

fn webhook_key(id: &str) -> String {
    format!("{WEBHOOK_PREFIX}{id}")
}

fn delivery_key(id: Uuid) -> String {
    format!("{DELIVERY_PREFIX}{id}")
}

fn delivery_event_key(webhook_id: &str, event_sequence: u64) -> String {
    format!("{DELIVERY_EVENT_PREFIX}{webhook_id}:{event_sequence:020}")
}

fn cursor_key(id: &str) -> String {
    format!("{CURSOR_PREFIX}{id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivery(status: WebhookDeliveryStatusRecord) -> WebhookDeliveryRecord {
        WebhookDeliveryRecord {
            id: Uuid::nil(),
            webhook_id: "webhook".into(),
            event_sequence: 1,
            event_id: Uuid::nil(),
            event_type: "identity.created".into(),
            status,
            attempt_count: 1,
            response_status: None,
            latency_milliseconds: 10,
            created_at: 1,
            next_attempt_at: None,
            completed_at: None,
            error_class: String::new(),
        }
    }

    #[test]
    fn analytics_events_are_emitted_only_for_backlog_and_terminal_transitions() {
        let pending = delivery(WebhookDeliveryStatusRecord::Pending);
        let retrying = delivery(WebhookDeliveryStatusRecord::Retrying);
        let succeeded = delivery(WebhookDeliveryStatusRecord::Succeeded);
        assert_eq!(
            delivery_transition_event(None, &pending),
            Some("analytics.webhook.delivery.queued")
        );
        assert_eq!(delivery_transition_event(Some(&pending), &retrying), None);
        assert_eq!(
            delivery_transition_event(Some(&retrying), &succeeded),
            Some("analytics.webhook.delivery.succeeded")
        );
        assert_eq!(
            delivery_transition_event(Some(&succeeded), &succeeded),
            None
        );
    }
}
