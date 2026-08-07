//! Append-only auth event log with gap-free sequencing.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Store, now};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthEvent {
    pub sequence: u64,
    pub id: Uuid,
    pub tenant_id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub subject: Option<Uuid>,
    pub occurred_at: u64,
    #[serde(default = "empty_event_data")]
    pub data: serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
pub enum EventLogIntegrityError {
    #[error("auth event log is missing sequence {0}")]
    MissingSequence(u64),
    #[error("auth event log record {sequence} is malformed")]
    MalformedRecord { sequence: u64 },
    #[error("auth event log record {expected} contains sequence {actual}")]
    UnexpectedSequence { expected: u64, actual: u64 },
}

impl Store {
    pub async fn append_event(&self, event_type: &str, subject: Option<Uuid>) -> Result<AuthEvent> {
        let _snapshot = self.snapshot_gate.read().await;
        self.append_event_within_snapshot(event_type, subject).await
    }

    /// Appends one event. The caller must already hold the snapshot gate; this
    /// acquires the mutation lock, so a caller holding it must use
    /// [`Self::append_event_locked`] instead — the mutex is not reentrant.
    pub(super) async fn append_event_within_snapshot(
        &self,
        event_type: &str,
        subject: Option<Uuid>,
    ) -> Result<AuthEvent> {
        let _guard = self.mutation.lock().await;
        self.append_event_locked(event_type, subject).await
    }

    /// Appends one event, assuming the caller holds both the snapshot gate and
    /// the mutation lock.
    pub(super) async fn append_event_locked(
        &self,
        event_type: &str,
        subject: Option<Uuid>,
    ) -> Result<AuthEvent> {
        let mut events = self
            .pending_events(vec![(event_type.to_owned(), subject)])
            .await?;
        let event = events.pop().expect("one event input produces one event");
        let mut connection = self.redis.clone();
        let mut pipeline = redis::pipe();
        pipeline.atomic();
        queue_events(&mut pipeline, std::slice::from_ref(&event))?;
        let _: () = pipeline.query_async(&mut connection).await?;
        Ok(event)
    }

    pub(super) async fn pending_events(
        &self,
        inputs: Vec<(String, Option<Uuid>)>,
    ) -> Result<Vec<AuthEvent>> {
        let first = self
            .latest_event_sequence()
            .await?
            .checked_add(1)
            .context("auth event sequence exhausted")?;
        inputs
            .into_iter()
            .enumerate()
            .map(|(index, (event_type, subject))| {
                let sequence = first
                    .checked_add(index as u64)
                    .context("auth event sequence exhausted")?;
                Ok(AuthEvent {
                    sequence,
                    id: Uuid::new_v4(),
                    tenant_id: self.tenant_id.clone(),
                    event_type,
                    subject,
                    occurred_at: now(),
                    data: empty_event_data(),
                })
            })
            .collect()
    }

    pub async fn events(&self, after: u64, limit: u64) -> Result<Vec<AuthEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let latest = self.latest_event_sequence().await?;
        let end = latest.min(after.saturating_add(limit));
        if end <= after {
            return Ok(Vec::new());
        }
        let keys = (after + 1..=end)
            .map(|sequence| format!("auth:event:{sequence}"))
            .collect::<Vec<_>>();
        let mut connection = self.redis.clone();
        let values: Vec<Option<String>> = redis::cmd("MGET")
            .arg(&keys)
            .query_async(&mut connection)
            .await
            .context("read auth event batch")?;
        let mut result = Vec::with_capacity(values.len());
        for (index, value) in values.into_iter().enumerate() {
            let expected = after + index as u64 + 1;
            let value = value.ok_or(EventLogIntegrityError::MissingSequence(expected))?;
            let event = serde_json::from_str::<AuthEvent>(&value)
                .map_err(|_| EventLogIntegrityError::MalformedRecord { sequence: expected })?;
            if event.sequence != expected {
                return Err(EventLogIntegrityError::UnexpectedSequence {
                    expected,
                    actual: event.sequence,
                }
                .into());
            }
            result.push(event);
        }
        Ok(result)
    }

    pub async fn latest_event_sequence(&self) -> Result<u64> {
        Ok(self.get::<u64>("auth:event-sequence").await?.unwrap_or(0))
    }
}

fn empty_event_data() -> serde_json::Value {
    serde_json::json!({})
}

pub(super) fn queue_events(pipeline: &mut redis::Pipeline, events: &[AuthEvent]) -> Result<()> {
    for event in events {
        pipeline.set(
            format!("auth:event:{}", event.sequence),
            serde_json::to_string(event)?,
        );
    }
    if let Some(event) = events.last() {
        pipeline.set("auth:event-sequence", event.sequence);
    }
    Ok(())
}
