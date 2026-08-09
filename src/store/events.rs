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
    #[error(
        "auth event cursor is older than the retained window; minimum available sequence is {minimum_available}"
    )]
    CursorExpired { minimum_available: u64 },
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

    pub async fn append_event_with_data(
        &self,
        event_type: &str,
        subject: Option<Uuid>,
        data: serde_json::Value,
    ) -> Result<AuthEvent> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut events = self
            .pending_events(vec![(event_type.to_owned(), subject)])
            .await?;
        let mut event = events.pop().expect("one event input produces one event");
        event.data = data;
        let mut connection = self.redis.clone();
        let mut pipeline = redis::pipe();
        pipeline.atomic();
        queue_events(&mut pipeline, std::slice::from_ref(&event))?;
        let _: () = pipeline.query_async(&mut connection).await?;
        Ok(event)
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
        let minimum = self.minimum_event_sequence().await?;
        if after.saturating_add(1) < minimum {
            return Err(EventLogIntegrityError::CursorExpired {
                minimum_available: minimum,
            }
            .into());
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

    pub async fn minimum_event_sequence(&self) -> Result<u64> {
        Ok(self
            .get::<u64>("auth:event-min-sequence")
            .await?
            .unwrap_or(1))
    }

    /// Removes a bounded chronological prefix older than `cutoff`, but never
    /// crosses the slowest webhook cursor. Consumers behind the retained window
    /// receive an explicit cursor-expired error instead of a false data-loss gap.
    pub async fn prune_events_older_than(&self, cutoff: u64, maximum: usize) -> Result<usize> {
        if maximum == 0 {
            return Ok(0);
        }
        let _snapshot = self.snapshot_gate.write().await;
        let _guard = self.mutation.lock().await;
        let latest = self.latest_event_sequence().await?;
        let webhook_safe_sequence = self
            .webhooks()
            .await?
            .into_iter()
            .map(|record| record.id)
            .collect::<Vec<_>>();
        let mut safe_sequence = latest;
        if let Some(projector_cursor) = self.get::<u64>("analytics:projector-cursor").await? {
            safe_sequence = safe_sequence.min(projector_cursor);
        }
        for id in webhook_safe_sequence {
            safe_sequence = safe_sequence.min(self.webhook_cursor(&id).await?);
        }
        let minimum = self.minimum_event_sequence().await?;
        if minimum > safe_sequence {
            return Ok(0);
        }
        let end = safe_sequence.min(minimum.saturating_add(maximum.saturating_sub(1) as u64));
        let keys = (minimum..=end)
            .map(|sequence| format!("auth:event:{sequence}"))
            .collect::<Vec<_>>();
        let mut connection = self.redis.clone();
        let values: Vec<Option<String>> = redis::cmd("MGET")
            .arg(&keys)
            .query_async(&mut connection)
            .await
            .context("read auth events for retention")?;
        let mut last_deleted = None;
        for (index, value) in values.into_iter().enumerate() {
            let sequence = minimum + index as u64;
            let value = value.ok_or(EventLogIntegrityError::MissingSequence(sequence))?;
            let event = serde_json::from_str::<AuthEvent>(&value)
                .map_err(|_| EventLogIntegrityError::MalformedRecord { sequence })?;
            if event.sequence != sequence {
                return Err(EventLogIntegrityError::UnexpectedSequence {
                    expected: sequence,
                    actual: event.sequence,
                }
                .into());
            }
            if event.occurred_at >= cutoff {
                break;
            }
            last_deleted = Some(sequence);
        }
        let Some(last_deleted) = last_deleted else {
            return Ok(0);
        };
        let delete_keys = (minimum..=last_deleted)
            .map(|sequence| format!("auth:event:{sequence}"))
            .collect::<Vec<_>>();
        let next_minimum = last_deleted.saturating_add(1);
        let _: () = redis::pipe()
            .atomic()
            .del(delete_keys)
            .set("auth:event-min-sequence", next_minimum)
            .query_async(&mut connection)
            .await
            .context("apply auth event retention")?;
        Ok((last_deleted - minimum + 1) as usize)
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
