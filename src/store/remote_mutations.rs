//! Durable replay fencing for Fleet-initiated realm mutations.

use anyhow::{Context, Result};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Store, StorePolicyError, now};

const REMOTE_MUTATION_PREFIX: &str = "auth:remote-mutation:";
const REMOTE_MUTATION_RETENTION_SECONDS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum RemoteMutationState {
    Pending,
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteMutationReceipt {
    digest: String,
    state: RemoteMutationState,
    claimed_at: u64,
    completed_at: Option<u64>,
    succeeded: Option<bool>,
    summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteMutationClaim {
    Claimed,
    Completed {
        completed_at: u64,
        succeeded: bool,
        summary: String,
    },
}

impl Store {
    /// Claims a request ID before a remote side effect. The claim is persisted
    /// with a bounded TTL and request digest, so concurrent delivery cannot run
    /// twice and a reused ID cannot be retargeted to another operation.
    pub async fn claim_remote_mutation(
        &self,
        request_id: Uuid,
        digest: &str,
    ) -> Result<RemoteMutationClaim> {
        let key = remote_mutation_key(request_id);
        let receipt = RemoteMutationReceipt {
            digest: digest.to_owned(),
            state: RemoteMutationState::Pending,
            claimed_at: now(),
            completed_at: None,
            succeeded: None,
            summary: String::new(),
        };
        let mut connection = self.redis.clone();
        let inserted: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(serde_json::to_string(&receipt)?)
            .arg("NX")
            .arg("EX")
            .arg(REMOTE_MUTATION_RETENTION_SECONDS)
            .query_async(&mut connection)
            .await
            .context("claim remote Fleet mutation")?;
        if inserted.is_some() {
            return Ok(RemoteMutationClaim::Claimed);
        }
        let existing: String = connection
            .get(&key)
            .await
            .context("read remote Fleet mutation receipt")?;
        let existing: RemoteMutationReceipt =
            serde_json::from_str(&existing).context("decode remote Fleet mutation receipt")?;
        if existing.digest != digest {
            return Err(StorePolicyError::RemoteMutationIdempotencyConflict.into());
        }
        match (existing.state, existing.completed_at) {
            (RemoteMutationState::Completed, Some(completed_at)) => {
                Ok(RemoteMutationClaim::Completed {
                    completed_at,
                    succeeded: existing.succeeded.unwrap_or(false),
                    summary: existing.summary,
                })
            }
            _ => Err(StorePolicyError::RemoteMutationPending.into()),
        }
    }

    pub async fn complete_remote_mutation(
        &self,
        request_id: Uuid,
        digest: &str,
        succeeded: bool,
        summary: String,
    ) -> Result<u64> {
        let key = remote_mutation_key(request_id);
        let mut connection = self.redis.clone();
        let existing: String = connection
            .get(&key)
            .await
            .context("read claimed remote Fleet mutation")?;
        let mut receipt: RemoteMutationReceipt =
            serde_json::from_str(&existing).context("decode claimed remote Fleet mutation")?;
        if receipt.digest != digest {
            return Err(StorePolicyError::RemoteMutationIdempotencyConflict.into());
        }
        if receipt.state == RemoteMutationState::Completed {
            return receipt
                .completed_at
                .ok_or_else(|| StorePolicyError::RemoteMutationPending.into());
        }
        let completed_at = now();
        receipt.state = RemoteMutationState::Completed;
        receipt.completed_at = Some(completed_at);
        receipt.succeeded = Some(succeeded);
        receipt.summary = summary;
        let response: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(serde_json::to_string(&receipt)?)
            .arg("XX")
            .arg("EX")
            .arg(REMOTE_MUTATION_RETENTION_SECONDS)
            .query_async(&mut connection)
            .await
            .context("complete remote Fleet mutation")?;
        if response.is_none() {
            return Err(StorePolicyError::RemoteMutationPending.into());
        }
        Ok(completed_at)
    }
}

fn remote_mutation_key(request_id: Uuid) -> String {
    format!("{REMOTE_MUTATION_PREFIX}{request_id}")
}
