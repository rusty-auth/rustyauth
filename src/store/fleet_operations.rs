//! Short-lived Fleet operational projections.
//!
//! These records deliberately live outside the backup boundary. They contain
//! the safe, already-redacted management projections returned by a realm and
//! exist only to make a recently observed realm visibly stale instead of
//! silently turning an outage into zero values.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use buffa::Message;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::proto::rustyauth::management::v1::RealmOperationalSnapshot;

use super::{Store, now};

const OPERATIONS_CACHE_PREFIX: &str = "fleet:operations-cache:";
const OPERATIONS_CACHE_SECONDS: u64 = 15 * 60;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetOperationalCacheRecord {
    pub connection_id: Uuid,
    pub realm_id: String,
    pub payload_base64url: String,
    pub observed_at: u64,
    pub expires_at: u64,
}

impl FleetOperationalCacheRecord {
    pub fn snapshot(&self) -> Result<RealmOperationalSnapshot> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.payload_base64url)
            .context("decode cached Fleet operational snapshot")?;
        RealmOperationalSnapshot::decode_from_slice(&bytes)
            .context("decode cached Fleet operational snapshot payload")
    }
}

impl Store {
    pub async fn cache_fleet_operational_snapshot(
        &self,
        connection_id: Uuid,
        realm_id: &str,
        snapshot: &RealmOperationalSnapshot,
    ) -> Result<FleetOperationalCacheRecord> {
        if snapshot.realm_id != realm_id || snapshot.source != "live-realm" {
            bail!("operational snapshot does not match its trusted Fleet source");
        }
        let observed_at = now();
        let record = FleetOperationalCacheRecord {
            connection_id,
            realm_id: realm_id.to_owned(),
            payload_base64url: URL_SAFE_NO_PAD.encode(snapshot.encode_to_vec()),
            observed_at,
            expires_at: observed_at.saturating_add(OPERATIONS_CACHE_SECONDS),
        };
        self.set_json_ex(
            &operations_cache_key(connection_id),
            &record,
            OPERATIONS_CACHE_SECONDS,
        )
        .await?;
        Ok(record)
    }

    pub async fn fleet_operational_snapshot(
        &self,
        connection_id: Uuid,
        realm_id: &str,
    ) -> Result<Option<FleetOperationalCacheRecord>> {
        let record = self
            .get_json::<FleetOperationalCacheRecord>(&operations_cache_key(connection_id))
            .await?;
        let Some(record) = record else {
            return Ok(None);
        };
        if record.connection_id != connection_id
            || record.realm_id != realm_id
            || record.expires_at <= now()
        {
            return Ok(None);
        }
        let snapshot = record.snapshot()?;
        if snapshot.realm_id != realm_id || snapshot.source != "live-realm" {
            bail!("cached Fleet operational snapshot failed source validation");
        }
        Ok(Some(record))
    }
}

fn operations_cache_key(connection_id: Uuid) -> String {
    format!("{OPERATIONS_CACHE_PREFIX}{connection_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_keys_are_connection_scoped() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        assert_ne!(operations_cache_key(first), operations_cache_key(second));
        assert!(operations_cache_key(first).ends_with(&first.to_string()));
    }
}
