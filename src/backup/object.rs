//! S3-compatible object operations: tenant-scoped key naming, bounded encrypted
//! uploads with read-after-write verification, bounded downloads and listing.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use aws_sdk_s3::primitives::ByteStream;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tracing::info;
use uuid::Uuid;

use crate::{config::KeyRing, jwt::validate_snapshot_keyset, store::Store};

use super::{
    BackupStore,
    envelope::{decode_snapshot, encode_snapshot, envelope_key_id},
    snapshot::BackupSnapshot,
};

const MAX_ENVELOPE_BYTES: usize = 256 * 1024 * 1024;
const CONTENT_TYPE: &str = "application/vnd.rustyauth.backup.v2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupReceipt {
    pub snapshot_id: Uuid,
    pub object_key: String,
    pub captured_at: u64,
    pub record_count: u64,
    pub envelope_bytes: usize,
    pub encryption_key_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupObject {
    pub key: String,
    pub size: i64,
    pub last_modified: Option<String>,
}

impl BackupStore {
    pub(super) async fn create_inner(
        &self,
        store: &Store,
        tenant_id: &str,
        master_keys: &KeyRing,
    ) -> Result<BackupReceipt> {
        let snapshot = Arc::new(BackupSnapshot::capture(store, tenant_id).await?);
        validate_snapshot_keyset(snapshot.signing_keyset()?, master_keys)?;
        let envelope = {
            // Compressing and sealing up to 512 MiB of plaintext would stall every other
            // task sharing this executor thread for the whole operation.
            let keys = self.encryption_keys.clone();
            let snapshot = Arc::clone(&snapshot);
            tokio::task::spawn_blocking(move || encode_snapshot(&keys, &snapshot))
                .await
                .context("encode backup snapshot")??
        };
        if envelope.len() > MAX_ENVELOPE_BYTES {
            bail!("encrypted backup exceeds the 256 MiB object safety limit");
        }
        let checksum = STANDARD.encode(Sha256::digest(&envelope));
        let timestamp = OffsetDateTime::from_unix_timestamp(snapshot.captured_at as i64)?
            .format(&Rfc3339)?
            .replace(':', "-");
        let object_key = format!(
            "rustyauth-backups/v2/{tenant_id}/{timestamp}-{}.rauth",
            snapshot.snapshot_id
        );
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&object_key)
            .content_type(CONTENT_TYPE)
            .checksum_sha256(checksum)
            .metadata("snapshot-id", snapshot.snapshot_id.to_string())
            .metadata("key-id", self.encryption_keys.active().0)
            .body(ByteStream::from(envelope.clone()))
            .send()
            .await
            .context("upload encrypted auth snapshot")?;

        // Read-after-write proves that the provider returned the same decryptable object.
        let downloaded = self.download(&object_key, tenant_id).await?;
        if downloaded.snapshot_id != snapshot.snapshot_id
            || downloaded.manifest.content_sha256 != snapshot.manifest.content_sha256
        {
            bail!("uploaded backup failed read-after-write verification");
        }
        let receipt = BackupReceipt {
            snapshot_id: snapshot.snapshot_id,
            object_key,
            captured_at: snapshot.captured_at,
            record_count: snapshot.manifest.record_count,
            envelope_bytes: envelope.len(),
            encryption_key_id: self.encryption_keys.active().0.to_owned(),
        };
        info!(
            snapshot_id = %receipt.snapshot_id,
            object_key = %receipt.object_key,
            record_count = receipt.record_count,
            envelope_bytes = receipt.envelope_bytes,
            encryption_key_id = %receipt.encryption_key_id,
            "encrypted backup created and verified"
        );
        Ok(receipt)
    }

    pub async fn download(&self, object_key: &str, tenant_id: &str) -> Result<BackupSnapshot> {
        let (snapshot, _, _) = self.download_object(object_key, tenant_id).await?;
        Ok(snapshot)
    }

    async fn download_object(
        &self,
        object_key: &str,
        tenant_id: &str,
    ) -> Result<(BackupSnapshot, String, usize)> {
        validate_object_key(object_key, tenant_id)?;
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(object_key)
            .send()
            .await
            .context("download encrypted auth snapshot")?;
        check_advertised_length(output.content_length())?;
        let bytes = output
            .body
            .collect()
            .await
            .context("read encrypted auth snapshot")?
            .into_bytes();
        if bytes.len() > MAX_ENVELOPE_BYTES {
            bail!("backup object exceeds the 256 MiB safety limit");
        }
        let key_id = envelope_key_id(&bytes)?.to_owned();
        let envelope_bytes = bytes.len();
        // Unsealing and decompressing is the same unbounded CPU cost as sealing, and the
        // manifest digest walks every restored record, so none of it may run inline.
        let keys = self.encryption_keys.clone();
        let expected_tenant = tenant_id.to_owned();
        let snapshot = tokio::task::spawn_blocking(move || -> Result<BackupSnapshot> {
            let snapshot = decode_snapshot(&keys, &bytes)?;
            snapshot.validate(&expected_tenant)?;
            Ok(snapshot)
        })
        .await
        .context("decode backup snapshot")??;
        Ok((snapshot, key_id, envelope_bytes))
    }

    pub async fn verify(
        &self,
        object_key: &str,
        tenant_id: &str,
    ) -> Result<(BackupReceipt, BackupSnapshot)> {
        let (snapshot, key_id, envelope_bytes) =
            self.download_object(object_key, tenant_id).await?;
        let receipt = BackupReceipt {
            snapshot_id: snapshot.snapshot_id,
            object_key: object_key.to_owned(),
            captured_at: snapshot.captured_at,
            record_count: snapshot.manifest.record_count,
            envelope_bytes,
            encryption_key_id: key_id,
        };
        Ok((receipt, snapshot))
    }

    pub async fn list(&self, tenant_id: &str) -> Result<Vec<BackupObject>> {
        let prefix = format!("rustyauth-backups/v2/{tenant_id}/");
        let mut continuation = None;
        let mut objects = Vec::new();
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix);
            if let Some(token) = continuation.as_deref() {
                request = request.continuation_token(token);
            }
            let output = request.send().await.context("list auth backups")?;
            for object in output.contents() {
                let Some(key) = object.key() else {
                    continue;
                };
                objects.push(BackupObject {
                    key: key.to_owned(),
                    size: object.size().unwrap_or_default(),
                    last_modified: object.last_modified().map(ToString::to_string),
                });
            }
            if !output.is_truncated().unwrap_or(false) {
                break;
            }
            continuation = output.next_continuation_token().map(str::to_owned);
            if continuation.is_none() {
                bail!("backup listing was truncated without a continuation token");
            }
        }
        objects.sort_unstable_by(|left, right| right.key.cmp(&left.key));
        Ok(objects)
    }
}

// The body is buffered whole before its real length can be checked, so an object that
// declines to declare a length has to be refused rather than treated as empty.
fn check_advertised_length(content_length: Option<i64>) -> Result<()> {
    let length = content_length.context("backup object does not advertise a content length")?;
    let length =
        usize::try_from(length).context("backup object advertises a negative content length")?;
    if length > MAX_ENVELOPE_BYTES {
        bail!("backup object exceeds the 256 MiB safety limit");
    }
    Ok(())
}

fn validate_object_key(object_key: &str, tenant_id: &str) -> Result<()> {
    let prefix = format!("rustyauth-backups/v2/{tenant_id}/");
    if !object_key.starts_with(&prefix)
        || object_key.contains("..")
        || object_key.chars().any(char::is_control)
        || !object_key.ends_with(".rauth")
    {
        bail!("backup object key is outside the configured tenant prefix");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downloads_without_an_advertised_length_are_refused() {
        check_advertised_length(Some(0)).unwrap();
        check_advertised_length(Some(1)).unwrap();
        check_advertised_length(Some(MAX_ENVELOPE_BYTES as i64)).unwrap();
        assert!(check_advertised_length(None).is_err());
        assert!(check_advertised_length(Some(-1)).is_err());
        assert!(check_advertised_length(Some(MAX_ENVELOPE_BYTES as i64 + 1)).is_err());
    }

    #[test]
    fn object_keys_cannot_cross_tenant_boundaries() {
        assert!(
            validate_object_key("rustyauth-backups/v2/tenant-a/2026.rauth", "tenant-a").is_ok()
        );
        assert!(
            validate_object_key("rustyauth-backups/v2/tenant-b/2026.rauth", "tenant-a").is_err()
        );
    }
}
