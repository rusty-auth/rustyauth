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
    envelope::{decode_snapshot, encode_snapshot, envelope_format_version, envelope_key_id},
    snapshot::BackupSnapshot,
};

const MAX_ENVELOPE_BYTES: usize = 256 * 1024 * 1024;
const CONTENT_TYPE: &str = "application/vnd.rustyauth.backup.v3";
const RETENTION_CLOCK_SKEW_SECONDS: u64 = 300;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupReceipt {
    pub format_version: u8,
    pub snapshot_id: Uuid,
    pub object_key: String,
    pub captured_at: u64,
    pub record_count: u64,
    pub envelope_bytes: usize,
    pub encryption_key_id: String,
    pub object_version_id: Option<String>,
    pub retained_until: Option<u64>,
    pub server_side_encryption: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupObject {
    pub key: String,
    pub size: i64,
    pub last_modified: Option<String>,
}

#[derive(Debug)]
struct ObjectPosture {
    version_id: Option<String>,
    server_side_encryption: Option<String>,
    sse_kms_key_id: Option<String>,
    object_lock_mode: Option<String>,
    retained_until: Option<u64>,
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
            "rustyauth-backups/v3/{tenant_id}/{timestamp}-{}.rauth",
            snapshot.snapshot_id
        );
        let uploaded = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&object_key)
            .content_type(CONTENT_TYPE)
            .checksum_sha256(checksum)
            .metadata("snapshot-id", snapshot.snapshot_id.to_string())
            .metadata("key-id", self.encryption_keys.active().0)
            .metadata("format-version", "3")
            .metadata("scope", "complete-server-workspace")
            .body(ByteStream::from(envelope.clone()))
            .send()
            .await
            .context("upload encrypted auth snapshot")?;

        if uploaded.version_id().is_none() {
            bail!(
                "backup upload did not return an object version id; bucket versioning is required"
            );
        }

        // Read-after-write proves that the provider returned the same decryptable object.
        let (downloaded, _, _, posture, format_version) =
            self.download_object(&object_key, tenant_id).await?;
        if downloaded.snapshot_id != snapshot.snapshot_id
            || downloaded.manifest.content_sha256 != snapshot.manifest.content_sha256
        {
            bail!("uploaded backup failed read-after-write verification");
        }
        let receipt = BackupReceipt {
            format_version,
            snapshot_id: snapshot.snapshot_id,
            object_key,
            captured_at: snapshot.captured_at,
            record_count: snapshot.manifest.record_count,
            envelope_bytes: envelope.len(),
            encryption_key_id: self.encryption_keys.active().0.to_owned(),
            object_version_id: posture.version_id,
            retained_until: posture.retained_until,
            server_side_encryption: posture.server_side_encryption,
        };
        info!(
            snapshot_id = %receipt.snapshot_id,
            object_key = %receipt.object_key,
            record_count = receipt.record_count,
            envelope_bytes = receipt.envelope_bytes,
            encryption_key_id = %receipt.encryption_key_id,
            object_version_id = ?receipt.object_version_id,
            retained_until = ?receipt.retained_until,
            server_side_encryption = ?receipt.server_side_encryption,
            "encrypted backup created and verified"
        );
        Ok(receipt)
    }

    pub async fn download(&self, object_key: &str, tenant_id: &str) -> Result<BackupSnapshot> {
        let (snapshot, _, _, _, _) = self.download_object(object_key, tenant_id).await?;
        Ok(snapshot)
    }

    async fn download_object(
        &self,
        object_key: &str,
        tenant_id: &str,
    ) -> Result<(BackupSnapshot, String, usize, ObjectPosture, u8)> {
        validate_object_key(object_key, tenant_id)?;
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(object_key)
            .send()
            .await
            .context("download encrypted auth snapshot")?;
        let posture = ObjectPosture {
            version_id: output.version_id().map(str::to_owned),
            server_side_encryption: output
                .server_side_encryption()
                .map(|value| value.as_str().to_owned()),
            sse_kms_key_id: output.ssekms_key_id().map(str::to_owned),
            object_lock_mode: output
                .object_lock_mode()
                .map(|value| value.as_str().to_owned()),
            retained_until: output
                .object_lock_retain_until_date()
                .and_then(|value| u64::try_from(value.secs()).ok()),
        };
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
        let format_version = envelope_format_version(&bytes)?;
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
        self.validate_object_posture(object_key, &posture, snapshot.captured_at)?;
        Ok((snapshot, key_id, envelope_bytes, posture, format_version))
    }

    pub async fn verify(
        &self,
        object_key: &str,
        tenant_id: &str,
    ) -> Result<(BackupReceipt, BackupSnapshot)> {
        let (snapshot, key_id, envelope_bytes, posture, format_version) =
            self.download_object(object_key, tenant_id).await?;
        let receipt = BackupReceipt {
            format_version,
            snapshot_id: snapshot.snapshot_id,
            object_key: object_key.to_owned(),
            captured_at: snapshot.captured_at,
            record_count: snapshot.manifest.record_count,
            envelope_bytes,
            encryption_key_id: key_id,
            object_version_id: posture.version_id,
            retained_until: posture.retained_until,
            server_side_encryption: posture.server_side_encryption,
        };
        Ok((receipt, snapshot))
    }

    pub async fn list(&self, tenant_id: &str) -> Result<Vec<BackupObject>> {
        let mut objects = self
            .list_prefix(&format!("rustyauth-backups/v3/{tenant_id}/"))
            .await?;
        objects.extend(
            self.list_prefix(&format!("rustyauth-backups/v2/{tenant_id}/"))
                .await?,
        );
        objects.sort_unstable_by(|left, right| right.key.cmp(&left.key));
        Ok(objects)
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<BackupObject>> {
        let mut continuation = None;
        let mut objects = Vec::new();
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix);
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
        Ok(objects)
    }

    fn validate_object_posture(
        &self,
        object_key: &str,
        posture: &ObjectPosture,
        captured_at: u64,
    ) -> Result<()> {
        // Existing v2 recovery points remain readable. Every newly-created v3
        // object must prove versioning, WORM retention and the configured
        // provider-side encryption in addition to the application AES envelope.
        if object_key.contains("/v2/") {
            return Ok(());
        }
        if posture.version_id.as_deref().is_none_or(str::is_empty) {
            bail!("backup object has no version id; bucket versioning is required");
        }
        if posture.object_lock_mode.as_deref() != Some("COMPLIANCE") {
            bail!("backup object is not protected by Object Lock compliance mode");
        }
        let expected_until = captured_at
            .saturating_add(self.retention_days.saturating_mul(86_400))
            .saturating_sub(RETENTION_CLOCK_SKEW_SECONDS);
        if posture
            .retained_until
            .is_none_or(|value| value < expected_until)
        {
            bail!(
                "backup object retention is shorter than configured {} days",
                self.retention_days
            );
        }
        let expected_sse = self.server_side_encryption.as_str();
        if expected_sse != "provider"
            && posture.server_side_encryption.as_deref() != Some(expected_sse)
        {
            bail!("backup object did not use required server-side encryption {expected_sse}");
        }
        if let Some(expected_key) = self.sse_kms_key_id.as_deref()
            && posture.sse_kms_key_id.as_deref() != Some(expected_key)
        {
            bail!("backup object did not use the configured SSE-KMS key");
        }
        Ok(())
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
    let v3_prefix = format!("rustyauth-backups/v3/{tenant_id}/");
    let v2_prefix = format!("rustyauth-backups/v2/{tenant_id}/");
    if !(object_key.starts_with(&v3_prefix) || object_key.starts_with(&v2_prefix))
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
        assert!(
            validate_object_key("rustyauth-backups/v3/tenant-a/2026.rauth", "tenant-a").is_ok()
        );
    }
}
