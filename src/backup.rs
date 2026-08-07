use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use anyhow::{Context, Result};
use aws_credential_types::Credentials;
use aws_sdk_s3::{Client, config::Region, primitives::ByteStream};
use base64::{Engine, engine::general_purpose::STANDARD};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::config::BackupConfig;

const MAGIC: &[u8; 8] = b"PAUTHBK1";

#[derive(Clone)]
#[allow(
    dead_code,
    reason = "snapshot scheduler is ported in the next implementation phase"
)]
pub struct BackupStore {
    client: Client,
    bucket: String,
    encryption_key: [u8; 32],
}

impl BackupStore {
    pub async fn new(config: BackupConfig) -> Result<Self> {
        let credentials = Credentials::new(
            config.access_key_id.expose_secret(),
            config.secret_access_key.expose_secret(),
            None,
            None,
            "passkey-auth-template",
        );
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .credentials_provider(credentials)
            .region(Region::new(config.region))
            .endpoint_url(config.endpoint.to_string())
            .load()
            .await;
        let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
            .force_path_style(config.force_path_style)
            .build();

        Ok(Self {
            client: Client::from_conf(s3_config),
            bucket: config.bucket,
            encryption_key: config.encryption_key,
        })
    }

    #[allow(
        dead_code,
        reason = "snapshot scheduler is ported in the next implementation phase"
    )]
    pub async fn put_snapshot(&self, tenant_id: &str, plaintext: &[u8]) -> Result<String> {
        let envelope = encrypt_snapshot(self.encryption_key, plaintext)?;
        let checksum = STANDARD.encode(Sha256::digest(&envelope));
        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)?
            .replace(':', "-");
        let key = format!(
            "auth-backups/v1/{tenant_id}/{timestamp}-{}.pauth",
            Uuid::new_v4()
        );

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .content_type("application/vnd.passkey-auth.backup.v1")
            .checksum_sha256(checksum)
            .body(ByteStream::from(envelope))
            .send()
            .await
            .context("upload encrypted auth snapshot")?;

        Ok(key)
    }
}

fn encrypt_snapshot(key: [u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::rand_core::{OsRng, RngCore};

    let cipher = Aes256Gcm::new_from_slice(&key).expect("AES-256 key has validated length");
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt((&nonce).into(), plaintext)
        .map_err(|_| anyhow::anyhow!("encrypt auth backup"))?;
    let mut envelope = Vec::with_capacity(MAGIC.len() + nonce.len() + ciphertext.len());
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_envelope_is_versioned_and_randomized() {
        let key = [7_u8; 32];
        let one = encrypt_snapshot(key, b"snapshot").unwrap();
        let two = encrypt_snapshot(key, b"snapshot").unwrap();
        assert!(one.starts_with(MAGIC));
        assert_ne!(one, two);
        assert_ne!(&one[20..], b"snapshot");
    }
}
