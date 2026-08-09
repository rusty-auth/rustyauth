//! Versioned, authenticated logical backups and S3-compatible object storage.

mod envelope;
mod object;
mod scheduler;
mod snapshot;

pub use self::object::{BackupObject, BackupReceipt};
pub use self::scheduler::BackupStatus;
pub use self::snapshot::BackupSnapshot;

use std::sync::Arc;

use anyhow::Result;
use aws_credential_types::Credentials;
use aws_sdk_s3::{Client, config::Region};
use secrecy::ExposeSecret;
use tokio::sync::{Mutex, RwLock};

use crate::config::{BackupConfig, BackupServerSideEncryption, BackupStorageProfile, KeyRing};

#[derive(Clone)]
pub struct BackupStore {
    client: Client,
    bucket: String,
    encryption_keys: KeyRing,
    interval_seconds: u64,
    rpo_seconds: u64,
    retention_days: u64,
    alert_after_failures: u64,
    storage_profile: BackupStorageProfile,
    server_side_encryption: BackupServerSideEncryption,
    sse_kms_key_id: Option<String>,
    operation: Arc<Mutex<()>>,
    status: Arc<RwLock<BackupStatus>>,
}

impl BackupStore {
    pub async fn new(config: BackupConfig) -> Result<Self> {
        let credentials = Credentials::new(
            config.access_key_id.expose_secret(),
            config.secret_access_key.expose_secret(),
            None,
            None,
            "rustyauth",
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
            encryption_keys: config.encryption_keys,
            interval_seconds: config.interval_seconds,
            rpo_seconds: config.rpo_seconds,
            retention_days: config.retention_days,
            alert_after_failures: config.alert_after_failures,
            storage_profile: config.storage_profile,
            server_side_encryption: config.server_side_encryption,
            sse_kms_key_id: config.sse_kms_key_id,
            operation: Arc::new(Mutex::new(())),
            status: Arc::new(RwLock::new(BackupStatus::default())),
        })
    }
}
