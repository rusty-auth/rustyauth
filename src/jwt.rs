//! ES256 signing-key custody, staged rotation, JWKS publication, and token issuance.

mod issuance;
mod key_material;
mod keyset;
mod rotation;
mod runtime;

pub use self::issuance::{IssuedServiceAccountToken, IssuedToken};
pub(crate) use self::keyset::KEYSET_KEY;
pub use self::keyset::validate_snapshot_keyset;
pub use self::rotation::SigningKeyStatus;

use std::sync::{Arc, RwLock};

use anyhow::Result;
use tokio::sync::Mutex;

use crate::{
    config::{KeyRing, SigningRotationConfig},
    store::{SnapshotGate, now},
};

use self::keyset::{load_or_create_keyset, validate_keyset};
use self::runtime::{RuntimeKeySet, runtime_keyset};

#[derive(Clone)]
pub struct JwtIssuer {
    inner: Arc<Inner>,
}

struct Inner {
    redis: redis::aio::ConnectionManager,
    master_keys: KeyRing,
    rotation: SigningRotationConfig,
    snapshot_gate: SnapshotGate,
    maintenance: Mutex<()>,
    runtime: RwLock<RuntimeKeySet>,
    issuer: String,
    audience: String,
    tenant_id: String,
    access_token_seconds: u64,
}

impl JwtIssuer {
    #[allow(clippy::too_many_arguments)]
    pub async fn load_or_create(
        redis: redis::aio::ConnectionManager,
        master_keys: KeyRing,
        rotation: SigningRotationConfig,
        snapshot_gate: SnapshotGate,
        issuer: String,
        audience: String,
        tenant_id: String,
        access_token_seconds: u64,
    ) -> Result<Self> {
        let keyset = load_or_create_keyset(redis.clone(), &master_keys, now()).await?;
        validate_keyset(&keyset, &master_keys)?;
        let runtime = runtime_keyset(&keyset, &master_keys, now())?;
        let issuer = Self {
            inner: Arc::new(Inner {
                redis,
                master_keys,
                rotation,
                snapshot_gate,
                maintenance: Mutex::new(()),
                runtime: RwLock::new(runtime),
                issuer,
                audience,
                tenant_id,
                access_token_seconds,
            }),
        };
        issuer.maintain_at(now(), false, false).await?;
        Ok(issuer)
    }
}
