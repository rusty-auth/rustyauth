//! ES256 signing-key custody, staged rotation, JWKS publication, and token issuance.

use std::sync::{Arc, RwLock};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::{
    PublicKey,
    ecdsa::SigningKey,
    elliptic_curve::rand_core::{OsRng, RngCore},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Mutex, watch};
use tracing::{error, info};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    config::{KeyRing, SigningRotationConfig},
    store::{Session, SnapshotGate, User, now},
};

pub(crate) const KEYSET_KEY: &str = "auth:jwt:keyset:v1";
const LEGACY_SIGNING_KEY: &str = "auth:jwt:active";
const MAINTENANCE_LOCK_KEY: &str = "auth:jwt:maintenance-lock";
const KEYSET_VERSION: u8 = 1;

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

struct RuntimeKeySet {
    active_kid: String,
    encoding: EncodingKey,
    jwks: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredKeySet {
    version: u8,
    active: StoredSigningKey,
    #[serde(default)]
    staged: Option<StagedSigningKey>,
    #[serde(default)]
    retired: Vec<RetiredPublicKey>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredSigningKey {
    kid: String,
    public_jwk: Value,
    created_at: u64,
    encrypted_private_key: EncryptedPrivateKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedPrivateKey {
    wrapping_key_id: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StagedSigningKey {
    key: StoredSigningKey,
    activate_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RetiredPublicKey {
    kid: String,
    public_jwk: Value,
    publish_until: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyStoredKey {
    kid: String,
    public_jwk: Value,
    nonce: String,
    encrypted_private_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningKeyStatus {
    pub active_kid: String,
    pub staged_kid: Option<String>,
    pub staged_activates_at: Option<u64>,
    pub retired_kids: Vec<String>,
    pub next_rotation_at: u64,
}

#[derive(Debug, Serialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    exp: u64,
    iat: u64,
    jti: String,
    sid: String,
    token_type: &'static str,
    tenant_id: String,
    amr: Vec<String>,
    auth_time: u64,
    session_version: u64,
}

#[derive(Debug, Serialize)]
struct ServiceAccountClaims {
    iss: String,
    aud: String,
    sub: String,
    exp: u64,
    iat: u64,
    jti: String,
    token_type: &'static str,
    tenant_id: String,
    client_id: String,
    scope: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedToken {
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone_number: Option<String>,
    pub phone_number_verified: bool,
    pub profile: crate::store::AccountProfile,
    pub token: String,
    pub expires_in: u64,
}

#[derive(Debug)]
pub struct IssuedServiceAccountToken {
    pub token: String,
    pub expires_in: u64,
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

    pub fn jwks(&self) -> Value {
        self.inner
            .runtime
            .read()
            .expect("JWT runtime lock is poisoned")
            .jwks
            .clone()
    }

    pub fn issue(&self, user: &User, session: &Session) -> Result<IssuedToken> {
        let issued_at = now();
        let claims = Claims {
            iss: self.inner.issuer.clone(),
            aud: self.inner.audience.clone(),
            sub: user.id.to_string(),
            exp: issued_at + self.inner.access_token_seconds,
            iat: issued_at,
            jti: Uuid::new_v4().to_string(),
            sid: session.id.to_string(),
            token_type: "spacetime-access",
            tenant_id: self.inner.tenant_id.clone(),
            amr: vec![
                match session.auth_method.as_str() {
                    "passkey" => "hwk",
                    "agent" => "agent",
                    _ => "email",
                }
                .into(),
            ],
            auth_time: session.created_at,
            session_version: session.session_version,
        };
        let runtime = self
            .inner
            .runtime
            .read()
            .map_err(|_| anyhow::anyhow!("JWT runtime lock is poisoned"))?;
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(runtime.active_kid.clone());
        header.typ = Some("JWT".into());
        let token = encode(&header, &claims, &runtime.encoding).context("sign access token")?;
        let email = user.primary_email();
        let phone = user.primary_phone();
        Ok(IssuedToken {
            email: email.map(|identifier| identifier.value.clone()),
            email_verified: email.is_some_and(|identifier| identifier.verified),
            phone_number: phone.map(|identifier| identifier.value.clone()),
            phone_number_verified: phone.is_some_and(|identifier| identifier.verified),
            profile: user.profile.clone(),
            token,
            expires_in: self.inner.access_token_seconds,
        })
    }

    pub fn issue_service_account(
        &self,
        service_account_id: Uuid,
        scopes: Vec<String>,
    ) -> Result<IssuedServiceAccountToken> {
        let issued_at = now();
        let claims = ServiceAccountClaims {
            iss: self.inner.issuer.clone(),
            aud: self.inner.audience.clone(),
            sub: format!("service-account:{service_account_id}"),
            exp: issued_at + self.inner.access_token_seconds,
            iat: issued_at,
            jti: Uuid::new_v4().to_string(),
            token_type: "service-account",
            tenant_id: self.inner.tenant_id.clone(),
            client_id: service_account_id.to_string(),
            scope: scopes,
        };
        let runtime = self
            .inner
            .runtime
            .read()
            .map_err(|_| anyhow::anyhow!("JWT runtime lock is poisoned"))?;
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(runtime.active_kid.clone());
        header.typ = Some("JWT".into());
        let token = encode(&header, &claims, &runtime.encoding)
            .context("sign service-account access token")?;
        Ok(IssuedServiceAccountToken {
            token,
            expires_in: self.inner.access_token_seconds,
        })
    }

    pub async fn stored_status(&self) -> Result<SigningKeyStatus> {
        let keyset = read_keyset(self.inner.redis.clone()).await?;
        Ok(status_for(&keyset, &self.inner.rotation))
    }

    pub async fn force_rotate(&self, activate_immediately: bool) -> Result<SigningKeyStatus> {
        self.maintain_at(now(), true, activate_immediately).await?;
        self.stored_status().await
    }

    pub async fn run_maintenance(self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            self.inner.rotation.maintenance_seconds,
        ));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(error) = self.maintain_at(now(), false, false).await {
                        error!(error = %error, "signing-key maintenance failed");
                    }
                }
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }

    async fn maintain_at(
        &self,
        current: u64,
        force_stage: bool,
        activate_immediately: bool,
    ) -> Result<()> {
        let _maintenance = self.inner.maintenance.lock().await;
        let _snapshot = self.inner.snapshot_gate.read().await;
        let Some(lock_token) = acquire_maintenance_lock(self.inner.redis.clone()).await? else {
            let keyset = read_keyset(self.inner.redis.clone()).await?;
            let runtime = runtime_keyset(&keyset, &self.inner.master_keys, current)?;
            *self
                .inner
                .runtime
                .write()
                .map_err(|_| anyhow::anyhow!("JWT runtime lock is poisoned"))? = runtime;
            if force_stage {
                bail!("another process is rotating signing keys; retry in a few seconds");
            }
            return Ok(());
        };
        let result = self
            .maintain_while_locked(current, force_stage, activate_immediately)
            .await;
        release_maintenance_lock(self.inner.redis.clone(), &lock_token).await;
        result
    }

    async fn maintain_while_locked(
        &self,
        current: u64,
        force_stage: bool,
        activate_immediately: bool,
    ) -> Result<()> {
        let mut keyset = read_keyset(self.inner.redis.clone()).await?;
        let before = keyset.clone();
        maintain_keyset(
            &mut keyset,
            &self.inner.master_keys,
            &self.inner.rotation,
            current,
            force_stage,
            activate_immediately,
        )?;
        validate_keyset(&keyset, &self.inner.master_keys)?;
        if keyset != before {
            let mut redis = self.inner.redis.clone();
            let serialized = serde_json::to_string(&keyset)?;
            let _: () = redis.set(KEYSET_KEY, serialized).await?;
            log_transitions(&before, &keyset);
        }
        let runtime = runtime_keyset(&keyset, &self.inner.master_keys, current)?;
        *self
            .inner
            .runtime
            .write()
            .map_err(|_| anyhow::anyhow!("JWT runtime lock is poisoned"))? = runtime;
        Ok(())
    }
}

async fn acquire_maintenance_lock(
    mut redis: redis::aio::ConnectionManager,
) -> Result<Option<String>> {
    let token = Uuid::new_v4().to_string();
    let response: Option<String> = redis::cmd("SET")
        .arg(MAINTENANCE_LOCK_KEY)
        .arg(&token)
        .arg("NX")
        .arg("EX")
        .arg(60_u8)
        .query_async(&mut redis)
        .await
        .context("acquire signing-key maintenance lock")?;
    Ok(response.map(|_| token))
}

async fn release_maintenance_lock(mut redis: redis::aio::ConnectionManager, token: &str) {
    let current: redis::RedisResult<Option<String>> = redis.get(MAINTENANCE_LOCK_KEY).await;
    if current.ok().flatten().as_deref() == Some(token) {
        let _: redis::RedisResult<usize> = redis.del(MAINTENANCE_LOCK_KEY).await;
    }
}

pub(crate) fn validate_snapshot_keyset(value: &str, master_keys: &KeyRing) -> Result<()> {
    let keyset: StoredKeySet =
        serde_json::from_str(value).context("decode signing keyset from snapshot")?;
    validate_keyset(&keyset, master_keys)
}

async fn load_or_create_keyset(
    mut redis: redis::aio::ConnectionManager,
    master_keys: &KeyRing,
    current: u64,
) -> Result<StoredKeySet> {
    if let Some(value) = redis.get::<_, Option<String>>(KEYSET_KEY).await? {
        return serde_json::from_str(&value).context("decode stored signing keyset");
    }

    let active = match redis.get::<_, Option<String>>(LEGACY_SIGNING_KEY).await? {
        Some(value) => {
            let legacy: LegacyStoredKey =
                serde_json::from_str(&value).context("decode legacy signing key")?;
            migrate_legacy(legacy, master_keys, current)?
        }
        None => generate(master_keys, current)?,
    };
    let generated = StoredKeySet {
        version: KEYSET_VERSION,
        active,
        staged: None,
        retired: Vec::new(),
    };
    let inserted: bool = redis
        .set_nx(KEYSET_KEY, serde_json::to_string(&generated)?)
        .await?;
    if inserted {
        Ok(generated)
    } else {
        read_keyset(redis).await
    }
}

async fn read_keyset(mut redis: redis::aio::ConnectionManager) -> Result<StoredKeySet> {
    let value: String = redis
        .get(KEYSET_KEY)
        .await
        .context("stored signing keyset is missing")?;
    serde_json::from_str(&value).context("decode stored signing keyset")
}

fn migrate_legacy(
    legacy: LegacyStoredKey,
    master_keys: &KeyRing,
    current: u64,
) -> Result<StoredSigningKey> {
    let nonce = URL_SAFE_NO_PAD
        .decode(&legacy.nonce)
        .context("decode legacy signing-key nonce")?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&legacy.encrypted_private_key)
        .context("decode legacy encrypted signing key")?;
    let mut private_der = None;
    for key_id in master_keys.key_ids() {
        let key = master_keys
            .get(key_id)
            .expect("key returned by key_ids must resolve");
        let cipher = Aes256Gcm::new_from_slice(key).expect("validated AES-256 key");
        if let Ok(value) = cipher.decrypt(nonce.as_slice().into(), ciphertext.as_slice()) {
            private_der = Some(value);
            break;
        }
    }
    let private_der = Zeroizing::new(private_der.context(
        "legacy signing key cannot be decrypted by AUTH_MASTER_KEY_HEX or its previous keys",
    )?);
    let encrypted_private_key = seal_private_key(master_keys, &legacy.kid, private_der.as_slice())?;
    Ok(StoredSigningKey {
        kid: legacy.kid,
        public_jwk: legacy.public_jwk,
        created_at: current,
        encrypted_private_key,
    })
}

fn generate(master_keys: &KeyRing, created_at: u64) -> Result<StoredSigningKey> {
    let signing = SigningKey::random(&mut OsRng);
    let verifying = signing.verifying_key();
    let point = verifying.to_encoded_point(false);
    let kid = Uuid::new_v4().to_string();
    let public_jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().context("P-256 point has no x coordinate")?),
        "y": URL_SAFE_NO_PAD.encode(point.y().context("P-256 point has no y coordinate")?),
        "alg": "ES256",
        "use": "sig",
        "kid": kid,
    });
    let private_der = signing.to_pkcs8_der()?;
    let encrypted_private_key = seal_private_key(master_keys, &kid, private_der.as_bytes())?;
    Ok(StoredSigningKey {
        kid,
        public_jwk,
        created_at,
        encrypted_private_key,
    })
}

fn seal_private_key(
    master_keys: &KeyRing,
    kid: &str,
    private_der: &[u8],
) -> Result<EncryptedPrivateKey> {
    let (wrapping_key_id, key) = master_keys.active();
    let cipher = Aes256Gcm::new_from_slice(key).expect("validated AES-256 key");
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let aad = signing_key_aad(kid, wrapping_key_id);
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: private_der,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt signing key"))?;
    Ok(EncryptedPrivateKey {
        wrapping_key_id: wrapping_key_id.to_owned(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

fn open_private_key(
    master_keys: &KeyRing,
    record: &StoredSigningKey,
) -> Result<Zeroizing<Vec<u8>>> {
    let encrypted = &record.encrypted_private_key;
    let key = master_keys
        .get(&encrypted.wrapping_key_id)
        .with_context(|| {
            format!(
                "master key {} required by signing key {} is unavailable",
                encrypted.wrapping_key_id, record.kid
            )
        })?;
    let nonce = URL_SAFE_NO_PAD
        .decode(&encrypted.nonce)
        .context("decode signing-key nonce")?;
    if nonce.len() != 12 {
        bail!("signing-key nonce must contain exactly 12 bytes");
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&encrypted.ciphertext)
        .context("decode encrypted signing key")?;
    let cipher = Aes256Gcm::new_from_slice(key).expect("validated AES-256 key");
    let aad = signing_key_aad(&record.kid, &encrypted.wrapping_key_id);
    cipher
        .decrypt(
            nonce.as_slice().into(),
            Payload {
                msg: &ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| anyhow::anyhow!("decrypt signing key {}", record.kid))
}

fn signing_key_aad(kid: &str, wrapping_key_id: &str) -> String {
    format!("rustyauth-signing-key-v1\0{kid}\0{wrapping_key_id}")
}

fn maintain_keyset(
    keyset: &mut StoredKeySet,
    master_keys: &KeyRing,
    rotation: &SigningRotationConfig,
    current: u64,
    force_stage: bool,
    activate_immediately: bool,
) -> Result<()> {
    keyset.retired.retain(|key| key.publish_until > current);
    rewrap_if_needed(&mut keyset.active, master_keys)?;
    if let Some(staged) = &mut keyset.staged {
        rewrap_if_needed(&mut staged.key, master_keys)?;
    }

    // Recovery rotation must create fresh material at recovery time, even when the
    // restored snapshot happened to contain a prepublished key.
    if activate_immediately {
        keyset.staged = Some(StagedSigningKey {
            key: generate(master_keys, current)?,
            activate_at: current,
        });
        activate_staged(keyset, rotation, current)?;
        return Ok(());
    }

    if keyset
        .staged
        .as_ref()
        .is_some_and(|staged| staged.activate_at <= current)
    {
        activate_staged(keyset, rotation, current)?;
    }

    if keyset.staged.is_none()
        && (force_stage
            || current
                >= keyset
                    .active
                    .created_at
                    .saturating_add(rotation.rotation_seconds))
    {
        keyset.staged = Some(StagedSigningKey {
            key: generate(master_keys, current)?,
            activate_at: current.saturating_add(rotation.prepublish_seconds),
        });
    }
    Ok(())
}

fn activate_staged(
    keyset: &mut StoredKeySet,
    rotation: &SigningRotationConfig,
    current: u64,
) -> Result<()> {
    let staged = keyset.staged.take().context("staged key is missing")?;
    let previous = std::mem::replace(&mut keyset.active, staged.key);
    keyset.retired.retain(|key| key.kid != previous.kid);
    keyset.retired.push(RetiredPublicKey {
        kid: previous.kid,
        public_jwk: previous.public_jwk,
        publish_until: current.saturating_add(rotation.overlap_seconds),
    });
    Ok(())
}

fn rewrap_if_needed(record: &mut StoredSigningKey, master_keys: &KeyRing) -> Result<()> {
    if record.encrypted_private_key.wrapping_key_id == master_keys.active().0 {
        return Ok(());
    }
    let private_der = open_private_key(master_keys, record)?;
    record.encrypted_private_key =
        seal_private_key(master_keys, &record.kid, private_der.as_slice())?;
    Ok(())
}

fn validate_keyset(keyset: &StoredKeySet, master_keys: &KeyRing) -> Result<()> {
    if keyset.version != KEYSET_VERSION {
        bail!("unsupported signing keyset version {}", keyset.version);
    }
    let mut kids = std::collections::HashSet::new();
    validate_signing_key(&keyset.active, master_keys)?;
    kids.insert(keyset.active.kid.as_str());
    if let Some(staged) = &keyset.staged {
        validate_signing_key(&staged.key, master_keys)?;
        if !kids.insert(staged.key.kid.as_str()) {
            bail!("signing keyset contains duplicate kid {}", staged.key.kid);
        }
    }
    for retired in &keyset.retired {
        validate_public_jwk(&retired.kid, &retired.public_jwk)?;
        if !kids.insert(retired.kid.as_str()) {
            bail!("signing keyset contains duplicate kid {}", retired.kid);
        }
    }
    Ok(())
}

fn validate_signing_key(record: &StoredSigningKey, master_keys: &KeyRing) -> Result<()> {
    validate_public_jwk(&record.kid, &record.public_jwk)?;
    let private_der = open_private_key(master_keys, record)?;
    let signing = SigningKey::from_pkcs8_der(private_der.as_slice())
        .context("stored signing key is not valid P-256 PKCS#8 material")?;
    let point = signing.verifying_key().to_encoded_point(false);
    let expected_x = URL_SAFE_NO_PAD.encode(
        point
            .x()
            .context("stored P-256 signing key has no x coordinate")?,
    );
    let expected_y = URL_SAFE_NO_PAD.encode(
        point
            .y()
            .context("stored P-256 signing key has no y coordinate")?,
    );
    if record.public_jwk.get("x").and_then(Value::as_str) != Some(expected_x.as_str())
        || record.public_jwk.get("y").and_then(Value::as_str) != Some(expected_y.as_str())
    {
        bail!(
            "public JWK does not match private signing key {}",
            record.kid
        );
    }
    Ok(())
}

fn validate_public_jwk(kid: &str, jwk: &Value) -> Result<()> {
    let value = |name: &str| jwk.get(name).and_then(Value::as_str);
    if value("kid") != Some(kid)
        || value("kty") != Some("EC")
        || value("crv") != Some("P-256")
        || value("alg") != Some("ES256")
        || value("use") != Some("sig")
        || value("x").is_none()
        || value("y").is_none()
    {
        bail!("public JWK for {kid} is invalid");
    }
    let x = URL_SAFE_NO_PAD
        .decode(value("x").expect("validated x presence"))
        .with_context(|| format!("public JWK x coordinate for {kid} is invalid"))?;
    let y = URL_SAFE_NO_PAD
        .decode(value("y").expect("validated y presence"))
        .with_context(|| format!("public JWK y coordinate for {kid} is invalid"))?;
    if x.len() != 32 || y.len() != 32 {
        bail!("public JWK coordinates for {kid} must contain 32 bytes");
    }
    let mut sec1 = [0_u8; 65];
    sec1[0] = 4;
    sec1[1..33].copy_from_slice(&x);
    sec1[33..].copy_from_slice(&y);
    PublicKey::from_sec1_bytes(&sec1)
        .with_context(|| format!("public JWK coordinates for {kid} are not on P-256"))?;
    Ok(())
}

fn runtime_keyset(
    keyset: &StoredKeySet,
    master_keys: &KeyRing,
    current: u64,
) -> Result<RuntimeKeySet> {
    validate_keyset(keyset, master_keys)?;
    let private_der = open_private_key(master_keys, &keyset.active)?;
    let encoding = EncodingKey::from_ec_der(private_der.as_slice());
    let mut keys = vec![keyset.active.public_jwk.clone()];
    if let Some(staged) = &keyset.staged {
        keys.push(staged.key.public_jwk.clone());
    }
    keys.extend(
        keyset
            .retired
            .iter()
            .filter(|key| key.publish_until > current)
            .map(|key| key.public_jwk.clone()),
    );
    Ok(RuntimeKeySet {
        active_kid: keyset.active.kid.clone(),
        encoding,
        jwks: json!({ "keys": keys }),
    })
}

fn status_for(keyset: &StoredKeySet, rotation: &SigningRotationConfig) -> SigningKeyStatus {
    SigningKeyStatus {
        active_kid: keyset.active.kid.clone(),
        staged_kid: keyset.staged.as_ref().map(|value| value.key.kid.clone()),
        staged_activates_at: keyset.staged.as_ref().map(|value| value.activate_at),
        retired_kids: keyset
            .retired
            .iter()
            .map(|value| value.kid.clone())
            .collect(),
        next_rotation_at: keyset
            .active
            .created_at
            .saturating_add(rotation.rotation_seconds),
    }
}

fn log_transitions(before: &StoredKeySet, after: &StoredKeySet) {
    if let (None, Some(staged)) = (&before.staged, &after.staged) {
        info!(kid = %staged.key.kid, activate_at = staged.activate_at, "signing key staged");
    }
    if before.active.kid != after.active.kid {
        info!(old_kid = %before.active.kid, new_kid = %after.active.kid, "signing key activated");
    }
    if before.active.encrypted_private_key.wrapping_key_id
        != after.active.encrypted_private_key.wrapping_key_id
    {
        info!(kid = %after.active.kid, wrapping_key_id = %after.active.encrypted_private_key.wrapping_key_id, "signing key rewrapped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation, decode, jwk::Jwk};
    use zeroize::Zeroize;

    fn rotation() -> SigningRotationConfig {
        SigningRotationConfig {
            rotation_seconds: 100,
            prepublish_seconds: 10,
            overlap_seconds: 20,
            maintenance_seconds: 5,
        }
    }

    #[test]
    fn rotation_prepublicizes_then_retires_the_previous_key() {
        let keys = KeyRing::new("master", [1; 32], Vec::new()).unwrap();
        let active = generate(&keys, 1_000).unwrap();
        let old_kid = active.kid.clone();
        let mut keyset = StoredKeySet {
            version: KEYSET_VERSION,
            active,
            staged: None,
            retired: Vec::new(),
        };

        maintain_keyset(&mut keyset, &keys, &rotation(), 1_100, false, false).unwrap();
        let staged_kid = keyset.staged.as_ref().unwrap().key.kid.clone();
        assert_eq!(keyset.active.kid, old_kid);
        assert_eq!(keyset.staged.as_ref().unwrap().activate_at, 1_110);
        assert_eq!(
            runtime_keyset(&keyset, &keys, 1_100).unwrap().jwks["keys"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        maintain_keyset(&mut keyset, &keys, &rotation(), 1_110, false, false).unwrap();
        assert_eq!(keyset.active.kid, staged_kid);
        assert_eq!(keyset.retired[0].kid, old_kid);
        assert_eq!(keyset.retired[0].publish_until, 1_130);

        maintain_keyset(&mut keyset, &keys, &rotation(), 1_130, false, false).unwrap();
        assert!(keyset.retired.is_empty());
    }

    #[test]
    fn wrapping_key_rollover_reencrypts_without_changing_the_signing_key() {
        let old = KeyRing::new("master", [2; 32], Vec::new()).unwrap();
        let active = generate(&old, 1_000).unwrap();
        let kid = active.kid.clone();
        let new = KeyRing::new("master", [3; 32], vec![[2; 32]]).unwrap();
        let mut keyset = StoredKeySet {
            version: KEYSET_VERSION,
            active,
            staged: None,
            retired: Vec::new(),
        };
        maintain_keyset(&mut keyset, &new, &rotation(), 1_001, false, false).unwrap();
        assert_eq!(keyset.active.kid, kid);
        assert_eq!(
            keyset.active.encrypted_private_key.wrapping_key_id,
            new.active().0
        );
        validate_keyset(&keyset, &new).unwrap();
    }

    #[test]
    fn associated_data_detects_signing_key_metadata_tampering() {
        let keys = KeyRing::new("master", [4; 32], Vec::new()).unwrap();
        let mut record = generate(&keys, 1_000).unwrap();
        record.kid = Uuid::new_v4().to_string();
        assert!(open_private_key(&keys, &record).is_err());
    }

    #[test]
    fn public_key_must_match_the_encrypted_private_key() {
        let keys = KeyRing::new("master", [14; 32], Vec::new()).unwrap();
        let mut record = generate(&keys, 1_000).unwrap();
        let other = generate(&keys, 1_001).unwrap();
        record.public_jwk["x"] = other.public_jwk["x"].clone();
        record.public_jwk["y"] = other.public_jwk["y"].clone();
        assert!(validate_signing_key(&record, &keys).is_err());
    }

    #[test]
    fn recovery_rotation_replaces_even_a_restored_staged_key() {
        let keys = KeyRing::new("master", [15; 32], Vec::new()).unwrap();
        let active = generate(&keys, 1_000).unwrap();
        let old_kid = active.kid.clone();
        let staged = generate(&keys, 1_001).unwrap();
        let restored_staged_kid = staged.kid.clone();
        let mut keyset = StoredKeySet {
            version: KEYSET_VERSION,
            active,
            staged: Some(StagedSigningKey {
                key: staged,
                activate_at: 1_500,
            }),
            retired: Vec::new(),
        };

        maintain_keyset(&mut keyset, &keys, &rotation(), 1_002, true, true).unwrap();
        assert_ne!(keyset.active.kid, old_kid);
        assert_ne!(keyset.active.kid, restored_staged_kid);
        assert!(keyset.staged.is_none());
        assert_eq!(keyset.retired[0].kid, old_kid);
    }

    #[test]
    fn old_and_new_tokens_verify_during_the_retirement_overlap() {
        let keys = KeyRing::new("master", [5; 32], Vec::new()).unwrap();
        let active = generate(&keys, 1_000).unwrap();
        let old_kid = active.kid.clone();
        let mut keyset = StoredKeySet {
            version: KEYSET_VERSION,
            active,
            staged: None,
            retired: Vec::new(),
        };
        let old_runtime = runtime_keyset(&keyset, &keys, 1_000).unwrap();
        let old_token = test_token(&old_runtime);

        maintain_keyset(&mut keyset, &keys, &rotation(), 1_100, false, false).unwrap();
        maintain_keyset(&mut keyset, &keys, &rotation(), 1_110, false, false).unwrap();
        let new_runtime = runtime_keyset(&keyset, &keys, 1_110).unwrap();
        let new_token = test_token(&new_runtime);
        let jwks = new_runtime.jwks["keys"].as_array().unwrap();
        assert!(verify_with_kid(&old_token, &old_kid, jwks));
        assert!(verify_with_kid(&new_token, &new_runtime.active_kid, jwks));

        maintain_keyset(&mut keyset, &keys, &rotation(), 1_130, false, false).unwrap();
        let after_overlap = runtime_keyset(&keyset, &keys, 1_130).unwrap();
        assert!(
            !after_overlap.jwks["keys"]
                .as_array()
                .unwrap()
                .iter()
                .any(|jwk| jwk["kid"] == old_kid)
        );
    }

    #[test]
    fn legacy_key_migration_preserves_kid_and_signing_material() {
        let keys = KeyRing::new("master", [6; 32], Vec::new()).unwrap();
        let signing = SigningKey::random(&mut OsRng);
        let mut private_der = signing.to_pkcs8_der().unwrap().as_bytes().to_vec();
        let cipher = Aes256Gcm::new_from_slice(keys.active().1).unwrap();
        let nonce = [9_u8; 12];
        let ciphertext = cipher
            .encrypt((&nonce).into(), private_der.as_slice())
            .unwrap();
        let kid = Uuid::new_v4().to_string();
        let point = signing.verifying_key().to_encoded_point(false);
        let legacy = LegacyStoredKey {
            kid: kid.clone(),
            public_jwk: json!({
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
                "alg": "ES256",
                "use": "sig",
                "kid": kid.clone(),
            }),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            encrypted_private_key: URL_SAFE_NO_PAD.encode(ciphertext),
        };
        let migrated = migrate_legacy(legacy, &keys, 1_000).unwrap();
        assert_eq!(migrated.kid, kid);
        assert_eq!(
            open_private_key(&keys, &migrated).unwrap().as_slice(),
            private_der
        );
        private_der.zeroize();
    }

    fn test_token(runtime: &RuntimeKeySet) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(runtime.active_kid.clone());
        encode(
            &header,
            &json!({ "sub": "test", "exp": 4_000_000_000_u64 }),
            &runtime.encoding,
        )
        .unwrap()
    }

    fn verify_with_kid(token: &str, kid: &str, jwks: &[Value]) -> bool {
        let Some(value) = jwks.iter().find(|jwk| jwk["kid"] == kid) else {
            return false;
        };
        let jwk: Jwk = serde_json::from_value(value.clone()).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        decode::<Value>(token, &DecodingKey::from_jwk(&jwk).unwrap(), &validation).is_ok()
    }
}
