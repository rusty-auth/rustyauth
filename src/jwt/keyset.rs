//! Durable signing-keyset document: stored model, SableDB persistence, legacy
//! migration and whole-set validation.

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::config::KeyRing;

use super::key_material::{
    StoredSigningKey, generate, seal_private_key, validate_public_jwk, validate_signing_key,
};

pub(crate) const KEYSET_KEY: &str = "auth:jwt:keyset:v1";
const LEGACY_SIGNING_KEY: &str = "auth:jwt:active";
pub(super) const KEYSET_VERSION: u8 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StoredKeySet {
    pub(super) version: u8,
    pub(super) active: StoredSigningKey,
    #[serde(default)]
    pub(super) staged: Option<StagedSigningKey>,
    #[serde(default)]
    pub(super) retired: Vec<RetiredPublicKey>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StagedSigningKey {
    pub(super) key: StoredSigningKey,
    pub(super) activate_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RetiredPublicKey {
    pub(super) kid: String,
    pub(super) public_jwk: Value,
    pub(super) publish_until: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyStoredKey {
    kid: String,
    public_jwk: Value,
    nonce: String,
    encrypted_private_key: String,
}

pub fn validate_snapshot_keyset(value: &str, master_keys: &KeyRing) -> Result<()> {
    let keyset: StoredKeySet =
        serde_json::from_str(value).context("decode signing keyset from snapshot")?;
    validate_keyset(&keyset, master_keys)
}

pub(super) async fn load_or_create_keyset(
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

pub(super) async fn read_keyset(mut redis: redis::aio::ConnectionManager) -> Result<StoredKeySet> {
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

pub(super) fn validate_keyset(keyset: &StoredKeySet, master_keys: &KeyRing) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng, pkcs8::EncodePrivateKey};
    use serde_json::json;
    use uuid::Uuid;
    use zeroize::Zeroize;

    use super::super::key_material::open_private_key;

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
}
