//! Per-key ES256 signing material: generation, AES-GCM encryption at rest and
//! public/private consistency validation.

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    PublicKey,
    ecdsa::SigningKey,
    elliptic_curve::rand_core::{OsRng, RngCore},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::KeyRing;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StoredSigningKey {
    pub(super) kid: String,
    pub(super) public_jwk: Value,
    pub(super) created_at: u64,
    pub(super) encrypted_private_key: EncryptedPrivateKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct EncryptedPrivateKey {
    pub(super) wrapping_key_id: String,
    pub(super) nonce: String,
    pub(super) ciphertext: String,
}

pub(super) fn generate(master_keys: &KeyRing, created_at: u64) -> Result<StoredSigningKey> {
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

pub(super) fn seal_private_key(
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

pub(super) fn open_private_key(
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

pub(super) fn validate_signing_key(record: &StoredSigningKey, master_keys: &KeyRing) -> Result<()> {
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

pub(super) fn validate_public_jwk(kid: &str, jwk: &Value) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
