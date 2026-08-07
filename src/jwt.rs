//! ES256 signing-key custody, JWKS publication, and access-token issuance.

use std::sync::Arc;

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::{
    ecdsa::SigningKey,
    elliptic_curve::rand_core::{OsRng, RngCore},
    pkcs8::EncodePrivateKey,
};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::store::{Session, User, now};

const SIGNING_KEY: &str = "auth:jwt:active";

#[derive(Clone)]
pub struct JwtIssuer {
    inner: Arc<Inner>,
}

struct Inner {
    kid: String,
    encoding: EncodingKey,
    jwk: Value,
    issuer: String,
    audience: String,
    tenant_id: String,
    access_token_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredKey {
    kid: String,
    public_jwk: Value,
    nonce: String,
    encrypted_private_key: String,
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
#[serde(rename_all = "camelCase")]
pub struct IssuedToken {
    pub email: String,
    pub email_verified: bool,
    pub token: String,
    pub expires_in: u64,
}

impl JwtIssuer {
    pub async fn load_or_create(
        mut redis: redis::aio::ConnectionManager,
        master_key: &[u8; 32],
        issuer: String,
        audience: String,
        tenant_id: String,
        access_token_seconds: u64,
    ) -> Result<Self> {
        let stored: Option<String> = redis.get(SIGNING_KEY).await?;
        let record = match stored {
            Some(value) => {
                serde_json::from_str::<StoredKey>(&value).context("decode stored signing key")?
            }
            None => {
                let generated = generate(master_key)?;
                let value = serde_json::to_string(&generated)?;
                let inserted: bool = redis.set_nx(SIGNING_KEY, value).await?;
                if inserted {
                    generated
                } else {
                    let value: String = redis
                        .get(SIGNING_KEY)
                        .await
                        .context("load concurrently-created signing key")?;
                    serde_json::from_str(&value)?
                }
            }
        };
        let mut private_der = open(master_key, &record)?;
        let encoding = EncodingKey::from_ec_der(&private_der);
        private_der.zeroize();
        Ok(Self {
            inner: Arc::new(Inner {
                kid: record.kid,
                encoding,
                jwk: record.public_jwk,
                issuer,
                audience,
                tenant_id,
                access_token_seconds,
            }),
        })
    }

    pub fn jwks(&self) -> Value {
        json!({ "keys": [self.inner.jwk.clone()] })
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
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.inner.kid.clone());
        header.typ = Some("JWT".into());
        let token = encode(&header, &claims, &self.inner.encoding).context("sign access token")?;
        Ok(IssuedToken {
            email: user.email.clone(),
            email_verified: user.email_verified,
            token,
            expires_in: self.inner.access_token_seconds,
        })
    }
}

fn generate(master_key: &[u8; 32]) -> Result<StoredKey> {
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
    let mut private_der = signing.to_pkcs8_der()?.as_bytes().to_vec();
    let cipher = Aes256Gcm::new_from_slice(master_key).expect("validated 32-byte master key");
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt((&nonce).into(), private_der.as_slice())
        .map_err(|_| anyhow::anyhow!("encrypt signing key"))?;
    private_der.zeroize();
    Ok(StoredKey {
        kid,
        public_jwk,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        encrypted_private_key: URL_SAFE_NO_PAD.encode(encrypted),
    })
}

fn open(master_key: &[u8; 32], record: &StoredKey) -> Result<Vec<u8>> {
    let nonce = URL_SAFE_NO_PAD
        .decode(&record.nonce)
        .context("decode signing-key nonce")?;
    let encrypted = URL_SAFE_NO_PAD
        .decode(&record.encrypted_private_key)
        .context("decode encrypted signing key")?;
    let cipher = Aes256Gcm::new_from_slice(master_key).expect("validated 32-byte master key");
    cipher
        .decrypt(nonce.as_slice().into(), encrypted.as_slice())
        .map_err(|_| anyhow::anyhow!("decrypt signing key"))
}
