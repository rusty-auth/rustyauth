//! In-memory signing runtime: the active encoding key and the published JWKS
//! document.

use anyhow::Result;
use jsonwebtoken::EncodingKey;
use serde_json::{Value, json};

use crate::config::KeyRing;

use super::{
    JwtIssuer,
    key_material::open_private_key,
    keyset::{StoredKeySet, validate_keyset},
};

pub(super) struct RuntimeKeySet {
    pub(super) active_kid: String,
    pub(super) encoding: EncodingKey,
    pub(super) jwks: Value,
}

impl JwtIssuer {
    pub fn jwks(&self) -> Value {
        self.inner
            .runtime
            .read()
            .expect("JWT runtime lock is poisoned")
            .jwks
            .clone()
    }
}

pub(super) fn runtime_keyset(
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

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::{
        key_material::generate,
        keyset::{KEYSET_VERSION, RetiredPublicKey, StagedSigningKey},
    };

    #[test]
    fn jwks_never_publishes_private_key_material() {
        let keys = KeyRing::new("master", [16; 32], Vec::new()).unwrap();
        let retired = generate(&keys, 900).unwrap();
        let keyset = StoredKeySet {
            version: KEYSET_VERSION,
            active: generate(&keys, 1_000).unwrap(),
            staged: Some(StagedSigningKey {
                key: generate(&keys, 1_001).unwrap(),
                activate_at: 1_100,
            }),
            retired: vec![RetiredPublicKey {
                kid: retired.kid,
                public_jwk: retired.public_jwk,
                publish_until: 1_200,
            }],
        };
        let jwks = runtime_keyset(&keyset, &keys, 1_002).unwrap().jwks;
        let published = jwks["keys"].as_array().unwrap();
        assert_eq!(published.len(), 3);
        for jwk in published {
            assert!(
                jwk.get("d").is_none(),
                "JWKS leaked private material: {jwk}"
            );
        }
        let serialized = jwks.to_string();
        assert!(!serialized.contains(r#""d""#));
        assert!(!serialized.contains("encryptedPrivateKey"));
    }
}
