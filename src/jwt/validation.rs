//! Validation for short-lived service-account JWTs used by private RPC services.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::store::now;

use super::JwtIssuer;

const CLOCK_SKEW_SECONDS: u64 = 60;

#[derive(Debug, Deserialize)]
struct ServiceAccountClaims {
    iss: String,
    aud: String,
    sub: String,
    exp: u64,
    iat: u64,
    jti: String,
    token_type: String,
    tenant_id: String,
    client_id: String,
    scope: Vec<String>,
}

impl JwtIssuer {
    /// Verifies that `token` is one of this realm's currently valid
    /// service-account tokens and carries `required_scope`.
    ///
    /// Authentication intentionally uses the in-memory JWKS so an active,
    /// staged or still-published retired signing key follows the exact same
    /// rotation boundary exposed to external JWT consumers.
    pub(crate) fn authorizes_service_account(&self, token: &str, required_scope: &str) -> bool {
        let Ok(runtime) = self.inner.runtime.read() else {
            return false;
        };
        service_account_authorized(
            token,
            required_scope,
            &runtime.jwks,
            &self.inner.issuer,
            &self.inner.audience,
            &self.inner.tenant_id,
            now(),
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn service_account_authorized(
    token: &str,
    required_scope: &str,
    jwks: &Value,
    issuer: &str,
    audience: &str,
    tenant_id: &str,
    current: u64,
) -> bool {
    let Ok(header) = decode_header(token) else {
        return false;
    };
    if header.alg != Algorithm::ES256 {
        return false;
    }
    let Some(kid) = header.kid.as_deref() else {
        return false;
    };
    let Ok(jwks) = serde_json::from_value::<JwkSet>(jwks.clone()) else {
        return false;
    };
    let Some(jwk) = jwks.find(kid) else {
        return false;
    };
    let Ok(key) = DecodingKey::from_jwk(jwk) else {
        return false;
    };

    let mut validation = Validation::new(Algorithm::ES256);
    validation.leeway = CLOCK_SKEW_SECONDS;
    validation.set_audience(&[audience]);
    validation.set_issuer(&[issuer]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let Ok(decoded) = decode::<ServiceAccountClaims>(token, &key, &validation) else {
        return false;
    };
    let claims = decoded.claims;
    let Ok(client_id) = Uuid::parse_str(&claims.client_id) else {
        return false;
    };

    claims.iss == issuer
        && claims.aud == audience
        && claims.token_type == "service-account"
        && claims.tenant_id == tenant_id
        && claims.sub == format!("service-account:{client_id}")
        && Uuid::parse_str(&claims.jti).is_ok()
        && claims.iat <= current.saturating_add(CLOCK_SKEW_SECONDS)
        && claims.exp > claims.iat
        && claims.scope.iter().any(|scope| scope == required_scope)
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{Header, encode};
    use serde_json::json;

    use crate::config::KeyRing;

    use super::*;
    use crate::jwt::{
        key_material::generate,
        keyset::{KEYSET_VERSION, StoredKeySet},
        runtime::runtime_keyset,
    };

    #[test]
    fn accepts_only_the_requested_scope_for_this_realm() {
        let current = now();
        let runtime = test_runtime();
        let service_account_id = Uuid::new_v4();
        let token = token(
            &runtime,
            json!({
                "iss": "https://auth.test.invalid",
                "aud": "rustyauth-test",
                "sub": format!("service-account:{service_account_id}"),
                "exp": current + 300,
                "iat": current,
                "jti": Uuid::new_v4().to_string(),
                "token_type": "service-account",
                "tenant_id": "tenant-a",
                "client_id": service_account_id.to_string(),
                "scope": ["events.read", "identity.read"]
            }),
        );

        assert!(authorized(&token, "events.read", &runtime.jwks, current));
        assert!(authorized(&token, "identity.read", &runtime.jwks, current));
        assert!(!authorized(
            &token,
            "identity.write",
            &runtime.jwks,
            current
        ));
        assert!(!service_account_authorized(
            &token,
            "events.read",
            &runtime.jwks,
            "https://other.invalid",
            "rustyauth-test",
            "tenant-a",
            current,
        ));
        assert!(!service_account_authorized(
            &token,
            "events.read",
            &runtime.jwks,
            "https://auth.test.invalid",
            "other-audience",
            "tenant-a",
            current,
        ));
        assert!(!service_account_authorized(
            &token,
            "events.read",
            &runtime.jwks,
            "https://auth.test.invalid",
            "rustyauth-test",
            "tenant-b",
            current,
        ));
    }

    #[test]
    fn rejects_wrong_token_class_subject_and_time_bounds() {
        let current = now();
        let runtime = test_runtime();
        let service_account_id = Uuid::new_v4();
        let base = |token_type: &str, sub: String, iat: u64, exp: u64| {
            token(
                &runtime,
                json!({
                    "iss": "https://auth.test.invalid",
                    "aud": "rustyauth-test",
                    "sub": sub,
                    "exp": exp,
                    "iat": iat,
                    "jti": Uuid::new_v4().to_string(),
                    "token_type": token_type,
                    "tenant_id": "tenant-a",
                    "client_id": service_account_id.to_string(),
                    "scope": ["events.read"]
                }),
            )
        };

        let access_token = base(
            "spacetime-access",
            format!("service-account:{service_account_id}"),
            current,
            current + 300,
        );
        assert!(!authorized(
            &access_token,
            "events.read",
            &runtime.jwks,
            current
        ));

        let wrong_subject = base(
            "service-account",
            format!("service-account:{}", Uuid::new_v4()),
            current,
            current + 300,
        );
        assert!(!authorized(
            &wrong_subject,
            "events.read",
            &runtime.jwks,
            current
        ));

        let future = base(
            "service-account",
            format!("service-account:{service_account_id}"),
            current + CLOCK_SKEW_SECONDS + 1,
            current + 600,
        );
        assert!(!authorized(&future, "events.read", &runtime.jwks, current));
    }

    fn authorized(token: &str, scope: &str, jwks: &Value, current: u64) -> bool {
        service_account_authorized(
            token,
            scope,
            jwks,
            "https://auth.test.invalid",
            "rustyauth-test",
            "tenant-a",
            current,
        )
    }

    fn token(runtime: &super::super::runtime::RuntimeKeySet, claims: Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(runtime.active_kid.clone());
        encode(&header, &claims, &runtime.encoding).unwrap()
    }

    fn test_runtime() -> super::super::runtime::RuntimeKeySet {
        let keys = KeyRing::new("master", [29; 32], Vec::new()).unwrap();
        let keyset = StoredKeySet {
            version: KEYSET_VERSION,
            active: generate(&keys, 1_000).unwrap(),
            staged: None,
            retired: Vec::new(),
        };
        runtime_keyset(&keyset, &keys, 1_000).unwrap()
    }
}
