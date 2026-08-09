//! Access- and service-account token claims and ES256 token signing.

use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, Header, encode};
use serde::Serialize;
use uuid::Uuid;

use crate::store::{Session, User, now};

use super::{JwtIssuer, runtime::RuntimeKeySet};

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
    pub fn issue(&self, user: &User, session: &Session) -> Result<IssuedToken> {
        let claims = access_claims(
            &self.inner.issuer,
            &self.inner.audience,
            &self.inner.tenant_id,
            self.inner.access_token_seconds,
            user,
            session,
            now(),
        );
        let runtime = self
            .inner
            .runtime
            .read()
            .map_err(|_| anyhow::anyhow!("JWT runtime lock is poisoned"))?;
        let token = sign_claims(&runtime, &claims, "sign access token")?;
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
        let claims = service_account_claims(
            &self.inner.issuer,
            &self.inner.audience,
            &self.inner.tenant_id,
            self.inner.access_token_seconds,
            service_account_id,
            scopes,
            now(),
        );
        let runtime = self
            .inner
            .runtime
            .read()
            .map_err(|_| anyhow::anyhow!("JWT runtime lock is poisoned"))?;
        let token = sign_claims(&runtime, &claims, "sign service-account access token")?;
        Ok(IssuedServiceAccountToken {
            token,
            expires_in: self.inner.access_token_seconds,
        })
    }
}

fn access_claims(
    issuer: &str,
    audience: &str,
    tenant_id: &str,
    access_token_seconds: u64,
    user: &User,
    session: &Session,
    issued_at: u64,
) -> Claims {
    Claims {
        iss: issuer.to_owned(),
        aud: audience.to_owned(),
        sub: user.id.to_string(),
        exp: issued_at + access_token_seconds,
        iat: issued_at,
        jti: Uuid::new_v4().to_string(),
        sid: session.id.to_string(),
        token_type: "spacetime-access",
        tenant_id: tenant_id.to_owned(),
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
    }
}

fn service_account_claims(
    issuer: &str,
    audience: &str,
    tenant_id: &str,
    access_token_seconds: u64,
    service_account_id: Uuid,
    scopes: Vec<String>,
    issued_at: u64,
) -> ServiceAccountClaims {
    ServiceAccountClaims {
        iss: issuer.to_owned(),
        aud: audience.to_owned(),
        sub: format!("service-account:{service_account_id}"),
        exp: issued_at + access_token_seconds,
        iat: issued_at,
        jti: Uuid::new_v4().to_string(),
        token_type: "service-account",
        tenant_id: tenant_id.to_owned(),
        client_id: service_account_id.to_string(),
        scope: scopes,
    }
}

fn sign_claims<C: Serialize>(
    runtime: &RuntimeKeySet,
    claims: &C,
    context: &'static str,
) -> Result<String> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(runtime.active_kid.clone());
    header.typ = Some("JWT".into());
    encode(&header, claims, &runtime.encoding).context(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation, decode, jwk::Jwk};
    use serde_json::{Value, json};

    use crate::config::KeyRing;

    use super::super::{
        key_material::generate,
        keyset::{KEYSET_VERSION, StoredKeySet},
        runtime::runtime_keyset,
    };

    #[test]
    fn access_tokens_carry_the_whole_session_claim_set() {
        let runtime = test_runtime(17);
        let user = test_user();
        let session = test_session(user.id);
        let claims = access_claims(
            "https://auth.test.invalid",
            "rustyauth-test",
            "tenant-a",
            300,
            &user,
            &session,
            1_700,
        );
        let decoded = decode_claims(
            &sign_claims(&runtime, &claims, "sign access token").unwrap(),
            &runtime,
        );
        assert_eq!(decoded["iss"], "https://auth.test.invalid");
        assert_eq!(decoded["aud"], "rustyauth-test");
        assert_eq!(decoded["sub"], user.id.to_string());
        assert_eq!(decoded["iat"], 1_700);
        assert_eq!(decoded["exp"], 2_000);
        assert!(Uuid::parse_str(decoded["jti"].as_str().unwrap()).is_ok());
        assert_eq!(decoded["sid"], session.id.to_string());
        assert_eq!(decoded["token_type"], "spacetime-access");
        assert_eq!(decoded["tenant_id"], "tenant-a");
        assert_eq!(decoded["amr"], json!(["hwk"]));
        assert_eq!(decoded["auth_time"], 1_234);
        assert_eq!(decoded["session_version"], 7);
        assert_eq!(decoded.as_object().unwrap().len(), 12);

        for (method, expected) in [
            ("passkey", "hwk"),
            ("agent", "agent"),
            ("magic-link", "email"),
        ] {
            let mut other = test_session(user.id);
            other.auth_method = method.into();
            let claims = access_claims("iss", "aud", "tenant-a", 300, &user, &other, 1_700);
            assert_eq!(claims.amr, vec![expected.to_owned()]);
        }
    }

    #[test]
    fn service_account_tokens_carry_the_whole_client_claim_set() {
        let runtime = test_runtime(18);
        let service_account_id = Uuid::new_v4();
        let claims = service_account_claims(
            "https://auth.test.invalid",
            "rustyauth-test",
            "tenant-a",
            600,
            service_account_id,
            vec!["identity.read".into(), "identity.write".into()],
            2_400,
        );
        let decoded = decode_claims(
            &sign_claims(&runtime, &claims, "sign service-account access token").unwrap(),
            &runtime,
        );
        assert_eq!(decoded["iss"], "https://auth.test.invalid");
        assert_eq!(decoded["aud"], "rustyauth-test");
        assert_eq!(
            decoded["sub"],
            format!("service-account:{service_account_id}")
        );
        assert_eq!(decoded["iat"], 2_400);
        assert_eq!(decoded["exp"], 3_000);
        assert!(Uuid::parse_str(decoded["jti"].as_str().unwrap()).is_ok());
        assert_eq!(decoded["token_type"], "service-account");
        assert_eq!(decoded["tenant_id"], "tenant-a");
        assert_eq!(decoded["client_id"], service_account_id.to_string());
        assert_eq!(decoded["scope"], json!(["identity.read", "identity.write"]));
        assert!(decoded.get("sid").is_none());
        assert_eq!(decoded.as_object().unwrap().len(), 10);
    }

    fn test_runtime(seed: u8) -> RuntimeKeySet {
        let keys = KeyRing::new("master", [seed; 32], Vec::new()).unwrap();
        let keyset = StoredKeySet {
            version: KEYSET_VERSION,
            active: generate(&keys, 1_000).unwrap(),
            staged: None,
            retired: Vec::new(),
        };
        runtime_keyset(&keyset, &keys, 1_000).unwrap()
    }

    fn test_user() -> User {
        User {
            id: Uuid::new_v4(),
            email: "clinician@example.invalid".into(),
            email_verified: true,
            profile: crate::store::AccountProfile::default(),
            identifiers: Vec::new(),
            session_version: 7,
            recovery_codes: Vec::new(),
            created_at: 900,
            passkeys: Vec::new(),
        }
    }

    fn test_session(user_id: Uuid) -> Session {
        Session {
            id: Uuid::new_v4(),
            user_id,
            auth_method: "passkey".into(),
            current_credential_id: None,
            session_version: 7,
            created_at: 1_234,
            step_up_at: Some(1_234),
            last_seen_at: 1_500,
            absolute_expires_at: 90_000,
        }
    }

    fn decode_claims(token: &str, runtime: &RuntimeKeySet) -> Value {
        let jwk: Jwk = serde_json::from_value(runtime.jwks["keys"][0].clone()).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        decode::<Value>(token, &DecodingKey::from_jwk(&jwk).unwrap(), &validation)
            .unwrap()
            .claims
    }
}
