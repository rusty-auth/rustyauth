//! Software WebAuthn authenticator for tests.
//!
//! Produces the exact bytes a browser hands back from `navigator.credentials`,
//! so registration and authentication ceremonies can be driven end to end
//! against the real `webauthn-rs` verifier instead of being asserted only at
//! their edges. Test-only: this module is never compiled into the binary.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::value::{Integer, Value as Cbor};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate as _,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FLAG_USER_PRESENT: u8 = 0b0000_0001;
const FLAG_USER_VERIFIED: u8 = 0b0000_0100;
const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0b0100_0000;

/// A single-credential authenticator with a P-256 key and a sign counter.
pub struct SoftAuthenticator {
    key: SigningKey,
    credential_id: Vec<u8>,
    next_counter: u32,
}

/// Every input a browser contributes to an assertion, so negative cases can vary
/// one field at a time.
pub struct AssertionRequest<'a> {
    pub challenge: &'a str,
    pub rp_id: &'a str,
    pub origin: &'a str,
    pub user_verified: bool,
    pub user_handle: Option<&'a [u8]>,
}

impl<'a> AssertionRequest<'a> {
    /// The assertion a compliant browser would produce for `options`.
    pub fn new(options: &'a Value, origin: &'a str) -> Self {
        Self {
            challenge: challenge_of(options),
            rp_id: options["publicKey"]["rpId"]
                .as_str()
                .expect("authentication options carry an rpId"),
            origin,
            user_verified: true,
            user_handle: None,
        }
    }
}

impl SoftAuthenticator {
    pub fn new() -> Self {
        let credential_id = rand::random::<[u8; 32]>().to_vec();
        Self {
            key: SigningKey::generate(),
            credential_id,
            next_counter: 1,
        }
    }

    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Replays or rewinds the sign count reported by the next assertion, which
    /// is the cloned-credential signal `store::apply_authentication` screens for.
    pub fn set_next_counter(&mut self, value: u32) {
        self.next_counter = value;
    }

    /// The `RegisterPublicKeyCredential` JSON for the ceremony described by the
    /// serialized `CreationChallengeResponse` in `options`.
    pub fn register(&self, options: &Value, origin: &str) -> Value {
        let rp_id = options["publicKey"]["rp"]["id"]
            .as_str()
            .expect("registration options carry an rp id");
        self.register_with(challenge_of(options), rp_id, origin, true)
    }

    /// Registration response with the relying party binding and the UV flag under
    /// test control.
    pub fn register_with(
        &self,
        challenge: &str,
        rp_id: &str,
        origin: &str,
        user_verified: bool,
    ) -> Value {
        let client_data = client_data("webauthn.create", challenge, origin);
        // AT must be set for attested credential data to be parsed at all, and
        // passkey ceremonies pin UserVerificationPolicy::Required, so a
        // registration without UV is refused outright.
        let mut flags = FLAG_USER_PRESENT | FLAG_ATTESTED_CREDENTIAL_DATA;
        if user_verified {
            flags |= FLAG_USER_VERIFIED;
        }
        let mut auth_data = authenticator_data(rp_id, flags, 0);
        auth_data.extend_from_slice(&[0_u8; 16]);
        auth_data.extend_from_slice(
            &u16::try_from(self.credential_id.len())
                .expect("credential id is 32 bytes")
                .to_be_bytes(),
        );
        auth_data.extend_from_slice(&self.credential_id);
        auth_data.extend_from_slice(&self.cose_public_key());

        // "none" attestation carries an empty attStmt map; the verifier borrows
        // fmt and authData straight out of this buffer, so both must be
        // definite-length CBOR items.
        let attestation = cbor(&Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(Vec::new())),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
        ]));

        json!({
            "id": URL_SAFE_NO_PAD.encode(&self.credential_id),
            "rawId": URL_SAFE_NO_PAD.encode(&self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data),
                "attestationObject": URL_SAFE_NO_PAD.encode(&attestation),
            },
            "clientExtensionResults": {},
        })
    }

    /// The `PublicKeyCredential` JSON for the ceremony described by the
    /// serialized `RequestChallengeResponse` in `options`.
    pub fn authenticate(&mut self, options: &Value, origin: &str) -> Value {
        self.assert_with(AssertionRequest::new(options, origin))
    }

    /// Assertion with every browser-supplied input under test control.
    pub fn assert_with(&mut self, request: AssertionRequest<'_>) -> Value {
        let counter = self.next_counter;
        self.next_counter = self.next_counter.saturating_add(1);

        let client_data = client_data("webauthn.get", request.challenge, request.origin);
        let mut flags = FLAG_USER_PRESENT;
        if request.user_verified {
            flags |= FLAG_USER_VERIFIED;
        }
        let auth_data = authenticator_data(request.rp_id, flags, counter);

        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let signature: Signature = self.key.sign(&signed);

        json!({
            "id": URL_SAFE_NO_PAD.encode(&self.credential_id),
            "rawId": URL_SAFE_NO_PAD.encode(&self.credential_id),
            "type": "public-key",
            "response": {
                "authenticatorData": URL_SAFE_NO_PAD.encode(&auth_data),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data),
                "signature": URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
                "userHandle": request.user_handle.map(|handle| URL_SAFE_NO_PAD.encode(handle)),
            },
            "clientExtensionResults": {},
        })
    }

    fn cose_public_key(&self) -> Vec<u8> {
        let point = self.key.verifying_key().to_sec1_point(false);
        let x = point.x().expect("uncompressed point has an x coordinate");
        let y = point.y().expect("uncompressed point has a y coordinate");
        // COSE labels 3/-1/-2/-3 are negative integers. Encoding any of them as
        // unsigned yields a structurally valid CBOR map that no longer describes
        // an ES256 key, and every ceremony then fails at key parsing.
        cbor(&Cbor::Map(vec![
            (label(1), label(2)),
            (label(3), label(-7)),
            (label(-1), label(1)),
            (label(-2), Cbor::Bytes(x.to_vec())),
            (label(-3), Cbor::Bytes(y.to_vec())),
        ]))
    }
}

impl Default for SoftAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

fn challenge_of(options: &Value) -> &str {
    options["publicKey"]["challenge"]
        .as_str()
        .expect("options carry a base64url challenge")
}

fn client_data(ceremony: &str, challenge: &str, origin: &str) -> Vec<u8> {
    json!({
        "type": ceremony,
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    })
    .to_string()
    .into_bytes()
}

fn authenticator_data(rp_id: &str, flags: u8, counter: u32) -> Vec<u8> {
    let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
    data.push(flags);
    data.extend_from_slice(&counter.to_be_bytes());
    data
}

fn label(value: i64) -> Cbor {
    Cbor::Integer(Integer::from(value))
}

fn cbor(value: &Cbor) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).expect("CBOR value is encodable");
    encoded
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::Value;
    use url::Url;
    use uuid::Uuid;
    use webauthn_rs::{
        WebauthnBuilder,
        prelude::{
            Passkey, PublicKeyCredential, RegisterPublicKeyCredential, Webauthn, WebauthnError,
        },
    };

    use super::{AssertionRequest, SoftAuthenticator};

    const RP_ID: &str = "localhost";
    const ORIGIN: &str = "http://localhost:3000";

    fn relying_party() -> Webauthn {
        let origin = Url::parse(ORIGIN).unwrap();
        WebauthnBuilder::new(RP_ID, &origin)
            .unwrap()
            .rp_name("RustyAuth tests")
            .build()
            .unwrap()
    }

    fn register(webauthn: &Webauthn, authenticator: &SoftAuthenticator) -> Passkey {
        let (options, state) = webauthn
            .start_passkey_registration(
                Uuid::new_v4(),
                "ceremony@example.invalid",
                "Ceremony",
                None,
            )
            .unwrap();
        let response = authenticator.register(&serde_json::to_value(&options).unwrap(), ORIGIN);
        webauthn
            .finish_passkey_registration(&registration(response), &state)
            .unwrap()
    }

    fn registration(response: Value) -> RegisterPublicKeyCredential {
        serde_json::from_value(response).unwrap()
    }

    fn assertion(response: Value) -> PublicKeyCredential {
        serde_json::from_value(response).unwrap()
    }

    #[test]
    fn registration_ceremony_completes_and_binds_the_authenticator_credential() {
        let webauthn = relying_party();
        let authenticator = SoftAuthenticator::new();
        let (options, state) = webauthn
            .start_passkey_registration(Uuid::new_v4(), "new@example.invalid", "New", None)
            .unwrap();
        let options = serde_json::to_value(&options).unwrap();

        let passkey = webauthn
            .finish_passkey_registration(
                &registration(authenticator.register(&options, ORIGIN)),
                &state,
            )
            .expect("attestation object and COSE key are spec correct");

        assert_eq!(passkey.cred_id().as_ref(), authenticator.credential_id());
    }

    #[test]
    fn authentication_ceremony_completes_with_user_verification() {
        let webauthn = relying_party();
        let mut authenticator = SoftAuthenticator::new();
        let passkey = register(&webauthn, &authenticator);

        let (options, state) = webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let options = serde_json::to_value(&options).unwrap();
        let result = webauthn
            .finish_passkey_authentication(
                &assertion(authenticator.authenticate(&options, ORIGIN)),
                &state,
            )
            .expect("assertion signature covers authData and the client data hash");

        assert!(result.user_verified());
        assert_eq!(result.cred_id().as_ref(), authenticator.credential_id());
    }

    #[test]
    fn assertions_without_user_verification_are_refused_by_the_passkey_ceremony() {
        let webauthn = relying_party();
        let mut authenticator = SoftAuthenticator::new();
        let passkey = register(&webauthn, &authenticator);

        let (options, state) = webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let options = serde_json::to_value(&options).unwrap();
        let mut request = AssertionRequest::new(&options, ORIGIN);
        request.user_verified = false;

        let error = webauthn
            .finish_passkey_authentication(&assertion(authenticator.assert_with(request)), &state)
            .unwrap_err();

        assert!(matches!(error, WebauthnError::UserNotVerified));
    }

    #[test]
    fn authentication_result_reports_a_missing_user_verified_flag() {
        // Passkey ceremonies pin UserVerificationPolicy::Required, so a non-UV
        // assertion never reaches the `!result.user_verified()` guard in
        // `auth::authentication_verify`. Security-key ceremonies use Preferred,
        // which is the only way to observe that `user_verified()` mirrors the
        // authData flag rather than being hard-wired true.
        let webauthn = relying_party();
        let mut authenticator = SoftAuthenticator::new();
        let (options, state) = webauthn
            .start_securitykey_registration(
                Uuid::new_v4(),
                "unverified@example.invalid",
                "Unverified",
                None,
                None,
                None,
            )
            .unwrap();
        let options = serde_json::to_value(&options).unwrap();
        let security_key = webauthn
            .finish_securitykey_registration(
                &registration(authenticator.register_with(
                    options["publicKey"]["challenge"].as_str().unwrap(),
                    RP_ID,
                    ORIGIN,
                    false,
                )),
                &state,
            )
            .unwrap();

        let (options, state) = webauthn
            .start_securitykey_authentication(std::slice::from_ref(&security_key))
            .unwrap();
        let options = serde_json::to_value(&options).unwrap();
        let mut request = AssertionRequest::new(&options, ORIGIN);
        request.user_verified = false;
        let result = webauthn
            .finish_securitykey_authentication(
                &assertion(authenticator.assert_with(request)),
                &state,
            )
            .unwrap();

        assert!(!result.user_verified());
    }

    #[test]
    fn assertions_from_another_origin_are_rejected() {
        let webauthn = relying_party();
        let mut authenticator = SoftAuthenticator::new();
        let passkey = register(&webauthn, &authenticator);

        let (options, state) = webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let options = serde_json::to_value(&options).unwrap();
        let mut request = AssertionRequest::new(&options, ORIGIN);
        request.origin = "https://phish.example.invalid";

        let error = webauthn
            .finish_passkey_authentication(&assertion(authenticator.assert_with(request)), &state)
            .unwrap_err();

        assert!(matches!(error, WebauthnError::InvalidRPOrigin));
    }

    #[test]
    fn assertions_replaying_a_stale_challenge_are_rejected() {
        let webauthn = relying_party();
        let mut authenticator = SoftAuthenticator::new();
        let passkey = register(&webauthn, &authenticator);

        let (stale_options, _) = webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let (_, fresh_state) = webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let stale =
            authenticator.authenticate(&serde_json::to_value(&stale_options).unwrap(), ORIGIN);

        let error = webauthn
            .finish_passkey_authentication(&assertion(stale), &fresh_state)
            .unwrap_err();

        assert!(matches!(error, WebauthnError::MismatchedChallenge));
    }

    #[test]
    fn assertions_bound_to_another_relying_party_are_rejected() {
        let webauthn = relying_party();
        let mut authenticator = SoftAuthenticator::new();
        let passkey = register(&webauthn, &authenticator);

        let (options, state) = webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let options = serde_json::to_value(&options).unwrap();
        let mut request = AssertionRequest::new(&options, ORIGIN);
        request.rp_id = "attacker.example.invalid";

        let error = webauthn
            .finish_passkey_authentication(&assertion(authenticator.assert_with(request)), &state)
            .unwrap_err();

        assert!(matches!(error, WebauthnError::InvalidRPIDHash));
    }

    #[test]
    fn tampered_assertion_signatures_are_rejected() {
        let webauthn = relying_party();
        let mut authenticator = SoftAuthenticator::new();
        let passkey = register(&webauthn, &authenticator);

        let (options, state) = webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let options = serde_json::to_value(&options).unwrap();
        let mut response = authenticator.authenticate(&options, ORIGIN);

        // Flip a bit inside the DER-encoded `s` value so the signature still
        // parses and the failure can only come from verification.
        let signature = response["response"]["signature"].as_str().unwrap();
        let mut signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
        let last = signature.len() - 1;
        signature[last] ^= 0x01;
        response["response"]["signature"] = URL_SAFE_NO_PAD.encode(&signature).into();

        let error = webauthn
            .finish_passkey_authentication(&assertion(response), &state)
            .unwrap_err();

        assert!(matches!(error, WebauthnError::AuthenticationFailure));
    }

    #[test]
    fn sign_counter_advances_and_a_regression_is_visible_to_the_caller() {
        let webauthn = relying_party();
        let mut authenticator = SoftAuthenticator::new();
        let passkey = register(&webauthn, &authenticator);

        let authenticate = |authenticator: &mut SoftAuthenticator, passkey: &Passkey| {
            let (options, state) = webauthn
                .start_passkey_authentication(std::slice::from_ref(passkey))
                .unwrap();
            let options = serde_json::to_value(&options).unwrap();
            webauthn.finish_passkey_authentication(
                &assertion(authenticator.authenticate(&options, ORIGIN)),
                &state,
            )
        };

        let first = authenticate(&mut authenticator, &passkey).unwrap();
        let second = authenticate(&mut authenticator, &passkey).unwrap();
        assert!(second.counter() > first.counter());

        // `store::apply_authentication` compares against its own mirror of the
        // counter, so it must be able to see a replayed value. It can: the
        // library only rejects the regression once the stored credential has
        // been advanced by `update_credential`.
        authenticator.set_next_counter(first.counter());
        let replayed = authenticate(&mut authenticator, &passkey).unwrap();
        assert_eq!(replayed.counter(), first.counter());
        assert!(replayed.counter() <= second.counter());

        let mut advanced = passkey.clone();
        advanced.update_credential(&second).unwrap();
        authenticator.set_next_counter(first.counter());
        let error = authenticate(&mut authenticator, &advanced).unwrap_err();
        assert!(matches!(error, WebauthnError::CredentialPossibleCompromise));
    }
}
