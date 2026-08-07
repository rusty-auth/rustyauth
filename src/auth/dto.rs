//! Transport-only request and response shapes.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::store::IdentifierKind;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IdentifierRequest {
    #[serde(rename = "type")]
    pub(super) kind: IdentifierKind,
    pub(super) value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RegistrationOptionsInput {
    #[serde(default)]
    pub(super) identifier: Option<IdentifierRequest>,
    #[serde(default)]
    pub(super) email: Option<String>,
    #[serde(default)]
    pub(super) phone: Option<String>,
    #[serde(default)]
    pub(super) given_name: Option<String>,
    #[serde(default)]
    pub(super) family_name: Option<String>,
    #[serde(default)]
    pub(super) display_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IdentifierLookupInput {
    #[serde(default)]
    pub(super) identifier: Option<IdentifierRequest>,
    #[serde(default)]
    pub(super) email: Option<String>,
    #[serde(default)]
    pub(super) phone: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct EmailInput {
    pub(super) email: String,
}

#[derive(Deserialize)]
pub(super) struct ChangeIdentifierInput {
    #[serde(rename = "type")]
    pub(super) kind: IdentifierKind,
    pub(super) value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UpdateProfileInput {
    #[serde(default)]
    pub(super) given_name: Option<String>,
    #[serde(default)]
    pub(super) family_name: Option<String>,
    #[serde(default)]
    pub(super) display_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RegistrationVerifyInput {
    pub(super) ceremony_id: Uuid,
    pub(super) response: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
pub(super) struct AddRegistrationOptionsInput {
    pub(super) label: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RenameCredentialInput {
    pub(super) credential_id: String,
    pub(super) label: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RevokeCredentialInput {
    pub(super) credential_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CredentialOutput {
    pub(super) id: String,
    pub(super) label: String,
    pub(super) created_at: String,
    pub(super) last_used_at: String,
    pub(super) authenticator: &'static str,
    pub(super) current: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IdentifierOutput {
    #[serde(rename = "type")]
    pub(super) kind: IdentifierKind,
    pub(super) value: String,
    pub(super) verified: bool,
    pub(super) verified_at: Option<String>,
    pub(super) primary: bool,
    pub(super) created_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticationVerifyInput {
    pub(super) ceremony_id: Uuid,
    pub(super) response: PublicKeyCredential,
}

#[derive(Deserialize)]
pub(super) struct EventsQuery {
    pub(super) after: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct LocalAgentHandoffQuery {
    pub(super) code: String,
}
