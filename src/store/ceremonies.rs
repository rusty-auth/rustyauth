//! One-time ceremony and handoff state, consumed atomically.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

use super::{AccountProfile, IdentifierKind, IdentifierValue, Store, handoff_key, now};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationCeremony {
    pub id: Uuid,
    pub user_id: Uuid,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub identifier: Option<IdentifierValue>,
    #[serde(default)]
    pub profile: AccountProfile,
    #[serde(default)]
    pub purpose: RegistrationPurpose,
    #[serde(default)]
    pub initiating_session_id: Option<Uuid>,
    #[serde(default)]
    pub invitation_id: Option<Uuid>,
    #[serde(default)]
    pub invitation_digest: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    pub expires_at: u64,
    pub state: PasskeyRegistration,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RegistrationPurpose {
    #[default]
    Initial,
    AddCredential,
    RecoverAccount,
}

impl RegistrationCeremony {
    pub fn account_identifier(&self) -> Option<IdentifierValue> {
        self.identifier.clone().or_else(|| {
            (!self.email.is_empty()).then(|| IdentifierValue {
                kind: IdentifierKind::Email,
                value: self.email.clone(),
            })
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationCeremony {
    pub id: Uuid,
    pub user_id: Uuid,
    #[serde(default)]
    pub purpose: AuthenticationPurpose,
    #[serde(default)]
    pub initiating_session_id: Option<Uuid>,
    pub expires_at: u64,
    pub state: PasskeyAuthentication,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthenticationPurpose {
    #[default]
    SignIn,
    StepUp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalAgentHandoff {
    pub user_id: Uuid,
    pub redirect_url: String,
    pub expires_at: u64,
}

impl Store {
    pub async fn save_registration(&self, ceremony: &RegistrationCeremony) -> Result<()> {
        let _snapshot = self.snapshot_gate.read().await;
        self.set_json_ex(
            &format!("auth:registration:{}", ceremony.id),
            ceremony,
            ceremony.expires_at.saturating_sub(now()).max(1),
        )
        .await
    }

    pub async fn take_registration(&self, id: Uuid) -> Result<RegistrationCeremony> {
        let _snapshot = self.snapshot_gate.read().await;
        let ceremony: RegistrationCeremony = self
            .take_json(&format!("auth:registration:{id}"))
            .await?
            .context("registration ceremony is missing or already used")?;
        if ceremony.expires_at <= now() {
            bail!("registration ceremony has expired");
        }
        Ok(ceremony)
    }

    pub async fn save_authentication(&self, ceremony: &AuthenticationCeremony) -> Result<()> {
        let _snapshot = self.snapshot_gate.read().await;
        self.set_json_ex(
            &format!("auth:authentication:{}", ceremony.id),
            ceremony,
            ceremony.expires_at.saturating_sub(now()).max(1),
        )
        .await
    }

    pub async fn take_authentication(&self, id: Uuid) -> Result<AuthenticationCeremony> {
        let _snapshot = self.snapshot_gate.read().await;
        let ceremony: AuthenticationCeremony = self
            .take_json(&format!("auth:authentication:{id}"))
            .await?
            .context("authentication ceremony is missing or already used")?;
        if ceremony.expires_at <= now() {
            bail!("authentication ceremony has expired");
        }
        Ok(ceremony)
    }

    pub async fn create_local_agent_handoff(
        &self,
        email: &str,
        redirect_url: String,
        lifetime_seconds: u64,
    ) -> Result<String> {
        let _snapshot = self.snapshot_gate.read().await;
        let user = self
            .user_by_email(email)
            .await?
            .context("account does not exist")?;
        let code = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let handoff = LocalAgentHandoff {
            user_id: user.id,
            redirect_url,
            expires_at: now().saturating_add(lifetime_seconds),
        };
        self.set_json_ex(&handoff_key(&code), &handoff, lifetime_seconds)
            .await?;
        self.append_event_within_snapshot("agent.handoff.created", Some(user.id))
            .await?;
        Ok(code)
    }

    pub async fn take_local_agent_handoff(&self, code: &str) -> Result<LocalAgentHandoff> {
        let _snapshot = self.snapshot_gate.read().await;
        if code.len() < 32 || code.len() > 256 {
            bail!("agent handoff code is invalid");
        }
        let handoff: LocalAgentHandoff = self
            .take_json(&handoff_key(code))
            .await?
            .context("agent handoff is missing or already used")?;
        if handoff.expires_at <= now() {
            bail!("agent handoff has expired");
        }
        Ok(handoff)
    }
}
