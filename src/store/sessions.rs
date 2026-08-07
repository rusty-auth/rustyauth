//! Browser session records and the policy that ends them.

use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Store, User, now, session_key};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub auth_method: String,
    #[serde(default)]
    pub current_credential_id: Option<String>,
    pub session_version: u64,
    pub created_at: u64,
    pub last_seen_at: u64,
    pub absolute_expires_at: u64,
}

impl Store {
    pub async fn create_session(
        &self,
        user: &User,
        auth_method: &str,
        current_credential_id: Option<String>,
        absolute_seconds: u64,
    ) -> Result<(String, Session)> {
        let _snapshot = self.snapshot_gate.read().await;
        let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let current = now();
        let session = Session {
            id: Uuid::new_v4(),
            user_id: user.id,
            auth_method: auth_method.into(),
            current_credential_id,
            session_version: user.session_version,
            created_at: current,
            last_seen_at: current,
            absolute_expires_at: current.saturating_add(absolute_seconds),
        };
        self.set_json_ex(&session_key(&token), &session, absolute_seconds)
            .await?;
        self.append_event_within_snapshot("session.created", Some(user.id))
            .await?;
        Ok((token, session))
    }

    pub async fn session(&self, token: &str, idle_seconds: u64) -> Result<Option<(Session, User)>> {
        let _snapshot = self.snapshot_gate.read().await;
        if token.len() < 32 || token.len() > 256 {
            return Ok(None);
        }
        let key = session_key(token);
        let Some(mut session) = self.get_json::<Session>(&key).await? else {
            return Ok(None);
        };
        let current = now();
        // Expiry is decided before the account is read. Reading first would spend a
        // datastore round trip on every request holding an already-dead session,
        // and would turn an expired session on a corrupt account — where `user`
        // fails closed — into a 500 that also leaves the dead key behind, instead
        // of the 401 and reclaim it should be.
        if session_expired(&session, idle_seconds, current) {
            self.delete(&key).await?;
            return Ok(None);
        }
        let Some(user) = self.user(session.user_id).await? else {
            self.delete(&key).await?;
            return Ok(None);
        };
        let verdict = {
            let credential_ids = user
                .passkeys
                .iter()
                .map(|passkey| passkey.id.as_str())
                .collect::<Vec<_>>();
            session_verdict(
                &session,
                user.session_version,
                &credential_ids,
                idle_seconds,
                current,
            )
        };
        if verdict != SessionVerdict::Valid {
            self.delete(&key).await?;
            return Ok(None);
        }
        session.last_seen_at = current;
        self.set_json_ex(&key, &session, session.absolute_expires_at - current)
            .await?;
        Ok(Some((session, user)))
    }

    pub async fn delete_session(&self, token: &str) -> Result<()> {
        let _snapshot = self.snapshot_gate.read().await;
        self.delete(&session_key(token)).await
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionVerdict {
    Valid,
    AbsoluteExpiry,
    IdleExpiry,
    VersionRevoked,
    CredentialRevoked,
}

/// Whether the session has run out of time, decidable without reading the account.
fn session_expired(session: &Session, idle_seconds: u64, now: u64) -> bool {
    session.absolute_expires_at <= now || session.last_seen_at.saturating_add(idle_seconds) <= now
}

fn session_verdict(
    session: &Session,
    account_session_version: u64,
    credential_ids: &[&str],
    idle_seconds: u64,
    now: u64,
) -> SessionVerdict {
    if session.absolute_expires_at <= now {
        return SessionVerdict::AbsoluteExpiry;
    }
    if session.last_seen_at.saturating_add(idle_seconds) <= now {
        return SessionVerdict::IdleExpiry;
    }
    if session.session_version != account_session_version {
        return SessionVerdict::VersionRevoked;
    }
    // Revoking a passkey must end the sessions that passkey created, or the
    // control the dashboard presents as the stolen-device stop leaves the
    // thief authenticated until the absolute lifetime expires. Sessions with
    // no originating credential (agent handoffs) are unaffected.
    if let Some(credential_id) = &session.current_credential_id
        && !credential_ids.contains(&credential_id.as_str())
    {
        return SessionVerdict::CredentialRevoked;
    }
    SessionVerdict::Valid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(current_credential_id: Option<&str>) -> Session {
        Session {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            auth_method: "passkey".into(),
            current_credential_id: current_credential_id.map(str::to_owned),
            session_version: 3,
            created_at: 1_000,
            last_seen_at: 1_000,
            absolute_expires_at: 10_000,
        }
    }

    #[test]
    fn a_live_session_on_a_registered_passkey_is_valid() {
        assert_eq!(
            session_verdict(
                &session(Some("cred-a")),
                3,
                &["cred-b", "cred-a"],
                300,
                1_200
            ),
            SessionVerdict::Valid
        );
    }

    /// The expiry pre-check must agree with the verdict, or a session would be
    /// discarded by one and accepted by the other depending on which ran first.
    #[test]
    fn the_expiry_precheck_agrees_with_the_full_verdict() {
        for (label, session, idle, now) in [
            ("live", session(None), 300_u64, 1_200_u64),
            ("idle expired", session(None), 300, 1_300),
            ("absolutely expired", session(None), 300_000, 10_000),
        ] {
            let expired = session_expired(&session, idle, now);
            let verdict = session_verdict(&session, 3, &[], idle, now);
            let verdict_says_expired = matches!(
                verdict,
                SessionVerdict::IdleExpiry | SessionVerdict::AbsoluteExpiry
            );
            assert_eq!(expired, verdict_says_expired, "{label}");
        }
    }

    #[test]
    fn sessions_end_at_the_idle_and_absolute_limits() {
        assert_eq!(
            session_verdict(&session(None), 3, &[], 300, 1_299),
            SessionVerdict::Valid
        );
        assert_eq!(
            session_verdict(&session(None), 3, &[], 300, 1_300),
            SessionVerdict::IdleExpiry
        );
        assert_eq!(
            session_verdict(&session(None), 3, &[], 300_000, 9_999),
            SessionVerdict::Valid
        );
        assert_eq!(
            session_verdict(&session(None), 3, &[], 300_000, 10_000),
            SessionVerdict::AbsoluteExpiry
        );
    }

    #[test]
    fn a_session_version_bump_ends_the_session() {
        assert_eq!(
            session_verdict(&session(Some("cred-a")), 4, &["cred-a"], 300, 1_200),
            SessionVerdict::VersionRevoked
        );
    }

    #[test]
    fn revoking_the_originating_passkey_ends_the_session() {
        assert_eq!(
            session_verdict(&session(Some("cred-a")), 3, &["cred-b"], 300, 1_200),
            SessionVerdict::CredentialRevoked
        );
        assert_eq!(
            session_verdict(&session(Some("cred-a")), 3, &[], 300, 1_200),
            SessionVerdict::CredentialRevoked
        );
    }

    #[test]
    fn an_agent_session_has_no_originating_passkey_to_revoke() {
        assert_eq!(
            session_verdict(&session(None), 3, &[], 300, 1_200),
            SessionVerdict::Valid
        );
        assert_eq!(
            session_verdict(&session(None), 3, &["cred-a"], 300, 1_200),
            SessionVerdict::Valid
        );
    }
}
