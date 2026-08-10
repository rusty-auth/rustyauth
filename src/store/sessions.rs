//! Browser session records and the policy that ends them.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Store, User, now, session_activity_key, session_key};

// Persisting `last_seen_at` on every authenticated request turns the read path
// into a write-heavy workload and drives avoidable LSM compaction. A session is
// touched at most once per five minutes (and more frequently for short idle
// windows). Six persisted observations per idle window keep the worst-case
// early expiry bounded to one sixth of that operator-selected window while
// preventing a large active population from turning reads into a write stream.
// The stored timestamp can therefore trail real activity by this bounded
// interval, which may end an idle session slightly early but never extends it
// beyond the configured security boundary.
const MAX_SESSION_TOUCH_INTERVAL_SECONDS: u64 = 5 * 60;
const SESSION_TOUCHES_PER_IDLE_WINDOW: u64 = 6;

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
    /// Last time a passkey ceremony explicitly verified the account holder.
    /// Old sessions deserialize as `None` and must step up before a sensitive
    /// mutation; session creation time is not silently treated as proof.
    #[serde(default)]
    pub step_up_at: Option<u64>,
    pub last_seen_at: u64,
    pub absolute_expires_at: u64,
}

/// How a session came to exist.
///
/// A passkey session carries the credential that produced it, because revoking
/// that credential has to be able to end the session. Modelling it as an enum
/// rather than a `&str` plus an `Option` is what stops a caller creating a
/// passkey session with no originating credential: that combination would make
/// the revocation check in `session_verdict` silently unreachable, and no test
/// of that function would notice, because the fixture would still be valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionOrigin {
    Passkey {
        credential_id: String,
    },
    /// A short-lived native-console handoff minted from a freshly verified
    /// passkey session. Keeping the credential binding means revoking the
    /// passkey also revokes every device token derived from it.
    Device {
        credential_id: String,
    },
    /// A local agent handoff. No credential produced it, so passkey revocation
    /// does not apply.
    Agent,
}

impl SessionOrigin {
    fn auth_method(&self) -> &'static str {
        match self {
            Self::Passkey { .. } => "passkey",
            Self::Device { .. } => "device",
            Self::Agent => "agent",
        }
    }

    fn token_prefix(&self) -> &'static str {
        match self {
            Self::Device { .. } => "rdt_",
            Self::Passkey { .. } | Self::Agent => "",
        }
    }

    fn credential_id(self) -> Option<String> {
        match self {
            Self::Passkey { credential_id } | Self::Device { credential_id } => Some(credential_id),
            Self::Agent => None,
        }
    }
}

impl Store {
    pub async fn create_session(
        &self,
        user: &User,
        origin: SessionOrigin,
        absolute_seconds: u64,
    ) -> Result<(String, Session)> {
        let auth_method = origin.auth_method();
        let token_prefix = origin.token_prefix();
        let current_credential_id = origin.credential_id();
        let _snapshot = self.snapshot_gate.read().await;
        let token = format!(
            "{token_prefix}{}",
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
        );
        let current = now();
        let session = Session {
            id: Uuid::new_v4(),
            user_id: user.id,
            auth_method: auth_method.into(),
            current_credential_id,
            session_version: user.session_version,
            created_at: current,
            // A device session can only be minted immediately after a browser
            // passkey step-up. It carries that assurance for the remainder of
            // the same five-minute administrative window, never beyond it.
            step_up_at: matches!(auth_method, "passkey" | "device").then_some(current),
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
        let activity_key = session_activity_key(token);
        let mut connection = self.redis.clone();
        let (session_json, activity): (Option<String>, Option<u64>) = redis::pipe()
            .get(&key)
            .get(&activity_key)
            .query_async(&mut connection)
            .await?;
        let Some(session_json) = session_json else {
            return Ok(None);
        };
        let mut session: Session =
            serde_json::from_str(&session_json).context("decode stored session JSON")?;
        let current = now();
        // Activity is an isolated, write-behind timestamp. It can advance only
        // to a time observed by an authenticated request and is ignored if a
        // corrupt value claims to come from the future.
        apply_session_activity(&mut session, activity, current);
        // Expiry is decided before the account is read. Reading first would spend a
        // datastore round trip on every request holding an already-dead session,
        // and would turn an expired session on a corrupt account — where `user`
        // fails closed — into a 500 that also leaves the dead key behind, instead
        // of the 401 and reclaim it should be.
        if session_expired(&session, idle_seconds, current) {
            self.delete_session_records(&key, &activity_key).await?;
            return Ok(None);
        }
        let Some(user) = self.user(session.user_id).await? else {
            self.delete_session_records(&key, &activity_key).await?;
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
            self.delete_session_records(&key, &activity_key).await?;
            return Ok(None);
        }
        let touch_due = session_touch_due(&session, idle_seconds, current);
        session.last_seen_at = current;
        if touch_due {
            self.enqueue_session_touch(
                activity_key,
                current,
                session.absolute_expires_at - current,
            );
        }
        Ok(Some((session, user)))
    }

    pub async fn delete_session(&self, token: &str) -> Result<()> {
        let _snapshot = self.snapshot_gate.read().await;
        self.delete_session_records(&session_key(token), &session_activity_key(token))
            .await
    }

    pub async fn mark_session_step_up(
        &self,
        token: &str,
        expected_session_id: Uuid,
        credential_id: String,
    ) -> Result<Session> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let key = session_key(token);
        let mut session = self
            .get_json::<Session>(&key)
            .await?
            .filter(|session| session.id == expected_session_id)
            .ok_or_else(|| anyhow::anyhow!("session is missing or changed"))?;
        let current = now();
        if session.absolute_expires_at <= current {
            self.delete(&key).await?;
            return Err(anyhow::anyhow!("session has expired"));
        }
        session.auth_method = "passkey".into();
        session.current_credential_id = Some(credential_id);
        session.step_up_at = Some(current);
        session.last_seen_at = current;
        let activity_key = session_activity_key(token);
        let mut connection = self.redis.clone();
        let _: () = redis::pipe()
            .atomic()
            .set_ex(
                &key,
                serde_json::to_string(&session)?,
                session.absolute_expires_at - current,
            )
            .ignore()
            .del(&activity_key)
            .ignore()
            .query_async(&mut connection)
            .await?;
        self.append_event_within_snapshot("session.step_up.completed", Some(session.user_id))
            .await?;
        Ok(session)
    }

    async fn delete_session_records(&self, key: &str, activity_key: &str) -> Result<()> {
        let mut connection = self.redis.clone();
        let _: () = redis::pipe()
            .del(key)
            .ignore()
            .del(activity_key)
            .ignore()
            .query_async(&mut connection)
            .await?;
        Ok(())
    }

    /// Persists sliding activity outside the request's critical path.
    ///
    /// The activity key is deliberately separate from the session record: a
    /// delayed write can never recreate a signed-out session or overwrite a
    /// concurrent step-up/revocation mutation. A bounded, de-duplicated queue
    /// prevents datastore failure from creating unbounded tasks. Dropping a
    /// touch can end a session early, but can never extend either expiry bound.
    fn enqueue_session_touch(&self, activity_key: String, observed_at: u64, ttl_seconds: u64) {
        let Ok(permit) = self.session_touch_permits.clone().try_acquire_owned() else {
            return;
        };
        {
            let mut pending = self
                .session_touches_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !pending.insert(activity_key.clone()) {
                return;
            }
        }

        let store = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut connection = store.redis.clone();
            let result: redis::RedisResult<()> = connection
                .set_ex(&activity_key, observed_at, ttl_seconds)
                .await;
            store
                .session_touches_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&activity_key);
            if let Err(error) = result {
                tracing::warn!(%error, "could not persist deferred session activity");
            }
        });
    }

    /// Invalidates every browser session for an account through the durable
    /// session-version boundary. Individual session keys are deliberately not
    /// scanned; each is rejected and reclaimed on its next request.
    pub async fn revoke_all_sessions(&self, user_id: Uuid) -> Result<User> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut user = self
            .user(user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("account is missing"))?;
        user.session_version = user.session_version.saturating_add(1);
        self.persist_user_with_event(&user, "session.revoked_all", "revoke every account session")
            .await?;
        Ok(user)
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

fn session_touch_interval(idle_seconds: u64) -> u64 {
    (idle_seconds / SESSION_TOUCHES_PER_IDLE_WINDOW).clamp(1, MAX_SESSION_TOUCH_INTERVAL_SECONDS)
}

fn session_touch_due(session: &Session, idle_seconds: u64, now: u64) -> bool {
    now.saturating_sub(session.last_seen_at) >= session_touch_interval(idle_seconds)
}

fn apply_session_activity(session: &mut Session, activity: Option<u64>, now: u64) {
    if let Some(activity) = activity.filter(|activity| *activity <= now) {
        session.last_seen_at = session.last_seen_at.max(activity);
    }
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
            step_up_at: Some(1_000),
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

    /// A passkey session cannot exist without the credential that made it.
    ///
    /// This is what keeps the revocation branch in `session_verdict` reachable.
    /// Before `SessionOrigin` existed the caller passed a `&str` and an
    /// `Option`, so passing `None` for a passkey login compiled fine, disabled
    /// credential-scoped revocation entirely, and left every test green.
    #[test]
    fn a_passkey_session_always_carries_its_originating_credential() {
        let passkey = SessionOrigin::Passkey {
            credential_id: "cred-a".to_owned(),
        };
        assert_eq!(passkey.auth_method(), "passkey");
        assert_eq!(passkey.credential_id(), Some("cred-a".to_owned()));

        // An agent handoff has no credential, and must survive revocation.
        assert_eq!(SessionOrigin::Agent.auth_method(), "agent");
        assert_eq!(SessionOrigin::Agent.credential_id(), None);
    }

    #[test]
    fn a_device_session_is_passkey_bound_and_uses_a_distinct_token_namespace() {
        let device = SessionOrigin::Device {
            credential_id: "cred-a".to_owned(),
        };
        assert_eq!(device.auth_method(), "device");
        assert_eq!(device.token_prefix(), "rdt_");
        assert_eq!(device.credential_id(), Some("cred-a".to_owned()));
    }

    /// Sessions written before credential-scoped revocation and explicit
    /// step-up existed must keep authenticating, but must not inherit either
    /// assurance from their creation timestamp during an upgrade.
    #[test]
    fn a_legacy_session_loads_without_fabricating_credential_or_step_up_proof() {
        let legacy = serde_json::json!({
            "id": Uuid::new_v4(),
            "userId": Uuid::new_v4(),
            "authMethod": "passkey",
            "sessionVersion": 3,
            "createdAt": 1_000,
            "lastSeenAt": 1_100,
            "absoluteExpiresAt": 10_000,
        });
        let decoded: Session =
            serde_json::from_value(legacy).expect("a pre-upgrade session still decodes");
        assert_eq!(decoded.current_credential_id, None);
        assert_eq!(decoded.step_up_at, None);
        assert_eq!(decoded.created_at, 1_000);
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
    fn session_touches_are_coalesced_without_extending_the_idle_boundary() {
        let session = session(None);
        assert_eq!(session_touch_interval(1_800), 300);
        assert!(!session_touch_due(&session, 1_800, 1_299));
        assert!(session_touch_due(&session, 1_800, 1_300));

        // Short idle windows retain six persisted touch opportunities and
        // never use a zero-second interval.
        assert_eq!(session_touch_interval(300), 50);
        assert_eq!(session_touch_interval(1), 1);

        // Coalescing cannot change the expiry predicate: the persisted value
        // is never advanced into the future to buy performance headroom.
        assert!(session_expired(&session, 300, 1_300));
    }

    #[test]
    fn deferred_activity_advances_only_to_an_observed_non_future_time() {
        let mut candidate = session(None);
        apply_session_activity(&mut candidate, Some(1_200), 1_250);
        assert_eq!(candidate.last_seen_at, 1_200);

        apply_session_activity(&mut candidate, Some(1_100), 1_250);
        assert_eq!(candidate.last_seen_at, 1_200);

        apply_session_activity(&mut candidate, Some(1_300), 1_250);
        assert_eq!(candidate.last_seen_at, 1_200);
    }

    #[test]
    fn deferred_activity_uses_a_distinct_key_with_the_same_token_digest() {
        let token = "a-token-that-is-long-enough-for-a-session-key";
        let session = session_key(token);
        let activity = session_activity_key(token);
        assert_eq!(
            session.strip_prefix("auth:session:"),
            activity.strip_prefix("auth:session-activity:")
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
