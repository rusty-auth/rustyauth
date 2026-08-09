//! Shared request guards: origin and bootstrap checks, rate limiting and
//! authenticated-session extraction.

use std::net::SocketAddr;

use axum::http::{HeaderMap, header};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    app_state::AppState,
    rate_limit::{RateLimitClass, client_address},
    store::{Session, now},
};

use super::{CEREMONY_SECONDS, error::ApiError, session::session_cookie};

/// Charges one request against the caller's budget for `class`.
///
/// Both the client address and the value being attempted are charged. Limiting on
/// address alone lets a botnet spread an attack across hosts; limiting on the
/// attempted value alone lets one host walk through many accounts.
pub(super) fn require_rate_limit(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
    class: RateLimitClass,
    subject: Option<&str>,
) -> Result<(), ApiError> {
    let forwarded = joined_forwarded_for(headers);
    let address = client_address(peer.ip(), forwarded.as_deref(), state.trusted_proxy_hops);
    let mut decisions = vec![state.rate_limiter.check(class, &format!("addr:{address}"))];
    if let Some(subject) = subject {
        decisions.push(state.rate_limiter.check(class, &format!("subj:{subject}")));
    }
    match decisions.iter().find(|decision| !decision.allowed) {
        Some(refused) => Err(ApiError::too_many_requests(refused.retry_after_seconds)),
        None => Ok(()),
    }
}

/// Joins every `X-Forwarded-For` header line into one comma-separated value.
///
/// A proxy may append a second header rather than extending the first. Reading
/// only the first line would then leave a client-supplied value in front, and the
/// caller could choose its own rate-limit bucket — which is the whole thing
/// `AUTH_TRUSTED_PROXY_HOPS` exists to prevent.
fn joined_forwarded_for(headers: &HeaderMap) -> Option<String> {
    let joined = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");
    (!joined.is_empty()).then_some(joined)
}

pub(super) fn require_origin(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let expected = state.rp_origin.trim_end_matches('/');
    let actual = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if actual != Some(expected) {
        return Err(ApiError::unauthorized("request origin is not allowed"));
    }
    Ok(())
}

pub(super) fn require_bootstrap(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let supplied = headers
        .get("x-bootstrap-token")
        .and_then(|value| value.to_str().ok());
    if !bootstrap_token_matches(state.bootstrap_token.expose_secret(), supplied) {
        return Err(ApiError::unauthorized("enrolment is not authorized"));
    }
    Ok(())
}

/// Compares over fixed-width digests in constant time.
///
/// String equality short-circuits on the first differing byte, which leaks the
/// token to an attacker timing this unauthenticated endpoint one byte at a time.
/// Hashing first also keeps the comparison independent of the token's length.
fn bootstrap_token_matches(expected: &str, supplied: Option<&str>) -> bool {
    let expected = Sha256::digest(expected.as_bytes());
    let supplied = Sha256::digest(supplied.unwrap_or_default().as_bytes());
    bool::from(expected.ct_eq(&supplied))
}

pub(super) fn require_recent_passkey(session: &Session) -> Result<(), ApiError> {
    require_passkey_session(session)?;
    let current = now();
    if session.created_at > current || current.saturating_sub(session.created_at) > CEREMONY_SECONDS
    {
        return Err(ApiError::unauthorized(
            "confirm with a recent passkey before changing account security",
        ));
    }
    Ok(())
}

pub(super) fn require_passkey_session(session: &Session) -> Result<(), ApiError> {
    if session.auth_method != "passkey" {
        return Err(ApiError::unauthorized(
            "confirm with a passkey before changing account identity",
        ));
    }
    Ok(())
}

pub(super) async fn authenticated<'a>(
    state: &AppState,
    headers: &'a HeaderMap,
) -> Result<(&'a str, crate::store::Session, crate::store::User), ApiError> {
    require_origin(state, headers)?;
    let raw = session_cookie(headers, state.secure_cookie)
        .ok_or_else(|| ApiError::unauthorized("authentication required"))?;
    let (session, user) = state
        .store
        .session(raw, state.session_idle_seconds)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::unauthorized("authentication required"))?;
    Ok((raw, session, user))
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use http::HeaderMap;

    use super::{
        CEREMONY_SECONDS, bootstrap_token_matches, joined_forwarded_for, require_passkey_session,
        require_recent_passkey,
    };
    use crate::store::{Session, now};

    /// A proxy may append a second header line rather than extending the first.
    ///
    /// Reading only the first would leave a client-supplied value in front, and
    /// `client_address` would then select from the caller's own list — letting the
    /// caller choose its rate-limit bucket, which is exactly what the trusted-hop
    /// setting exists to prevent. The rate_limit tests pass a pre-joined string and
    /// so cannot see this; only the header read can.
    #[test]
    fn every_forwarded_for_line_is_joined_in_order() {
        let mut headers = HeaderMap::new();
        assert_eq!(joined_forwarded_for(&headers), None);

        headers.append("x-forwarded-for", "9.9.9.9".parse().unwrap());
        assert_eq!(joined_forwarded_for(&headers).as_deref(), Some("9.9.9.9"));

        // The proxy's own line arrives as a separate header and must come last.
        headers.append("x-forwarded-for", "198.51.100.7".parse().unwrap());
        assert_eq!(
            joined_forwarded_for(&headers).as_deref(),
            Some("9.9.9.9,198.51.100.7")
        );
    }

    #[test]
    fn bootstrap_enrolment_rejects_every_token_but_the_configured_one() {
        let token = "bootstrap-token-longer-than-32-characters";
        assert!(bootstrap_token_matches(token, Some(token)));
        assert!(!bootstrap_token_matches(token, None));
        assert!(!bootstrap_token_matches(token, Some("")));
        // A prefix must not be accepted: the digest comparison is over the whole
        // value, so no amount of correct leading bytes gets an attacker closer.
        assert!(!bootstrap_token_matches(
            token,
            Some(&token[..token.len() - 1])
        ));
        assert!(!bootstrap_token_matches(
            token,
            Some(&format!("{token}trailing"))
        ));
        assert!(!bootstrap_token_matches(
            token,
            Some("BOOTSTRAP-TOKEN-LONGER-THAN-32-CHARACTERS")
        ));
    }

    #[test]
    fn sensitive_account_changes_require_a_recent_passkey_session() {
        let current = now();
        let session = |auth_method: &str, created_at: u64| Session {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            auth_method: auth_method.into(),
            current_credential_id: None,
            session_version: 1,
            created_at,
            last_seen_at: current,
            absolute_expires_at: current + 3_600,
        };
        assert!(require_recent_passkey(&session("passkey", current)).is_ok());
        assert!(require_passkey_session(&session("passkey", current)).is_ok());
        assert!(require_recent_passkey(&session("agent", current)).is_err());
        assert!(require_passkey_session(&session("agent", current)).is_err());
        assert!(require_passkey_session(&session("passkey", current - 301)).is_ok());
        assert!(require_recent_passkey(&session("passkey", current + 1)).is_err());
        assert!(
            require_recent_passkey(&session(
                "passkey",
                current.saturating_sub(CEREMONY_SECONDS + 1),
            ))
            .is_err()
        );
    }
}
