//! Fixed-window request throttling for unauthenticated and credential-bearing routes.
//!
//! RustyAuth has no external WAF in front of it, so brute-force and flood
//! resistance has to live in the process. Two independent dimensions are limited:
//! the client address, and the identifier or credential being attempted. Limiting
//! only by address lets a botnet spread an attack across many hosts; limiting only
//! by identifier lets one host enumerate many accounts. Both are cheap.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

/// A request class, each with its own budget.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RateLimitClass {
    /// Starting or finishing a WebAuthn ceremony.
    Ceremony,
    /// Anything that names an account before proving anything about it.
    IdentifierProbe,
    /// The unauthenticated service-account token exchange.
    CredentialExchange,
}

impl RateLimitClass {
    /// Requests permitted per window. Deliberately generous enough that a human
    /// retrying a failed passkey tap is never throttled, and tight enough that
    /// automated enumeration is not free.
    const fn budget(self) -> u32 {
        match self {
            Self::Ceremony => 30,
            Self::IdentifierProbe => 10,
            Self::CredentialExchange => 60,
        }
    }

    const fn window(self) -> Duration {
        Duration::from_secs(60)
    }
}

/// The outcome of a limit check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RateLimitDecision {
    pub(crate) allowed: bool,
    /// Seconds until the window resets, for a `Retry-After` header.
    pub(crate) retry_after_seconds: u64,
}

struct Window {
    count: u32,
    started_at: Instant,
}

/// Fixed-window counters over a bounded map.
///
/// A fixed window admits up to twice the budget across a window boundary. That is
/// accepted: the goal is to make enumeration expensive, not to meter precisely,
/// and a fixed window costs one integer per key instead of a timestamp list.
pub struct RateLimiter {
    windows: Mutex<HashMap<(RateLimitClass, [u8; 16]), Window>>,
    capacity: usize,
}

impl RateLimiter {
    /// `capacity` bounds the tracking map so that a flood of distinct keys cannot
    /// grow it without limit — the map is itself an attack surface.
    pub fn new(capacity: usize) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Records one request against `subject` and reports whether it may proceed.
    ///
    /// Subjects are stored as truncated digests rather than raw values so the
    /// limiter never holds email addresses or credential secrets in memory.
    pub(crate) fn check(&self, class: RateLimitClass, subject: &str) -> RateLimitDecision {
        self.check_at(class, subject, Instant::now())
    }

    fn check_at(&self, class: RateLimitClass, subject: &str, now: Instant) -> RateLimitDecision {
        let key = (class, subject_key(class, subject));
        let window = class.window();
        let Ok(mut windows) = self.windows.lock() else {
            // A poisoned lock means another thread panicked while holding it. Fail
            // closed: an unmetered auth surface is worse than a rejected request.
            return RateLimitDecision {
                allowed: false,
                retry_after_seconds: window.as_secs(),
            };
        };

        if windows.len() >= self.capacity && !windows.contains_key(&key) {
            windows.retain(|_, entry| now.duration_since(entry.started_at) < window);
            if windows.len() >= self.capacity {
                return RateLimitDecision {
                    allowed: false,
                    retry_after_seconds: window.as_secs(),
                };
            }
        }

        let entry = windows.entry(key).or_insert(Window {
            count: 0,
            started_at: now,
        });
        let elapsed = now.duration_since(entry.started_at);
        if elapsed >= window {
            entry.count = 0;
            entry.started_at = now;
        }
        entry.count = entry.count.saturating_add(1);
        let allowed = entry.count <= class.budget();
        RateLimitDecision {
            allowed,
            retry_after_seconds: window
                .saturating_sub(now.duration_since(entry.started_at))
                .as_secs()
                + 1,
        }
    }
}

fn subject_key(class: RateLimitClass, subject: &str) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(format!("{class:?}").as_bytes());
    hasher.update([0]);
    hasher.update(subject.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0_u8; 16];
    key.copy_from_slice(&digest[..16]);
    key
}

/// Resolves the client address from the peer address and `X-Forwarded-For`.
///
/// `trusted_hops` is how many reverse proxies sit in front of this service. At the
/// default of zero the header is ignored entirely, because a client can send any
/// value it likes and would otherwise choose its own rate-limit bucket. With one
/// or more trusted hops, the address is taken that many entries from the right —
/// the rightmost entries are the ones appended by infrastructure we control.
pub(crate) fn client_address(
    peer: IpAddr,
    forwarded_for: Option<&str>,
    trusted_hops: usize,
) -> IpAddr {
    if trusted_hops == 0 {
        return peer;
    }
    let Some(header) = forwarded_for else {
        return peer;
    };
    header
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .iter()
        .rev()
        .nth(trusted_hops - 1)
        .and_then(|value| value.parse::<IpAddr>().ok())
        .unwrap_or(peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn address(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn requests_are_allowed_up_to_the_budget_then_refused() {
        let limiter = RateLimiter::new(1_024);
        let budget = RateLimitClass::IdentifierProbe.budget();
        for attempt in 1..=budget {
            assert!(
                limiter
                    .check(RateLimitClass::IdentifierProbe, "10.0.0.1")
                    .allowed,
                "attempt {attempt} within budget must be allowed"
            );
        }
        let refused = limiter.check(RateLimitClass::IdentifierProbe, "10.0.0.1");
        assert!(!refused.allowed);
        assert!(refused.retry_after_seconds > 0);
    }

    #[test]
    fn budgets_are_tracked_per_subject_and_per_class() {
        let limiter = RateLimiter::new(1_024);
        for _ in 0..RateLimitClass::IdentifierProbe.budget() {
            limiter.check(RateLimitClass::IdentifierProbe, "attacker");
        }
        assert!(
            !limiter
                .check(RateLimitClass::IdentifierProbe, "attacker")
                .allowed
        );
        // A different subject must not inherit the exhausted budget.
        assert!(
            limiter
                .check(RateLimitClass::IdentifierProbe, "bystander")
                .allowed
        );
        // Nor must a different class for the same subject.
        assert!(limiter.check(RateLimitClass::Ceremony, "attacker").allowed);
    }

    #[test]
    fn the_window_resets_once_it_elapses() {
        let limiter = RateLimiter::new(1_024);
        let start = Instant::now();
        for _ in 0..RateLimitClass::IdentifierProbe.budget() {
            limiter.check_at(RateLimitClass::IdentifierProbe, "subject", start);
        }
        assert!(
            !limiter
                .check_at(RateLimitClass::IdentifierProbe, "subject", start)
                .allowed
        );
        let next_window = start + RateLimitClass::IdentifierProbe.window() + Duration::from_secs(1);
        assert!(
            limiter
                .check_at(RateLimitClass::IdentifierProbe, "subject", next_window)
                .allowed,
            "a fresh window must admit requests again"
        );
    }

    #[test]
    fn the_tracking_map_cannot_grow_without_bound() {
        let limiter = RateLimiter::new(8);
        let start = Instant::now();
        for index in 0..64 {
            limiter.check_at(RateLimitClass::Ceremony, &format!("subject-{index}"), start);
        }
        assert!(
            limiter.windows.lock().unwrap().len() <= 8,
            "a flood of distinct subjects must not grow the map past its capacity"
        );
    }

    #[test]
    fn forwarded_for_is_ignored_unless_a_proxy_is_configured() {
        let peer = address(1);
        // Untrusted by default: a client that sends the header must not be able to
        // pick its own bucket, or the limit is trivially bypassed.
        assert_eq!(client_address(peer, Some("203.0.113.9"), 0), peer);
        assert_eq!(client_address(peer, None, 0), peer);
    }

    #[test]
    fn one_trusted_hop_takes_the_rightmost_forwarded_address() {
        let peer = address(1);
        let expected: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(
            client_address(peer, Some("198.51.100.7, 203.0.113.9"), 1),
            expected
        );
        // A client prepending forged entries cannot shift which entry is selected.
        assert_eq!(
            client_address(peer, Some("1.1.1.1, 2.2.2.2, 198.51.100.7, 203.0.113.9"), 1),
            expected
        );
    }

    #[test]
    fn a_client_cannot_choose_its_bucket_by_prepending_its_own_header() {
        // The caller sends `X-Forwarded-For: 9.9.9.9`; the proxy appends a second
        // header line rather than extending the first. Joining every line puts the
        // proxy's entry last, so the rightmost-of-one-hop selection still lands on
        // the address the proxy observed, not the one the client claimed.
        let peer = address(1);
        let joined = "9.9.9.9,198.51.100.7";
        assert_eq!(
            client_address(peer, Some(joined), 1),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_malformed_or_short_forwarded_header_falls_back_to_the_peer() {
        let peer = address(1);
        assert_eq!(client_address(peer, Some("not-an-address"), 1), peer);
        assert_eq!(client_address(peer, Some(""), 1), peer);
        // Fewer entries than trusted hops means the chain is not what we expect.
        assert_eq!(client_address(peer, Some("203.0.113.9"), 3), peer);
    }
}
