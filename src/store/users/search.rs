//! Operator account search: direct index lookups, bounded namespace scans and
//! resumable page cursors.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use uuid::Uuid;

use crate::store::{MAX_SEARCH_CANDIDATES, MAX_SNAPSHOT_KEYS, Store};

use super::{IdentifierValue, User};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserSearch {
    pub user_id: Option<Uuid>,
    pub identifier: Option<IdentifierValue>,
    pub passkey_credential_id: Option<String>,
    pub passkey_label: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct UserSearchPage {
    pub users: Vec<User>,
    pub next_after: Option<Uuid>,
}

impl UserSearch {
    pub fn is_empty(&self) -> bool {
        self.user_id.is_none()
            && self.identifier.is_none()
            && self.passkey_credential_id.is_none()
            && self.passkey_label.is_none()
            && self.given_name.is_none()
            && self.family_name.is_none()
            && self.display_name.is_none()
    }

    fn matches(&self, user: &User) -> bool {
        self.user_id.is_none_or(|value| user.id == value)
            && self.identifier.as_ref().is_none_or(|value| {
                user.identifiers
                    .iter()
                    .any(|stored| stored.kind == value.kind && stored.value == value.value)
            })
            && self
                .passkey_credential_id
                .as_ref()
                .is_none_or(|value| user.passkeys.iter().any(|stored| stored.id == *value))
            && self
                .passkey_label
                .as_ref()
                .is_none_or(|value| user.passkeys.iter().any(|stored| stored.label == *value))
            && self
                .given_name
                .as_ref()
                .is_none_or(|value| user.profile.given_name.as_ref() == Some(value))
            && self
                .family_name
                .as_ref()
                .is_none_or(|value| user.profile.family_name.as_ref() == Some(value))
            && self
                .display_name
                .as_ref()
                .is_none_or(|value| user.profile.display_name.as_ref() == Some(value))
    }
}

impl Store {
    pub async fn list_users(
        &self,
        after: Option<Uuid>,
        page_size: usize,
    ) -> Result<UserSearchPage> {
        if page_size == 0 || page_size > 100 {
            bail!("user list page size must be between 1 and 100");
        }
        let mut users = Vec::with_capacity(page_size.saturating_add(1));
        for id in self
            .candidate_ids(after, page_size.saturating_add(1))
            .await?
        {
            match self.user(id).await {
                Ok(Some(user)) => users.push(user),
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(user_id = %id, error = %error, "skipping unreadable account during listing");
                }
            }
        }
        let next_after = (users.len() > page_size).then(|| users[page_size - 1].id);
        users.truncate(page_size);
        Ok(UserSearchPage { users, next_after })
    }

    pub async fn search_users(
        &self,
        search: &UserSearch,
        after: Option<Uuid>,
        page_size: usize,
    ) -> Result<UserSearchPage> {
        if search.is_empty() {
            bail!("at least one user search criterion is required");
        }
        if page_size == 0 || page_size > 100 {
            bail!("user search page size must be between 1 and 100");
        }

        let direct_lookup = search.user_id.is_some()
            || search.identifier.is_some()
            || search.passkey_credential_id.is_some();
        let direct = if let Some(user_id) = search.user_id {
            self.user(user_id).await?
        } else if let Some(identifier) = &search.identifier {
            self.user_by_identifier(identifier).await?
        } else if let Some(credential_id) = &search.passkey_credential_id {
            self.user_by_credential_id(credential_id).await?
        } else {
            None
        };

        if direct_lookup {
            let users = direct
                .filter(|user| after.is_none_or(|cursor| user.id > cursor))
                .filter(|user| search.matches(user))
                .into_iter()
                .collect();
            return Ok(UserSearchPage {
                users,
                next_after: None,
            });
        }

        let mut users = Vec::with_capacity(page_size.saturating_add(1));
        let mut examined = 0_usize;
        let mut last_examined = None;
        for id in self.candidate_ids(after, MAX_SEARCH_CANDIDATES).await? {
            if examined == MAX_SEARCH_CANDIDATES {
                break;
            }
            examined += 1;
            last_examined = Some(id);
            // A record that is missing or will not validate is skipped, not
            // propagated. `user` fails closed on a corrupt record by design, so
            // propagating here would let a single unreadable account break every
            // operator search permanently, with no way to page past it.
            let user = match self.user(id).await {
                Ok(Some(user)) => user,
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(user_id = %id, error = %error, "skipping unreadable account during search");
                    continue;
                }
            };
            if search.matches(&user) {
                users.push(user);
                if users.len() > page_size {
                    break;
                }
            }
        }
        let next_after = search_page_cursor(
            &users,
            page_size,
            examined == MAX_SEARCH_CANDIDATES,
            last_examined,
        );
        users.truncate(page_size);
        Ok(UserSearchPage { users, next_after })
    }

    /// The next candidate ids after `after`, in ascending order, at most `limit`.
    ///
    /// SCAN returns keys in arbitrary order, so ordered paging needs the whole
    /// namespace considered — but not held. Only the smallest `limit` ids above
    /// the cursor are kept, and larger ones are dropped as they arrive, so memory
    /// is bounded by the page budget rather than by the number of accounts. On a
    /// million-account tenant the previous version materialised every id per
    /// request; this keeps a few thousand.
    ///
    /// The walk itself remains proportional to the namespace. That is inherent to
    /// a search no index can answer, and it is why the caller charges a budget:
    /// SCAN is cheap per key, the per-account reads it gates are not.
    async fn candidate_ids(&self, after: Option<Uuid>, limit: usize) -> Result<Vec<Uuid>> {
        let mut cursor = 0_u64;
        let mut ids: BTreeSet<Uuid> = BTreeSet::new();
        let mut scanned = 0_usize;
        loop {
            let mut connection = self.redis.clone();
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("auth:user:*")
                .arg("COUNT")
                .arg(500_u16)
                .query_async(&mut connection)
                .await
                .context("scan RustyAuth users")?;
            // Counting the keys actually returned, not the COUNT hint. SCAN treats
            // COUNT as advisory and commonly returns fewer, so assuming 500 per
            // iteration overcounts and trips the safety limit on a namespace far
            // smaller than a million — which would break search rather than
            // protect it.
            scanned = scanned.saturating_add(batch.len());
            let mut parsed = Vec::with_capacity(batch.len());
            for key in batch {
                let id = key
                    .strip_prefix("auth:user:")
                    .context("user scan returned an invalid key")?;
                parsed.push(Uuid::parse_str(id).context("stored user key has an invalid id")?);
            }
            ids = accumulate_candidates(ids.into_iter().chain(parsed), after, limit);
            if scanned > MAX_SNAPSHOT_KEYS {
                bail!("RustyAuth user namespace exceeds the one-million-key safety limit");
            }
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        Ok(ids.into_iter().collect())
    }
}

/// The `limit` smallest ids strictly greater than `after`, from an arbitrary
/// arrival order.
///
/// Factored out of the SCAN loop so the paging invariant can be tested without a
/// datastore: SCAN returns keys in arbitrary order, so this ordered, bounded
/// accumulation is what makes paging safe while keeping memory proportional to a
/// page rather than to the account namespace.
fn accumulate_candidates<I: IntoIterator<Item = Uuid>>(
    ids: I,
    after: Option<Uuid>,
    limit: usize,
) -> BTreeSet<Uuid> {
    let mut kept: BTreeSet<Uuid> = BTreeSet::new();
    for id in ids {
        if after.is_some_and(|cursor| id <= cursor) {
            continue;
        }
        kept.insert(id);
        if kept.len() > limit {
            let highest = *kept.iter().next_back().expect("just inserted");
            kept.remove(&highest);
        }
    }
    kept
}

/// Chooses the cursor a search page hands back.
///
/// A page that stopped on the scan budget has not reached the end of the
/// account namespace even when it is short, so it returns the last account it
/// examined. Without that the caller reads a short page as the end of the
/// results and never sees the accounts past the budget.
fn search_page_cursor(
    matched: &[User],
    page_size: usize,
    budget_spent: bool,
    last_examined: Option<Uuid>,
) -> Option<Uuid> {
    if matched.len() > page_size {
        return matched.get(page_size.saturating_sub(1)).map(|user| user.id);
    }
    if budget_spent {
        return last_examined;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{AccountIdentifier, AccountProfile, IdentifierKind};

    /// Paging must neither skip nor repeat an account.
    ///
    /// SCAN returns keys in arbitrary order and the accumulator keeps only a
    /// page's worth, so this is the invariant that makes those two facts safe
    /// together: walking the pages in order must reproduce every id exactly once,
    /// in ascending order, whatever order the scan produced them in.
    #[test]
    fn paging_covers_every_account_exactly_once() {
        let mut all: Vec<Uuid> = (0..50).map(|_| Uuid::new_v4()).collect();
        // An arrival order deliberately unrelated to sort order.
        all.sort_by_key(|id| std::cmp::Reverse(id.as_u128()));
        let arrival = all.clone();

        let mut sorted = all.clone();
        sorted.sort();

        let page = 7_usize;
        let mut seen: Vec<Uuid> = Vec::new();
        let mut after: Option<Uuid> = None;
        for _ in 0..(sorted.len() / page + 2) {
            let batch: Vec<Uuid> = accumulate_candidates(arrival.iter().copied(), after, page)
                .into_iter()
                .collect();
            if batch.is_empty() {
                break;
            }
            assert!(
                batch.windows(2).all(|pair| pair[0] < pair[1]),
                "a page must be ascending"
            );
            after = batch.last().copied();
            seen.extend(batch);
        }
        assert_eq!(seen, sorted, "paging must reproduce every id exactly once");
    }

    #[test]
    fn the_accumulator_keeps_the_smallest_ids_above_the_cursor() {
        let ids: Vec<Uuid> = (0..20).map(|_| Uuid::new_v4()).collect();
        let mut sorted = ids.clone();
        sorted.sort();

        let kept: Vec<Uuid> = accumulate_candidates(ids.iter().copied(), None, 5)
            .into_iter()
            .collect();
        assert_eq!(kept, sorted[..5], "must keep the five smallest");

        // Everything at or below the cursor is excluded, never merely reordered.
        let cursor = sorted[9];
        let after: Vec<Uuid> = accumulate_candidates(ids.iter().copied(), Some(cursor), 5)
            .into_iter()
            .collect();
        assert_eq!(after, sorted[10..15]);

        // A limit of zero yields nothing rather than panicking on the eviction.
        assert!(accumulate_candidates(ids.iter().copied(), None, 0).is_empty());
    }

    fn account(id: Uuid, session_version: u64) -> User {
        User {
            id,
            email: "person@example.com".into(),
            email_verified: true,
            profile: AccountProfile::default(),
            identifiers: vec![AccountIdentifier {
                kind: IdentifierKind::Email,
                value: "person@example.com".into(),
                verified: true,
                verified_at: Some(100),
                primary: true,
                created_at: 100,
            }],
            session_version,
            recovery_codes: Vec::new(),
            created_at: 100,
            passkeys: Vec::new(),
        }
    }

    #[test]
    fn a_full_search_page_resumes_after_its_last_returned_account() {
        let matched = [
            account(Uuid::from_u128(1), 1),
            account(Uuid::from_u128(2), 1),
            account(Uuid::from_u128(3), 1),
        ];
        assert_eq!(
            search_page_cursor(&matched, 2, false, Some(Uuid::from_u128(9))),
            Some(Uuid::from_u128(2))
        );
        assert_eq!(
            search_page_cursor(&matched[..2], 2, false, Some(Uuid::from_u128(9))),
            None
        );
    }

    #[test]
    fn a_search_stopped_by_the_scan_budget_resumes_instead_of_reporting_the_end() {
        let last = Uuid::from_u128(7);
        assert_eq!(search_page_cursor(&[], 25, true, Some(last)), Some(last));
        assert_eq!(
            search_page_cursor(&[account(Uuid::from_u128(1), 1)], 25, true, Some(last)),
            Some(last)
        );
        assert_eq!(search_page_cursor(&[], 25, false, Some(last)), None);
    }
}
