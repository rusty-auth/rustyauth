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
        for id in self.user_ids().await? {
            if after.is_some_and(|cursor| id <= cursor) {
                continue;
            }
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

    async fn user_ids(&self) -> Result<Vec<Uuid>> {
        let mut cursor = 0_u64;
        let mut ids = BTreeSet::new();
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
            for key in batch {
                let id = key
                    .strip_prefix("auth:user:")
                    .context("user scan returned an invalid key")?;
                ids.insert(Uuid::parse_str(id).context("stored user key has an invalid id")?);
            }
            if ids.len() > MAX_SNAPSHOT_KEYS {
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
