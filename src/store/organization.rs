//! The single organization record and its operator roles.

use anyhow::{Context, Result};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    OPERATOR_PREFIX, OPERATOR_SEEN_PREFIX, ORGANIZATION_KEY, Store, StorePolicyError, User,
    events::queue_events, now,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRoleRecord {
    Owner,
    Administrator,
    Support,
    Auditor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationRecord {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorRecord {
    pub user_id: Uuid,
    pub role: OperatorRoleRecord,
    pub created_at: u64,
    /// When the grant was withdrawn, if it was.
    ///
    /// Revocation is a tombstone rather than a deletion because the browser
    /// bootstrap path re-creates a missing record as Owner for any account
    /// holding a verified allowlisted address. Deleting would therefore promote
    /// the operator being removed. Defaulted so records written before this field
    /// existed load as live grants.
    #[serde(default)]
    pub revoked_at: Option<u64>,
}

/// What `ensure_operator` should do with the record it found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GrantDecision {
    /// A live grant exists; use it.
    Honour,
    /// Not an operator, and must not become one on this request.
    Deny,
    /// No record at all, and the account is allowlisted: create the first grant.
    Bootstrap,
}

/// Decides whether an account is an operator on this request.
///
/// The revoked case is the one that matters. Bootstrap re-creates a MISSING
/// record as Owner for any account holding a verified allowlisted address, so if
/// revocation deleted the record instead of marking it, the removed operator's
/// very next request would recreate the grant — at Owner, which is usually more
/// privilege than they held before. A tombstone must therefore deny without
/// falling through to bootstrap.
fn grant_decision(stored: Option<&OperatorRecord>, bootstrap_allowed: bool) -> GrantDecision {
    match stored {
        Some(record) if record.revoked_at.is_none() => GrantDecision::Honour,
        Some(_) => GrantDecision::Deny,
        None if bootstrap_allowed => GrantDecision::Bootstrap,
        None => GrantDecision::Deny,
    }
}

/// One row of the operator listing.
///
/// Revoked grants are included so an access review can see that a withdrawal
/// happened, rather than a removed operator simply vanishing from the record.
#[derive(Clone, Debug)]
pub struct OperatorListing {
    pub operator: OperatorRecord,
    pub user: User,
    pub last_authenticated_at: Option<u64>,
}

impl Store {
    pub async fn ensure_organization(&self, default_name: &str) -> Result<OrganizationRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        if let Some(organization) = self.get_json(ORGANIZATION_KEY).await? {
            return Ok(organization);
        }
        let organization = OrganizationRecord {
            id: Uuid::new_v4(),
            slug: self.tenant_id.clone(),
            name: default_name.to_owned(),
            created_at: now(),
        };
        let mut connection = self.redis.clone();
        let inserted: bool = connection
            .set_nx(ORGANIZATION_KEY, serde_json::to_string(&organization)?)
            .await?;
        if inserted {
            self.append_event_within_snapshot("organization.created", None)
                .await?;
            Ok(organization)
        } else {
            self.get_json(ORGANIZATION_KEY)
                .await?
                .context("organization disappeared during initialization")
        }
    }

    pub async fn organization(&self) -> Result<Option<OrganizationRecord>> {
        self.get_json(ORGANIZATION_KEY).await
    }

    pub async fn update_organization(&self, name: String) -> Result<OrganizationRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut organization = self
            .get_json::<OrganizationRecord>(ORGANIZATION_KEY)
            .await?
            .ok_or(StorePolicyError::OrganizationMissing)?;
        organization.name = name;
        let events = self
            .pending_events(vec![("organization.updated".to_owned(), None)])
            .await?;
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(ORGANIZATION_KEY, serde_json::to_string(&organization)?);
        queue_events(&mut pipeline, &events)?;
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("update organization")?;
        Ok(organization)
    }

    pub async fn operator(&self, user_id: Uuid) -> Result<Option<OperatorRecord>> {
        self.get_json(&format!("{OPERATOR_PREFIX}{user_id}")).await
    }

    pub async fn ensure_operator(
        &self,
        user: &User,
        bootstrap_allowed: bool,
    ) -> Result<Option<OperatorRecord>> {
        // Every durable write belongs inside the snapshot gate, or a backup taken
        // concurrently captures the operator record without its creation event.
        let _snapshot = self.snapshot_gate.read().await;
        let key = format!("{OPERATOR_PREFIX}{}", user.id);
        let stored = self.get_json::<OperatorRecord>(&key).await?;
        match grant_decision(stored.as_ref(), bootstrap_allowed) {
            GrantDecision::Honour => {
                self.record_operator_seen(user.id).await;
                return Ok(stored);
            }
            GrantDecision::Deny => return Ok(None),
            GrantDecision::Bootstrap => {}
        }
        let _guard = self.mutation.lock().await;
        let operator = OperatorRecord {
            user_id: user.id,
            role: OperatorRoleRecord::Owner,
            created_at: now(),
            revoked_at: None,
        };
        let mut connection = self.redis.clone();
        let inserted: bool = connection
            .set_nx(&key, serde_json::to_string(&operator)?)
            .await?;
        if inserted {
            self.append_event_locked("operator.created", Some(user.id))
                .await?;
            Ok(Some(operator))
        } else {
            self.get_json(&key).await
        }
    }

    /// Records that an operator authenticated, without touching their grant.
    ///
    /// Kept in its own key because the authorization path runs on every operator
    /// request and the CLI runs in a different process. A read-modify-write of the
    /// grant record here would race a concurrent demotion and restore the role it
    /// removed, and the mutation mutex cannot prevent that because the two
    /// processes do not share it. Failure is logged rather than propagated: a
    /// missing last-seen timestamp must never deny an authorized operator.
    async fn record_operator_seen(&self, user_id: Uuid) {
        let mut connection = self.redis.clone();
        let result: redis::RedisResult<()> = connection
            .set(
                format!("{OPERATOR_SEEN_PREFIX}{user_id}"),
                now().to_string(),
            )
            .await;
        if let Err(error) = result {
            tracing::warn!(user_id = %user_id, error = %error, "record operator last-seen");
        }
    }

    async fn operator_seen_at(&self, user_id: Uuid) -> Option<u64> {
        self.get::<String>(&format!("{OPERATOR_SEEN_PREFIX}{user_id}"))
            .await
            .ok()
            .flatten()
            .and_then(|value| value.parse().ok())
    }

    /// Grants an operator role out of band, from the host rather than the browser.
    ///
    /// This is the supported way to create the first Owner. Browser bootstrap
    /// requires an already-verified operator address, which nothing can set until
    /// an operator exists; breaking that cycle deliberately costs host access.
    /// Grants an operator role to a named account.
    ///
    /// Takes a user id rather than an address on purpose. Resolving an address
    /// would grant the role to whichever account currently holds it, and any
    /// enrolled user can attach an unclaimed address to themselves through the
    /// self-service API — so an attacker who claims the allowlisted address first
    /// receives Owner the moment an administrator runs the promotion they were
    /// always going to run.
    pub async fn promote_operator(
        &self,
        user_id: Uuid,
        role: OperatorRoleRecord,
    ) -> Result<(OperatorRecord, User)> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let user = self
            .user(user_id)
            .await?
            .ok_or(StorePolicyError::UserMissing)?;
        let key = format!("{OPERATOR_PREFIX}{}", user.id);
        let existing = self.get_json::<OperatorRecord>(&key).await?;
        let operator = OperatorRecord {
            user_id: user.id,
            role,
            created_at: existing.map_or_else(now, |record| record.created_at),
            // An explicit promotion is a deliberate re-grant, so it clears a
            // previous revocation.
            revoked_at: None,
        };
        let mut connection = self.redis.clone();
        let _: () = connection
            .set(&key, serde_json::to_string(&operator)?)
            .await
            .context("persist promoted operator")?;
        self.append_event_locked("operator.promoted", Some(user.id))
            .await?;
        Ok((operator, user))
    }

    /// Removes an operator record entirely.
    ///
    /// Taking an address off AUTH_OPERATOR_EMAILS does not revoke anything —
    /// `ensure_operator` returns a stored record before it consults the allowlist —
    /// so without this a grant could never be withdrawn from the product at all.
    pub async fn demote_operator(&self, user_id: Uuid) -> Result<bool> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let key = format!("{OPERATOR_PREFIX}{user_id}");
        let Some(mut operator) = self.get_json::<OperatorRecord>(&key).await? else {
            return Ok(false);
        };
        if operator.revoked_at.is_some() {
            return Ok(false);
        }
        // Marked, not deleted. Deleting would let the browser bootstrap path
        // re-create the grant as Owner on this account's very next request,
        // turning the offboarding command into a promotion.
        operator.revoked_at = Some(now());
        let mut connection = self.redis.clone();
        let _: () = connection
            .set(&key, serde_json::to_string(&operator)?)
            .await
            .context("revoke operator")?;
        self.append_event_locked("operator.demoted", Some(user_id))
            .await?;
        Ok(true)
    }

    pub async fn operators(&self) -> Result<Vec<OperatorListing>> {
        let mut operators = Vec::new();
        for user_id in self
            .record_ids(OPERATOR_PREFIX, "scan RustyAuth operators")
            .await?
        {
            let operator = self
                .operator(user_id)
                .await?
                .context("operator disappeared during listing")?;
            let user = self
                .user(user_id)
                .await?
                .context("operator points to an unknown user")?;
            let last_authenticated_at = self.operator_seen_at(user_id).await;
            operators.push(OperatorListing {
                operator,
                user,
                last_authenticated_at,
            });
        }
        Ok(operators)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(role: OperatorRoleRecord, revoked_at: Option<u64>) -> OperatorRecord {
        OperatorRecord {
            user_id: Uuid::new_v4(),
            role,
            created_at: 1_000,
            revoked_at,
        }
    }

    /// Revocation must survive the bootstrap path, or offboarding promotes.
    ///
    /// `ensure_operator` re-creates a MISSING record as Owner for any account
    /// holding a verified allowlisted address. If demotion deleted the record, the
    /// removed operator's very next request would recreate it — at Owner, which is
    /// strictly more privilege than most of them held. This is the assertion that
    /// makes `operator demote` a revocation rather than a promotion.
    #[test]
    fn a_revoked_grant_denies_and_never_falls_through_to_bootstrap() {
        let revoked = grant(OperatorRoleRecord::Support, Some(2_000));
        // Allowlisted is the dangerous case: it is the only one that can bootstrap.
        assert_eq!(grant_decision(Some(&revoked), true), GrantDecision::Deny);
        assert_eq!(grant_decision(Some(&revoked), false), GrantDecision::Deny);
    }

    #[test]
    fn a_live_grant_is_honoured_and_an_absent_one_bootstraps_only_when_allowed() {
        let live = grant(OperatorRoleRecord::Support, None);
        assert_eq!(grant_decision(Some(&live), false), GrantDecision::Honour);
        assert_eq!(grant_decision(Some(&live), true), GrantDecision::Honour);

        assert_eq!(grant_decision(None, true), GrantDecision::Bootstrap);
        assert_eq!(grant_decision(None, false), GrantDecision::Deny);
    }

    /// Records written before the field existed must load as live grants, not as
    /// revoked ones — the alternative locks every existing operator out on upgrade.
    #[test]
    fn a_record_without_the_field_loads_as_a_live_grant() {
        let legacy = serde_json::json!({
            "userId": Uuid::new_v4(),
            "role": "owner",
            "createdAt": 1_000,
            "lastAuthenticatedAt": 1_500,
        });
        let decoded: OperatorRecord =
            serde_json::from_value(legacy).expect("a pre-upgrade record still decodes");
        assert_eq!(decoded.revoked_at, None);
        assert_eq!(decoded.role, OperatorRoleRecord::Owner);
    }
}
