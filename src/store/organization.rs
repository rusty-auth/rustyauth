//! The single organization record and its operator roles.

use anyhow::{Context, Result};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    OPERATOR_PREFIX, ORGANIZATION_KEY, Store, StorePolicyError, User, events::queue_events, now,
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
    pub last_authenticated_at: u64,
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
        if let Some(operator) = self.get_json::<OperatorRecord>(&key).await? {
            if operator.last_authenticated_at.saturating_add(60) <= now() {
                // Re-read under the lock and write back only the timestamp. Writing
                // the record read before the lock would carry a stale `role` with
                // it, so a sign-in racing a demotion silently restores the role the
                // operator just lost.
                let _guard = self.mutation.lock().await;
                if let Some(mut current) = self.get_json::<OperatorRecord>(&key).await? {
                    current.last_authenticated_at = now();
                    let mut connection = self.redis.clone();
                    let _: () = connection
                        .set(&key, serde_json::to_string(&current)?)
                        .await?;
                    return Ok(Some(current));
                }
                // Demoted between the two reads; the grant is gone.
                return Ok(None);
            }
            return Ok(Some(operator));
        }
        if !bootstrap_allowed {
            return Ok(None);
        }
        let _guard = self.mutation.lock().await;
        let operator = OperatorRecord {
            user_id: user.id,
            role: OperatorRoleRecord::Owner,
            created_at: now(),
            last_authenticated_at: now(),
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
            last_authenticated_at: now(),
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
        if self.get_json::<OperatorRecord>(&key).await?.is_none() {
            return Ok(false);
        }
        let mut connection = self.redis.clone();
        let _: () = connection.del(&key).await.context("remove operator")?;
        self.append_event_locked("operator.demoted", Some(user_id))
            .await?;
        Ok(true)
    }

    pub async fn operators(&self) -> Result<Vec<(OperatorRecord, User)>> {
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
            operators.push((operator, user));
        }
        Ok(operators)
    }
}
