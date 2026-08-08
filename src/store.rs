//! SableDB persistence boundary.
//!
//! All durable key construction and serialization is centralized here. Public
//! HTTP handlers do not issue database commands directly. Compound mutations
//! use atomic pipelines and are serialized within the single supported writer.

mod ceremonies;
mod credentials;
mod events;
mod organization;
mod service_accounts;
mod sessions;
mod snapshot;
mod users;

pub use self::ceremonies::{
    AuthenticationCeremony, LocalAgentHandoff, RegistrationCeremony, RegistrationPurpose,
};
pub use self::credentials::StoredPasskey;
pub use self::events::{AuthEvent, EventLogIntegrityError};
pub use self::organization::{OperatorRecord, OperatorRoleRecord, OrganizationRecord};
pub(crate) use self::service_accounts::ServiceCredentialLocator;
pub use self::service_accounts::{
    ServiceAccountCredentialRecord, ServiceAccountGrant, ServiceAccountRecord,
    ServiceAccountStatusRecord,
};
pub use self::sessions::{Session, SessionOrigin};
pub use self::snapshot::StoreRecord;
pub(crate) use self::users::forbidden_display_character;
pub use self::users::{
    AccountIdentifier, AccountProfile, IdentifierKind, IdentifierValidationError, IdentifierValue,
    ProfileValidationError, User, UserSearch, UserSearchPage,
};

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::AsyncCommands;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use self::events::queue_events;

#[derive(Debug, thiserror::Error)]
pub(crate) enum StorePolicyError {
    #[error("identifier already has an account")]
    IdentifierAlreadyExists,
    #[error("account has reached the identifier limit")]
    IdentifierLimit,
    #[error("identifier is not linked to this user")]
    IdentifierNotLinked,
    #[error("the final identifier cannot be removed")]
    FinalIdentifier,
    #[error("passkey is already registered")]
    CredentialAlreadyExists,
    #[error("user is missing")]
    UserMissing,
    #[error("passkey is not linked to this user")]
    CredentialNotLinked,
    #[error("the final passkey cannot be removed")]
    FinalCredential,
    #[error("organization is missing")]
    OrganizationMissing,
    #[error("service account is missing")]
    ServiceAccountMissing,
    #[error("service account credential is missing")]
    ServiceCredentialMissing,
    #[error("service account credential is invalid")]
    InvalidServiceCredential,
    #[error("requested scopes exceed the service account grant")]
    ServiceScopeDenied,
}

const RESTORE_SENTINEL: &str = "auth:restore:in-progress";
const BACKUP_LEASE_KEY: &str = "auth:backup:lease";
const ORGANIZATION_KEY: &str = "auth:organization";
const OPERATOR_PREFIX: &str = "auth:operator:";
const SERVICE_ACCOUNT_PREFIX: &str = "auth:service-account:";
const SERVICE_CREDENTIAL_PREFIX: &str = "auth:service-credential:";
const MAX_SNAPSHOT_KEYS: usize = 1_000_000;
const MAX_SNAPSHOT_VALUE_BYTES: usize = 8 * 1024 * 1024;
const MAX_IDENTIFIERS: usize = 20;
// A search that no index can answer reads one account record per candidate, so
// without a ceiling a single request walks the entire account namespace and one
// operator session can saturate the database. A page that stops here is not the
// end of the results: it returns the last account it examined as its cursor, so
// the caller pages on instead of losing everything past the budget.
const MAX_SEARCH_CANDIDATES: usize = 2_000;

#[derive(Clone)]
pub struct Store {
    redis: redis::aio::ConnectionManager,
    mutation: Arc<Mutex<()>>,
    snapshot_gate: SnapshotGate,
    tenant_id: String,
}

pub type SnapshotGate = Arc<RwLock<()>>;

impl Store {
    pub fn new(redis: redis::aio::ConnectionManager, tenant_id: String) -> Self {
        Self {
            redis,
            mutation: Arc::new(Mutex::new(())),
            snapshot_gate: Arc::new(RwLock::new(())),
            tenant_id,
        }
    }

    pub fn connection(&self) -> redis::aio::ConnectionManager {
        self.redis.clone()
    }

    pub fn snapshot_gate(&self) -> SnapshotGate {
        self.snapshot_gate.clone()
    }

    async fn record_ids(&self, prefix: &str, context: &'static str) -> Result<Vec<Uuid>> {
        let mut cursor = 0_u64;
        let mut ids = BTreeSet::new();
        loop {
            let mut connection = self.redis.clone();
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{prefix}*"))
                .arg("COUNT")
                .arg(500_u16)
                .query_async(&mut connection)
                .await
                .context(context)?;
            for key in batch {
                let id = key
                    .strip_prefix(prefix)
                    .context("record scan returned an invalid key")?;
                ids.insert(Uuid::parse_str(id).context("stored record key has an invalid id")?);
            }
            if ids.len() > MAX_SNAPSHOT_KEYS {
                bail!("RustyAuth record family exceeds the one-million-key safety limit");
            }
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        Ok(ids.into_iter().collect())
    }

    async fn get<T: redis::FromRedisValue>(&self, key: &str) -> Result<Option<T>> {
        let mut connection = self.redis.clone();
        connection.get(key).await.context("read SableDB value")
    }

    async fn get_json<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let Some(value) = self.get::<String>(key).await? else {
            return Ok(None);
        };
        Ok(Some(
            serde_json::from_str(&value).context("decode stored JSON")?,
        ))
    }

    async fn take_json<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let mut connection = self.redis.clone();
        let value: Option<String> = redis::cmd("GETDEL")
            .arg(key)
            .query_async(&mut connection)
            .await?;
        value
            .map(|value| serde_json::from_str(&value).context("decode one-time stored JSON"))
            .transpose()
    }

    async fn persist_user(&self, user: &User, context: &'static str) -> Result<()> {
        let mut connection = self.redis.clone();
        let _: () = redis::pipe()
            .atomic()
            .set(
                format!("auth:user:{}", user.id),
                serde_json::to_string(user)?,
            )
            .query_async(&mut connection)
            .await
            .context(context)?;
        Ok(())
    }

    async fn persist_user_with_event(
        &self,
        user: &User,
        event_type: &str,
        context: &'static str,
    ) -> Result<()> {
        let events = self
            .pending_events(vec![(event_type.to_owned(), Some(user.id))])
            .await?;
        let mut pipeline = redis::pipe();
        pipeline.atomic().set(
            format!("auth:user:{}", user.id),
            serde_json::to_string(user)?,
        );
        queue_events(&mut pipeline, &events)?;
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context(context)?;
        Ok(())
    }

    async fn set_json_ex<T: Serialize>(&self, key: &str, value: &T, seconds: u64) -> Result<()> {
        let mut connection = self.redis.clone();
        let _: () = connection
            .set_ex(key, serde_json::to_string(value)?, seconds)
            .await?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut connection = self.redis.clone();
        let _: usize = connection.del(key).await?;
        Ok(())
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

fn require_canonical_identifier(identifier: &IdentifierValue) -> Result<()> {
    let canonical = IdentifierValue::canonical(identifier.kind, &identifier.value)?;
    if canonical != *identifier {
        bail!("account identifier is not canonical");
    }
    Ok(())
}

fn credential_id(passkey: &Passkey) -> String {
    URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref())
}

fn identifier_key(identifier: &IdentifierValue) -> String {
    format!(
        "auth:identifier:{}:{}",
        identifier.kind.as_str(),
        identifier.value
    )
}

fn session_key(token: &str) -> String {
    format!("auth:session:{:x}", Sha256::digest(token.as_bytes()))
}

fn service_credential_key(secret: &str) -> String {
    format!(
        "{SERVICE_CREDENTIAL_PREFIX}{:x}",
        Sha256::digest(secret.as_bytes())
    )
}

fn handoff_key(code: &str) -> String {
    format!("auth:agent-handoff:{:x}", Sha256::digest(code.as_bytes()))
}

/// Store behaviour that only a real SableDB can answer.
///
/// These are ignored by default and run against the `compose.integration.yaml`
/// source service, the same way `integration_tests` does.
#[cfg(test)]
mod live_store_tests {
    use std::env;

    use super::*;

    #[tokio::test]
    #[ignore = "requires the compose.integration.yaml SableDB service"]
    async fn a_backup_lease_is_released_only_by_the_run_that_holds_it() -> Result<()> {
        let store = live_store().await?;
        store.delete(BACKUP_LEASE_KEY).await?;

        let token = store
            .acquire_backup_lease()
            .await?
            .context("first backup run acquires the lease")?;
        assert_eq!(store.acquire_backup_lease().await?, None);

        store.release_backup_lease("a-different-backup-run").await;
        assert_eq!(
            store.get::<String>(BACKUP_LEASE_KEY).await?.as_deref(),
            Some(token.as_str())
        );
        assert_eq!(store.acquire_backup_lease().await?, None);

        store.release_backup_lease(&token).await;
        assert_eq!(store.get::<String>(BACKUP_LEASE_KEY).await?, None);
        assert!(store.acquire_backup_lease().await?.is_some());

        store.delete(BACKUP_LEASE_KEY).await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires the compose.integration.yaml SableDB service"]
    async fn revoking_a_service_credential_removes_its_secret_lookup_key() -> Result<()> {
        let store = live_store().await?;
        let account = store
            .create_service_account(
                format!("revocation-{}", Uuid::new_v4()),
                "locator cleanup".into(),
                vec!["events.read".to_owned()],
                Uuid::new_v4(),
            )
            .await?;
        let (credential, raw) = store
            .create_service_credential(account.id, "primary".into(), None)
            .await?;
        let locator_key = service_credential_key(&raw);
        assert!(store.get::<String>(&locator_key).await?.is_some());
        store
            .exchange_service_credential(&raw, &["events.read".to_owned()])
            .await?;

        store
            .revoke_service_credential(account.id, credential.id)
            .await?;

        assert_eq!(store.get::<String>(&locator_key).await?, None);
        assert!(
            store
                .exchange_service_credential(&raw, &["events.read".to_owned()])
                .await
                .is_err()
        );

        store
            .delete(&format!("{SERVICE_ACCOUNT_PREFIX}{}", account.id))
            .await?;
        Ok(())
    }

    async fn live_store() -> Result<Store> {
        let url = env::var("RUSTYAUTH_TEST_SOURCE_SABLEDB_URL").context(
            "integration environment variable RUSTYAUTH_TEST_SOURCE_SABLEDB_URL is missing",
        )?;
        let client = redis::Client::open(url).context("create live store client")?;
        let connection = redis::aio::ConnectionManager::new(client)
            .await
            .context("connect to the live store")?;
        Ok(Store::new(
            connection,
            format!("store-test-{}", Uuid::new_v4()),
        ))
    }
}
