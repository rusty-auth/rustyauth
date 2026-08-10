//! SableDB persistence boundary.
//!
//! All durable key construction and serialization is centralized here. Public
//! HTTP handlers do not issue database commands directly. Compound mutations
//! use atomic pipelines and are serialized within the single supported writer.

mod analytics_store;
mod ceremonies;
mod credentials;
mod events;
mod fleet;
mod fleet_analytics;
mod fleet_analytics_control;
mod fleet_operations;
mod invitations;
mod management;
mod organization;
mod recovery;
mod remote_mutations;
mod service_accounts;
mod sessions;
mod snapshot;
mod users;
mod verification;
mod webhooks;
mod writer_lease;

pub use self::analytics_store::{LocalMetricBucket, ProjectionResult, TelemetryOutboxRecord};
pub use self::ceremonies::{
    AuthenticationCeremony, AuthenticationPurpose, LocalAgentHandoff, RegistrationCeremony,
    RegistrationPurpose,
};
pub use self::credentials::StoredPasskey;
pub use self::events::{AuthEvent, EventLogIntegrityError};
pub use self::fleet::{
    EncryptedFleetCredential, FleetAuditRecord, FleetConnectionAttemptRecord,
    FleetConnectionModeRecord, FleetConnectionRecord, FleetConnectionStateRecord,
    FleetEnvironmentKindRecord, FleetEnvironmentRecord, FleetOrganizationRecord,
    FleetProjectRecord, FleetResourceKindRecord, FleetResourceStateRecord, FleetRoleBindingRecord,
    FleetRoleRecord,
};
pub use self::fleet_analytics::{AcceptedFleetTelemetryBatch, FleetTelemetryBucketRecord};
pub use self::fleet_analytics_control::{
    FleetAnalyticsIngestionAuditRecord, FleetAnalyticsMaintenanceActionRecord,
    FleetAnalyticsMaintenanceAuditRecord, FleetAnalyticsMaintenanceOutcomeRecord,
    FleetAnalyticsManifestRecord, FleetAnalyticsManifestStateRecord, FleetAnalyticsPolicyRecord,
    FleetAnalyticsQuarantineRecord, FleetAnalyticsResidencyRecord,
};
pub use self::fleet_operations::FleetOperationalCacheRecord;
pub use self::invitations::AccountInvitationRecord;
pub use self::management::{RealmFleetGrantRecord, RealmPairingRecord, RealmSummaryCounts};
pub use self::organization::{
    OperatorListing, OperatorRecord, OperatorRoleRecord, OrganizationRecord,
};
pub use self::remote_mutations::RemoteMutationClaim;
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
    ProfileValidationError, RecoveryCodeRecord, User, UserSearch, UserSearchPage,
};
pub use self::verification::IdentifierVerificationChallenge;
pub use self::webhooks::{
    EncryptedWebhookSecret, WebhookDeliveryRecord, WebhookDeliveryStatusRecord,
    WebhookManagementSourceRecord, WebhookRecord, WebhookStatusRecord,
};
pub use self::writer_lease::WriterLease;
#[cfg(test)]
use self::writer_lease::{WRITER_LEASE_KEY, WRITER_LEASE_SECONDS};

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
    #[error("fleet resource is missing")]
    FleetResourceMissing,
    #[error("fleet resource slug is already in use")]
    FleetSlugConflict,
    #[error("fleet resource parent is archived")]
    FleetParentArchived,
    #[error("fleet resource still has active children")]
    FleetHasActiveChildren,
    #[error("fleet mutation request id was already used for another action")]
    FleetIdempotencyConflict,
    #[error("fleet connection attempt has expired or was already consumed")]
    FleetConnectionAttemptExpired,
    #[error("fleet connection already exists for this realm and environment")]
    FleetConnectionConflict,
    #[error("analytics mutation request id was already used for another operation")]
    FleetAnalyticsIdempotencyConflict,
    #[error("realm pairing code is invalid, expired or already consumed")]
    RealmPairingInvalid,
    #[error("realm Fleet grant is invalid or revoked")]
    RealmFleetGrantInvalid,
    #[error("remote mutation request id was already used for another operation")]
    RemoteMutationIdempotencyConflict,
    #[error("remote mutation outcome is pending manual reconciliation")]
    RemoteMutationPending,
}

const RESTORE_SENTINEL: &str = "auth:restore:in-progress";
const BACKUP_LEASE_KEY: &str = "auth:backup:lease";
const ORGANIZATION_KEY: &str = "auth:organization";
const OPERATOR_PREFIX: &str = "auth:operator:";
/// Operator last-seen timestamps. Operational telemetry, not a grant, so it is
/// written on the hot path and deliberately excluded from snapshots.
const OPERATOR_SEEN_PREFIX: &str = "auth:operator-seen:";
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
    redis: MeasuredConnection,
    mutation: Arc<Mutex<()>>,
    snapshot_gate: SnapshotGate,
    tenant_id: String,
}

/// A connection manager that measures the complete API-to-SableDB round trip
/// only while benchmark request timing is active. Implementing Redis's native
/// connection trait keeps the measurement below every command and pipeline,
/// including store modules that do not pass through the convenience helpers.
#[derive(Clone)]
pub struct MeasuredConnection(redis::aio::ConnectionManager);

impl redis::aio::ConnectionLike for MeasuredConnection {
    fn req_packed_command<'a>(
        &'a mut self,
        command: &'a redis::Cmd,
    ) -> redis::RedisFuture<'a, redis::Value> {
        Box::pin(async move {
            let started = std::time::Instant::now();
            let result = self.0.req_packed_command(command).await;
            crate::request_timing::record_sabledb_round_trip(started.elapsed());
            result
        })
    }

    fn req_packed_commands<'a>(
        &'a mut self,
        pipeline: &'a redis::Pipeline,
        offset: usize,
        count: usize,
    ) -> redis::RedisFuture<'a, Vec<redis::Value>> {
        Box::pin(async move {
            let started = std::time::Instant::now();
            let result = self.0.req_packed_commands(pipeline, offset, count).await;
            crate::request_timing::record_sabledb_round_trip(started.elapsed());
            result
        })
    }

    fn get_db(&self) -> i64 {
        self.0.get_db()
    }
}

pub type SnapshotGate = Arc<RwLock<()>>;

impl Store {
    pub fn new(redis: redis::aio::ConnectionManager, tenant_id: String) -> Self {
        Self {
            redis: MeasuredConnection(redis),
            mutation: Arc::new(Mutex::new(())),
            snapshot_gate: Arc::new(RwLock::new(())),
            tenant_id,
        }
    }

    pub fn connection(&self) -> MeasuredConnection {
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
    format!(
        "auth:session:{}",
        hex::encode(Sha256::digest(token.as_bytes()))
    )
}

fn service_credential_key(secret: &str) -> String {
    format!(
        "{SERVICE_CREDENTIAL_PREFIX}{}",
        hex::encode(Sha256::digest(secret.as_bytes()))
    )
}

fn handoff_key(code: &str) -> String {
    format!(
        "auth:agent-handoff:{}",
        hex::encode(Sha256::digest(code.as_bytes()))
    )
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
    async fn writer_lease_renews_on_pinned_sabledb_and_fences_a_replaced_owner() -> Result<()> {
        let store = live_store().await?;
        let lease = store.acquire_writer_lease().await?;
        assert!(lease.renew().await?, "the live owner renews its lease");

        let replacement = format!("replacement-owner-{}", Uuid::new_v4());
        let mut connection = store.redis.clone();
        redis::cmd("SET")
            .arg(WRITER_LEASE_KEY)
            .arg(&replacement)
            .arg("EX")
            .arg(WRITER_LEASE_SECONDS)
            .query_async::<String>(&mut connection)
            .await?;

        assert!(
            !lease.renew().await?,
            "a process whose token was replaced must fence itself"
        );
        let current: Option<String> = redis::cmd("GET")
            .arg(WRITER_LEASE_KEY)
            .query_async(&mut connection)
            .await?;
        assert_eq!(current.as_deref(), Some(replacement.as_str()));
        assert!(
            !lease.release().await?,
            "the stale process must not release the replacement owner's lease"
        );

        let removed: i64 = redis::cmd("DELIFEQ")
            .arg(WRITER_LEASE_KEY)
            .arg(&replacement)
            .query_async(&mut connection)
            .await?;
        assert_eq!(removed, 1);
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

    #[tokio::test]
    #[ignore = "requires the compose.integration.yaml SableDB service"]
    async fn fleet_hierarchy_is_idempotent_audited_and_archived_bottom_up() -> Result<()> {
        let store = live_store().await?;
        let suffix = Uuid::new_v4().simple().to_string();
        let slug = format!("fleet-{}", &suffix[..12]);
        let operator_id = Uuid::new_v4();
        let organization_request = Uuid::new_v4();
        let project_request = Uuid::new_v4();
        let environment_request = Uuid::new_v4();
        let environment_archive_request = Uuid::new_v4();
        let project_archive_request = Uuid::new_v4();
        let organization_archive_request = Uuid::new_v4();

        let organization = store
            .create_fleet_organization(
                slug.clone(),
                "Fleet test organization".into(),
                organization_request,
                operator_id,
                "integration test".into(),
            )
            .await?;
        let replayed = store
            .create_fleet_organization(
                slug.clone(),
                "ignored on replay".into(),
                organization_request,
                operator_id,
                "integration test replay".into(),
            )
            .await?;
        assert_eq!(replayed.id, organization.id);
        assert!(
            store
                .update_fleet_organization(
                    organization.id,
                    "conflicting action".into(),
                    organization_request,
                    operator_id,
                    "must fail".into(),
                )
                .await
                .is_err()
        );

        let project = store
            .create_fleet_project(
                organization.id,
                slug.clone(),
                "Fleet test project".into(),
                "Hierarchy integration coverage".into(),
                project_request,
                operator_id,
                "integration test".into(),
            )
            .await?;
        let environment = store
            .create_fleet_environment(
                organization.id,
                project.id,
                slug.clone(),
                "Production".into(),
                FleetEnvironmentKindRecord::Production,
                "railway".into(),
                "eu-west".into(),
                environment_request,
                operator_id,
                "integration test".into(),
            )
            .await?;

        assert!(
            store
                .archive_fleet_organization(
                    organization.id,
                    organization_archive_request,
                    operator_id,
                    "must archive children first".into(),
                )
                .await
                .is_err()
        );
        assert!(
            store
                .archive_fleet_project(
                    organization.id,
                    project.id,
                    project_archive_request,
                    operator_id,
                    "must archive children first".into(),
                )
                .await
                .is_err()
        );
        store
            .archive_fleet_environment(
                organization.id,
                project.id,
                environment.id,
                environment_archive_request,
                operator_id,
                "bottom-up archive".into(),
            )
            .await?;
        store
            .archive_fleet_project(
                organization.id,
                project.id,
                project_archive_request,
                operator_id,
                "bottom-up archive".into(),
            )
            .await?;
        store
            .archive_fleet_organization(
                organization.id,
                organization_archive_request,
                operator_id,
                "bottom-up archive".into(),
            )
            .await?;

        let audits: Vec<_> = store
            .fleet_audit_records()
            .await?
            .into_iter()
            .filter(|audit| audit.operator_id == operator_id)
            .collect();
        assert_eq!(audits.len(), 6, "one audit per successful mutation");
        let (_, snapshot) = store.export_records().await?;
        assert!(
            snapshot
                .iter()
                .any(|record| record.key == format!("fleet:organization:{}", organization.id))
        );

        for key in [
            format!("fleet:organization:{}", organization.id),
            format!("fleet:organization-slug:{slug}"),
            format!("fleet:project:{}", project.id),
            format!("fleet:project-slug:{}:{slug}", organization.id),
            format!("fleet:environment:{}", environment.id),
            format!("fleet:environment-slug:{}:{slug}", project.id),
        ] {
            store.delete(&key).await?;
        }
        for request_id in [
            organization_request,
            project_request,
            environment_request,
            environment_archive_request,
            project_archive_request,
            organization_archive_request,
        ] {
            store
                .delete(&format!("fleet:idempotency:{request_id}"))
                .await?;
        }
        for audit in audits {
            store.delete(&format!("fleet:audit:{}", audit.id)).await?;
        }
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires the compose.integration.yaml SableDB service"]
    async fn realm_pairing_is_origin_bound_one_use_and_revocable() -> Result<()> {
        let store = live_store().await?;
        let control_plane_origin = "https://fleet.integration.example";
        let (_, wrong_origin_code) = store
            .create_realm_pairing(
                "realm-integration".into(),
                control_plane_origin.into(),
                vec!["realm.summary.read".into()],
                Uuid::new_v4(),
            )
            .await?;
        assert!(
            store
                .exchange_realm_pairing(
                    &wrong_origin_code,
                    "https://attacker.integration.example",
                    "fleet-attacker".into(),
                    1,
                )
                .await
                .is_err()
        );
        assert!(
            store
                .exchange_realm_pairing(
                    &wrong_origin_code,
                    control_plane_origin,
                    "fleet-integration".into(),
                    1,
                )
                .await
                .is_err(),
            "a failed origin check still consumes the one-use code"
        );

        let (_, code) = store
            .create_realm_pairing(
                "realm-integration".into(),
                control_plane_origin.into(),
                vec![
                    "realm.summary.read".into(),
                    "realm.connection.revoke".into(),
                ],
                Uuid::new_v4(),
            )
            .await?;
        let (grant, credential) = store
            .exchange_realm_pairing(&code, control_plane_origin, "fleet-integration".into(), 7)
            .await?;
        assert_eq!(grant.control_plane_origin, control_plane_origin);
        assert_eq!(grant.assignment_epoch, 7);
        assert_eq!(
            store
                .realm_fleet_grant_by_credential(&credential)
                .await?
                .context("new credential resolves to its grant")?
                .connection_id,
            grant.connection_id
        );
        assert!(
            store
                .exchange_realm_pairing(&code, control_plane_origin, "fleet-integration".into(), 7,)
                .await
                .is_err(),
            "a pairing code cannot be replayed"
        );

        let revoked = store.revoke_realm_fleet_grant(grant.connection_id).await?;
        assert!(revoked.revoked_at.is_some());
        assert_eq!(
            store.realm_fleet_grant_by_credential(&credential).await?,
            None
        );

        store
            .delete(&format!("auth:fleet-grant:{}", grant.connection_id))
            .await?;
        store
            .delete(&format!(
                "auth:fleet-grant-secret:{}",
                grant.credential_digest
            ))
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
