//! Service principals, their credentials and scoped token exchange.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    SERVICE_ACCOUNT_PREFIX, SERVICE_CREDENTIAL_PREFIX, Store, StorePolicyError,
    events::queue_events, now, service_credential_key,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAccountStatusRecord {
    Active,
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountCredentialRecord {
    pub id: Uuid,
    pub name: String,
    pub secret_hint: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub last_used_at: Option<u64>,
    pub revoked_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountRecord {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub status: ServiceAccountStatusRecord,
    pub scopes: Vec<String>,
    pub credentials: Vec<ServiceAccountCredentialRecord>,
    pub created_at: u64,
    pub created_by: Uuid,
    pub last_used_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceAccountGrant {
    pub service_account_id: Uuid,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServiceCredentialLocator {
    pub(crate) service_account_id: Uuid,
    pub(crate) credential_id: Uuid,
}

impl Store {
    pub async fn service_account(&self, id: Uuid) -> Result<Option<ServiceAccountRecord>> {
        self.get_json(&format!("{SERVICE_ACCOUNT_PREFIX}{id}"))
            .await
    }

    pub async fn service_accounts(&self) -> Result<Vec<ServiceAccountRecord>> {
        let mut accounts = Vec::new();
        for id in self
            .record_ids(SERVICE_ACCOUNT_PREFIX, "scan RustyAuth service accounts")
            .await?
        {
            accounts.push(
                self.service_account(id)
                    .await?
                    .context("service account disappeared during listing")?,
            );
        }
        Ok(accounts)
    }

    pub async fn create_service_account(
        &self,
        name: String,
        description: String,
        scopes: Vec<String>,
        created_by: Uuid,
    ) -> Result<ServiceAccountRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let account = ServiceAccountRecord {
            id: Uuid::new_v4(),
            name,
            description,
            status: ServiceAccountStatusRecord::Active,
            scopes,
            credentials: Vec::new(),
            created_at: now(),
            created_by,
            last_used_at: None,
        };
        let events = self
            .pending_events(vec![(
                "service_account.created".to_owned(),
                Some(account.id),
            )])
            .await?;
        let mut pipeline = redis::pipe();
        pipeline.atomic().set(
            format!("{SERVICE_ACCOUNT_PREFIX}{}", account.id),
            serde_json::to_string(&account)?,
        );
        queue_events(&mut pipeline, &events)?;
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("create service account")?;
        Ok(account)
    }

    pub async fn update_service_account(
        &self,
        id: Uuid,
        name: String,
        description: String,
        status: ServiceAccountStatusRecord,
        scopes: Vec<String>,
    ) -> Result<ServiceAccountRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut account = self
            .service_account(id)
            .await?
            .ok_or(StorePolicyError::ServiceAccountMissing)?;
        account.name = name;
        account.description = description;
        account.status = status;
        account.scopes = scopes;
        let events = self
            .pending_events(vec![(
                "service_account.updated".to_owned(),
                Some(account.id),
            )])
            .await?;
        let mut pipeline = redis::pipe();
        pipeline.atomic().set(
            format!("{SERVICE_ACCOUNT_PREFIX}{id}"),
            serde_json::to_string(&account)?,
        );
        queue_events(&mut pipeline, &events)?;
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("update service account")?;
        Ok(account)
    }

    pub async fn create_service_credential(
        &self,
        service_account_id: Uuid,
        name: String,
        expires_at: Option<u64>,
    ) -> Result<(ServiceAccountCredentialRecord, String)> {
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let mut account = self
            .service_account(service_account_id)
            .await?
            .ok_or(StorePolicyError::ServiceAccountMissing)?;
        let raw = format!("rsa_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let credential = ServiceAccountCredentialRecord {
            id: Uuid::new_v4(),
            name,
            secret_hint: raw
                .chars()
                .rev()
                .take(6)
                .collect::<String>()
                .chars()
                .rev()
                .collect(),
            created_at: now(),
            expires_at,
            last_used_at: None,
            revoked_at: None,
        };
        let locator_key = service_credential_key(&raw);
        if self.get::<String>(&locator_key).await?.is_some() {
            bail!("service account credential collision");
        }
        let locator = ServiceCredentialLocator {
            service_account_id,
            credential_id: credential.id,
        };
        account.credentials.push(credential.clone());
        let events = self
            .pending_events(vec![(
                "service_account.credential.created".to_owned(),
                Some(service_account_id),
            )])
            .await?;
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .set(
                format!("{SERVICE_ACCOUNT_PREFIX}{service_account_id}"),
                serde_json::to_string(&account)?,
            )
            .set(locator_key, serde_json::to_string(&locator)?);
        queue_events(&mut pipeline, &events)?;
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("create service account credential")?;
        Ok((credential, raw))
    }

    pub async fn revoke_service_credential(
        &self,
        service_account_id: Uuid,
        credential_id: Uuid,
    ) -> Result<ServiceAccountCredentialRecord> {
        let _snapshot = self.snapshot_gate.read().await;
        // Scanned before the mutation lock is taken. This walks every credential
        // locator in the tenant, and holding the global lock across it would stop
        // every login and every audit event for the duration — on the one code
        // path an operator runs while responding to a leaked credential.
        let locator_keys = self.service_credential_locator_keys(credential_id).await?;
        let _guard = self.mutation.lock().await;
        let mut account = self
            .service_account(service_account_id)
            .await?
            .ok_or(StorePolicyError::ServiceAccountMissing)?;
        let credential = account
            .credentials
            .iter_mut()
            .find(|credential| credential.id == credential_id)
            .ok_or(StorePolicyError::ServiceCredentialMissing)?;
        if credential.revoked_at.is_none() {
            credential.revoked_at = Some(now());
        }
        let credential = credential.clone();
        let events = self
            .pending_events(vec![(
                "service_account.credential.revoked".to_owned(),
                Some(service_account_id),
            )])
            .await?;
        let mut pipeline = redis::pipe();
        pipeline.atomic().set(
            format!("{SERVICE_ACCOUNT_PREFIX}{service_account_id}"),
            serde_json::to_string(&account)?,
        );
        // The locator is keyed by the hash of the raw secret. Exchange already
        // refuses a revoked credential, so leaving it behind is not an
        // authentication hole — it accumulates a dead key that every later backup
        // republishes. Removed in the same atomic write as the revocation.
        for key in &locator_keys {
            pipeline.del(key);
        }
        queue_events(&mut pipeline, &events)?;
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("revoke service account credential")?;
        Ok(credential)
    }

    pub async fn exchange_service_credential(
        &self,
        raw: &str,
        requested_scopes: &[String],
    ) -> Result<ServiceAccountGrant> {
        if raw.len() < 40 || raw.len() > 128 || !raw.starts_with("rsa_") {
            return Err(StorePolicyError::InvalidServiceCredential.into());
        }
        let _snapshot = self.snapshot_gate.read().await;
        let _guard = self.mutation.lock().await;
        let locator = self
            .get_json::<ServiceCredentialLocator>(&service_credential_key(raw))
            .await?
            .ok_or(StorePolicyError::InvalidServiceCredential)?;
        let mut account = self
            .service_account(locator.service_account_id)
            .await?
            .ok_or(StorePolicyError::InvalidServiceCredential)?;
        if account.status != ServiceAccountStatusRecord::Active {
            return Err(StorePolicyError::InvalidServiceCredential.into());
        }
        let current = now();
        let credential = account
            .credentials
            .iter_mut()
            .find(|credential| credential.id == locator.credential_id)
            .filter(|credential| {
                credential.revoked_at.is_none()
                    && credential.expires_at.is_none_or(|expiry| expiry > current)
            })
            .ok_or(StorePolicyError::InvalidServiceCredential)?;
        if requested_scopes
            .iter()
            .any(|scope| !account.scopes.contains(scope))
        {
            return Err(StorePolicyError::ServiceScopeDenied.into());
        }
        credential.last_used_at = Some(current);
        account.last_used_at = Some(current);
        let scopes = if requested_scopes.is_empty() {
            account.scopes.clone()
        } else {
            requested_scopes.to_vec()
        };
        let events = self
            .pending_events(vec![(
                "service_account.token.issued".to_owned(),
                Some(account.id),
            )])
            .await?;
        let mut pipeline = redis::pipe();
        pipeline.atomic().set(
            format!("{SERVICE_ACCOUNT_PREFIX}{}", account.id),
            serde_json::to_string(&account)?,
        );
        queue_events(&mut pipeline, &events)?;
        let mut connection = self.redis.clone();
        let _: () = pipeline
            .query_async(&mut connection)
            .await
            .context("exchange service account credential")?;
        Ok(ServiceAccountGrant {
            service_account_id: account.id,
            scopes,
        })
    }

    /// Finds every lookup key that resolves to one service account credential.
    ///
    /// A locator key is named by the hash of the raw secret, which revocation
    /// never sees, so the keys cannot be derived from the credential record and
    /// have to be scanned for.
    async fn service_credential_locator_keys(&self, credential_id: Uuid) -> Result<Vec<String>> {
        let mut cursor = 0_u64;
        let mut keys = Vec::new();
        loop {
            let mut connection = self.redis.clone();
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{SERVICE_CREDENTIAL_PREFIX}*"))
                .arg("COUNT")
                .arg(500_u16)
                .query_async(&mut connection)
                .await
                .context("scan RustyAuth service account credential locators")?;
            for key in batch {
                // A locator that will not decode is skipped rather than propagated.
                // Failing here would let one unreadable value block revocation of
                // every credential belonging to every service account — the exact
                // operation an incident response needs to work.
                match self.get_json::<ServiceCredentialLocator>(&key).await {
                    Ok(Some(locator)) if locator.credential_id == credential_id => {
                        keys.push(key);
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(key = %key, error = %error, "skipping undecodable service credential locator");
                    }
                }
            }
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        Ok(keys)
    }
}
