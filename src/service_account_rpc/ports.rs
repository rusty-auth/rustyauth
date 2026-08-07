//! Persistence, token-issuance and operator-authorization seams for the
//! service-account RPC, together with their production implementations.

use std::future::Future;

use anyhow::Result;
use connectrpc::ConnectError;
use http::HeaderMap;
use uuid::Uuid;

use crate::{
    jwt::{IssuedServiceAccountToken, JwtIssuer},
    operator_auth::{OperatorActor, OperatorAuthorizer, OperatorCapability},
    store::{
        ServiceAccountCredentialRecord, ServiceAccountGrant, ServiceAccountRecord,
        ServiceAccountStatusRecord, Store,
    },
};

/// Service-account persistence, behind a trait so the handlers can be exercised
/// without a live database.
pub(crate) trait ServiceAccountSource: Send + Sync + 'static {
    fn service_account(
        &self,
        id: Uuid,
    ) -> impl Future<Output = Result<Option<ServiceAccountRecord>>> + Send;

    fn service_accounts(&self) -> impl Future<Output = Result<Vec<ServiceAccountRecord>>> + Send;

    fn create_service_account(
        &self,
        name: String,
        description: String,
        scopes: Vec<String>,
        created_by: Uuid,
    ) -> impl Future<Output = Result<ServiceAccountRecord>> + Send;

    fn update_service_account(
        &self,
        id: Uuid,
        name: String,
        description: String,
        status: ServiceAccountStatusRecord,
        scopes: Vec<String>,
    ) -> impl Future<Output = Result<ServiceAccountRecord>> + Send;

    fn create_service_credential(
        &self,
        service_account_id: Uuid,
        name: String,
        expires_at: Option<u64>,
    ) -> impl Future<Output = Result<(ServiceAccountCredentialRecord, String)>> + Send;

    fn revoke_service_credential(
        &self,
        service_account_id: Uuid,
        credential_id: Uuid,
    ) -> impl Future<Output = Result<ServiceAccountCredentialRecord>> + Send;

    fn exchange_service_credential(
        &self,
        raw: &str,
        requested_scopes: &[String],
    ) -> impl Future<Output = Result<ServiceAccountGrant>> + Send;
}

impl ServiceAccountSource for Store {
    async fn service_account(&self, id: Uuid) -> Result<Option<ServiceAccountRecord>> {
        Store::service_account(self, id).await
    }

    async fn service_accounts(&self) -> Result<Vec<ServiceAccountRecord>> {
        Store::service_accounts(self).await
    }

    async fn create_service_account(
        &self,
        name: String,
        description: String,
        scopes: Vec<String>,
        created_by: Uuid,
    ) -> Result<ServiceAccountRecord> {
        Store::create_service_account(self, name, description, scopes, created_by).await
    }

    async fn update_service_account(
        &self,
        id: Uuid,
        name: String,
        description: String,
        status: ServiceAccountStatusRecord,
        scopes: Vec<String>,
    ) -> Result<ServiceAccountRecord> {
        Store::update_service_account(self, id, name, description, status, scopes).await
    }

    async fn create_service_credential(
        &self,
        service_account_id: Uuid,
        name: String,
        expires_at: Option<u64>,
    ) -> Result<(ServiceAccountCredentialRecord, String)> {
        Store::create_service_credential(self, service_account_id, name, expires_at).await
    }

    async fn revoke_service_credential(
        &self,
        service_account_id: Uuid,
        credential_id: Uuid,
    ) -> Result<ServiceAccountCredentialRecord> {
        Store::revoke_service_credential(self, service_account_id, credential_id).await
    }

    async fn exchange_service_credential(
        &self,
        raw: &str,
        requested_scopes: &[String],
    ) -> Result<ServiceAccountGrant> {
        Store::exchange_service_credential(self, raw, requested_scopes).await
    }
}

/// Access-token minting, behind a trait so credential exchange can be tested
/// without a signing keyset.
pub(crate) trait ServiceTokenIssuer: Send + Sync + 'static {
    fn issue_service_account(
        &self,
        service_account_id: Uuid,
        scopes: Vec<String>,
    ) -> Result<IssuedServiceAccountToken>;
}

impl ServiceTokenIssuer for JwtIssuer {
    fn issue_service_account(
        &self,
        service_account_id: Uuid,
        scopes: Vec<String>,
    ) -> Result<IssuedServiceAccountToken> {
        JwtIssuer::issue_service_account(self, service_account_id, scopes)
    }
}

/// Operator authorization, behind a trait so the handlers can be constructed in
/// tests. Test doubles deny every capability, keeping the authenticated surface
/// closed unless a test deliberately opens it.
pub(crate) trait OperatorGate: Send + Sync + 'static {
    fn authorize(
        &self,
        headers: &HeaderMap,
        capability: OperatorCapability,
    ) -> impl Future<Output = Result<OperatorActor, ConnectError>> + Send;
}

impl OperatorGate for OperatorAuthorizer {
    async fn authorize(
        &self,
        headers: &HeaderMap,
        capability: OperatorCapability,
    ) -> Result<OperatorActor, ConnectError> {
        OperatorAuthorizer::authorize(self, headers, capability).await
    }
}
