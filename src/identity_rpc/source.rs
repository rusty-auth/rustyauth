//! Persistence-facing identity source: the `IdentitySource` trait and its
//! `Store` implementation feeding the RPC handlers safe records.

use std::future::Future;

use anyhow::Result;
use uuid::Uuid;

use crate::store::{AccountProfile, IdentifierValue, Store, UserSearch, UserSearchPage};

use super::projection::{IdentityRecord, IdentitySearchPage};

pub(crate) trait IdentitySource: Clone + Send + Sync + 'static {
    fn get_user(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<Option<IdentityRecord>>> + Send;

    fn list_users(
        &self,
        after: Option<Uuid>,
        page_size: usize,
    ) -> impl Future<Output = Result<IdentitySearchPage>> + Send;

    fn search_users(
        &self,
        search: UserSearch,
        after: Option<Uuid>,
        page_size: usize,
    ) -> impl Future<Output = Result<IdentitySearchPage>> + Send;

    fn update_profile(
        &self,
        user_id: Uuid,
        profile: AccountProfile,
    ) -> impl Future<Output = Result<IdentityRecord>> + Send;

    fn add_identifier(
        &self,
        user_id: Uuid,
        identifier: IdentifierValue,
        verified: bool,
    ) -> impl Future<Output = Result<IdentityRecord>> + Send;

    fn remove_identifier(
        &self,
        user_id: Uuid,
        identifier: IdentifierValue,
    ) -> impl Future<Output = Result<IdentityRecord>> + Send;

    fn set_primary_identifier(
        &self,
        user_id: Uuid,
        identifier: IdentifierValue,
    ) -> impl Future<Output = Result<IdentityRecord>> + Send;

    fn set_identifier_verification(
        &self,
        user_id: Uuid,
        identifier: IdentifierValue,
        verified: bool,
    ) -> impl Future<Output = Result<IdentityRecord>> + Send;

    fn rename_passkey(
        &self,
        user_id: Uuid,
        credential_id: String,
        label: String,
    ) -> impl Future<Output = Result<IdentityRecord>> + Send;

    fn revoke_passkey(
        &self,
        user_id: Uuid,
        credential_id: String,
    ) -> impl Future<Output = Result<IdentityRecord>> + Send;
}

impl IdentitySource for Store {
    async fn get_user(&self, user_id: Uuid) -> Result<Option<IdentityRecord>> {
        Ok(self.user(user_id).await?.map(Into::into))
    }

    async fn list_users(
        &self,
        after: Option<Uuid>,
        page_size: usize,
    ) -> Result<IdentitySearchPage> {
        let UserSearchPage { users, next_after } =
            Store::list_users(self, after, page_size).await?;
        Ok(IdentitySearchPage {
            records: users.into_iter().map(Into::into).collect(),
            next_after,
        })
    }

    async fn search_users(
        &self,
        search: UserSearch,
        after: Option<Uuid>,
        page_size: usize,
    ) -> Result<IdentitySearchPage> {
        let UserSearchPage { users, next_after } =
            Store::search_users(self, &search, after, page_size).await?;
        Ok(IdentitySearchPage {
            records: users.into_iter().map(Into::into).collect(),
            next_after,
        })
    }

    async fn update_profile(
        &self,
        user_id: Uuid,
        profile: AccountProfile,
    ) -> Result<IdentityRecord> {
        Ok(Store::update_profile(self, user_id, profile).await?.into())
    }

    async fn add_identifier(
        &self,
        user_id: Uuid,
        identifier: IdentifierValue,
        verified: bool,
    ) -> Result<IdentityRecord> {
        Ok(Store::add_identifier(self, user_id, identifier, verified)
            .await?
            .into())
    }

    async fn remove_identifier(
        &self,
        user_id: Uuid,
        identifier: IdentifierValue,
    ) -> Result<IdentityRecord> {
        Ok(Store::remove_identifier(self, user_id, &identifier)
            .await?
            .into())
    }

    async fn set_primary_identifier(
        &self,
        user_id: Uuid,
        identifier: IdentifierValue,
    ) -> Result<IdentityRecord> {
        Ok(Store::set_primary_identifier(self, user_id, &identifier)
            .await?
            .into())
    }

    async fn set_identifier_verification(
        &self,
        user_id: Uuid,
        identifier: IdentifierValue,
        verified: bool,
    ) -> Result<IdentityRecord> {
        Ok(
            Store::set_identifier_verification(self, user_id, &identifier, verified)
                .await?
                .into(),
        )
    }

    async fn rename_passkey(
        &self,
        user_id: Uuid,
        credential_id: String,
        label: String,
    ) -> Result<IdentityRecord> {
        Ok(Store::rename_passkey(self, user_id, &credential_id, label)
            .await?
            .into())
    }

    async fn revoke_passkey(&self, user_id: Uuid, credential_id: String) -> Result<IdentityRecord> {
        Ok(Store::revoke_passkey(self, user_id, &credential_id)
            .await?
            .into())
    }
}
