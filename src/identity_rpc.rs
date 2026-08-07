//! Private gRPC identity control plane.
//!
//! Domain users are converted to `IdentityRecord` before they cross this
//! boundary. That safe view deliberately omits stored WebAuthn credentials,
//! counters, session versions, and every other authentication secret.

use std::future::Future;

use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    proto::rustyauth::identity::v1::{
        AddIdentifierRequest, GetUserRequest, Identifier as ProtoIdentifier,
        IdentifierMutationRequest, IdentifierType, IdentityService, Passkey as ProtoPasskey,
        Profile as ProtoProfile, RenamePasskeyRequest, RevokePasskeyRequest, SearchUsersRequest,
        SearchUsersResponse, SetIdentifierVerificationRequest, UpdateProfileRequest,
        User as ProtoUser,
    },
    store::{
        AccountIdentifier, AccountProfile, IdentifierKind, IdentifierValue, Store,
        StorePolicyError, User, UserSearch, UserSearchPage,
    },
};

const DEFAULT_PAGE_SIZE: usize = 25;
const MAX_PAGE_SIZE: usize = 100;

#[derive(Clone, Debug)]
pub(crate) struct PasskeyMetadata {
    credential_id: String,
    label: String,
    created_at: u64,
    last_used_at: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct IdentityRecord {
    id: Uuid,
    profile: AccountProfile,
    identifiers: Vec<AccountIdentifier>,
    passkeys: Vec<PasskeyMetadata>,
    created_at: u64,
}

impl From<User> for IdentityRecord {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            profile: user.profile,
            identifiers: user.identifiers,
            passkeys: user
                .passkeys
                .into_iter()
                .map(|passkey| PasskeyMetadata {
                    credential_id: passkey.id,
                    label: passkey.label,
                    created_at: passkey.created_at,
                    last_used_at: passkey.last_used_at,
                })
                .collect(),
            created_at: user.created_at,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IdentitySearchPage {
    records: Vec<IdentityRecord>,
    next_after: Option<Uuid>,
}

pub(crate) trait IdentitySource: Clone + Send + Sync + 'static {
    fn get_user(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<Option<IdentityRecord>>> + Send;

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

pub(crate) struct IdentityRpc<S> {
    source: S,
}

impl<S> IdentityRpc<S> {
    pub(crate) fn new(source: S) -> Self {
        Self { source }
    }
}

#[allow(refining_impl_trait)]
impl<S: IdentitySource> IdentityService for IdentityRpc<S> {
    async fn get_user(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetUserRequest>,
    ) -> ServiceResult<ProtoUser> {
        let user_id = parse_user_id(request.user_id)?;
        let record = self
            .source
            .get_user(user_id)
            .await
            .map_err(source_error)?
            .ok_or_else(user_not_found)?;
        Response::ok(record_to_proto(record)?)
    }

    async fn search_users(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, SearchUsersRequest>,
    ) -> ServiceResult<SearchUsersResponse> {
        let search = search_from_request(&request)?;
        let after = decode_page_token(request.page_token)?;
        let page_size = match request.page_size {
            0 => DEFAULT_PAGE_SIZE,
            value if value as usize <= MAX_PAGE_SIZE => value as usize,
            _ => {
                return Err(invalid_argument(format!(
                    "page_size must not exceed {MAX_PAGE_SIZE}"
                )));
            }
        };
        let page = self
            .source
            .search_users(search, after, page_size)
            .await
            .map_err(source_error)?;
        let users = page
            .records
            .into_iter()
            .map(record_to_proto)
            .collect::<Result<Vec<_>, _>>()?;
        Response::ok(SearchUsersResponse {
            users,
            next_page_token: page.next_after.map(encode_page_token).unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn update_profile(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, UpdateProfileRequest>,
    ) -> ServiceResult<ProtoUser> {
        let user_id = parse_user_id(request.user_id)?;
        let profile = request
            .profile
            .as_option()
            .ok_or_else(|| invalid_argument("profile is required"))?;
        let profile = AccountProfile::canonical(
            optional_string(profile.given_name),
            optional_string(profile.family_name),
            optional_string(profile.display_name),
        )
        .map_err(|error| invalid_argument(error.to_string()))?;
        let record = self
            .source
            .update_profile(user_id, profile)
            .await
            .map_err(source_error)?;
        Response::ok(record_to_proto(record)?)
    }

    async fn add_identifier(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, AddIdentifierRequest>,
    ) -> ServiceResult<ProtoUser> {
        let user_id = parse_user_id(request.user_id)?;
        let identifier = parse_identifier(request.identifier.as_option())?;
        let record = self
            .source
            .add_identifier(user_id, identifier, request.verified)
            .await
            .map_err(source_error)?;
        Response::ok(record_to_proto(record)?)
    }

    async fn remove_identifier(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, IdentifierMutationRequest>,
    ) -> ServiceResult<ProtoUser> {
        let user_id = parse_user_id(request.user_id)?;
        let identifier = parse_identifier(request.identifier.as_option())?;
        let record = self
            .source
            .remove_identifier(user_id, identifier)
            .await
            .map_err(source_error)?;
        Response::ok(record_to_proto(record)?)
    }

    async fn set_primary_identifier(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, IdentifierMutationRequest>,
    ) -> ServiceResult<ProtoUser> {
        let user_id = parse_user_id(request.user_id)?;
        let identifier = parse_identifier(request.identifier.as_option())?;
        let record = self
            .source
            .set_primary_identifier(user_id, identifier)
            .await
            .map_err(source_error)?;
        Response::ok(record_to_proto(record)?)
    }

    async fn set_identifier_verification(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, SetIdentifierVerificationRequest>,
    ) -> ServiceResult<ProtoUser> {
        let user_id = parse_user_id(request.user_id)?;
        let identifier = parse_identifier(request.identifier.as_option())?;
        let record = self
            .source
            .set_identifier_verification(user_id, identifier, request.verified)
            .await
            .map_err(source_error)?;
        Response::ok(record_to_proto(record)?)
    }

    async fn rename_passkey(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, RenamePasskeyRequest>,
    ) -> ServiceResult<ProtoUser> {
        let user_id = parse_user_id(request.user_id)?;
        let credential_id = canonical_credential_id(request.credential_id)?;
        let label = canonical_passkey_label(request.label)?;
        let record = self
            .source
            .rename_passkey(user_id, credential_id, label)
            .await
            .map_err(source_error)?;
        Response::ok(record_to_proto(record)?)
    }

    async fn revoke_passkey(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, RevokePasskeyRequest>,
    ) -> ServiceResult<ProtoUser> {
        let user_id = parse_user_id(request.user_id)?;
        let credential_id = canonical_credential_id(request.credential_id)?;
        let record = self
            .source
            .revoke_passkey(user_id, credential_id)
            .await
            .map_err(source_error)?;
        Response::ok(record_to_proto(record)?)
    }
}

fn search_from_request(request: &SearchUsersRequestView<'_>) -> Result<UserSearch, ConnectError> {
    let user_id = (!request.user_id.is_empty())
        .then(|| parse_user_id(request.user_id))
        .transpose()?;
    let identifier = request
        .identifier
        .as_option()
        .map(|value| parse_identifier(Some(value)))
        .transpose()?;
    let passkey_credential_id = (!request.passkey_credential_id.is_empty())
        .then(|| canonical_credential_id(request.passkey_credential_id))
        .transpose()?;
    let passkey_label = (!request.passkey_label.is_empty())
        .then(|| canonical_passkey_label(request.passkey_label))
        .transpose()?;
    let given_name = profile_search_value(request.given_name, ProfileField::Given)?;
    let family_name = profile_search_value(request.family_name, ProfileField::Family)?;
    let display_name = profile_search_value(request.display_name, ProfileField::Display)?;
    let search = UserSearch {
        user_id,
        identifier,
        passkey_credential_id,
        passkey_label,
        given_name,
        family_name,
        display_name,
    };
    if search.is_empty() {
        return Err(invalid_argument(
            "at least one user search criterion is required",
        ));
    }
    Ok(search)
}

// Name the generated view explicitly so validation remains zero-copy.
type SearchUsersRequestView<'a> =
    crate::proto::rustyauth::identity::v1::__buffa::view::SearchUsersRequestView<'a>;

fn parse_user_id(value: &str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(value).map_err(|_| invalid_argument("user_id must be a UUID"))
}

fn parse_identifier(
    value: Option<&crate::proto::rustyauth::identity::v1::__buffa::view::IdentifierValueView<'_>>,
) -> Result<IdentifierValue, ConnectError> {
    let value = value.ok_or_else(|| invalid_argument("identifier is required"))?;
    let kind = match value.r#type.to_i32() {
        value if value == IdentifierType::Email as i32 => IdentifierKind::Email,
        value if value == IdentifierType::Phone as i32 => IdentifierKind::Phone,
        _ => return Err(invalid_argument("identifier type must be EMAIL or PHONE")),
    };
    IdentifierValue::canonical(kind, value.value)
        .map_err(|error| invalid_argument(error.to_string()))
}

#[derive(Clone, Copy)]
enum ProfileField {
    Given,
    Family,
    Display,
}

fn profile_search_value(value: &str, field: ProfileField) -> Result<Option<String>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    let profile = match field {
        ProfileField::Given => AccountProfile::canonical(Some(value.to_owned()), None, None),
        ProfileField::Family => AccountProfile::canonical(None, Some(value.to_owned()), None),
        ProfileField::Display => AccountProfile::canonical(None, None, Some(value.to_owned())),
    }
    .map_err(|error| invalid_argument(error.to_string()))?;
    let canonical = match field {
        ProfileField::Given => profile.given_name,
        ProfileField::Family => profile.family_name,
        ProfileField::Display => profile.display_name,
    };
    canonical
        .map(Some)
        .ok_or_else(|| invalid_argument("profile search values cannot be blank"))
}

fn optional_string(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

fn canonical_credential_id(value: &str) -> Result<String, ConnectError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 1024
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid_argument("invalid passkey credential id"));
    }
    Ok(value.to_owned())
}

fn canonical_passkey_label(value: &str) -> Result<String, ConnectError> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > 80
        || value.chars().any(forbidden_display_character)
    {
        return Err(invalid_argument(
            "passkey label must contain 1-80 safe characters",
        ));
    }
    Ok(value.to_owned())
}

fn forbidden_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{200B}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

fn record_to_proto(record: IdentityRecord) -> Result<ProtoUser, ConnectError> {
    let profile = ProtoProfile {
        given_name: record.profile.given_name.unwrap_or_default(),
        family_name: record.profile.family_name.unwrap_or_default(),
        display_name: record.profile.display_name.unwrap_or_default(),
        ..Default::default()
    };
    let identifiers = record
        .identifiers
        .into_iter()
        .map(|identifier| {
            Ok(ProtoIdentifier {
                r#type: match identifier.kind {
                    IdentifierKind::Email => IdentifierType::Email.into(),
                    IdentifierKind::Phone => IdentifierType::Phone.into(),
                },
                value: identifier.value,
                verified: identifier.verified,
                verified_at: identifier
                    .verified_at
                    .map(format_timestamp)
                    .transpose()?
                    .unwrap_or_default(),
                primary: identifier.primary,
                created_at: format_timestamp(identifier.created_at)?,
                ..Default::default()
            })
        })
        .collect::<Result<Vec<_>, ConnectError>>()?;
    let passkeys = record
        .passkeys
        .into_iter()
        .map(|passkey| {
            Ok(ProtoPasskey {
                credential_id: passkey.credential_id,
                label: passkey.label,
                created_at: format_timestamp(passkey.created_at)?,
                last_used_at: passkey
                    .last_used_at
                    .map(format_timestamp)
                    .transpose()?
                    .unwrap_or_default(),
                ..Default::default()
            })
        })
        .collect::<Result<Vec<_>, ConnectError>>()?;
    Ok(ProtoUser {
        id: record.id.to_string(),
        profile: buffa::MessageField::some(profile),
        identifiers,
        passkeys,
        created_at: format_timestamp(record.created_at)?,
        ..Default::default()
    })
}

fn format_timestamp(value: u64) -> Result<String, ConnectError> {
    let value = i64::try_from(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "stored timestamp is invalid"))?;
    OffsetDateTime::from_unix_timestamp(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "stored timestamp is invalid"))?
        .format(&Rfc3339)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "format identity timestamp"))
}

fn encode_page_token(value: Uuid) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

fn decode_page_token(value: &str) -> Result<Option<Uuid>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid_argument("invalid page_token"))?;
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| invalid_argument("invalid page_token"))?;
    Ok(Some(Uuid::from_bytes(bytes)))
}

fn source_error(error: anyhow::Error) -> ConnectError {
    if let Some(policy) = error.downcast_ref::<StorePolicyError>() {
        return match policy {
            StorePolicyError::UserMissing => user_not_found(),
            StorePolicyError::IdentifierAlreadyExists
            | StorePolicyError::CredentialAlreadyExists => {
                ConnectError::new(ErrorCode::AlreadyExists, policy.to_string())
            }
            StorePolicyError::IdentifierLimit => {
                ConnectError::new(ErrorCode::ResourceExhausted, policy.to_string())
            }
            StorePolicyError::IdentifierNotLinked | StorePolicyError::CredentialNotLinked => {
                ConnectError::new(ErrorCode::NotFound, policy.to_string())
            }
            StorePolicyError::FinalIdentifier | StorePolicyError::FinalCredential => {
                ConnectError::new(ErrorCode::FailedPrecondition, policy.to_string())
            }
            _ => {
                tracing::error!("identity RPC received an unrelated store policy failure");
                ConnectError::new(ErrorCode::Unavailable, "identity store unavailable")
            }
        };
    }
    tracing::error!("identity RPC persistence operation failed");
    ConnectError::new(ErrorCode::Unavailable, "identity store unavailable")
}

fn invalid_argument(message: impl Into<String>) -> ConnectError {
    ConnectError::new(ErrorCode::InvalidArgument, message)
}

fn user_not_found() -> ConnectError {
    ConnectError::new(ErrorCode::NotFound, "user not found")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use connectrpc::{
        ConnectRpcService, Protocol,
        client::{ClientConfig, HttpClient},
    };
    use tokio::sync::RwLock;

    use super::*;
    use crate::proto::rustyauth::identity::v1::{
        IdentifierValue as ProtoIdentifierValue, IdentityServiceClient, IdentityServiceServer,
    };
    use crate::rpc::RpcAuth;

    const EVENT_TOKEN: &str = "event-rpc-test-token-longer-than-32-characters";
    const IDENTITY_TOKEN: &str = "identity-rpc-test-token-longer-than-32-characters";

    #[derive(Clone)]
    struct MemoryIdentitySource {
        records: Arc<RwLock<Vec<IdentityRecord>>>,
    }

    impl MemoryIdentitySource {
        fn new(records: Vec<IdentityRecord>) -> Self {
            Self {
                records: Arc::new(RwLock::new(records)),
            }
        }

        async fn mutate(
            &self,
            user_id: Uuid,
            operation: impl FnOnce(&mut IdentityRecord) -> Result<()>,
        ) -> Result<IdentityRecord> {
            let mut records = self.records.write().await;
            let record = records
                .iter_mut()
                .find(|record| record.id == user_id)
                .ok_or(StorePolicyError::UserMissing)?;
            operation(record)?;
            Ok(record.clone())
        }
    }

    impl IdentitySource for MemoryIdentitySource {
        async fn get_user(&self, user_id: Uuid) -> Result<Option<IdentityRecord>> {
            Ok(self
                .records
                .read()
                .await
                .iter()
                .find(|record| record.id == user_id)
                .cloned())
        }

        async fn search_users(
            &self,
            search: UserSearch,
            after: Option<Uuid>,
            page_size: usize,
        ) -> Result<IdentitySearchPage> {
            let mut records = self
                .records
                .read()
                .await
                .iter()
                .filter(|record| after.is_none_or(|value| record.id > value))
                .filter(|record| record_matches(record, &search))
                .cloned()
                .collect::<Vec<_>>();
            records.sort_by_key(|record| record.id);
            let next_after = (records.len() > page_size).then(|| records[page_size - 1].id);
            records.truncate(page_size);
            Ok(IdentitySearchPage {
                records,
                next_after,
            })
        }

        async fn update_profile(
            &self,
            user_id: Uuid,
            profile: AccountProfile,
        ) -> Result<IdentityRecord> {
            self.mutate(user_id, |record| {
                record.profile = profile;
                Ok(())
            })
            .await
        }

        async fn add_identifier(
            &self,
            user_id: Uuid,
            identifier: IdentifierValue,
            verified: bool,
        ) -> Result<IdentityRecord> {
            self.mutate(user_id, |record| {
                record.identifiers.push(AccountIdentifier {
                    kind: identifier.kind,
                    value: identifier.value,
                    verified,
                    verified_at: verified.then_some(1_700_000_100),
                    primary: false,
                    created_at: 1_700_000_100,
                });
                Ok(())
            })
            .await
        }

        async fn remove_identifier(
            &self,
            user_id: Uuid,
            identifier: IdentifierValue,
        ) -> Result<IdentityRecord> {
            self.mutate(user_id, |record| {
                let position = record
                    .identifiers
                    .iter()
                    .position(|stored| {
                        stored.kind == identifier.kind && stored.value == identifier.value
                    })
                    .ok_or(StorePolicyError::IdentifierNotLinked)?;
                record.identifiers.remove(position);
                Ok(())
            })
            .await
        }

        async fn set_primary_identifier(
            &self,
            user_id: Uuid,
            identifier: IdentifierValue,
        ) -> Result<IdentityRecord> {
            self.mutate(user_id, |record| {
                if !record.identifiers.iter().any(|stored| {
                    stored.kind == identifier.kind && stored.value == identifier.value
                }) {
                    return Err(StorePolicyError::IdentifierNotLinked.into());
                }
                for stored in &mut record.identifiers {
                    stored.primary =
                        stored.kind == identifier.kind && stored.value == identifier.value;
                }
                Ok(())
            })
            .await
        }

        async fn set_identifier_verification(
            &self,
            user_id: Uuid,
            identifier: IdentifierValue,
            verified: bool,
        ) -> Result<IdentityRecord> {
            self.mutate(user_id, |record| {
                let stored = record
                    .identifiers
                    .iter_mut()
                    .find(|stored| {
                        stored.kind == identifier.kind && stored.value == identifier.value
                    })
                    .ok_or(StorePolicyError::IdentifierNotLinked)?;
                stored.verified = verified;
                stored.verified_at = verified.then_some(1_700_000_200);
                Ok(())
            })
            .await
        }

        async fn rename_passkey(
            &self,
            user_id: Uuid,
            credential_id: String,
            label: String,
        ) -> Result<IdentityRecord> {
            self.mutate(user_id, |record| {
                let passkey = record
                    .passkeys
                    .iter_mut()
                    .find(|passkey| passkey.credential_id == credential_id)
                    .ok_or(StorePolicyError::CredentialNotLinked)?;
                passkey.label = label;
                Ok(())
            })
            .await
        }

        async fn revoke_passkey(
            &self,
            user_id: Uuid,
            credential_id: String,
        ) -> Result<IdentityRecord> {
            self.mutate(user_id, |record| {
                let position = record
                    .passkeys
                    .iter()
                    .position(|passkey| passkey.credential_id == credential_id)
                    .ok_or(StorePolicyError::CredentialNotLinked)?;
                record.passkeys.remove(position);
                Ok(())
            })
            .await
        }
    }

    fn record_matches(record: &IdentityRecord, search: &UserSearch) -> bool {
        search.user_id.is_none_or(|value| record.id == value)
            && search.identifier.as_ref().is_none_or(|value| {
                record
                    .identifiers
                    .iter()
                    .any(|stored| stored.kind == value.kind && stored.value == value.value)
            })
            && search.passkey_credential_id.as_ref().is_none_or(|value| {
                record
                    .passkeys
                    .iter()
                    .any(|stored| stored.credential_id == *value)
            })
            && search
                .passkey_label
                .as_ref()
                .is_none_or(|value| record.passkeys.iter().any(|stored| stored.label == *value))
            && search
                .given_name
                .as_ref()
                .is_none_or(|value| record.profile.given_name.as_ref() == Some(value))
            && search
                .family_name
                .as_ref()
                .is_none_or(|value| record.profile.family_name.as_ref() == Some(value))
            && search
                .display_name
                .as_ref()
                .is_none_or(|value| record.profile.display_name.as_ref() == Some(value))
    }

    fn fixture() -> IdentityRecord {
        IdentityRecord {
            id: Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            profile: AccountProfile {
                given_name: Some("Ada".into()),
                family_name: Some("Lovelace".into()),
                display_name: Some("Ada L.".into()),
            },
            identifiers: vec![
                AccountIdentifier {
                    kind: IdentifierKind::Email,
                    value: "ada@example.com".into(),
                    verified: true,
                    verified_at: Some(1_700_000_001),
                    primary: true,
                    created_at: 1_700_000_000,
                },
                AccountIdentifier {
                    kind: IdentifierKind::Phone,
                    value: "+447700900123".into(),
                    verified: true,
                    verified_at: Some(1_700_000_002),
                    primary: false,
                    created_at: 1_700_000_001,
                },
            ],
            passkeys: vec![
                PasskeyMetadata {
                    credential_id: "credential-one".into(),
                    label: "MacBook".into(),
                    created_at: 1_700_000_003,
                    last_used_at: Some(1_700_000_004),
                },
                PasskeyMetadata {
                    credential_id: "credential-two".into(),
                    label: "Security key".into(),
                    created_at: 1_700_000_005,
                    last_used_at: None,
                },
            ],
            created_at: 1_700_000_000,
        }
    }

    async fn spawn_test_service(
        source: MemoryIdentitySource,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let dispatcher = IdentityServiceServer::new(IdentityRpc::new(source));
        let service = ConnectRpcService::new(dispatcher).with_interceptor(RpcAuth::new(
            &secrecy::SecretString::from(EVENT_TOKEN),
            &secrecy::SecretString::from(IDENTITY_TOKEN),
        ));
        let app = axum::Router::new().fallback_service(service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind identity RPC test server");
        let address = listener.local_addr().expect("identity RPC test address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve identity RPC test server");
        });
        (format!("http://{address}"), server)
    }

    fn client(
        base_url: &str,
        protocol: Protocol,
        authorized: bool,
    ) -> IdentityServiceClient<HttpClient> {
        let transport = if protocol == Protocol::Grpc {
            HttpClient::plaintext_http2_only()
        } else {
            HttpClient::plaintext()
        };
        let mut config = ClientConfig::new(base_url.parse().expect("valid identity RPC URL"))
            .with_protocol(protocol)
            .with_default_timeout(std::time::Duration::from_secs(2));
        if authorized {
            config = config.with_default_header(
                http::header::AUTHORIZATION,
                format!("Bearer {IDENTITY_TOKEN}"),
            );
        }
        IdentityServiceClient::new(transport, config)
    }

    fn proto_identifier(kind: IdentifierType, value: &str) -> ProtoIdentifierValue {
        ProtoIdentifierValue {
            r#type: kind.into(),
            value: value.into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn identity_reads_and_searches_every_field_over_all_protocols() {
        for protocol in [Protocol::Connect, Protocol::GrpcWeb, Protocol::Grpc] {
            let record = fixture();
            let (base_url, server) =
                spawn_test_service(MemoryIdentitySource::new(vec![record.clone()])).await;
            let client = client(&base_url, protocol, true);
            let user = client
                .get_user(GetUserRequest {
                    user_id: record.id.to_string(),
                    ..Default::default()
                })
                .await
                .unwrap_or_else(|error| panic!("{protocol:?} GetUser failed: {error}"))
                .into_owned();
            assert_eq!(user.id, record.id.to_string());
            assert_eq!(user.profile.display_name, "Ada L.");
            assert_eq!(user.identifiers.len(), 2);
            assert_eq!(user.passkeys.len(), 2);
            let serialized = serde_json::to_string(&user).unwrap();
            assert!(!serialized.contains("publicKey"));
            assert!(!serialized.contains("counter"));
            assert!(!serialized.contains("passkey\""));

            let found = client
                .search_users(SearchUsersRequest {
                    user_id: record.id.to_string(),
                    identifier: buffa::MessageField::some(proto_identifier(
                        IdentifierType::Email,
                        "ADA@EXAMPLE.COM",
                    )),
                    passkey_credential_id: "credential-one".into(),
                    passkey_label: "MacBook".into(),
                    given_name: "Ada".into(),
                    family_name: "Lovelace".into(),
                    display_name: "Ada L.".into(),
                    page_size: 10,
                    ..Default::default()
                })
                .await
                .unwrap_or_else(|error| panic!("{protocol:?} SearchUsers failed: {error}"))
                .into_owned();
            assert_eq!(found.users.len(), 1);
            assert_eq!(found.users[0].id, record.id.to_string());
            server.abort();
        }
    }

    #[tokio::test]
    async fn identity_mutations_cover_profile_identifiers_and_passkey_metadata() {
        let record = fixture();
        let (base_url, server) =
            spawn_test_service(MemoryIdentitySource::new(vec![record.clone()])).await;
        let client = client(&base_url, Protocol::Connect, true);
        let user_id = record.id.to_string();

        let updated = client
            .update_profile(UpdateProfileRequest {
                user_id: user_id.clone(),
                profile: buffa::MessageField::some(ProtoProfile {
                    given_name: "Augusta Ada".into(),
                    family_name: "Lovelace".into(),
                    display_name: "Countess of Lovelace".into(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(updated.profile.given_name, "Augusta Ada");

        let added = client
            .add_identifier(AddIdentifierRequest {
                user_id: user_id.clone(),
                identifier: buffa::MessageField::some(proto_identifier(
                    IdentifierType::Email,
                    "ada+work@example.com",
                )),
                verified: true,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(added.identifiers.len(), 3);

        let mutation = IdentifierMutationRequest {
            user_id: user_id.clone(),
            identifier: buffa::MessageField::some(proto_identifier(
                IdentifierType::Email,
                "ada+work@example.com",
            )),
            ..Default::default()
        };
        let primary = client
            .set_primary_identifier(mutation.clone())
            .await
            .unwrap()
            .into_owned();
        assert!(
            primary
                .identifiers
                .iter()
                .any(|value| value.value == "ada+work@example.com" && value.primary)
        );
        let unverified = client
            .set_identifier_verification(SetIdentifierVerificationRequest {
                user_id: user_id.clone(),
                identifier: mutation.identifier.clone(),
                verified: false,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert!(
            unverified
                .identifiers
                .iter()
                .any(|value| value.value == "ada+work@example.com" && !value.verified)
        );
        let removed = client
            .remove_identifier(mutation)
            .await
            .unwrap()
            .into_owned();
        assert_eq!(removed.identifiers.len(), 2);

        let renamed = client
            .rename_passkey(RenamePasskeyRequest {
                user_id: user_id.clone(),
                credential_id: "credential-two".into(),
                label: "Travel key".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert!(
            renamed
                .passkeys
                .iter()
                .any(|value| value.label == "Travel key")
        );
        let revoked = client
            .revoke_passkey(RevokePasskeyRequest {
                user_id,
                credential_id: "credential-two".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(revoked.passkeys.len(), 1);
        server.abort();
    }

    #[test]
    fn empty_search_and_unsafe_metadata_are_rejected() {
        assert!(canonical_passkey_label("safe label").is_ok());
        assert!(canonical_passkey_label("unsafe\nlabel").is_err());
        assert!(canonical_credential_id("credential_123-abc").is_ok());
        assert!(canonical_credential_id("credential/id").is_err());
        assert!(decode_page_token("not-a-page-token").is_err());
    }

    #[tokio::test]
    async fn identity_wire_authentication_fails_closed() {
        let record = fixture();
        let (base_url, server) =
            spawn_test_service(MemoryIdentitySource::new(vec![record.clone()])).await;
        let error = client(&base_url, Protocol::Connect, false)
            .get_user(GetUserRequest {
                user_id: record.id.to_string(),
                ..Default::default()
            })
            .await
            .expect_err("missing identity bearer token must fail");
        assert_eq!(error.code, ErrorCode::Unauthenticated);
        server.abort();
    }
}
