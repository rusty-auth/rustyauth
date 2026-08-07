//! ConnectRPC `IdentityService` handlers: validated requests flow through an
//! `IdentitySource` and only safe projections leave the boundary.

use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};

use crate::{
    proto::rustyauth::identity::v1::{
        AddIdentifierRequest, GetUserRequest, IdentifierMutationRequest, IdentityService,
        RenamePasskeyRequest, RevokePasskeyRequest, SearchUsersRequest, SearchUsersResponse,
        SetIdentifierVerificationRequest, UpdateProfileRequest, User as ProtoUser,
    },
    store::AccountProfile,
};

use super::{
    errors::{invalid_argument, source_error, user_not_found},
    projection::record_to_proto,
    source::IdentitySource,
    validation::{
        canonical_credential_id, canonical_passkey_label, decode_page_token, encode_page_token,
        optional_string, parse_identifier, parse_user_id, search_from_request,
    },
};

const DEFAULT_PAGE_SIZE: usize = 25;
const MAX_PAGE_SIZE: usize = 100;

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
        // Attaching an address and asserting the account controls it are separate
        // decisions at separate privilege levels. Honouring `verified` here would
        // let any Support-capable caller mint a trusted `email_verified` claim for
        // an address nobody owns, bypassing identity verification entirely.
        if request.verified {
            return Err(invalid_argument(
                "verified may not be set when adding an identifier; use SetIdentifierVerification",
            ));
        }
        let record = self
            .source
            .add_identifier(user_id, identifier, false)
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::Result;
    use connectrpc::{
        ConnectRpcService, ErrorCode, Protocol,
        client::{ClientConfig, HttpClient},
    };
    use tokio::sync::RwLock;
    use uuid::Uuid;

    use super::*;
    use crate::identity_rpc::projection::{IdentityRecord, IdentitySearchPage, PasskeyMetadata};
    use crate::proto::rustyauth::identity::v1::{
        IdentifierType, IdentifierValue as ProtoIdentifierValue, IdentityServiceClient,
        IdentityServiceServer, Profile as ProtoProfile,
    };
    use crate::rpc::RpcAuth;
    use crate::store::{
        AccountIdentifier, IdentifierKind, IdentifierValue, StorePolicyError, UserSearch,
    };

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

        // Attaching an address may never assert control of it in the same call.
        let escalation = client
            .add_identifier(AddIdentifierRequest {
                user_id: user_id.clone(),
                identifier: buffa::MessageField::some(proto_identifier(
                    IdentifierType::Email,
                    "ada+work@example.com",
                )),
                verified: true,
                ..Default::default()
            })
            .await;
        assert_eq!(
            escalation.err().map(|error| error.code),
            Some(ErrorCode::InvalidArgument),
            "AddIdentifier must refuse to mint a verified identifier"
        );

        let added = client
            .add_identifier(AddIdentifierRequest {
                user_id: user_id.clone(),
                identifier: buffa::MessageField::some(proto_identifier(
                    IdentifierType::Email,
                    "ada+work@example.com",
                )),
                verified: false,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(added.identifiers.len(), 3);
        assert!(
            added
                .identifiers
                .iter()
                .any(|value| value.value == "ada+work@example.com" && !value.verified),
            "a newly added identifier must start unverified"
        );

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
        // Identity proofing is operator-only. Reaching it with the service token
        // would make that token Owner-equivalent, because a verified allowlisted
        // address is exactly what browser operator bootstrap accepts.
        let proofing = client
            .set_identifier_verification(SetIdentifierVerificationRequest {
                user_id: user_id.clone(),
                identifier: mutation.identifier.clone(),
                verified: true,
                ..Default::default()
            })
            .await;
        assert_eq!(
            proofing.err().map(|error| error.code),
            Some(ErrorCode::Unauthenticated),
            "SetIdentifierVerification must not be reachable with the identity bearer token"
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
