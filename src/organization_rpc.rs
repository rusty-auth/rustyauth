//! Organization and operator views for the browser control plane.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    operator_auth::{OperatorActor, OperatorAuthorizer, OperatorCapability},
    proto::rustyauth::organization::v1::{
        AccountInvitation, AccountInvitationStatus, CreateAccountInvitationRequest,
        CreateAccountInvitationResponse, GetCurrentOperatorRequest, GetOrganizationRequest,
        ListAccountInvitationsRequest, ListAccountInvitationsResponse, ListOperatorsRequest,
        ListOperatorsResponse, Operator as ProtoOperator, OperatorRole, Organization,
        OrganizationService, RevokeAccountInvitationRequest, UpdateOrganizationRequest,
    },
    store::{
        AccountInvitationRecord, IdentifierKind, IdentifierValue, OperatorRecord,
        OperatorRoleRecord, OrganizationRecord, Store, User, now,
    },
};

const DEFAULT_PAGE_SIZE: usize = 25;
const MAX_PAGE_SIZE: usize = 100;
/// Length of the canonical unpadded base64 encoding of a 16-byte identifier.
const PAGE_TOKEN_LENGTH: usize = 22;

pub(crate) struct OrganizationRpc {
    store: Store,
    authorizer: OperatorAuthorizer,
}

impl OrganizationRpc {
    pub(crate) fn new(store: Store, authorizer: OperatorAuthorizer) -> Self {
        Self { store, authorizer }
    }
}

#[allow(refining_impl_trait)]
impl OrganizationService for OrganizationRpc {
    async fn get_organization(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, GetOrganizationRequest>,
    ) -> ServiceResult<Organization> {
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Read)
            .await?;
        let organization = self
            .store
            .organization()
            .await
            .map_err(source_error)?
            .ok_or_else(|| ConnectError::new(ErrorCode::NotFound, "organization is missing"))?;
        Response::ok(organization_to_proto(organization)?)
    }

    async fn get_current_operator(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, GetCurrentOperatorRequest>,
    ) -> ServiceResult<ProtoOperator> {
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Read)
            .await?;
        Response::ok(actor_to_proto(actor)?)
    }

    async fn update_organization(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateOrganizationRequest>,
    ) -> ServiceResult<Organization> {
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        let name = safe_text(request.name, "organization name", 120)?;
        let organization = self
            .store
            .update_organization(name)
            .await
            .map_err(source_error)?;
        Response::ok(organization_to_proto(organization)?)
    }

    async fn list_operators(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListOperatorsRequest>,
    ) -> ServiceResult<ListOperatorsResponse> {
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Read)
            .await?;
        let after = decode_page_token(request.page_token)?;
        let page_size = page_size(request.page_size)?;
        let mut operators = self.store.operators().await.map_err(source_error)?;
        // A revoked grant is retained in the store for audit but is not an operator.
        operators.retain(|listing| {
            listing.operator.revoked_at.is_none()
                && after.is_none_or(|after| listing.operator.user_id > after)
        });
        let next_page_token = (operators.len() > page_size)
            .then(|| encode_page_token(operators[page_size - 1].operator.user_id));
        operators.truncate(page_size);
        let operators = operators
            .into_iter()
            .map(|listing| {
                operator_to_proto(
                    listing.operator,
                    listing.user,
                    listing.last_authenticated_at,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Response::ok(ListOperatorsResponse {
            operators,
            next_page_token: next_page_token.unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn create_account_invitation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateAccountInvitationRequest>,
    ) -> ServiceResult<CreateAccountInvitationResponse> {
        let actor = self
            .authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        let identifier = invitation_identifier(request.identifier_type, request.identifier_value)?;
        let lifetime = if request.expires_in_seconds == 0 {
            86_400
        } else {
            request.expires_in_seconds
        };
        let (invitation, invitation_code) = self
            .store
            .create_account_invitation(identifier, actor.user.id, lifetime)
            .await
            .map_err(source_error)?;
        Response::ok(CreateAccountInvitationResponse {
            invitation: Some(invitation_to_proto(invitation)?).into(),
            invitation_code,
            ..Default::default()
        })
    }

    async fn list_account_invitations(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListAccountInvitationsRequest>,
    ) -> ServiceResult<ListAccountInvitationsResponse> {
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Read)
            .await?;
        let after = decode_page_token(request.page_token)?;
        let page_size = page_size(request.page_size)?;
        let mut invitations = self
            .store
            .account_invitations()
            .await
            .map_err(source_error)?;
        invitations.retain(|invitation| after.is_none_or(|after| invitation.id > after));
        invitations.sort_unstable_by_key(|invitation| invitation.id);
        let next_page_token = (invitations.len() > page_size)
            .then(|| encode_page_token(invitations[page_size - 1].id));
        invitations.truncate(page_size);
        Response::ok(ListAccountInvitationsResponse {
            invitations: invitations
                .into_iter()
                .map(invitation_to_proto)
                .collect::<Result<Vec<_>, _>>()?,
            next_page_token: next_page_token.unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn revoke_account_invitation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeAccountInvitationRequest>,
    ) -> ServiceResult<AccountInvitation> {
        self.authorizer
            .authorize(ctx.headers(), OperatorCapability::Administer)
            .await?;
        let id = Uuid::parse_str(request.invitation_id.trim()).map_err(|_| {
            ConnectError::new(ErrorCode::InvalidArgument, "invitation_id must be a UUID")
        })?;
        let invitation = self
            .store
            .revoke_account_invitation(id)
            .await
            .map_err(source_error)?;
        Response::ok(invitation_to_proto(invitation)?)
    }
}

fn invitation_identifier(kind: &str, value: &str) -> Result<IdentifierValue, ConnectError> {
    let kind = match kind.trim().to_ascii_lowercase().as_str() {
        "email" => IdentifierKind::Email,
        "phone" => IdentifierKind::Phone,
        _ => {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "identifier_type must be email or phone",
            ));
        }
    };
    IdentifierValue::canonical(kind, value).map_err(|_| {
        ConnectError::new(
            ErrorCode::InvalidArgument,
            "identifier_value is not valid for identifier_type",
        )
    })
}

fn invitation_to_proto(record: AccountInvitationRecord) -> Result<AccountInvitation, ConnectError> {
    let current = now();
    let status = if record.revoked_at.is_some() {
        AccountInvitationStatus::Revoked
    } else if record.consumed_at.is_some() {
        AccountInvitationStatus::Consumed
    } else if record.expires_at <= current {
        AccountInvitationStatus::Expired
    } else {
        AccountInvitationStatus::Pending
    };
    Ok(AccountInvitation {
        id: record.id.to_string(),
        identifier_type: record.identifier.kind.as_str().to_owned(),
        identifier_value: record.identifier.value,
        created_by: record.created_by.to_string(),
        created_at: format_timestamp(record.created_at)?,
        expires_at: format_timestamp(record.expires_at)?,
        consumed_at: optional_timestamp(record.consumed_at)?,
        revoked_at: optional_timestamp(record.revoked_at)?,
        status: status.into(),
        ..Default::default()
    })
}

fn optional_timestamp(value: Option<u64>) -> Result<String, ConnectError> {
    value
        .map(format_timestamp)
        .transpose()
        .map(Option::unwrap_or_default)
}

fn actor_to_proto(actor: OperatorActor) -> Result<ProtoOperator, ConnectError> {
    // The actor just authenticated, so its own view reports now.
    operator_to_proto(actor.operator, actor.user, Some(now()))
}

fn operator_to_proto(
    operator: OperatorRecord,
    user: User,
    last_authenticated_at: Option<u64>,
) -> Result<ProtoOperator, ConnectError> {
    let email = user
        .primary_email()
        .map(|identifier| identifier.value.clone())
        .unwrap_or_default();
    let display_name = user
        .profile
        .display_name
        .clone()
        .or_else(|| {
            let name = [
                user.profile.given_name.as_deref(),
                user.profile.family_name.as_deref(),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
            (!name.is_empty()).then_some(name)
        })
        .unwrap_or_else(|| email.clone());
    Ok(ProtoOperator {
        id: operator.user_id.to_string(),
        email,
        display_name,
        role: match operator.role {
            OperatorRoleRecord::Owner => OperatorRole::Owner.into(),
            OperatorRoleRecord::Administrator => OperatorRole::Administrator.into(),
            OperatorRoleRecord::Support => OperatorRole::Support.into(),
            OperatorRoleRecord::Auditor => OperatorRole::Auditor.into(),
        },
        created_at: format_timestamp(operator.created_at)?,
        last_authenticated_at: match last_authenticated_at {
            Some(seen) => format_timestamp(seen)?,
            None => String::new(),
        },
        ..Default::default()
    })
}

fn organization_to_proto(record: OrganizationRecord) -> Result<Organization, ConnectError> {
    Ok(Organization {
        id: record.id.to_string(),
        slug: record.slug,
        name: record.name,
        created_at: format_timestamp(record.created_at)?,
        ..Default::default()
    })
}

fn safe_text(value: &str, field: &'static str, maximum: usize) -> Result<String, ConnectError> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > maximum
        || value.chars().any(crate::store::forbidden_display_character)
    {
        return Err(ConnectError::new(
            ErrorCode::InvalidArgument,
            format!("{field} must contain 1-{maximum} safe characters"),
        ));
    }
    Ok(value.to_owned())
}

fn page_size(value: u32) -> Result<usize, ConnectError> {
    match value {
        0 => Ok(DEFAULT_PAGE_SIZE),
        value if value as usize <= MAX_PAGE_SIZE => Ok(value as usize),
        _ => Err(ConnectError::new(
            ErrorCode::InvalidArgument,
            format!("page_size must not exceed {MAX_PAGE_SIZE}"),
        )),
    }
}

fn format_timestamp(value: u64) -> Result<String, ConnectError> {
    let value = i64::try_from(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "stored timestamp is invalid"))?;
    OffsetDateTime::from_unix_timestamp(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "stored timestamp is invalid"))?
        .format(&Rfc3339)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "format operator timestamp"))
}

fn encode_page_token(value: Uuid) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

/// The cursor carries no signature, so a caller-supplied token cannot be proven
/// to be one this server issued. Pinning it to the single canonical encoding of
/// a non-nil 16-byte identifier is everything that is checkable without a key,
/// and keeps a rewritten token from being decoded into some other cursor shape.
fn decode_page_token(value: &str) -> Result<Option<Uuid>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() != PAGE_TOKEN_LENGTH {
        return Err(invalid_page_token());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid_page_token())?;
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| invalid_page_token())?;
    if URL_SAFE_NO_PAD.encode(bytes) != value {
        return Err(invalid_page_token());
    }
    let id = Uuid::from_bytes(bytes);
    if id.is_nil() {
        return Err(invalid_page_token());
    }
    Ok(Some(id))
}

fn invalid_page_token() -> ConnectError {
    ConnectError::new(ErrorCode::InvalidArgument, "invalid page_token")
}

fn source_error(error: anyhow::Error) -> ConnectError {
    tracing::error!(error = %error, "organization RPC failed");
    ConnectError::new(ErrorCode::Internal, "organization operation failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_names_and_page_tokens_are_bounded() {
        assert_eq!(
            safe_text("  RustyAuth  ", "name", 120).unwrap(),
            "RustyAuth"
        );
        assert!(safe_text("", "name", 120).is_err());
        let id = Uuid::new_v4();
        assert_eq!(decode_page_token(&encode_page_token(id)).unwrap(), Some(id));
        assert!(page_size(101).is_err());
    }

    /// A cursor the server never minted must not be honoured just because it
    /// happens to decode. Without a signing key this is the widest rejection
    /// available, so it has to hold for every shape a caller can send.
    #[test]
    fn page_tokens_reject_everything_the_server_did_not_mint() {
        let id = Uuid::new_v4();
        let token = encode_page_token(id);
        assert_eq!(decode_page_token(&token).unwrap(), Some(id));
        assert_eq!(decode_page_token("").unwrap(), None);

        assert!(decode_page_token(&URL_SAFE_NO_PAD.encode(Uuid::nil().as_bytes())).is_err());
        assert!(decode_page_token("not-a-page-token").is_err());
        assert!(decode_page_token(&token[..PAGE_TOKEN_LENGTH - 1]).is_err());
        assert!(decode_page_token(&format!("{token}A")).is_err());
        assert!(decode_page_token(&URL_SAFE_NO_PAD.encode([7u8; 8])).is_err());
        assert!(decode_page_token(&URL_SAFE_NO_PAD.encode([7u8; 24])).is_err());
        assert!(decode_page_token(&format!("{}=", &token[..PAGE_TOKEN_LENGTH - 1])).is_err());
    }
}
