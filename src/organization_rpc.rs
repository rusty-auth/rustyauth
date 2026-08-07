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
        GetCurrentOperatorRequest, GetOrganizationRequest, ListOperatorsRequest,
        ListOperatorsResponse, Operator as ProtoOperator, OperatorRole, Organization,
        OrganizationService, UpdateOrganizationRequest,
    },
    store::{OperatorRecord, OperatorRoleRecord, OrganizationRecord, Store, User},
};

const DEFAULT_PAGE_SIZE: usize = 25;
const MAX_PAGE_SIZE: usize = 100;

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
        operators.retain(|(operator, _)| after.is_none_or(|after| operator.user_id > after));
        let next_page_token = (operators.len() > page_size)
            .then(|| encode_page_token(operators[page_size - 1].0.user_id));
        operators.truncate(page_size);
        let operators = operators
            .into_iter()
            .map(|(operator, user)| operator_to_proto(operator, user))
            .collect::<Result<Vec<_>, _>>()?;
        Response::ok(ListOperatorsResponse {
            operators,
            next_page_token: next_page_token.unwrap_or_default(),
            ..Default::default()
        })
    }
}

fn actor_to_proto(actor: OperatorActor) -> Result<ProtoOperator, ConnectError> {
    operator_to_proto(actor.operator, actor.user)
}

fn operator_to_proto(operator: OperatorRecord, user: User) -> Result<ProtoOperator, ConnectError> {
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
        last_authenticated_at: format_timestamp(operator.last_authenticated_at)?,
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

fn decode_page_token(value: &str) -> Result<Option<Uuid>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ConnectError::new(ErrorCode::InvalidArgument, "invalid page_token"))?;
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| ConnectError::new(ErrorCode::InvalidArgument, "invalid page_token"))?;
    Ok(Some(Uuid::from_bytes(bytes)))
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
}
