//! Proto/domain projections for service accounts: status enum parsing and safe
//! record-to-proto conversion.

use connectrpc::{ConnectError, ErrorCode};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    proto::rustyauth::service_accounts::v1::{
        ServiceAccount as ProtoServiceAccount, ServiceAccountCredential as ProtoCredential,
        ServiceAccountStatus,
    },
    store::{ServiceAccountCredentialRecord, ServiceAccountRecord, ServiceAccountStatusRecord},
};

use super::errors::invalid_argument;

pub(super) fn parse_optional_status(
    value: i32,
) -> Result<Option<ServiceAccountStatusRecord>, ConnectError> {
    match value {
        value if value == ServiceAccountStatus::Unspecified as i32 => Ok(None),
        value if value == ServiceAccountStatus::Active as i32 => {
            Ok(Some(ServiceAccountStatusRecord::Active))
        }
        value if value == ServiceAccountStatus::Disabled as i32 => {
            Ok(Some(ServiceAccountStatusRecord::Disabled))
        }
        _ => Err(invalid_argument("invalid service-account status")),
    }
}

pub(super) fn parse_required_status(
    value: i32,
) -> Result<ServiceAccountStatusRecord, ConnectError> {
    parse_optional_status(value)?
        .ok_or_else(|| invalid_argument("service-account status is required"))
}

pub(super) fn service_account_to_proto(
    account: ServiceAccountRecord,
) -> Result<ProtoServiceAccount, ConnectError> {
    let credentials = account
        .credentials
        .into_iter()
        .map(credential_to_proto)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ProtoServiceAccount {
        id: account.id.to_string(),
        name: account.name,
        description: account.description,
        status: match account.status {
            ServiceAccountStatusRecord::Active => ServiceAccountStatus::Active.into(),
            ServiceAccountStatusRecord::Disabled => ServiceAccountStatus::Disabled.into(),
        },
        scopes: account.scopes,
        credentials,
        created_at: format_timestamp(account.created_at)?,
        created_by: account.created_by.to_string(),
        last_used_at: account
            .last_used_at
            .map(format_timestamp)
            .transpose()?
            .unwrap_or_default(),
        ..Default::default()
    })
}

pub(super) fn credential_to_proto(
    credential: ServiceAccountCredentialRecord,
) -> Result<ProtoCredential, ConnectError> {
    Ok(ProtoCredential {
        id: credential.id.to_string(),
        name: credential.name,
        secret_hint: credential.secret_hint,
        created_at: format_timestamp(credential.created_at)?,
        expires_at: credential
            .expires_at
            .map(format_timestamp)
            .transpose()?
            .unwrap_or_default(),
        last_used_at: credential
            .last_used_at
            .map(format_timestamp)
            .transpose()?
            .unwrap_or_default(),
        revoked_at: credential
            .revoked_at
            .map(format_timestamp)
            .transpose()?
            .unwrap_or_default(),
        ..Default::default()
    })
}

pub(super) fn format_timestamp(value: u64) -> Result<String, ConnectError> {
    let value = i64::try_from(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "stored timestamp is invalid"))?;
    OffsetDateTime::from_unix_timestamp(value)
        .map_err(|_| ConnectError::new(ErrorCode::DataLoss, "stored timestamp is invalid"))?
        .format(&Rfc3339)
        .map_err(|_| ConnectError::new(ErrorCode::Internal, "format service-account timestamp"))
}
