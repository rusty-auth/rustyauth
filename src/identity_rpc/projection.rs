//! Safe identity projection: domain users become `IdentityRecord` views and
//! proto users without any WebAuthn secret material.

use connectrpc::{ConnectError, ErrorCode};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    proto::rustyauth::identity::v1::{
        Identifier as ProtoIdentifier, IdentifierType, Passkey as ProtoPasskey,
        Profile as ProtoProfile, User as ProtoUser,
    },
    store::{AccountIdentifier, AccountProfile, IdentifierKind, User},
};

#[derive(Clone, Debug)]
pub(crate) struct PasskeyMetadata {
    pub(super) credential_id: String,
    pub(super) label: String,
    pub(super) created_at: u64,
    pub(super) last_used_at: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct IdentityRecord {
    pub(super) id: Uuid,
    pub(super) profile: AccountProfile,
    pub(super) identifiers: Vec<AccountIdentifier>,
    pub(super) passkeys: Vec<PasskeyMetadata>,
    pub(super) created_at: u64,
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
    pub(super) records: Vec<IdentityRecord>,
    pub(super) next_after: Option<Uuid>,
}

pub(crate) fn record_to_proto(record: IdentityRecord) -> Result<ProtoUser, ConnectError> {
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
