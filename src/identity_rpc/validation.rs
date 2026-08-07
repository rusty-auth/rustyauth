//! Zero-copy request validation: identifier, profile and passkey-metadata
//! canonicalization plus opaque page-token parsing for the identity RPC.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use connectrpc::ConnectError;
use uuid::Uuid;

use crate::{
    proto::rustyauth::identity::v1::IdentifierType,
    store::{AccountProfile, IdentifierKind, IdentifierValue, UserSearch},
};

use super::errors::invalid_argument;

pub(super) fn search_from_request(
    request: &SearchUsersRequestView<'_>,
) -> Result<UserSearch, ConnectError> {
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

pub(super) fn parse_user_id(value: &str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(value).map_err(|_| invalid_argument("user_id must be a UUID"))
}

pub(super) fn parse_identifier(
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

pub(super) fn optional_string(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

pub(super) fn canonical_credential_id(value: &str) -> Result<String, ConnectError> {
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

pub(super) fn canonical_passkey_label(value: &str) -> Result<String, ConnectError> {
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

pub(super) fn encode_page_token(value: Uuid) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

pub(super) fn decode_page_token(value: &str) -> Result<Option<Uuid>, ConnectError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_search_and_unsafe_metadata_are_rejected() {
        assert!(canonical_passkey_label("safe label").is_ok());
        assert!(canonical_passkey_label("unsafe\nlabel").is_err());
        assert!(canonical_credential_id("credential_123-abc").is_ok());
        assert!(canonical_credential_id("credential/id").is_err());
        assert!(decode_page_token("not-a-page-token").is_err());
    }
}
