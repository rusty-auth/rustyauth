//! Canonical forms shared across handler modules: identifiers, profiles and
//! public RFC 3339 timestamps.

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::store::{AccountProfile, IdentifierKind, IdentifierValue};

use super::{dto::IdentifierRequest, error::ApiError};

pub(super) fn lookup_identifier_ref(
    identifier: Option<&IdentifierRequest>,
    email: Option<&str>,
    phone: Option<&str>,
) -> Result<IdentifierValue, ApiError> {
    let supplied = usize::from(identifier.is_some())
        + usize::from(email.is_some())
        + usize::from(phone.is_some());
    if supplied != 1 {
        return Err(ApiError::bad_request(
            "provide exactly one email or phone identifier",
        ));
    }
    if let Some(identifier) = identifier {
        return canonical_identifier(identifier.kind, &identifier.value);
    }
    if let Some(email) = email {
        return canonical_identifier(IdentifierKind::Email, email);
    }
    canonical_identifier(
        IdentifierKind::Phone,
        phone.expect("one identifier was validated above"),
    )
}

pub(super) fn canonical_identifier(
    kind: IdentifierKind,
    value: &str,
) -> Result<IdentifierValue, ApiError> {
    IdentifierValue::canonical(kind, value)
        .map_err(|error| ApiError::bad_request(error.to_string()))
}

pub(super) fn canonical_email(value: &str) -> Result<String, ApiError> {
    Ok(canonical_identifier(IdentifierKind::Email, value)?.value)
}

#[cfg(test)]
fn canonical_phone(value: &str) -> Result<String, ApiError> {
    Ok(canonical_identifier(IdentifierKind::Phone, value)?.value)
}

pub(super) fn account_profile(
    given_name: Option<String>,
    family_name: Option<String>,
    display_name: Option<String>,
) -> Result<AccountProfile, ApiError> {
    AccountProfile::canonical(given_name, family_name, display_name)
        .map_err(|error| ApiError::bad_request(error.to_string()))
}

pub(super) fn timestamp(value: u64) -> String {
    OffsetDateTime::from_unix_timestamp(value as i64)
        .ok()
        .and_then(|value| value.format(&Rfc3339).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        account_profile, canonical_email, canonical_phone, lookup_identifier_ref, timestamp,
    };
    use crate::{auth::dto::IdentifierRequest, store::IdentifierKind};

    #[test]
    fn credential_dates_are_rfc3339() {
        assert_eq!(timestamp(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn phone_numbers_are_normalized_to_e164() {
        assert_eq!(
            canonical_phone(" +44 (7700) 900-123 ").unwrap(),
            "+447700900123"
        );
        assert!(canonical_phone("07700 900123").is_err());
        assert!(canonical_phone("+0123456789").is_err());
        assert!(canonical_phone("+1234567").is_err());
        assert!(canonical_phone("+1234567890123456").is_err());
    }

    #[test]
    fn emails_use_a_strict_ascii_dot_atom_profile() {
        assert_eq!(
            canonical_email(" Ada.Lovelace+alerts@Example.COM ").unwrap(),
            "ada.lovelace+alerts@example.com"
        );
        for invalid in [
            "a@@example.com",
            "a b@example.com",
            "é@example.com",
            ".a@example.com",
            "a..b@example.com",
            "a@-example.com",
            "a@example-.com",
            "a@example..com",
        ] {
            assert!(canonical_email(invalid).is_err(), "accepted {invalid}");
        }
        assert!(canonical_email(&format!("a@{}.test", "x".repeat(64))).is_err());
    }

    #[test]
    fn identifier_input_is_unambiguous_and_backwards_compatible() {
        let email = lookup_identifier_ref(None, Some(" Person@Example.com "), None).unwrap();
        assert_eq!(email.kind, IdentifierKind::Email);
        assert_eq!(email.value, "person@example.com");

        let phone = IdentifierRequest {
            kind: IdentifierKind::Phone,
            value: "+44 7700 900123".into(),
        };
        assert_eq!(
            lookup_identifier_ref(Some(&phone), None, None)
                .unwrap()
                .value,
            "+447700900123"
        );
        assert!(lookup_identifier_ref(None, None, None).is_err());
        assert!(lookup_identifier_ref(Some(&phone), Some("a@b.test"), None).is_err());
    }

    #[test]
    fn basic_profile_names_are_trimmed_and_bounded() {
        let profile = account_profile(
            Some(" Ada ".into()),
            Some(" Lovelace ".into()),
            Some(" ".into()),
        )
        .unwrap();
        assert_eq!(profile.given_name.as_deref(), Some("Ada"));
        assert_eq!(profile.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(profile.display_name, None);
        assert!(account_profile(Some("bad\nname".into()), None, None).is_err());
        assert!(account_profile(Some("bad\u{200b}name".into()), None, None).is_err());
        assert!(account_profile(None, None, Some("bad\u{202e}name".into())).is_err());
        assert!(account_profile(Some("x".repeat(101)), None, None).is_err());
    }
}
