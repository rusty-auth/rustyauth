//! Request-field validation for service-account RPCs: scope allowlisting,
//! bounded credential lifetimes, display-safe text and identifier parsing.

use std::collections::BTreeSet;

use connectrpc::ConnectError;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::store::now;

use super::errors::invalid_argument;

const MIN_CREDENTIAL_LIFETIME_SECONDS: u64 = 60;
/// A machine credential that outlives a rotation cycle is a standing key, not a
/// credential, so the API refuses to mint one however far ahead the caller asks.
const MAX_CREDENTIAL_LIFETIME_SECONDS: u64 = 365 * 24 * 60 * 60;
const ALLOWED_SCOPES: &[&str] = &[
    "events.read",
    "identity.read",
    "identity.write",
    "metrics.read",
    "webhooks.manage",
];

pub(super) fn validated_scopes<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<Vec<String>, ConnectError> {
    let scopes = validated_scopes_allow_empty(values)?;
    if scopes.is_empty() {
        return Err(invalid_argument("at least one scope is required"));
    }
    Ok(scopes)
}

pub(super) fn validated_scopes_allow_empty<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<Vec<String>, ConnectError> {
    let mut scopes = BTreeSet::new();
    for value in values {
        if !ALLOWED_SCOPES.contains(&value) {
            return Err(invalid_argument("unsupported service-account scope"));
        }
        scopes.insert(value.to_owned());
    }
    if scopes.len() > ALLOWED_SCOPES.len() {
        return Err(invalid_argument("too many service-account scopes"));
    }
    Ok(scopes.into_iter().collect())
}

pub(super) fn parse_expiry(value: &str) -> Result<Option<u64>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    let expiry = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| invalid_argument("expires_at must be an RFC3339 timestamp"))?;
    let expiry = u64::try_from(expiry.unix_timestamp())
        .map_err(|_| invalid_argument("expires_at must be after the Unix epoch"))?;
    let current = now();
    if expiry <= current.saturating_add(MIN_CREDENTIAL_LIFETIME_SECONDS) {
        return Err(invalid_argument(
            "expires_at must be at least one minute in the future",
        ));
    }
    // Without a ceiling a caller can post a year-9999 expiry and hold a permanent
    // secret that still reports an expiry date, so nothing ever forces rotation
    // and no report flags the credential as stale.
    if expiry > current.saturating_add(MAX_CREDENTIAL_LIFETIME_SECONDS) {
        return Err(invalid_argument(
            "expires_at must be within one year of now",
        ));
    }
    Ok(Some(expiry))
}

pub(super) fn safe_text(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<String, ConnectError> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > maximum
        || value.chars().any(crate::store::forbidden_display_character)
    {
        return Err(invalid_argument(format!(
            "{field} must contain 1-{maximum} safe characters"
        )));
    }
    Ok(value.to_owned())
}

pub(super) fn optional_safe_text(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<String, ConnectError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    safe_text(value, field, maximum)
}

pub(super) fn parse_id(value: &str, field: &'static str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(value).map_err(|_| invalid_argument(format!("{field} must be a UUID")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_account_rpc::projection::format_timestamp;

    #[test]
    fn scopes_are_allowlisted_sorted_and_unique() {
        assert_eq!(
            validated_scopes(["metrics.read", "identity.read", "metrics.read"].into_iter())
                .unwrap(),
            vec!["identity.read", "metrics.read"]
        );
        assert!(validated_scopes(["root"].into_iter()).is_err());
        assert!(validated_scopes(std::iter::empty()).is_err());
    }

    /// A far-future expiry is a permanent secret wearing an expiry policy:
    /// nothing forces rotation and no staleness report ever flags it. The
    /// ceiling therefore matters as much as the floor.
    #[test]
    fn credential_expiry_is_bounded_at_both_ends() {
        let current = now();
        assert!(parse_expiry("").unwrap().is_none());
        assert!(parse_expiry("not-a-timestamp").is_err());
        assert!(parse_expiry(&timestamp(current + 3_600)).unwrap().is_some());

        assert!(parse_expiry(&timestamp(current + 30)).is_err());
        assert!(parse_expiry(&timestamp(current.saturating_sub(3_600))).is_err());

        assert!(parse_expiry("9999-12-31T23:59:59Z").is_err());
        assert!(
            parse_expiry(&timestamp(
                current + MAX_CREDENTIAL_LIFETIME_SECONDS + 3_600
            ))
            .is_err()
        );
        assert!(
            parse_expiry(&timestamp(
                current + MAX_CREDENTIAL_LIFETIME_SECONDS - 3_600
            ))
            .unwrap()
            .is_some()
        );
    }

    fn timestamp(value: u64) -> String {
        format_timestamp(value).expect("format test timestamp")
    }
}
