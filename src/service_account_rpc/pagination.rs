//! Cursor pagination for service-account listings: bounded page sizes and
//! canonical, single-encoding page tokens.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use connectrpc::ConnectError;
use uuid::Uuid;

use super::errors::invalid_argument;

const DEFAULT_PAGE_SIZE: usize = 25;
const MAX_PAGE_SIZE: usize = 100;
/// Length of the canonical unpadded base64 encoding of a 16-byte identifier.
const PAGE_TOKEN_LENGTH: usize = 22;

pub(super) fn page_size(value: u32) -> Result<usize, ConnectError> {
    match value {
        0 => Ok(DEFAULT_PAGE_SIZE),
        value if value as usize <= MAX_PAGE_SIZE => Ok(value as usize),
        _ => Err(invalid_argument(format!(
            "page_size must not exceed {MAX_PAGE_SIZE}"
        ))),
    }
}

pub(super) fn encode_page_token(value: Uuid) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

/// The cursor carries no signature, so a caller-supplied token cannot be proven
/// to be one this server issued. Pinning it to the single canonical encoding of
/// a non-nil 16-byte identifier is everything that is checkable without a key,
/// and keeps a rewritten token from being decoded into some other cursor shape.
pub(super) fn decode_page_token(value: &str) -> Result<Option<Uuid>, ConnectError> {
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
    invalid_argument("invalid page_token")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_account_page_tokens_round_trip() {
        let id = Uuid::new_v4();
        assert_eq!(decode_page_token(&encode_page_token(id)).unwrap(), Some(id));
    }

    /// A cursor the server never minted must not be honoured just because it
    /// happens to decode. Without a signing key this is the widest rejection
    /// available, so it has to hold for every shape a caller can send.
    #[test]
    fn service_account_page_tokens_reject_everything_the_server_did_not_mint() {
        let token = encode_page_token(Uuid::new_v4());
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
