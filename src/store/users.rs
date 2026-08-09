//! Account records: users, identifiers, profiles and operator search.

mod identifiers;
mod profile;
mod records;
mod search;

pub use self::identifiers::{
    AccountIdentifier, IdentifierKind, IdentifierValidationError, IdentifierValue,
};
pub(crate) use self::profile::forbidden_display_character;
pub use self::profile::{AccountProfile, ProfileValidationError};
pub use self::records::{RecoveryCodeRecord, User};
pub use self::search::{UserSearch, UserSearchPage};
