//! Failure mapping: store policy and internal errors become generic ConnectRPC
//! responses while precise context stays in server logs.

use connectrpc::{ConnectError, ErrorCode};

use crate::store::StorePolicyError;

pub(super) fn source_error(error: anyhow::Error) -> ConnectError {
    if let Some(policy) = error.downcast_ref::<StorePolicyError>() {
        return match policy {
            StorePolicyError::UserMissing => user_not_found(),
            StorePolicyError::IdentifierAlreadyExists
            | StorePolicyError::CredentialAlreadyExists => {
                ConnectError::new(ErrorCode::AlreadyExists, policy.to_string())
            }
            StorePolicyError::IdentifierLimit => {
                ConnectError::new(ErrorCode::ResourceExhausted, policy.to_string())
            }
            StorePolicyError::IdentifierNotLinked | StorePolicyError::CredentialNotLinked => {
                ConnectError::new(ErrorCode::NotFound, policy.to_string())
            }
            StorePolicyError::FinalIdentifier | StorePolicyError::FinalCredential => {
                ConnectError::new(ErrorCode::FailedPrecondition, policy.to_string())
            }
            _ => {
                tracing::error!("identity RPC received an unrelated store policy failure");
                ConnectError::new(ErrorCode::Unavailable, "identity store unavailable")
            }
        };
    }
    tracing::error!("identity RPC persistence operation failed");
    ConnectError::new(ErrorCode::Unavailable, "identity store unavailable")
}

pub(super) fn invalid_argument(message: impl Into<String>) -> ConnectError {
    ConnectError::new(ErrorCode::InvalidArgument, message)
}

pub(super) fn user_not_found() -> ConnectError {
    ConnectError::new(ErrorCode::NotFound, "user not found")
}
