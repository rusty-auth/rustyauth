//! Error construction shared by the service-account RPC: generic response
//! mapping that keeps precise failure context out of client-visible answers.

use connectrpc::{ConnectError, ErrorCode};

use crate::store::StorePolicyError;

pub(super) fn source_error(error: anyhow::Error) -> ConnectError {
    if let Some(policy) = error.downcast_ref::<StorePolicyError>() {
        return match policy {
            StorePolicyError::ServiceAccountMissing
            | StorePolicyError::ServiceCredentialMissing => {
                ConnectError::new(ErrorCode::NotFound, policy.to_string())
            }
            StorePolicyError::InvalidServiceCredential => {
                ConnectError::new(ErrorCode::Unauthenticated, "service credential is invalid")
            }
            StorePolicyError::ServiceScopeDenied => {
                ConnectError::new(ErrorCode::PermissionDenied, policy.to_string())
            }
            _ => ConnectError::new(ErrorCode::FailedPrecondition, policy.to_string()),
        };
    }
    tracing::error!(error = %error, "service-account RPC failed");
    ConnectError::new(ErrorCode::Internal, "service-account operation failed")
}

/// Collapses every policy failure of credential exchange into one answer.
///
/// This is the only unauthenticated RPC. A caller that can tell "no such
/// credential" from "revoked", "expired", "account disabled" or "scope not
/// held" can confirm a stolen secret and map an account's grant without ever
/// obtaining a token, so the endpoint must not distinguish them.
pub(super) fn invalid_argument(message: impl Into<String>) -> ConnectError {
    ConnectError::new(ErrorCode::InvalidArgument, message)
}
