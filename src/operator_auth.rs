//! Passkey-session authorization for the browser control plane.

use std::{collections::HashSet, sync::Arc};

use connectrpc::{ConnectError, ErrorCode};
use http::{HeaderMap, header};

use crate::store::{OperatorRecord, OperatorRoleRecord, Store, User};

const SESSION_COOKIE: &str = "passkey_auth_session";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperatorCapability {
    Read,
    Support,
    Administer,
}

#[derive(Clone, Debug)]
pub(crate) struct OperatorActor {
    pub(crate) user: User,
    pub(crate) operator: OperatorRecord,
}

#[derive(Clone)]
pub(crate) struct OperatorAuthorizer {
    store: Store,
    origin: String,
    session_idle_seconds: u64,
    bootstrap_emails: Arc<HashSet<String>>,
}

impl OperatorAuthorizer {
    pub(crate) fn new(
        store: Store,
        origin: String,
        session_idle_seconds: u64,
        bootstrap_emails: Vec<String>,
    ) -> Self {
        Self {
            store,
            origin: origin.trim_end_matches('/').to_owned(),
            session_idle_seconds,
            bootstrap_emails: Arc::new(bootstrap_emails.into_iter().collect()),
        }
    }

    pub(crate) async fn authorize(
        &self,
        headers: &HeaderMap,
        capability: OperatorCapability,
    ) -> Result<OperatorActor, ConnectError> {
        let origin = headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok());
        if origin != Some(self.origin.as_str()) {
            return Err(permission_denied("request origin is not allowed"));
        }
        let raw = session_cookie(headers)
            .ok_or_else(|| unauthenticated("passkey operator session required"))?;
        let (session, user) = self
            .store
            .session(raw, self.session_idle_seconds)
            .await
            .map_err(internal)?
            .ok_or_else(|| unauthenticated("passkey operator session required"))?;
        if session.auth_method != "passkey" {
            return Err(unauthenticated("passkey operator session required"));
        }
        let bootstrap_allowed = user
            .primary_email()
            .is_some_and(|identifier| self.bootstrap_emails.contains(&identifier.value));
        let operator = self
            .store
            .ensure_operator(&user, bootstrap_allowed)
            .await
            .map_err(internal)?
            .ok_or_else(|| permission_denied("account is not a RustyAuth operator"))?;
        if !allows(operator.role, capability) {
            return Err(permission_denied(
                "operator role does not permit this action",
            ));
        }
        Ok(OperatorActor { user, operator })
    }
}

fn allows(role: OperatorRoleRecord, capability: OperatorCapability) -> bool {
    match capability {
        OperatorCapability::Read => true,
        OperatorCapability::Support => matches!(
            role,
            OperatorRoleRecord::Owner
                | OperatorRoleRecord::Administrator
                | OperatorRoleRecord::Support
        ),
        OperatorCapability::Administer => matches!(
            role,
            OperatorRoleRecord::Owner | OperatorRoleRecord::Administrator
        ),
    }
}

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&format!("{SESSION_COOKIE}=")))
}

fn unauthenticated(message: &'static str) -> ConnectError {
    ConnectError::new(ErrorCode::Unauthenticated, message)
}

fn permission_denied(message: &'static str) -> ConnectError {
    ConnectError::new(ErrorCode::PermissionDenied, message)
}

fn internal(error: impl std::fmt::Display) -> ConnectError {
    tracing::error!(error = %error, "operator authorization failed");
    ConnectError::new(ErrorCode::Internal, "operator authorization failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_least_privilege() {
        assert!(allows(
            OperatorRoleRecord::Auditor,
            OperatorCapability::Read
        ));
        assert!(!allows(
            OperatorRoleRecord::Auditor,
            OperatorCapability::Support
        ));
        assert!(allows(
            OperatorRoleRecord::Support,
            OperatorCapability::Support
        ));
        assert!(!allows(
            OperatorRoleRecord::Support,
            OperatorCapability::Administer
        ));
        assert!(allows(
            OperatorRoleRecord::Owner,
            OperatorCapability::Administer
        ));
    }

    #[test]
    fn session_cookie_is_exact() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "other=x; passkey_auth_session=correct; suffix=y"
                .parse()
                .unwrap(),
        );
        assert_eq!(session_cookie(&headers), Some("correct"));
    }
}
