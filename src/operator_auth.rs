//! Passkey-session authorization for the browser control plane.

use std::{collections::HashSet, sync::Arc};

use connectrpc::{ConnectError, ErrorCode};
use http::{HeaderMap, header};
use uuid::Uuid;

use crate::store::{
    FleetResourceKindRecord, FleetRoleRecord, IdentifierKind, OperatorRecord, OperatorRoleRecord,
    Session, Store, User, now,
};

const STEP_UP_SECONDS: u64 = 300;

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
    pub(crate) session: Session,
}

#[derive(Clone)]
pub(crate) struct OperatorAuthorizer {
    store: Store,
    origin: String,
    session_idle_seconds: u64,
    secure_cookie: bool,
    bootstrap_emails: Arc<HashSet<String>>,
}

impl OperatorAuthorizer {
    pub(crate) fn new(
        store: Store,
        origin: String,
        session_idle_seconds: u64,
        secure_cookie: bool,
        bootstrap_emails: Vec<String>,
    ) -> Self {
        Self {
            store,
            origin: origin.trim_end_matches('/').to_owned(),
            session_idle_seconds,
            secure_cookie,
            bootstrap_emails: Arc::new(bootstrap_emails.into_iter().collect()),
        }
    }

    pub(crate) async fn authorize(
        &self,
        headers: &HeaderMap,
        capability: OperatorCapability,
    ) -> Result<OperatorActor, ConnectError> {
        let actor = self.authenticate(headers).await?;
        if !allows(actor.operator.role, capability) {
            return Err(operator_denied(
                actor.user.id,
                OperatorDenial::RoleLacksCapability(actor.operator.role, capability),
            ));
        }
        require_step_up_for(capability, &actor.session)?;
        Ok(actor)
    }

    pub(crate) async fn authorize_fleet(
        &self,
        headers: &HeaderMap,
        capability: OperatorCapability,
        resource_kind: FleetResourceKindRecord,
        resource_id: Uuid,
    ) -> Result<OperatorActor, ConnectError> {
        let actor = self.authenticate(headers).await?;
        if allows(actor.operator.role, capability) {
            require_step_up_for(capability, &actor.session)?;
            return Ok(actor);
        }
        let delegated = self
            .store
            .fleet_effective_role(actor.user.id, resource_kind, resource_id)
            .await
            .map_err(internal)?;
        if delegated.is_some_and(|role| fleet_allows(role, capability)) {
            require_step_up_for(capability, &actor.session)?;
            return Ok(actor);
        }
        Err(operator_denied(
            actor.user.id,
            OperatorDenial::RoleLacksCapability(actor.operator.role, capability),
        ))
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<OperatorActor, ConnectError> {
        let origin = headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok());
        let device = device_bearer(headers);
        let (raw, expected_method) = match device {
            Some(raw) => {
                // Browser JavaScript must stay on the HttpOnly cookie path. A
                // bearer carrying Origin is either leaked or an integration
                // mistake; accepting it would turn the native handoff into a
                // browser-readable long-lived credential pattern.
                if origin.is_some() {
                    return Err(permission_denied(
                        "device sessions are not accepted by browsers",
                    ));
                }
                (raw, "device")
            }
            None => {
                if origin != Some(self.origin.as_str()) {
                    return Err(permission_denied("request origin is not allowed"));
                }
                let raw = session_cookie(headers, self.secure_cookie)
                    .ok_or_else(|| unauthenticated("passkey operator session required"))?;
                (raw, "passkey")
            }
        };
        let (session, user) = self
            .store
            .session(raw, self.session_idle_seconds)
            .await
            .map_err(internal)?
            .ok_or_else(|| unauthenticated("passkey operator session required"))?;
        if session.auth_method != expected_method {
            return Err(unauthenticated("passkey operator session required"));
        }
        let allowed = bootstrap_allowed(&user, &self.bootstrap_emails);
        let Some(operator) = self
            .store
            .ensure_operator(&user, allowed)
            .await
            .map_err(internal)?
        else {
            return Err(operator_denied(user.id, OperatorDenial::NotAnOperator));
        };
        Ok(OperatorActor {
            user,
            operator,
            session,
        })
    }

    /// Rejects mutations against an operator whose global role outranks the
    /// actor. Non-operator accounts have no privileged role to dominate.
    pub(crate) async fn require_target_dominance(
        &self,
        actor: &OperatorActor,
        target_user_id: Uuid,
    ) -> Result<(), ConnectError> {
        if actor.user.id == target_user_id {
            return Ok(());
        }
        let target = self
            .store
            .operator(target_user_id)
            .await
            .map_err(internal)?;
        if target.is_some_and(|target| {
            operator_role_rank(actor.operator.role) > operator_role_rank(target.role)
        }) {
            return Err(permission_denied(
                "operator role does not dominate the target account",
            ));
        }
        Ok(())
    }

    /// Returns whether this actor may create, update, or revoke a scoped Fleet
    /// role. Global and delegated roles use the same dominance ordering.
    pub(crate) async fn require_fleet_role_dominance(
        &self,
        actor: &OperatorActor,
        resource_kind: FleetResourceKindRecord,
        resource_id: Uuid,
        target_role: FleetRoleRecord,
    ) -> Result<(), ConnectError> {
        let actor_role = match actor.operator.role {
            OperatorRoleRecord::Owner => FleetRoleRecord::Owner,
            OperatorRoleRecord::Administrator => FleetRoleRecord::Administrator,
            OperatorRoleRecord::Support | OperatorRoleRecord::Auditor => self
                .store
                .fleet_effective_role(actor.user.id, resource_kind, resource_id)
                .await
                .map_err(internal)?
                .ok_or_else(|| permission_denied("operator access denied"))?,
        };
        if fleet_role_rank(actor_role) > fleet_role_rank(target_role) {
            return Err(permission_denied(
                "operator role does not dominate the requested Fleet role",
            ));
        }
        Ok(())
    }
}

fn require_step_up_for(
    capability: OperatorCapability,
    session: &Session,
) -> Result<(), ConnectError> {
    if capability != OperatorCapability::Administer {
        return Ok(());
    }
    let current = now();
    if session.step_up_at.is_some_and(|step_up_at| {
        step_up_at <= current && current.saturating_sub(step_up_at) <= STEP_UP_SECONDS
    }) {
        return Ok(());
    }
    Err(unauthenticated("recent passkey step-up required"))
}

const fn operator_role_rank(role: OperatorRoleRecord) -> u8 {
    match role {
        OperatorRoleRecord::Owner => 0,
        OperatorRoleRecord::Administrator => 1,
        OperatorRoleRecord::Support => 2,
        OperatorRoleRecord::Auditor => 3,
    }
}

const fn fleet_role_rank(role: FleetRoleRecord) -> u8 {
    match role {
        FleetRoleRecord::Owner => 0,
        FleetRoleRecord::Administrator => 1,
        FleetRoleRecord::Operator => 2,
        FleetRoleRecord::Support => 3,
        FleetRoleRecord::Auditor => 4,
    }
}

/// Why an authenticated caller was refused operator access. Recorded in the log,
/// never in the response.
#[derive(Clone, Copy, Debug)]
enum OperatorDenial {
    NotAnOperator,
    RoleLacksCapability(OperatorRoleRecord, OperatorCapability),
}

/// Whether `user` may be bootstrapped into the operator table.
///
/// Operator bootstrap must never trust an address the account has not proven it
/// controls. Every identifier on the self-service API is attacker-chosen and
/// unverified in production, so dropping the `verified` check here would let any
/// enrolled account claim an unclaimed operator address and mint itself Owner.
/// All identifiers are scanned rather than only the primary one, so an attacker
/// cannot suppress a real operator's access by claiming primary on their behalf.
fn bootstrap_allowed(user: &User, bootstrap_emails: &HashSet<String>) -> bool {
    user.identifiers.iter().any(|identifier| {
        identifier.kind == IdentifierKind::Email
            && identifier.verified
            && bootstrap_emails.contains(&identifier.value)
    })
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

fn fleet_allows(role: FleetRoleRecord, capability: OperatorCapability) -> bool {
    match capability {
        OperatorCapability::Read => true,
        OperatorCapability::Support => !matches!(role, FleetRoleRecord::Auditor),
        OperatorCapability::Administer => {
            matches!(
                role,
                FleetRoleRecord::Owner | FleetRoleRecord::Administrator
            )
        }
    }
}

fn session_cookie(headers: &HeaderMap, secure: bool) -> Option<&str> {
    let name = crate::auth::session_cookie_name(secure);
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&format!("{name}=")))
}

/// Extracts only RustyAuth's native-device bearer namespace. Machine tokens and
/// arbitrary bearer values deliberately fall through to their existing policy.
fn device_bearer(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer")
        && token.starts_with("rdt_")
        && token.len() >= 36
        && token.len() <= 256
        && !token.chars().any(char::is_whitespace))
    .then_some(token)
}

fn unauthenticated(message: &'static str) -> ConnectError {
    ConnectError::new(ErrorCode::Unauthenticated, message)
}

fn permission_denied(message: &'static str) -> ConnectError {
    ConnectError::new(ErrorCode::PermissionDenied, message)
}

/// The one response every post-authentication operator failure gets.
///
/// Answering "you are not an operator" differently from "your role is too low"
/// turns any authenticated session into an oracle for enumerating who holds
/// privileged access, so the reason goes to the log and never to the caller.
fn operator_denied(user_id: Uuid, reason: OperatorDenial) -> ConnectError {
    match reason {
        OperatorDenial::NotAnOperator => {
            tracing::debug!(user_id = %user_id, "operator access denied: not an operator");
        }
        OperatorDenial::RoleLacksCapability(role, capability) => {
            tracing::debug!(
                user_id = %user_id,
                role = ?role,
                capability = ?capability,
                "operator access denied: role lacks the required capability"
            );
        }
    }
    permission_denied("operator access denied")
}

fn internal(error: impl std::fmt::Display) -> ConnectError {
    tracing::error!(error = %error, "operator authorization failed");
    ConnectError::new(ErrorCode::Internal, "operator authorization failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{AccountIdentifier, AccountProfile};

    const OPERATOR_EMAIL: &str = "operator@example.invalid";

    fn identifier(
        kind: IdentifierKind,
        value: &str,
        verified: bool,
        primary: bool,
    ) -> AccountIdentifier {
        AccountIdentifier {
            kind,
            value: value.to_owned(),
            verified,
            verified_at: verified.then_some(100),
            primary,
            created_at: 100,
        }
    }

    fn user_with(identifiers: Vec<AccountIdentifier>) -> User {
        User {
            id: Uuid::new_v4(),
            email: String::new(),
            email_verified: false,
            profile: AccountProfile::default(),
            identifiers,
            session_version: 1,
            recovery_codes: Vec::new(),
            created_at: 100,
            passkeys: Vec::new(),
        }
    }

    fn bootstrap_set() -> HashSet<String> {
        HashSet::from([OPERATOR_EMAIL.to_owned()])
    }

    /// Prevents privilege escalation to Owner: identifiers on the self-service
    /// API are attacker-chosen, so an account that merely *claims* an operator
    /// address must not be bootstrapped. Only a proven-controlled address counts.
    #[test]
    fn bootstrap_requires_a_verified_matching_email() {
        let emails = bootstrap_set();

        assert!(bootstrap_allowed(
            &user_with(vec![identifier(
                IdentifierKind::Email,
                OPERATOR_EMAIL,
                true,
                true
            )]),
            &emails
        ));
        assert!(!bootstrap_allowed(
            &user_with(vec![identifier(
                IdentifierKind::Email,
                OPERATOR_EMAIL,
                false,
                true
            )]),
            &emails
        ));
        assert!(!bootstrap_allowed(
            &user_with(vec![identifier(
                IdentifierKind::Email,
                "someone-else@example.invalid",
                true,
                true
            )]),
            &emails
        ));
        assert!(!bootstrap_allowed(
            &user_with(vec![identifier(
                IdentifierKind::Phone,
                OPERATOR_EMAIL,
                true,
                true
            )]),
            &emails
        ));
    }

    #[test]
    fn bootstrap_denies_everything_when_no_emails_are_configured() {
        let emails = HashSet::new();
        assert!(!bootstrap_allowed(
            &user_with(vec![identifier(
                IdentifierKind::Email,
                OPERATOR_EMAIL,
                true,
                true
            )]),
            &emails
        ));
        assert!(!bootstrap_allowed(&user_with(Vec::new()), &emails));
    }

    /// A verified operator address bootstraps even when some other identifier is
    /// primary, so an attacker cannot lock a real operator out by racing to claim
    /// the primary slot.
    #[test]
    fn bootstrap_accepts_a_verified_non_primary_email() {
        let user = user_with(vec![
            identifier(IdentifierKind::Phone, "+447700900123", true, true),
            identifier(
                IdentifierKind::Email,
                "personal@example.invalid",
                false,
                false,
            ),
            identifier(IdentifierKind::Email, OPERATOR_EMAIL, true, false),
        ]);
        assert!(bootstrap_allowed(&user, &bootstrap_set()));
    }

    #[test]
    fn bootstrap_ignores_an_unverified_duplicate_of_a_verified_match() {
        let user = user_with(vec![
            identifier(IdentifierKind::Email, OPERATOR_EMAIL, false, true),
            identifier(
                IdentifierKind::Email,
                "personal@example.invalid",
                true,
                false,
            ),
        ]);
        assert!(!bootstrap_allowed(&user, &bootstrap_set()));
    }

    /// A caller that already holds a valid session must not learn whether it is
    /// an operator, nor how privileged it is. Distinguishable refusals let any
    /// enrolled account enumerate the operator roster to phish or target it.
    #[test]
    fn post_authentication_denials_are_indistinguishable() {
        let user_id = Uuid::new_v4();
        let not_an_operator = operator_denied(user_id, OperatorDenial::NotAnOperator);
        let wrong_role = operator_denied(
            user_id,
            OperatorDenial::RoleLacksCapability(
                OperatorRoleRecord::Auditor,
                OperatorCapability::Administer,
            ),
        );
        assert_eq!(not_an_operator.code, ErrorCode::PermissionDenied);
        assert_eq!(not_an_operator.code, wrong_role.code);
        assert_eq!(not_an_operator.message, wrong_role.message);
        assert_eq!(
            not_an_operator.message.as_deref(),
            Some("operator access denied")
        );
        // The origin and session refusals stay distinct on purpose: they are not an
        // operator-status oracle and legitimate clients act on the difference.
        assert_ne!(
            permission_denied("request origin is not allowed").message,
            not_an_operator.message
        );
        assert_ne!(
            unauthenticated("passkey operator session required").code,
            not_an_operator.code
        );
    }

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
        assert_eq!(session_cookie(&headers, false), Some("correct"));

        let mut production = HeaderMap::new();
        production.insert(
            header::COOKIE,
            "passkey_auth_session=shadow; __Host-Http-rustyauth_session=secure"
                .parse()
                .unwrap(),
        );
        assert_eq!(session_cookie(&production, true), Some("secure"));
    }

    #[test]
    fn native_device_bearers_are_strictly_namespaced_and_unambiguous() {
        let token = format!("rdt_{}", "a".repeat(43));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        assert_eq!(device_bearer(&headers), Some(token.as_str()));

        headers.insert(
            header::AUTHORIZATION,
            "Bearer machine-token".parse().unwrap(),
        );
        assert_eq!(device_bearer(&headers), None);
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {token}").parse().unwrap(),
        );
        assert_eq!(device_bearer(&headers), None);
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token} trailing").parse().unwrap(),
        );
        assert_eq!(device_bearer(&headers), None);

        let mut duplicate = HeaderMap::new();
        duplicate.append(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        duplicate.append(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        assert_eq!(device_bearer(&duplicate), None);
    }
}
