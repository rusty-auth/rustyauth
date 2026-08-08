#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NavKey {
    Overview,
    Users,
    Organization,
    ServiceAccounts,
    Webhooks,
    Metrics,
}

impl NavKey {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Users => "Users",
            Self::Organization => "Organization",
            Self::ServiceAccounts => "Service accounts",
            Self::Webhooks => "Webhooks",
            Self::Metrics => "Metrics",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorView {
    pub id: &'static str,
    pub email: &'static str,
    pub display_name: &'static str,
    pub role: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationView {
    pub id: &'static str,
    pub slug: &'static str,
    pub name: String,
    pub created_at: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserView {
    pub id: &'static str,
    pub name: &'static str,
    pub primary_identifier: &'static str,
    pub identifiers: usize,
    pub passkeys: usize,
    pub last_active: &'static str,
    pub created_at: &'static str,
    pub status: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceCredentialView {
    pub id: &'static str,
    pub name: &'static str,
    pub hint: &'static str,
    pub created_at: &'static str,
    pub last_used_at: &'static str,
    pub revoked_at: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceAccountView {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub status: &'static str,
    pub scopes: Vec<&'static str>,
    pub credentials: Vec<ServiceCredentialView>,
    pub created_at: &'static str,
    pub last_used_at: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookView {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub status: &'static str,
    pub events: Vec<&'static str>,
    pub success_rate: &'static str,
    pub last_delivery: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricView {
    pub label: &'static str,
    pub value: &'static str,
    pub change: &'static str,
    pub direction: &'static str,
    pub note: &'static str,
}
