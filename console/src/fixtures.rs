use crate::models::{
    MetricView, OperatorView, OrganizationView, ServiceAccountView, ServiceCredentialView,
    UserView, WebhookView,
};
use crate::proto::rustyauth::fleet::v1::{
    ConnectionMode, ConnectionState, Environment, EnvironmentKind, Organization, Project,
    RealmConnection, ResourceState,
};

pub fn preview_fleet_organizations() -> Vec<Organization> {
    vec![Organization {
        id: "4da8d788-ea8d-4d99-b7db-73567db6f0fb".into(),
        slug: "rustyauth".into(),
        name: "RustyAuth".into(),
        state: ResourceState::Active.into(),
        created_at: "2026-07-18T09:42:00Z".into(),
        updated_at: "2026-08-08T08:20:00Z".into(),
        ..Default::default()
    }]
}

pub fn preview_fleet_projects() -> Vec<Project> {
    let organization_id = preview_fleet_organizations()[0].id.clone();
    vec![
        Project {
            id: "8d46e22a-5a4f-4bf2-a05a-20e81ee5cc49".into(),
            organization_id: organization_id.clone(),
            slug: "cloud".into(),
            name: "RustyAuth Cloud".into(),
            description: "Hosted authentication realms".into(),
            state: ResourceState::Active.into(),
            created_at: "2026-07-19T10:00:00Z".into(),
            updated_at: "2026-08-08T08:20:00Z".into(),
            ..Default::default()
        },
        Project {
            id: "2a288fe4-314f-40b0-82e6-1460a264ae53".into(),
            organization_id,
            slug: "studio".into(),
            name: "RustyAuth Studio".into(),
            description: "Internal product realm".into(),
            state: ResourceState::Active.into(),
            created_at: "2026-07-22T12:00:00Z".into(),
            updated_at: "2026-08-07T16:40:00Z".into(),
            ..Default::default()
        },
    ]
}

pub fn preview_fleet_environments() -> Vec<Environment> {
    let project = &preview_fleet_projects()[0];
    vec![
        Environment {
            id: "0c613c1c-5e77-4d48-b20e-c8831279ee6c".into(),
            organization_id: project.organization_id.clone(),
            project_id: project.id.clone(),
            slug: "production".into(),
            name: "Production".into(),
            kind: EnvironmentKind::Production.into(),
            provider: "Railway".into(),
            region: "europe-west4".into(),
            state: ResourceState::Active.into(),
            created_at: "2026-07-20T10:00:00Z".into(),
            updated_at: "2026-08-08T08:20:00Z".into(),
            ..Default::default()
        },
        Environment {
            id: "48f26545-271d-4c6c-8db3-7f9a354ba19f".into(),
            organization_id: project.organization_id.clone(),
            project_id: project.id.clone(),
            slug: "staging".into(),
            name: "Staging".into(),
            kind: EnvironmentKind::Staging.into(),
            provider: "Railway".into(),
            region: "europe-west4".into(),
            state: ResourceState::Active.into(),
            created_at: "2026-07-20T10:05:00Z".into(),
            updated_at: "2026-08-08T08:18:00Z".into(),
            ..Default::default()
        },
    ]
}

pub fn preview_fleet_connections() -> Vec<RealmConnection> {
    let environment = &preview_fleet_environments()[0];
    vec![RealmConnection {
        id: "dd87912a-ecf6-4516-bf6d-e6c7c93a123f".into(),
        organization_id: environment.organization_id.clone(),
        project_id: environment.project_id.clone(),
        environment_id: environment.id.clone(),
        realm_id: "realm-production-eu".into(),
        display_name: "Production EU".into(),
        mode: ConnectionMode::PublicEndpoint.into(),
        management_endpoint: "https://auth.example.com".into(),
        credential_reference: "fleet-credential://dd87912a-ecf6-4516-bf6d-e6c7c93a123f".into(),
        deployment_version: "1.0.0".into(),
        protocol_version: "1".into(),
        state: ConnectionState::Healthy.into(),
        last_seen_at: "2026-08-08T08:28:00Z".into(),
        created_at: "2026-08-01T10:00:00Z".into(),
        updated_at: "2026-08-08T08:28:00Z".into(),
        ..Default::default()
    }]
}

pub const PREVIEW_OPERATOR: OperatorView = OperatorView {
    id: "780a15cd-d5d9-4ebf-82a2-30aff74f06bf",
    email: "admin@rustyauth.local",
    display_name: "Local owner",
    role: "Owner",
};

pub fn preview_organization() -> OrganizationView {
    OrganizationView {
        id: "4da8d788-ea8d-4d99-b7db-73567db6f0fb",
        slug: "rustyauth-local",
        name: "RustyAuth Local".to_string(),
        created_at: "2026-07-18T09:42:00Z",
    }
}

pub fn preview_users() -> Vec<UserView> {
    vec![
        UserView {
            id: "96d0b40f-3a04-4e78-b88e-77a7dad52738",
            name: "Ada Lovelace",
            primary_identifier: "ada@example.com",
            identifiers: 2,
            passkeys: 2,
            last_active: "4 minutes ago",
            created_at: "2026-08-02T10:18:00Z",
            status: "Active",
        },
        UserView {
            id: "7bb23ad8-c3d5-4418-9a67-5b1f68676411",
            name: "Grace Hopper",
            primary_identifier: "grace@example.com",
            identifiers: 1,
            passkeys: 1,
            last_active: "18 minutes ago",
            created_at: "2026-07-29T15:06:00Z",
            status: "Active",
        },
        UserView {
            id: "24f162dc-a459-4e7c-b2d6-ff3c3c40428c",
            name: "Margaret Hamilton",
            primary_identifier: "+44 7700 900 214",
            identifiers: 2,
            passkeys: 3,
            last_active: "Yesterday",
            created_at: "2026-07-21T08:31:00Z",
            status: "Active",
        },
        UserView {
            id: "9366489b-991a-47fa-b7e4-e3a9354665ae",
            name: "Lin Chen",
            primary_identifier: "lin@example.com",
            identifiers: 1,
            passkeys: 1,
            last_active: "3 days ago",
            created_at: "2026-07-16T13:47:00Z",
            status: "Needs verification",
        },
    ]
}

pub fn preview_service_accounts() -> Vec<ServiceAccountView> {
    vec![
        ServiceAccountView {
            id: "59aed98a-8828-44fc-85d0-18986f3f0ed9",
            name: "production-api",
            description: "Token exchange for the primary application API.",
            status: "Active",
            scopes: vec!["identity.read", "events.read", "metrics.read"],
            credentials: vec![ServiceCredentialView {
                id: "90c97003-9078-4b39-a2df-bd5bc46cacb0",
                name: "Railway production",
                hint: "p8Q2km",
                created_at: "2026-07-22T11:15:00Z",
                last_used_at: "2 minutes ago",
                revoked_at: "",
            }],
            created_at: "2026-07-22T11:14:00Z",
            last_used_at: "2 minutes ago",
        },
        ServiceAccountView {
            id: "287d4418-f21b-41e7-8073-498b58f1ac16",
            name: "audit-exporter",
            description: "Read-only event stream consumer for the audit archive.",
            status: "Active",
            scopes: vec!["events.read"],
            credentials: vec![ServiceCredentialView {
                id: "e7afc711-bb7b-490e-9b9f-4752567cbb99",
                name: "Quarterly rotation",
                hint: "1jV7st",
                created_at: "2026-08-01T09:00:00Z",
                last_used_at: "11 minutes ago",
                revoked_at: "",
            }],
            created_at: "2026-07-18T08:22:00Z",
            last_used_at: "11 minutes ago",
        },
        ServiceAccountView {
            id: "47050303-04b4-4efc-8240-06d48f3b6da5",
            name: "legacy-worker",
            description: "Retained for migration verification only.",
            status: "Disabled",
            scopes: vec!["identity.read"],
            credentials: vec![],
            created_at: "2026-06-04T16:40:00Z",
            last_used_at: "29 days ago",
        },
    ]
}

pub fn preview_webhooks() -> Vec<WebhookView> {
    vec![
        WebhookView {
            id: "wh_01",
            name: "Application lifecycle",
            url: "https://api.example.com/hooks/rustyauth",
            status: "Healthy",
            events: vec![
                "user.created",
                "user.updated",
                "user.disabled",
                "session.created",
                "session.revoked",
                "passkey.registered",
                "passkey.removed",
                "service_account.credential.revoked",
            ],
            success_rate: "99.98%",
            last_delivery: "38 seconds ago",
        },
        WebhookView {
            id: "wh_02",
            name: "Security operations",
            url: "https://events.example.com/security",
            status: "Retrying",
            events: vec![
                "passkey.challenge.failed",
                "operator.session.created",
                "service_account.credential.created",
                "service_account.credential.revoked",
            ],
            success_rate: "96.42%",
            last_delivery: "7 minutes ago",
        },
        WebhookView {
            id: "wh_03",
            name: "Migration archive",
            url: "https://archive.example.com/rustyauth",
            status: "Paused",
            events: vec![
                "user.created",
                "user.updated",
                "user.disabled",
                "session.created",
                "session.revoked",
                "passkey.registered",
                "passkey.removed",
                "passkey.challenge.failed",
                "operator.session.created",
                "service_account.created",
                "service_account.credential.created",
                "service_account.credential.revoked",
            ],
            success_rate: "100%",
            last_delivery: "18 days ago",
        },
    ]
}

pub const PREVIEW_METRICS: [MetricView; 6] = [
    MetricView {
        label: "Authentication success",
        value: "98.72%",
        change: "+0.34%",
        direction: "up",
        note: "Last 24 hours",
    },
    MetricView {
        label: "Active users",
        value: "8,402",
        change: "+6.8%",
        direction: "up",
        note: "28-day window",
    },
    MetricView {
        label: "Passkey latency p95",
        value: "284 ms",
        change: "−18 ms",
        direction: "up",
        note: "Verification endpoint",
    },
    MetricView {
        label: "Failed challenges",
        value: "193",
        change: "+12",
        direction: "down",
        note: "Last 24 hours",
    },
    MetricView {
        label: "Tokens issued",
        value: "42,811",
        change: "+9.1%",
        direction: "up",
        note: "User and service tokens",
    },
    MetricView {
        label: "Webhook success",
        value: "99.31%",
        change: "−0.08%",
        direction: "down",
        note: "All destinations",
    },
];

pub const AUTH_VOLUME: [u16; 24] = [
    38, 46, 43, 51, 58, 64, 61, 74, 79, 72, 88, 92, 86, 96, 104, 99, 112, 121, 117, 126, 133, 129,
    142, 151,
];
