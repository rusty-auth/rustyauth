use crate::models::{
    MetricView, OperatorView, OrganizationView, ServiceAccountView, ServiceCredentialView,
    UserView, WebhookView,
};

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
