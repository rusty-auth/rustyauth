export interface DocsItem {
  label: string;
  href: string;
  description: string;
  keywords: string[];
  seoTitle: string;
}

export interface DocsGroup {
  label: string;
  items: DocsItem[];
}

export const docsNavigation: DocsGroup[] = [
  {
    label: "Start",
    items: [
      {
        label: "Documentation home",
        href: "/docs",
        seoTitle: "Self-Hosted Passkey Authentication Documentation | RustyAuth",
        description: "Choose a learning path and understand the current product boundary.",
        keywords: ["overview", "start", "documentation", "status"],
      },
      {
        label: "Getting started",
        href: "/docs/getting-started",
        seoTitle: "Self-Hosted Passkey Authentication Quickstart | RustyAuth",
        description: "Run the standalone or Fleet stack locally and verify it.",
        keywords: ["quickstart", "docker", "compose", "local", "install"],
      },
      {
        label: "Integrate an application",
        href: "/docs/integration",
        seoTitle: "Add Passkey Authentication to Your App | RustyAuth",
        description: "Add passkeys, sessions and verified JWTs to a web application.",
        keywords: ["client", "typescript", "webauthn", "jwt", "session", "token"],
      },
    ],
  },
  {
    label: "Understand",
    items: [
      {
        label: "Architecture",
        href: "/docs/architecture",
        seoTitle: "Rust Passkey Authentication Architecture | RustyAuth",
        description: "Service topology, trust boundaries and failure isolation.",
        keywords: ["services", "dashboard", "backend", "sabledb", "trust"],
      },
      {
        label: "Identity data",
        href: "/docs/identity-data",
        seoTitle: "Passkey Identity and Session Data Model | RustyAuth",
        description: "Accounts, identifiers, passkeys, sessions and exposure rules.",
        keywords: ["schema", "user", "account", "email", "phone", "passkey"],
      },
      {
        label: "Fleet control plane",
        href: "/docs/fleet",
        seoTitle: "Multi-Realm Authentication Control Plane | RustyAuth",
        description: "Organizations, projects, environments and isolated realms.",
        keywords: ["fleet", "organization", "project", "environment", "pairing", "multi tenant"],
      },
      {
        label: "Fleet Analytics",
        href: "/docs/fleet-analytics",
        seoTitle: "Authentication Fleet Analytics | RustyAuth",
        description: "Cross-cloud rollups, hierarchy attribution, GreptimeDB and staged delivery.",
        keywords: [
          "analytics",
          "telemetry",
          "rollup",
          "greptimedb",
          "parquet",
          "s3",
          "cross cloud",
        ],
      },
    ],
  },
  {
    label: "Reference",
    items: [
      {
        label: "HTTP and RPC API",
        href: "/docs/api",
        seoTitle: "Passkey Authentication HTTP and gRPC API | RustyAuth",
        description: "Browser JSON, Connect, gRPC-Web and native gRPC boundaries.",
        keywords: ["api", "rpc", "grpc", "protobuf", "connect", "openapi"],
      },
      {
        label: "Fleet Analytics V1",
        href: "/docs/fleet-analytics-v1",
        seoTitle: "Fleet Analytics Schema and Semantics | RustyAuth",
        description: "Exact bucket, metric, histogram, privacy, coverage and archive semantics.",
        keywords: [
          "metrics",
          "schema",
          "histogram",
          "coverage",
          "manifest",
          "protobuf",
          "parquet",
          "compatibility",
        ],
      },
      {
        label: "Configuration",
        href: "/docs/configuration",
        seoTitle: "Configure Self-Hosted Authentication | RustyAuth",
        description: "Versioned YAML, IaC ownership, secrets, webhooks and fail-closed startup policy.",
        keywords: [
          "yaml",
          "environment",
          "variables",
          "secrets",
          "config",
          "iac",
          "railway",
          "webhook",
          "backup schedule",
        ],
      },
    ],
  },
  {
    label: "Operate",
    items: [
      {
        label: "Deployment",
        href: "/docs/deployment",
        seoTitle: "Deploy Self-Hosted Authentication | RustyAuth",
        description: "Three-service topologies for Docker, Railway and Fleet.",
        keywords: ["railway", "container", "production", "topology", "scale"],
      },
      {
        label: "Kubernetes and K3s",
        href: "/docs/kubernetes",
        seoTitle: "Deploy Passkey Authentication on Kubernetes and Civo K3s | RustyAuth",
        description: "Integrated, Fleet and lightweight realm Helm charts for Kubernetes and Civo K3s.",
        keywords: ["kubernetes", "k3s", "civo", "helm", "traefik", "fleet", "wasm"],
      },
      {
        label: "Security",
        href: "/docs/security",
        seoTitle: "Passkey and WebAuthn Security Model | RustyAuth",
        description: "Security model, hardened defaults and production gates.",
        keywords: ["security", "cookies", "ssrf", "hardening", "threat model"],
      },
      {
        label: "Backups and recovery",
        href: "/docs/recovery",
        seoTitle: "Authentication Backups and Disaster Recovery | RustyAuth",
        description:
          "Snapshot scope, binary envelopes, immutable S3 storage, alerting, key rotation and clean-room restore.",
        keywords: [
          "backup",
          "restore",
          "rotation",
          "s3",
          "object lock",
          "aes",
          "postcard",
          "rpo",
          "recovery",
        ],
      },
    ],
  },
  {
    label: "Project",
    items: [
      {
        label: "Status and roadmap",
        href: "/docs/project-status",
        seoTitle: "RustyAuth Project Status and Roadmap",
        description: "What works today, what remains gated and what comes next.",
        keywords: ["status", "roadmap", "limitations", "release", "pre release"],
      },
    ],
  },
];

export const docsItems = docsNavigation.flatMap((group) =>
  group.items.map((item) => ({ ...item, group: group.label }))
);
