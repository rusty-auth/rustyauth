# RustyAuth documentation

This directory is the normative technical documentation for RustyAuth. The
[developer site](https://rustyauth.dev/docs) provides shorter learning paths; repository docs preserve
complete contracts, operational detail and product decisions alongside the code they describe.

RustyAuth is `0.1.0` pre-release software. Pin a release or commit when integrating. An implemented capability
is not necessarily production-qualified; use [Project status](#project-status) and the
[security policy](../SECURITY.md) before making deployment decisions.

## Choose a path

| Goal                                            | Start here                               | Continue with                                                                                                                   |
| ----------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Run one isolated realm locally                  | [Standalone quick start](QUICKSTART.md)  | [Configuration](CONFIGURATION.md), [Deployment](DEPLOYMENT.md)                                                                  |
| Add RustyAuth to an application                 | [Integration guide](INTEGRATION.md)      | [API](API.md), [Identity data model](IDENTITY_DATA_MODEL.md), [examples](../examples/README.md)                                 |
| Run the Dioxus operator dashboard               | [Standalone quick start](QUICKSTART.md)  | [Architecture](ARCHITECTURE.md), [Security hardening](SECURITY_HARDENING.md)                                                    |
| Manage organizations, projects and environments | [Fleet quick start](FLEET_QUICKSTART.md) | [Fleet control plane](FLEET_CONTROL_PLANE.md), [Fleet Analytics](FLEET_ANALYTICS.md)                                            |
| Build or review federated Fleet analytics       | [Fleet Analytics](FLEET_ANALYTICS.md)    | [V1 semantics](FLEET_ANALYTICS_V1.md), [developer guide](https://rustyauth.dev/docs/fleet-analytics)                            |
| Deploy to Kubernetes, Railway or containers     | [Deployment](DEPLOYMENT.md)              | [Kubernetes and Civo K3s](KUBERNETES.md), [Railway topology](RAILWAY_TEMPLATE.md), [Backups and recovery](BACKUPS.md)             |
| Standardize policy across environments          | [Configuration](CONFIGURATION.md)        | [JSON Schema](../schemas/rustyauth-config-v1alpha1.schema.json), [production example](../examples/config/realm-production.yaml) |
| Contribute safely                               | [Contributing](../CONTRIBUTING.md)       | [Engineering](ENGINEERING.md), [ADRs](#architecture-decisions)                                                                  |

## Deployment models

### Standalone realm

One project contains three independently deployable services:

```text
browser → Dioxus dashboard → RustyAuth realm backend → private realm SableDB
                                      └──────────────→ private backup bucket
```

The dashboard is presentation, the Rust backend is the authority, and SableDB is private durable state. Use
this for one app environment or any deployment that should remain operational without a central management
plane.

### Fleet control plane

A separate central project also contains three services:

```text
operator → Dioxus Fleet dashboard → Fleet control-plane API → private Fleet SableDB
                                            │
                                            ├── scoped realm management API → project A / production
                                            └── scoped realm management API → project B / staging
```

Fleet owns organizations, projects, environments, realm registrations, scoped roles, audit and aggregate
health. Each managed realm keeps its own users, credentials, sessions, keys, SableDB and backups. Fleet never
connects directly to a realm database.

## Core reference

| Document                                                | Authority                                                           |
| ------------------------------------------------------- | ------------------------------------------------------------------- |
| [Architecture](ARCHITECTURE.md)                         | Components, trust boundaries, state and end-to-end flows            |
| [Identity data model](IDENTITY_DATA_MODEL.md)           | Persisted fields, invariants, indexes and exposure rules            |
| [HTTP and RPC API](API.md)                              | Endpoint access, request/response contracts and typed services      |
| [OpenAPI](openapi.yaml)                                 | Machine-readable public HTTP contract                               |
| [Protobuf packages](../proto/)                          | Versioned Connect/gRPC message and service contracts                |
| [Configuration](CONFIGURATION.md)                       | YAML schema, secret inputs, compatibility and startup validation    |
| [Fleet control plane](FLEET_CONTROL_PLANE.md)           | Hierarchy, pairing, roles, isolation and cross-cloud management     |
| [Fleet Analytics V1](FLEET_ANALYTICS_V1.md)             | Metric semantics, buckets, coverage, privacy and compatibility      |
| [Fleet Analytics security](FLEET_ANALYTICS_SECURITY.md) | Internal threat/privacy assessment and residual release gates       |
| [Fleet Analytics runbook](FLEET_ANALYTICS_RUNBOOK.md)   | SLOs, monitoring, incidents, purge and clean-room recovery          |
| [Protocol qualification](PROTOCOL_QUALIFICATION.md)     | Version skew, fuzzing, fault injection, upgrade and rollback policy |

## Operations and recovery

| Document                                            | Use it for                                                      |
| --------------------------------------------------- | --------------------------------------------------------------- |
| [Deployment](DEPLOYMENT.md)                         | Docker, Kubernetes, Railway, private networking and release gates |
| [Kubernetes and Civo K3s](KUBERNETES.md)            | Integrated, Fleet and lightweight realm Helm deployments       |
| [Railway template](RAILWAY_TEMPLATE.md)             | Exact standalone, Fleet and evaluation service graphs           |
| [Configuration](CONFIGURATION.md)                   | Policy, secrets, backups and platform-specific inputs           |
| [Backups and recovery](BACKUPS.md)                  | Snapshot scope, binary format, S3 posture, health and restore   |
| [Security hardening](SECURITY_HARDENING.md)         | Container, runtime, supply-chain and qualification controls     |
| [Protocol qualification](PROTOCOL_QUALIFICATION.md) | Fuzz, skew, fault and upgrade qualification evidence            |
| [Web GA qualification](WEB_GA_QUALIFICATION.md)     | Supported browser/authenticator matrix and evidence contract    |
| [Security policy](../SECURITY.md)                   | Vulnerability reporting, threat model and known limitations     |
| [1.0.0 release readiness](RELEASE_READINESS.md)     | Passed local evidence and externally owned promotion gates      |
| [Native previews](NATIVE_PACKAGING.md)              | Ephemeral package matrix, local evidence and future signing gates |
| [Releasing](../RELEASING.md)                        | Tagged releases, containers and package publishing              |

The complete backup contract and clean-room procedure are documented in
[Backups and disaster recovery](BACKUPS.md). Treat a backup as usable only after a clean-room restore,
`rustyauth doctor`, and a real passkey sign-in.

## Product program

| Document                                      | Scope                                                  |
| --------------------------------------------- | ------------------------------------------------------ |
| [Roadmap](ROADMAP.md)                         | Current priorities, release gates and later directions |
| [Fleet Analytics program](FLEET_ANALYTICS.md) | Federated telemetry architecture and staged delivery   |
| [Engineering](ENGINEERING.md)                 | Module ownership, coding standards and quality gates   |
| [Brand](BRAND.md)                             | Naming, voice, logo and attribution                    |
| [Changelog](../CHANGELOG.md)                  | Release-facing changes and migration notes             |

## Architecture decisions

- [ADR 0001: dashboard control plane](decisions/0001-dashboard-control-plane.md)
- [ADR 0002: cross-platform Fleet console](decisions/0002-cross-platform-fleet-console.md)
- [ADR 0003: unified Dioxus Fleet control plane](decisions/0003-unified-dioxus-fleet-control-plane.md)
- [ADR 0004: federated Fleet Analytics](decisions/0004-federated-fleet-analytics.md)
- [ADR 0005: native device session tokens](decisions/0005-native-device-session-tokens.md)
- [ADR 0006: outbound Fleet connector trust](decisions/0006-outbound-fleet-connector-trust.md)

ADRs record why a boundary was chosen. Current reference documents and code win when an older ADR describes a
superseded migration state—for example, the shipped dashboard path is now Dioxus.

## Project status

Available for evaluation today:

- passkey registration and sign-in, revocable browser sessions and multiple credentials;
- ES256 tokens, JWKS, staged signing-key rotation and private identity/event RPC;
- supported Dioxus web dashboard plus shared preview-only desktop/mobile feature builds;
- single-organization operator and service-account management;
- Fleet organization/project/environment hierarchy, scoped roles, audit and realm pairing;
- encrypted logical backups, verification and empty-target restore; and
- versioned YAML configuration with separate secret inputs.

Before production `1.0`:

- publish and verify signed server, dashboard and SableDB images through clean install, upgrade and rollback;
- qualify the supported web browser/OS/authenticator matrix;
- complete the pinned Analytics scale, soak, chaos, upgrade/downgrade, cost and recovery matrix;
- run a real organization-policy Analytics canary and witnessed Realm/Fleet recovery drill; and
- complete independent application, deployment, pinned-SableDB and Analytics threat/privacy assessments.

Desktop, iOS and Android applications are previews outside `1.0.0`; their signing, update and real-device
matrices are post-1.0 release gates.

The detailed status matrix lives in the root [README](../README.md#project-status) and the delivery sequence
in the [roadmap](ROADMAP.md). The exact promotion decision is kept in the
[1.0.0 release-readiness record](RELEASE_READINESS.md).

## Documentation rules

When behavior changes, update the closest normative document in the same pull request:

- public HTTP behavior: `docs/API.md` and `docs/openapi.yaml`;
- Protobuf behavior: `proto/`, generated protocol packages and `docs/API.md`;
- persisted identity state: `docs/IDENTITY_DATA_MODEL.md`;
- configuration: schema, examples and `docs/CONFIGURATION.md`;
- backup or restore behavior: `docs/BACKUPS.md` and the Astro recovery guide;
- deployment or platform topology: `docs/DEPLOYMENT.md`, `docs/KUBERNETES.md` and `docs/RAILWAY_TEMPLATE.md` when relevant;
- Fleet behavior: `docs/FLEET_CONTROL_PLANE.md` or the Analytics documents; and
- security assumptions or limitations: `SECURITY.md` and `docs/SECURITY_HARDENING.md`.

Keep business-only plans outside the public repository. Public roadmap material must describe product
boundaries, technical sequencing and honest capability status without private commercial information.
