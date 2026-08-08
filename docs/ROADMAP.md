# RustyAuth delivery roadmap

**Status:** Active delivery plan

**Updated:** 8 August 2026

RustyAuth is pre-release security infrastructure. This roadmap is ordered by security and dependency gates, not
calendar promises. A capability is shipped only when it appears in the README status matrix and release notes.

## Product destination

RustyAuth ships two compatible deployment modes from separate services and one Dioxus dashboard codebase:

1. **Standalone:** a Dioxus dashboard service, one RustyAuth realm backend and one private SableDB service for
   local and break-glass administration.
2. **Fleet:** a separately deployed RustyAuth control plane and Dioxus dashboard manage many isolated realms
   across organizations, projects, environments, clouds and customer networks.

The hierarchy is `Organization -> Project -> Environment -> Realm connection`. Fleet shares a versioned
management protocol, never a customer identity database. Dioxus clients never receive database connection
strings or reusable realm-management credentials.

The controlling architecture decisions are:

- [ADR 0003: Unified Dioxus dashboard and multi-protocol Fleet control plane](decisions/0003-unified-dioxus-fleet-control-plane.md)
- [Fleet control-plane architecture](FLEET_CONTROL_PLANE.md)

## Transport contract

One generated Protobuf contract serves all clients. Binary Protobuf is the default wire format:

| Channel | Transport | Credential boundary |
| --- | --- | --- |
| Dioxus web -> Rust control plane | Same-origin Connect through the dashboard gateway | Passkey-backed Secure, HttpOnly, SameSite session cookie |
| Dioxus desktop/mobile -> Rust control plane | Connect or native gRPC | Short-lived device token in the OS vault |
| Fleet control plane -> public realm | Native gRPC or Connect over HTTPS/HTTP2 | Revocable environment-scoped credential |
| Private realm -> connector gateway | Bidirectional native gRPC over HTTP/2 | mTLS workload identity and signed commands |

The pinned ConnectRPC server handles Connect, gRPC and gRPC-Web with the same request limits, authorization
interceptors and audit policy. TLS, authentication, authorization and replay protection remain mandatory;
binary encoding alone is not a security boundary.

## Delivery sequence

### M0 — Architecture and migration lock

**State:** complete

- Accept Dioxus as the only dashboard implementation target.
- Preserve standalone and local break-glass operation while retiring SolidJS.
- Fix the control/data-plane boundary and prohibit direct database access from clients.
- Fix the Protobuf and transport matrix.
- Record security invariants and removal gates for SolidJS.

**Exit gate:** ADR 0003 is accepted and the Fleet architecture names every trust boundary.

### M1 — Fleet contract and durable identities

**State:** in progress

- Add a stable realm ID that is independent of issuer, RP ID and the legacy `AUTH_TENANT_ID` label.
- Add versioned Fleet Protobufs for organizations, projects, environments, connections, memberships, role
  bindings, discovery, capabilities, pairing, health and audit.
- Add explicit standalone and Fleet deployment roles to configuration.
- Generate the same contracts for the Rust server and Dioxus clients.
- Add additive-compatibility and breaking-change CI checks.

**Exit gate:** generated binary requests round-trip through Connect and native gRPC, and a realm reports stable
identity and capabilities across restarts.

### M2 — Authorized Fleet registry

**State:** pending

- Persist organizations, projects, environments, memberships and scoped role bindings in the Fleet datastore.
- Enforce parent-child integrity, normalized slugs, uniqueness, immutable IDs and soft deletion.
- Implement list/get/create/update/archive RPCs with bounded pagination.
- Evaluate every request from the authenticated operator and stored bindings; resource IDs never confer access.
- Record redacted central audit events for every mutation and authorization denial.
- Add cross-organization, cross-project and production-environment negative tests.

**Exit gate:** an owner can build a durable hierarchy, delegated operators see only their authorized scope, and
all isolation rejection tests pass.

### M3 — Pairing and realm connection lifecycle

**State:** pending

- Add realm discovery with protocol version, stable realm ID, issuer, RP ID, deployment version and explicit
  capability versions.
- Generate high-entropy, single-use, short-lived pairing codes from the realm CLI and local dashboard.
- Verify endpoint ownership, TLS, redirects, DNS resolution and SSRF policy before accepting a public endpoint.
- Exchange pairing codes for revocable environment-scoped credentials without exposing them to Dioxus.
- Add the outbound connector for private deployments using mTLS workload identity.
- Implement rotation, revocation, disconnect and stale/offline state on both sides.

**Exit gate:** an isolated test realm can be paired, queried, disconnected and re-paired without changing its
users, issuer, RP ID, sessions, signing keys or standalone availability.

### M4 — Live Dioxus control-plane journeys

**State:** pending

- Replace preview-only sign-in with real passkey registration, authentication, sign-out and session recovery.
- Add a binary Connect client with cookies on web and a platform transport adapter for native builds.
- Add organization creation and switching.
- Add project and environment setup wizards, including deploy-new and connect-existing branches.
- Add connection verification, capability, health and error/retry states.
- Replace fixture state with live RPC state while preserving loading, empty, partial and stale views.
- Preserve the current visual, responsive, keyboard and reduced-motion contract.

**Exit gate:** a new operator can sign in, create an organization/project/environment, pair a real isolated
realm, reload the application and recover the same authorized state from durable storage.

### M5 — Read-only Fleet operations

**State:** pending

- Aggregate bounded deployment, authentication, signing-key, backup and connection-health summaries.
- Fetch selected-realm users, events, service accounts, webhooks and metrics on demand.
- Make every value source-tagged and visibly stale when a realm is unavailable.
- Surface partial results instead of converting unavailable realms to zero.
- Enforce data-residency and retention limits on cached projections.

**Exit gate:** Fleet remains useful during partial realm failure without becoming authoritative for customer
identity data or leaking data across organization boundaries.

### M6 — Controlled remote administration

**State:** pending

- Separate read and mutation grants.
- Require recent passkey step-up and a human reason for sensitive production mutations.
- Add stable request IDs, idempotency, expiry and replay rejection.
- Record correlated local and central audit events.
- Add optional production approval and explicit break-glass policy.
- Exercise credential rotation, revocation and control-plane compromise recovery.

**Exit gate:** every remote mutation is scoped, stepped-up, idempotent, revocable and dual-audited; failure of
Fleet never interrupts user authentication in a realm.

### M7 — SolidJS retirement and cross-platform release

**State:** pending

- Complete the local dashboard RPC regression suite in Dioxus.
- Move the visual source assets and styles into the Dioxus-owned package boundary.
- Remove SolidJS, Vite and `@rustyauth/connect-solid` from production builds and CI.
- Publish the Dioxus web release as its own stateless dashboard image with a bounded same-origin Connect
  gateway to the configured private API service.
- Publish separate Fleet control-plane and realm-backend images.
- Add signed desktop packages and OS-vault device credentials.
- Qualify mobile passkey/device flows before publishing iOS or Android packages.

**Exit gate:** no production artifact contains the SolidJS runtime; dashboard, control-plane and realm-backend
images are independently deployable; and web/desktop/mobile feature builds use the same screens, models and
authorization semantics.

### M8 — Production operations and release

**State:** pending

- Publish pinned `ghcr.io/rusty-auth/rustyauth` and `ghcr.io/rusty-auth/sabledb` images with provenance, SBOMs
  and signatures.
- Add Railway standalone and Fleet templates with private SableDB networking and no public database domain.
- Add protocol conformance, end-to-end, recovery, version-skew, connector-failure and upgrade tests.
- Add SLOs, metrics, traces, security alerts, backup/restore drills and incident runbooks.
- Back up Fleet control-plane state independently from every realm and prove clean-room restoration of both
  boundaries without treating one as the other's source of truth.
- Complete independent data-plane and Fleet threat assessments before production claims.

**Exit gate:** a clean Railway deployment can create, pair, operate, back up, restore, upgrade and disconnect a
realm using published images and documented procedures.

## Non-negotiable security gates

- A client never receives a realm management credential or database connection string.
- One realm credential can never name, query or mutate another realm.
- Realm context comes from authenticated connection state and the registry, not an untrusted header alone.
- No signing, master, backup or session secret crosses the management API.
- All authorization is server-side and every remote mutation is audited locally and centrally.
- Realm authentication continues when the control plane or connector is unavailable.
- Cached Fleet data is bounded, source-tagged, retention-controlled and visibly stale.
- A realm can revoke Fleet without central cooperation.

## Roadmap rules

- The README status matrix and release notes, not this document, determine what is shipped.
- A new protocol, store, authentication factor, token class or trust boundary requires an architecture decision
  and threat review before production use.
- Marketing and documentation must distinguish implemented, preview and planned behavior.
- Shared-database multi-tenancy, shared-login SSO and multi-writer data planes remain separate decisions.
