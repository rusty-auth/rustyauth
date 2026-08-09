# RustyAuth delivery roadmap

**Status:** Active delivery plan

**Updated:** 9 August 2026

RustyAuth is pre-release security infrastructure. This roadmap is ordered by security and dependency gates,
not calendar promises. A capability is shipped only when it appears in the README status matrix and release
notes.

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
- [ADR 0004: Federated Fleet Analytics with trusted rollup ingestion](decisions/0004-federated-fleet-analytics.md)
- [Federated Fleet Analytics delivery program](FLEET_ANALYTICS.md)

ADR 0004 and the analytics program are post-Fleet work. The maintainer confirmed Fleet delivery and completed
M9's semantic compatibility gate and M10's realm projection/export gate on 9 August 2026. Paired realms now
advertise `telemetry.rollups.v1`, project locally and export over the realm-initiated connector. M11–M13 now
provide private GreptimeDB canonical/derived serving, the delegated hierarchy API, Dioxus journeys and signed
Parquet recovery. M14 production qualification, independent review and canary evidence remain open.

## Transport contract

One generated Protobuf contract serves all clients. Binary Protobuf is the default wire format:

| Channel                                             | Transport                                         | Credential boundary                                      |
| --------------------------------------------------- | ------------------------------------------------- | -------------------------------------------------------- |
| Dioxus web -> Rust control plane                    | Same-origin Connect through the dashboard gateway | Passkey-backed Secure, HttpOnly, SameSite session cookie |
| Dioxus desktop/mobile preview -> Rust control plane | Connect or native gRPC                            | Short-lived device token in the OS vault                 |
| Fleet control plane -> public realm                 | Native gRPC or Connect over HTTPS/HTTP2           | Revocable environment-scoped credential                  |
| Realm -> Fleet telemetry gateway                    | Bidirectional native gRPC over HTTP/2             | TLS plus a pairing-derived, connection-scoped proof      |

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

**State:** complete; generated compatibility and dual-protocol gates pass

- Add a stable realm ID that is independent of issuer, RP ID and the legacy `AUTH_TENANT_ID` label.
- Add versioned Fleet Protobufs for organizations, projects, environments, connections, memberships, role
  bindings, discovery, capabilities, pairing, health and audit.
- Add explicit standalone and Fleet deployment roles to configuration.
- Generate the same contracts for the Rust server and Dioxus clients.
- Add additive-compatibility and breaking-change CI checks.

**Exit gate:** generated binary requests round-trip through Connect and native gRPC, and a realm reports
stable identity and capabilities across restarts.

### M2 — Authorized Fleet registry

**State:** complete; hierarchy, delegation, audit and isolation gates pass

- Persist organizations, projects, environments, memberships and scoped role bindings in the Fleet datastore.
- Enforce parent-child integrity, normalized slugs, uniqueness, immutable IDs and soft deletion.
- Implement list/get/create/update/archive RPCs with bounded pagination.
- Evaluate every request from the authenticated operator and stored bindings; resource IDs never confer
  access.
- Record redacted central audit events for every mutation and authorization denial.
- Add cross-organization, cross-project and production-environment negative tests.

**Exit gate:** an owner can build a durable hierarchy, delegated operators see only their authorized scope,
and all isolation rejection tests pass.

### M3 — Pairing and realm connection lifecycle

**State:** complete; public and realm-initiated connector lifecycles are qualified

- Add realm discovery with protocol version, stable realm ID, issuer, RP ID, deployment version and explicit
  capability versions.
- Generate high-entropy, single-use, short-lived pairing codes from the realm CLI and local dashboard.
- Verify endpoint ownership, TLS, redirects, DNS resolution and SSRF policy before accepting a public
  endpoint.
- Exchange pairing codes for revocable environment-scoped credentials without exposing them to Dioxus.
- Add the outbound connector for private deployments using mTLS workload identity.
- Implement rotation, revocation, disconnect and stale/offline state on both sides.

**Exit gate:** an isolated test realm can be paired, queried, disconnected and re-paired without changing its
users, issuer, RP ID, sessions, signing keys or standalone availability.

### M4 — Live Dioxus control-plane journeys

**State:** complete; web and native transport/vault adapters share the live journeys

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

**State:** complete; bounded source-tagged operations and partial/stale states are live

- Aggregate bounded deployment, authentication, signing-key, backup and connection-health summaries.
- Fetch selected-realm users, events, service accounts, webhooks and metrics on demand.
- Make every value source-tagged and visibly stale when a realm is unavailable.
- Surface partial results instead of converting unavailable realms to zero.
- Enforce data-residency and retention limits on cached projections.

**Exit gate:** Fleet remains useful during partial realm failure without becoming authoritative for customer
identity data or leaking data across organization boundaries.

### M6 — Controlled remote administration

**State:** implemented; production approval/canary qualification remains under M8

- Separate read and mutation grants.
- Require recent passkey step-up and a human reason for sensitive production mutations.
- Add stable request IDs, idempotency, expiry and replay rejection.
- Record correlated local and central audit events.
- Add optional production approval and explicit break-glass policy.
- Exercise credential rotation, revocation and control-plane compromise recovery.

**Exit gate:** every remote mutation is scoped, stepped-up, idempotent, revocable and dual-audited; failure of
Fleet never interrupts user authentication in a realm.

### M7 — SolidJS retirement, web GA and native preview

**State:** complete for 1.0; web is the supported GA client and native clients are explicit previews

- Complete the local dashboard RPC regression suite in Dioxus.
- Keep the visual source assets and styles inside the Dioxus-owned package boundary.
- Keep SolidJS, Vite and `@rustyauth/connect-solid` out of product sources, builds and CI.
- Publish the Dioxus web release as its own stateless dashboard image with a bounded same-origin Connect
  gateway to the configured private API service.
- Publish separate Fleet control-plane and realm-backend images.
- Keep desktop/mobile feature builds and OS-vault device credentials available for preview qualification.
- Do not publish desktop, iOS or Android packages as part of `1.0.0`.

**Exit gate:** no production artifact contains the SolidJS runtime; dashboard, control-plane and realm-backend
images are independently deployable; the supported web client passes its live regression suite; and native
feature builds remain clearly labelled, ephemeral, unsigned previews outside the GA support contract.

### M8 — Production operations and release

**State:** implementation and local container qualification complete; published-artifact and independent gates pending

- Harden supplied containers with non-root users, read-only roots, dropped capabilities, no-new-privileges,
  bounded process counts and private database networking.
- Keep the locked Rust graph free of known advisories and publish release-image SBOM and provenance
  attestations.
- Publish pinned `ghcr.io/rusty-auth/rustyauth` and `ghcr.io/rusty-auth/sabledb` images with provenance, SBOMs
  and signatures.
- Enforce production Fleet endpoint and network egress policy against private, link-local and instance
  metadata destinations; qualify redirects and DNS rebinding defenses.
- Add Railway standalone and Fleet templates with private SableDB networking and no public database domain.
- Add protocol conformance, end-to-end, recovery, version-skew, connector-failure and upgrade tests.
- Add SLOs, metrics, traces, security alerts, backup/restore drills and incident runbooks.
- Back up Fleet control-plane state independently from every realm and prove clean-room restoration of both
  boundaries without treating one as the other's source of truth.
- Complete independent data-plane and Fleet threat assessments before production claims.

**Exit gate:** a clean Railway deployment can create, pair, operate, back up, restore, upgrade and disconnect
a realm using published images and documented procedures.

## Post-1.0 program — Native distribution

Desktop, iOS and Android reuse the Dioxus screens, models, binary protocol and native device-session/vault
adapters implemented before 1.0, but they are not 1.0 release artifacts or supported clients. A future native
release must separately:

- sign, notarize and publish supported macOS, Windows and Linux packages;
- qualify clean install, update, rollback and removal on each supported architecture;
- accept the Apple toolchain terms under owner authority and qualify iOS passkey/device-vault flows on real
  hardware with an authorized team/profile;
- pin the Android SDK/NDK and qualify the same flows on real hardware with an authorized keystore; and
- add machine-readable release evidence before any preview package is promoted to a supported channel.

Unsigned preview packages remain pull-request/manual workflow artifacts with seven-day retention. They never
run on, attach to or block server/container/web GA tags.

## Post-Fleet program — Federated Fleet Analytics

The milestones below activated on 9 August 2026. Their complete contracts, workstreams, qualification matrix
and definition of done are maintained in [Federated Fleet Analytics delivery program](FLEET_ANALYTICS.md). The
main roadmap records them here so Fleet completion has one explicit next program rather than an implicit
expansion of M5.

### M9 — Analytics activation and semantic lock

**State:** complete on 9 August 2026

- Revalidate ADR 0004 against the shipped connector, hierarchy, authorization and recovery implementation.
- Lock metric names, units, histogram boundaries, allowed dimensions, bucket closure and correction semantics.
- Add versioned rollup, acknowledgement, coverage and archive-manifest Protobuf contracts.
- Publish canonical metric-bucket Parquet schemas and compatibility fixtures.

**Exit gate:** supported releases produce byte- and result-compatible fixtures, and incompatible or
high-cardinality input fails closed.

### M10 — Realm projection and reliable cross-cloud export

**State:** complete on 9 August 2026

- Project bounded five-minute metric snapshots locally and expose them through the standalone MetricsService.
- Add a durable SableDB telemetry outbox with full-snapshot revisions and source watermarks.
- Carry rollups over the realm-initiated authenticated connector with exact acknowledgements and bounded
  retry.
- Prove central outage, exporter panic and queue pressure never affect authentication.

**Exit gate:** a realm can disconnect for 24 hours, restart and replay logically once without blocking any
authentication path.

### M11 — Trusted ingestion and canonical analytical storage

**State:** complete; poisoning/correction tests and the measured medium gate pass

- Promote M10's trusted hierarchy stamping and exact-revision acceptance ledger into the canonical store
  adapter.
- Add policy, coverage and manifest coordination beside the existing authoritative revision/cursor state.
- Deploy a private, pinned GreptimeDB store behind an internal analytics adapter.
- Qualify schema, partitioning, TTL, quotas, repair and recovery at small, medium and large tiers.

**Exit gate:** cross-organization poisoning tests pass, the medium performance tier meets its targets and loss
of analytical storage has no realm-authentication effect.

### M12 — Hierarchical Analytics RPC and Dioxus product

**State:** complete; delegated scopes, comparison, coverage and Dioxus states are implemented

- Evolve the shipped organization-required ledger overview into bounded, delegated-scope Analytics RPCs;
  Dioxus never sends SQL.
- Ship realm, environment, project, organization and authorized fleet scopes.
- Add drill-down, sibling comparison, failure contribution and 24-hour/7-day/28-day views.
- Return expected, reporting, stale, disabled and unsupported coverage with every result.

**Exit gate:** an authorized operator can trace a fleet regression to one realm while a different organization
cannot infer that realm's existence, values or freshness.

### M13 — Materialized history, Parquet backfill and residency

**State:** complete; clean-room/live convergence and correction gates pass

- Add hourly and daily scope rollups derived directly from canonical realm buckets.
- Add signed metric-bucket manifests and manifest-driven import from approved customer or central buckets.
- Support rollups-only, customer-owned archive and central-landing residency modes.
- Add retention reduction, disconnect cleanup, audited purge and deterministic correction repair.

**Exit gate:** a clean central deployment can rebuild the qualified window from approved archives while live
ingestion continues and converges without double-counting.

### M14 — Fleet Analytics production qualification

**State:** in progress; measured medium-scale, recovery and runbook gates pass; full production qualification,
independent review and canary remain pending

- Complete scale, soak, chaos, upgrade, cost and clean-room recovery qualification.
- Complete independent analytics threat and privacy assessments.
- Publish SLOs, monitoring, alerts, deployment guidance and incident/recovery runbooks.
- Canary behind organization policy before updating the README status matrix and release notes.

**Exit gate:** analytics is bounded, authorized, residency-aware, recoverable and supported at published
scale; turning it off leaves a fully supported Fleet deployment.

### M15 — Advanced insights

**State:** gated by M14; not required for Fleet Analytics V1

- Correlate deployment releases with regressions.
- Add anomaly detection, saved comparisons and approved alerts.
- Add SIEM/warehouse export and longer enterprise retention where qualified.
- Consider opt-in cross-customer cohort benchmarking only under a separate accepted privacy decision.

**Exit gate:** each separately released insight has an explicit semantic, authorization, privacy,
false-positive and rollback contract.

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
- A new protocol, store, authentication factor, token class or trust boundary requires an architecture
  decision and threat review before production use.
- Marketing and documentation must distinguish implemented, preview and planned behavior.
- Shared-database multi-tenancy, shared-login SSO and multi-writer data planes remain separate decisions.
