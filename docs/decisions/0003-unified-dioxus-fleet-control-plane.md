# 0003: Unified Dioxus dashboard and multi-protocol Fleet control plane

**Status:** Accepted

**Date:** 8 August 2026

**Supersedes:** ADR 0001's SolidJS client choice and ADR 0002's permanent two-client strategy

## Context

The Dioxus clone has reached visual and interaction parity with the embedded dashboard and is a materially
better foundation for a Rust product that must ship on the web, desktop and later mobile. Keeping SolidJS as a
second production client would duplicate every Fleet workflow, authorization state and regression surface.

RustyAuth also needs to manage many isolated auth realms across organizations, projects, environments, clouds
and customer networks. That does not justify sharing identity databases or putting realm credentials in a UI.
The dashboard remains an untrusted client; Rust services remain the authorization, routing, secret-custody and
audit boundaries.

The existing `connectrpc` runtime already serves Connect, gRPC and gRPC-Web from one generated Protobuf
contract and accepts binary Protobuf messages. Introducing a second RPC framework would duplicate policy and
generated types without adding protocol coverage.

## Decision

### One Dioxus dashboard, deployed as its own service

`console/` becomes the only dashboard implementation and is renamed at the product level to the RustyAuth
Dashboard. The web build is a separate stateless service; it is not compiled into either Rust API image. The
shared Rust application supports three client packages:

- separately deployed web dashboard, configured for either a standalone realm or Fleet control plane;
- signed desktop packages; and
- mobile packages after device credential storage and platform passkey flows are qualified.

The SolidJS runtime and `@rustyauth/connect-solid` are retired once the Dioxus client uses live APIs and passes
the standalone regression suite. The existing SolidJS implementation remains a temporary visual reference
during that migration, not a separately evolving product.

### One Protobuf contract, three compatible transports

All control-plane and realm-management services are versioned under `proto/rustyauth/*/v1`. Binary Protobuf is
the default wire format.

| Caller | Protocol | Authentication |
| --- | --- | --- |
| Dioxus web | Same-origin Connect through the stateless dashboard gateway | Secure, HttpOnly, SameSite passkey session cookie plus Origin and CSRF checks |
| Dioxus desktop/mobile | Connect or native gRPC over HTTPS/HTTP2 | Short-lived device token held in the OS credential vault |
| Fleet control plane to public realm endpoint | Native gRPC or Connect over HTTPS/HTTP2 | Environment-scoped credential, later mTLS where supported |
| Outbound realm connector | Bidirectional native gRPC over HTTP/2 | mTLS workload identity plus signed, scoped and expiring commands |

The server continues to use `connectrpc` so the same generated service, interceptor, size limits and audit
policy govern Connect, gRPC and gRPC-Web. JSON Protobuf remains a diagnostic compatibility option, not the
dashboard default.

### Separate dashboard, control plane, data plane and datastores

The production topology uses independent service boundaries:

- `rustyauth-dashboard` is the stateless Dioxus web service and same-origin Connect gateway; it contains no
  reusable backend credential and makes no authorization decision;
- `rustyauth-control-plane` is a distinct Rust service that owns Fleet operator policy, organizations, projects,
  environments, connections, bounded read models, orchestration and central audit records;
- `rustyauth-backend` is the existing Rust realm service and owns one isolated authentication realm; and
- each stateful Rust service has its own private SableDB service and persistent volume.

The dashboard, control plane and realm backend are separate images and Railway services. Code and generated
Protobuf contracts may be shared through Rust crates; processes, credentials, scaling and failure boundaries
are not shared.

`fleet-sabledb` is the control plane's authoritative state store. It is not a cache of any realm database. It
contains Fleet operator identity and session state, resource hierarchy, scoped role bindings, connection and
device-grant metadata, idempotency records, central audit history and bounded source-tagged projections. It has
its own encrypted logical backup stream and clean-room restore procedure. The Dioxus service has no database;
web and native caches are disposable and never authoritative.

For web, the dashboard service serves the Dioxus assets and forwards only bounded authentication and RPC paths
to the configured private API service. This preserves a single browser origin, strict cookies and a restrictive
`connect-src 'self'` CSP without combining the service processes. The gateway preserves `Origin`, request IDs,
Connect headers, response status and `Set-Cookie`; it does not add identity or scope headers. Desktop and mobile
clients call the public native API endpoint with their own short-lived device credentials.

The Fleet control plane never serves customer end-user authentication. A realm never depends on Fleet for
registration, authentication, token issuance, session validation, JWKS, backup or recovery.

### Railway service groups

A standalone Railway template contains three services:

```text
rustyauth-dashboard -> rustyauth-backend -> realm-sabledb
```

The central Fleet project also contains three services:

```text
rustyauth-dashboard -> rustyauth-control-plane -> fleet-sabledb
```

An encrypted `fleet-backups` object-storage bucket is a fourth Railway resource, but not a continuously running
service. A dedicated `fleet-worker` may later become a fourth runtime service when polling, connector sessions
or backup orchestration need to scale independently from request handling.

Each managed application environment adds its own `rustyauth-backend` and `realm-sabledb`. A development
template that includes Fleet and one local realm therefore contains five services. An outbound connector
gateway may become a sixth independently scaled service when connection volume requires it; it begins inside
the control-plane service to avoid an empty operational boundary.

The Dioxus service can scale horizontally. SableDB is independently sized and persisted but remains a
stateful single service. The control plane and realm backend remain at one writer replica until distributed
idempotency, locking and event sequencing are qualified.

### Resource and authorization model

The authoritative hierarchy is:

```text
Organization
└── Project
    └── Environment
        └── Realm connection
```

Fleet memberships and role bindings are separate records scoped to an organization, project or environment.
Authorization is evaluated in Rust for every RPC from the authenticated operator and stored binding graph.
Client-selected IDs only identify a requested target; they never confer scope.

Environment registration uses a short-lived, single-use pairing token or an outbound connector. The dashboard
never asks for a SableDB URL, database credential, signing key, master key or backup key. Reusable connection
credentials are encrypted at rest or held by an external secret provider and are never returned to a client.

### Delivery gates

SolidJS is removed from the production build only after all of the following pass:

1. Dioxus completes real passkey sign-in and sign-out against the same-origin service.
2. Every currently shipped local dashboard RPC and mutation works in Dioxus.
3. Organization, project and environment CRUD is durable, authorized and audited.
4. Pairing, discovery, capability negotiation, health and revocation work against an isolated test realm.
5. Cross-organization and cross-environment negative authorization tests pass.
6. Web, desktop and mobile feature builds pass; desktop credentials use the OS vault.
7. Separate dashboard, control-plane and realm-backend images build and the Rust images no longer contain a
   JavaScript dashboard runtime.
8. Recovery, version skew and Fleet-unavailable behavior are documented and exercised.

## Consequences

- Product and interaction work happens once in Dioxus instead of being synchronized across Rust and
  TypeScript clients.
- A standalone dashboard remains independent of Fleet because its configured API target is the local realm
  service.
- Browser sessions, native device tokens and connector identities remain separate credential classes even
  though they call the same Protobuf services.
- The Fleet control plane has a broader blast radius and therefore needs step-up authentication, isolated
  credential custody, strong audit retention, connection revocation drills and an independent threat review
  before production mutations are enabled.
- Direct database connectivity from any dashboard remains prohibited.
- Independent Railway services allow the dashboard, APIs and stateful stores to be deployed, sized, observed
  and upgraded without coupling their process lifecycles.

## Rejected alternatives

### Keep SolidJS for standalone indefinitely

Rejected because it doubles the implementation and regression burden precisely when organization, project,
environment and capability-aware workflows become more complex.

### Put remote database connection strings in Dioxus

Rejected because desktop packaging does not make a client a trusted secret boundary and direct database access
bypasses realm policy, validation, redaction and audit.

### Introduce Tonic only to claim native gRPC support

Rejected for the control-plane server because the pinned ConnectRPC runtime already serves native gRPC,
gRPC-Web and Connect from the same binary Protobuf service. A second runtime may be considered only if a
measured interoperability gap cannot be solved within the existing server.
