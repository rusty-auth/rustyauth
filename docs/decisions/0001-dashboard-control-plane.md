# 0001: Rust control plane with a SolidJS dashboard

- Status: accepted
- Date: 2026-08-07

## Context

RustyAuth needs an operator dashboard for user search and account support, organization settings,
service accounts, webhook operations, and authentication metrics. The dashboard will be built with
SolidJS and Deno and deployed with the Railway template. SableDB is a persistence engine, not an
authorization boundary, and cannot be exposed to a browser.

The existing `@rustyauth/connect-solid` concept is useful for client caching and cancellation, but
Solid integration necessarily remains TypeScript. The authoritative API, policy, persistence, and
secret handling belong in Rust.

## Decision

The browser uses ConnectRPC v2 over HTTPS to the public RustyAuth service. RustyAuth alone reaches
SableDB over Railway private networking. The production dashboard is served from the same origin as
the Rust service so operator authentication can use a Secure, HttpOnly, SameSite cookie plus exact
origin validation.

The repository owns two complementary packages:

- `@rustyauth/connect-solid` contains transport, Solid Query option factories, cancellation, and
  bounded stream helpers. It contains no generated service contract or authorization policy.
- `@rustyauth/protocol` contains TypeScript descriptors generated from the same protobuf files that
  `connectrpc-build` compiles into Rust.

The control-plane contract is divided by policy boundary:

- `IdentityService` supports exact, indexed user search and explicit account mutations.
- `OrganizationService` represents the one organization configured for an instance and its
  operators. Its resource shape permits a future multi-organization migration without claiming
  multi-tenant isolation today.
- `ServiceAccountService` manages non-human principals, scoped credentials, and short-lived token
  exchange. Raw credentials are returned only when created and are never listable.
- `WebhookService` manages signed endpoints, secret rotation, tests, delivery history, and replay.
- `MetricsService` returns bounded aggregates and time series without user, identifier, IP address,
  credential, or webhook URL dimensions.

Service account, webhook, organization, and metrics protobuf services are contract foundations.
They must not be mounted until their Rust storage and policy implementations have operator/session
authorization and rejection-path tests. The existing private event and identity RPC bearer tokens
remain transitional service credentials; they are not dashboard credentials and must never be
embedded in browser code.

## Security and operational properties

- Every administrative mutation is authorized in Rust and produces a redacted audit event.
- Service credentials and webhook signing secrets are high-entropy, independently rotatable,
  stored only as one-way digests or encrypted secret material, and shown once at creation.
- Webhook delivery uses a durable outbox, bounded retries, idempotent event IDs, destination
  validation, and egress controls before it is enabled.
- Metrics are recorded as bounded-cardinality counters, histograms, and rollups. Raw secrets and
  identifiers are never metric labels.
- SableDB has no public Railway domain. Only RustyAuth is exposed through Railway HTTP networking.
- One writer remains the supported topology until cross-instance locking is qualified.

## Consequences

The dashboard and server share one versioned protobuf contract and can evolve independently without
duplicating request types. Browser code stays idiomatic Solid/TypeScript while all trust decisions
stay in Rust. A later split into a separate dashboard service remains possible, but would require an
explicit cross-origin session and CSRF design.

This decision does not claim that the dashboard UI, service-account persistence, webhook delivery,
or metric rollups are implemented. Those capabilities become shipped only when their Rust handlers,
storage migrations, operator authorization, tests, and Railway deployment checks land.
