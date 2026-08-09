# 0001: Rust control plane with a SolidJS dashboard

- Status: superseded for the dashboard client by ADR 0003; the Rust authorization and database boundary remains accepted
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

Organization and service-account services are mounted only behind the Rust passkey-operator policy.
The first passkey-authenticated user whose canonical primary email appeared in
`AUTH_OPERATOR_EMAILS` bootstrapped the owner record. That rule was superseded: bootstrap now
requires the address to be **verified**, and the first Owner is created from the host with
`rustyauth operator promote <user-id> owner`, because an unverified address is one any enrolled
account can claim through the self-service API. Service credentials are generated once, indexed
by SHA-256, independently revocable and exchangeable only for an allowed subset of their account's
scopes. Webhook and metrics services were gated until their durable storage, policy and
rejection-path tests landed; current main mounts both services. Short-lived service-account JWTs
now authorize exact method scopes, while the private event and identity RPC bearer tokens remain
transitional credentials. None are dashboard credentials and none may be embedded in browser code.

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

The original SolidJS client described by this decision was superseded by Dioxus. Passkey operator
authorization, organization persistence, service-account token exchange, signed webhook delivery
and standalone metric rollups are implemented on current main. Cross-realm Fleet Analytics
projection remains a separate staged program.

## Future fleet evolution

This decision describes the embedded single-instance dashboard. The future
[fleet control-plane direction](../FLEET_CONTROL_PLANE.md) preserves its core rule that browsers call
an authorized Rust service rather than SableDB. Fleet mode would add a central dashboard and control
API that connect to versioned RustyAuth management endpoints or outbound connectors for many isolated
deployments. It does not make the browser a direct database client and does not change the current
one-organization-per-instance claim.
