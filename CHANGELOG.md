# Changelog

All notable RustyAuth changes will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project intends to use semantic versioning
after its public contract stabilises.

## Unreleased

This release is primarily a security hardening pass. It contains breaking changes to configuration, the
identity RPC contract and the operator-bootstrap procedure. Read [Breaking changes](#breaking-changes) before
upgrading.

### Breaking changes

- **The crate and binary are renamed from `passkey-auth-service` to `rustyauth`.** Custom container
  entrypoints, healthchecks and operator runbooks that invoke the old binary name must switch to
  `rustyauth`; the repository's own Dockerfile and compose files are already updated.
- **`AUTH_ENV` is now required.** There is no default. A deployment that omits it fails to start instead of
  silently selecting development, which would have dropped `Secure` from the session cookie, accepted an HTTP
  relying-party origin and treated every self-service identifier as verified.
- **`AUTH_MASTER_KEY_HEX` and `AUTH_BACKUP_ENCRYPTION_KEY_HEX` reject placeholder keys.** A 32-byte key whose
  bytes are all identical is refused, including the all-zero key this repository previously shipped in
  `.env.example` and `compose.yaml`. Both fixtures now carry a real — but still public — development key.
  Generate a per-environment key with `openssl rand -hex 32`; the rule applies in development too.
- **`AddIdentifier` rejects `verified: true`.** The identity RPC returns `invalid_argument` instead of
  creating a verified identifier. Callers that relied on the one-step behaviour must now call `AddIdentifier`
  followed by `SetIdentifierVerification`.
- **`SetIdentifierVerification` requires the Administer capability.** It previously required Support. Support
  operators can still add, remove and re-prioritize identifiers; they can no longer assert that an account
  controls one.
- **`AUTH_OPERATOR_EMAILS` alone no longer grants operator access.** Browser bootstrap additionally requires
  the account to hold a *verified* email identifier from that list. Create the first Owner with
  `rustyauth operator promote <user-id> owner`.
- **Revoking a passkey ends the sessions created with it.** Deployments that relied on a session surviving
  its credential's removal will see those sessions rejected on their next request.

### Added

- `rustyauth operator promote <email> <owner|administrator|support|auditor>` and
  `rustyauth operator list`. Promotion is the supported way to create the first Owner: browser
  bootstrap requires an operator email the account has already verified, and nothing can verify one until an
  operator exists to do it. The CLI breaks that cycle and deliberately costs shell access to the deployment
  rather than control of an inbox.
- Response security headers on every response: `Content-Security-Policy` (self-only script, style, font,
  image and connect sources, `frame-ancestors 'none'`, `base-uri 'none'`, `object-src 'none'`),
  `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin` and
  `Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()`.
- `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` in production only. It is
  withheld in development because pinning it from a `http://localhost` origin would hold the browser to HTTPS
  for that host for two years.
- A 30-second request timeout, returning `408`. Size limits cap how much a client sends, never how long it
  takes; without a deadline a slow-body client holds a connection open indefinitely.
- A 256 KiB request body limit on the REST handlers, returning `413`, replacing axum's 2 MiB default. The RPC
  layer keeps its tighter 64 KiB body and 256 KiB message limits.
- A 20-second bounded shutdown grace for background signing and backup workers, so a backup mid-upload can
  checkpoint rather than die mid-write while a single stuck worker or open event stream cannot block a deploy
  indefinitely.
- `SABLEDB_URL` accepts the `rediss` scheme so a deployment can encrypt datastore traffic. In production a
  `redis` URL must still be on Railway private networking; a `rediss` URL is accepted from any host.
- A canonical identity data-model reference in the repository and developer site covering every persisted
  field, index, lifecycle record, API projection and deliberately excluded data class.
- Multiple email and E.164 phone identifiers per stable passkey account, with primary selection, guarded
  removal and backwards-compatible email request bodies.
- Optional given, family and display names for account and WebAuthn presentation.
- Automatic staged ES256 signing-key rotation with JWKS prepublication, retired-key overlap and transparent
  master-key rewrapping.
- Scheduled, authenticated logical backups to S3-compatible storage, plus `create`, `list`, `verify` and
  empty-target `restore` operator commands.
- A clean-room recovery integration test against two real SableDB instances and MinIO.
- Versioned Connect/gRPC/gRPC-Web services for resumable auth-event streaming and trusted identity reads,
  exact search, profile/contact updates, and passkey metadata operations.
- A generated TypeScript protocol package and Solid-friendly Connect transport helpers.
- A Deno/SolidJS operator dashboard for user search, organization settings, scoped service-account issuance
  and common authentication metrics, bundled into the Rust/Railway container.
- Durable organization, operator and service-account records with one-time credential issuance, revocation and
  short-lived scoped ES256 token exchange.
- RustyAuth public identity, logo lockup and brand guidance.
- Architecture, API, configuration, deployment, security and contribution documentation.
- Apache-2.0 project licence and explicit SableDB attribution.
- `@rustyauth/client`, a dependency-free browser package wrapping the public WebAuthn ceremony,
  token and credential-management endpoints, including the JSON encodings the ceremonies require.
- Runnable `examples/`: a static relying party exercising registration, sign-in and token minting,
  and a Node downstream service verifying issued tokens against JWKS.
- An OpenAPI 3.1 document for the public HTTP API at `docs/openapi.yaml`.
- A tag-triggered release workflow that publishes the container images to
  `ghcr.io/rusty-auth/rustyauth` and `ghcr.io/rusty-auth/sabledb` and the TypeScript packages to
  JSR, documented in `RELEASING.md`.
- Cached, parallel CI: independent Rust lint/test lanes and a dashboard lane, a dependency layer in
  the Dockerfile so source edits no longer recompile the dependency graph, BuildKit layer caches
  shared between CI and releases, and a cached SableDB image reused by the integration drill
  instead of a from-source database build every run.
- The protobuf module is named `buf.build/rusty-auth/rustyauth` for Buf Schema Registry
  publication.

### Changed

- RPC authorization is an exhaustive `METHOD_POLICIES` table naming every method individually, replacing
  suffix matching with a fallback capability. A method with no entry is denied, and a test that reads the
  checked-in `.proto` sources fails until someone assigns it a policy — so a newly generated method can no
  longer become reachable, at whatever capability the `else` branch happened to hold, simply by existing.
- `SetIdentifierVerification` moved from the Support to the Administer capability.
- Operator bootstrap requires a verified email identifier rather than any matching identifier.
- `Cookie` and `x-bootstrap-token` request headers and the `Set-Cookie` response header are now marked
  sensitive by the service itself, alongside `Authorization`. Operator tooling still has to redact them in
  proxy logs, APM collectors, log shippers and support bundles; the service can only protect its own logs.
- `docs/DEPLOYMENT.md` records the platform-side timeout and drain windows a deployment must allow for the
  new request timeout and shutdown grace.

### Fixed

- Sessions created by a revoked passkey are no longer accepted. Session validation checks that the session's
  originating credential is still attached to the account and deletes the session when it is not.
- Operator creation runs inside the snapshot gate, so a backup taken concurrently can no longer capture an
  operator record without the `operator.created` event that explains it.
- A `rediss://` datastore URL is accepted instead of being rejected as an unknown scheme.

### Security

- **Passkey revocation is now a containment control.** Previously, revoking a passkey left the sessions it
  had created alive until the absolute session lifetime elapsed — up to seven days at the default
  `AUTH_SESSION_ABSOLUTE_SECONDS`. An operator responding to a lost or stolen authenticator removed the
  credential, watched it disappear from the dashboard, and the thief's browser session kept working. The
  guarantee is now that revoking a passkey ends every session created with it, on that session's next
  request. This is not a revoke-all: other passkeys on the account keep their sessions, and sessions with no
  originating credential (development agent handoffs) are unaffected.
- **Operator bootstrap cannot be claimed with an unverified address.** Every identifier on the self-service
  API is caller-chosen, and production stores new ones unverified. Matching an unverified identifier against
  `AUTH_OPERATOR_EMAILS` let any enrolled account attach an unclaimed operator address to itself and be
  granted Owner on its next dashboard request. Bootstrap now requires the identifier to be verified.
- **`AddIdentifier` can no longer mint a verified identifier.** Honouring `verified: true` let any
  Support-capable caller produce a trusted `email_verified` claim for an address nobody proved control of,
  and — combined with the bootstrap path — create the exact verified operator address that grants Owner.
  Attaching an address and asserting control of it are now separate operations at separate privilege levels.
- **Unknown RPC methods are denied.** Suffix-based authorization resolved any unrecognized method on a known
  service to its fallback capability, so a method added to a `.proto` file became reachable before anyone
  reviewed what it should require.
- **`AUTH_ENV` cannot fail open.** It gates Secure cookies, HTTPS origin validation and
  identity-verification enforcement; defaulting it meant a production deployment that forgot to set it ran
  with all three relaxed while reporting healthy.
- **Placeholder encryption keys are rejected.** The all-zero master key was published in this repository's
  own fixtures. An operator who never replaced it wrapped every stored signing key and every backup envelope
  under a public value, producing encryption at rest that satisfies an inventory question and stops nobody.
- **The bootstrap token is compared in constant time** over SHA-256 digests. String equality short-circuits
  at the first differing byte, which leaks the token to an attacker timing this unauthenticated enrolment
  endpoint one byte at a time. Hashing first also makes the comparison independent of token length.
- **Unauthenticated endpoints are rate limited per caller address.** Naming an account cost nothing, so an
  attacker could enumerate which addresses hold accounts, and open ceremonies without bound. Identifier
  probes, ceremonies and service-account token exchange now carry separate per-minute budgets over a fixed
  60-second window and answer `429` with `Retry-After` once a budget is exhausted. The budgets are
  deliberately generous enough that a person retrying a failed passkey tap is never throttled.
- **Clickjacking, injected script and cross-origin leakage have browser-enforced boundaries.** The dashboard
  is an administrative surface on the same origin as the authentication API; CSP, `X-Frame-Options`, COOP and
  CORP now deny framing, inline and remote script, `base` rewriting and cross-origin subresource embedding.
- **A slow-body client can no longer hold a connection indefinitely.** The RPC size limits bound how much a
  caller sends, not how long it takes; the 30-second timeout bounds duration.
- **Datastore traffic can be encrypted.** Rejecting `rediss` forced every deployment onto a plaintext link
  carrying sessions and wrapped signing keys.

- Identity and credential mutations reject agent sessions; high-impact identifier and passkey enrolment
  changes require a passkey session created within five minutes, and add-passkey ceremonies are bound to the
  initiating session.
- Account records, canonical identity inputs and backup reverse indexes are validated fail-closed; invisible
  directional-formatting characters are rejected from profile names.
- Backup manifests validate tenant, digest, indexes, expiry policy, signing state and ordered-event continuity
  before restore writes anything.
- Restore invalidates sessions by default, rotates signing material and fails startup closed when an
  interrupted recovery marker remains.
- Signing and backup keyrings derive non-secret key IDs, redact key material and retain explicitly configured
  previous keys during rotation.
- Event and identity RPCs fail closed behind distinct bearer credentials, and passkey responses are projected
  through a metadata-only type that cannot expose stored WebAuthn credential material.
- Operator RPCs require an exact-origin passkey session and enforce owner, administrator, support and auditor
  capabilities; local-agent sessions cannot enter the control plane.
- Service-account secrets are returned once, indexed only by SHA-256 and rejected when disabled, expired,
  revoked or asked to escalate scopes.

## 0.1.0 - 2026-08-07

### Added

- Passkey registration and authentication using `webauthn-rs`.
- Single-use, server-side WebAuthn ceremony state.
- Persistent users, passkeys and sessions on private SableDB.
- Passkey listing, addition, rename and protected revocation.
- ES256 access tokens, encrypted signing material, OpenID-style discovery and JWKS.
- Exact-origin CORS/request enforcement and fail-closed production configuration.
- Ordered authentication events over cursor-based HTTP polling.
- Health, readiness, structured logging and request IDs.
- Development-only existing-account browser-agent handoff.
- AES-256-GCM S3 backup-envelope upload primitive.

### Known limitations

- No complete email delivery, lost-authenticator recovery, webhook delivery, multi-writer qualification or
  independent security assessment.
