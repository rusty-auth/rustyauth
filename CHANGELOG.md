# Changelog

All notable RustyAuth changes will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic versioning for the
supported `1.x` contract.

## Unreleased

### Fixed

- Stop archiving obsolete SableDB write-ahead logs on supported single-writer realms. The prior 24-hour WAL
  retention could turn a megabyte-scale account dataset into tens of gigabytes of volume usage; image
  qualification now replays production-shaped transactions, restarts the database, verifies durability and
  enforces a storage ceiling.
- Prepare isolated benchmark realms with bounded atomic batches and validate the resulting users, sessions,
  indexes and complete gap-free auth event log through the production storage model before a run is accepted.

## 1.0.0 - 2026-08-09

This release is primarily a security hardening pass. It contains breaking changes to configuration, the
identity RPC contract and the operator-bootstrap procedure. Read [Breaking changes](#breaking-changes) before
upgrading.

### Breaking changes

- **The crate and binary are renamed from `passkey-auth-service` to `rustyauth`.** Custom container
  entrypoints, healthchecks and operator runbooks that invoke the old binary name must switch to `rustyauth`;
  the repository's own Dockerfile and compose files are already updated.
- **`AUTH_ENV` is now required.** There is no default. A deployment that omits it fails to start instead of
  silently selecting development, which would have dropped `Secure` from the session cookie, accepted an HTTP
  relying-party origin and treated every self-service identifier as verified.
- **`AUTH_MASTER_KEY_HEX` and `AUTH_BACKUP_ENCRYPTION_KEY_HEX` reject placeholder keys.** A 32-byte key whose
  bytes are all identical is refused, including the all-zero key this repository previously shipped.
- **No secret ships with a value.** `.env.example` leaves every secret blank and `compose.yaml` refuses to
  substitute a default, so an unpopulated `.env` now stops the stack by name. The placeholder check cannot
  tell a generated key from a published one, so a committed development default would have passed it while
  remaining readable in this repository. Generate each secret, including for local work.
- **`AUTH_TRUSTED_PROXY_HOPS` is required in production.** State the number of reverse proxies in front of the
  service — `1` when the platform terminates TLS. Without it the rate limiter either trusts a client-supplied
  `X-Forwarded-For` or collapses every client into the edge's single bucket.
- **Absolute session expiry must exceed idle expiry.** Startup rejects an
  `AUTH_SESSION_ABSOLUTE_SECONDS` value equal to or shorter than `AUTH_SESSION_IDLE_SECONDS` instead of
  accepting a self-contradictory session policy.
- **`AUTH_BACKUP_ENDPOINT` must use HTTPS in production.** A plaintext endpoint exposed snapshots and the
  SigV4 credential scope on the wire.
- **`AddIdentifier` rejects `verified: true`.** The identity RPC returns `invalid_argument` instead of
  creating a verified identifier. Callers that relied on the one-step behaviour must now call `AddIdentifier`
  followed by `SetIdentifierVerification`.
- **`SetIdentifierVerification` requires the Administer capability.** It previously required Support. Support
  operators can still add, remove and re-prioritize identifiers; they can no longer assert that an account
  controls one.
- **`AUTH_OPERATOR_EMAILS` alone no longer grants operator access.** Browser bootstrap additionally requires
  the account to hold a _verified_ email identifier from that list. Create the first Owner with
  `rustyauth operator promote <user-id> owner`.
- **Revoking a passkey ends the sessions created with it.** Deployments that relied on a session surviving its
  credential's removal will see those sessions rejected on their next request.

### Added

- Native AWS KMS envelope-key inputs for the active and previous master/backup keys. KMS decrypts use
  purpose- and tenant-bound encryption context, reject plaintext/KMS ambiguity, require exactly 32 plaintext
  bytes and zeroize decrypted material after configuration assembly.
- A shared, fail-closed SableDB rate limiter for production authentication and RPC budgets. Counter keys use
  tenant/subject digests, survive process replacement and are excluded as transient state from backups.
- DNS-rebinding-resistant Fleet management transport: every production call resolves under a deadline,
  rejects empty or mixed public/private answers, pins the accepted addresses while retaining hostname TLS,
  disables redirects and bounds response bytes.
- Exact management protocol/version negotiation, additive capability handling, legacy-session compatibility
  fixtures and seeded fuzz targets for Analytics batches, management wire messages and archive manifests.
- Host-native unsigned Dioxus packaging qualification for macOS, Windows and Linux, including stable bundle
  metadata and an explicit fail-closed signing gate for tagged releases.
- Checksum-pinned Trivy qualification that rejects every HIGH/CRITICAL finding in the API, dashboard and
  SableDB runtime images before CI or tagged-release promotion.
- Auditable dependency metadata in the API, SableDB and Dioxus WebAssembly artifacts, plus independent root,
  console and SableDB lockfile audits, so scratch-image scans and SBOM generators can describe shipped Rust
  components instead of seeing an opaque stripped binary.
- A reusable hardened scratch-runtime smoke gate covering non-root/read-only execution, shell absence,
  capabilities, private networking, bounded gateway routing, security headers, asset MIME types and repeated
  writer-lease renewals; tagged releases execute the same gate before live-service qualification.
- Dependency-free HTTP/Redis container health probes with success and failure tests, allowing every production
  image to use a shell-free scratch runtime.
- Dedicated passkey step-up ceremonies, account-wide session revocation, one-time offline recovery codes and
  recovery passkey enrolment. Recovery revokes prior sessions and invalidates every remaining recovery code.
- Identifier-bound production invitations managed through operator RPCs. Raw invitation codes are returned
  once and their claim is consumed atomically with creation of the account and first passkey.
- One-time email/phone verification challenges delivered only through exact signed-webhook subscriptions;
  challenge codes are neither logged nor persisted in webhook delivery metadata.
- Durable signed webhook delivery with bounded retries, delivery history, replay, per-destination cursors and
  retention-aware event replay.

- The transport-neutral `rustyauth.analytics.v1` Fleet Analytics contract with closed five-minute snapshots,
  exact-revision acknowledgements, registry coverage and signed archive manifests. Strict Rust validation,
  fixed histogram profiles, a canonical Parquet schema and golden wire/result fixtures establish the M9
  compatibility baseline.
- M10 realm telemetry: request-path events project asynchronously into bounded five-minute SableDB snapshots,
  the standalone MetricsService reads those local facts, and a 288-bucket durable outbox exports complete
  revisions over an authenticated realm-initiated gRPC connector. Fleet stamps stored hierarchy into its
  acceptance ledger and acknowledges only after commit; outage, restart, duplicate-delivery, queue-pressure
  and exporter-panic qualification keep authentication independent.
- A dedicated `rustyauth.analytics.v1.AnalyticsService` with authorized Fleet, organization, project,
  environment and realm scopes; bounded overview/series/funnel/failure/coverage/comparison reads; and explicit
  organization retention/residency policy administration.
- A private GreptimeDB adapter with wide canonical five-minute facts, database-namespaced hourly/daily Flow
  materialization, deterministic correction replacement, retention enforcement, disconnect purge and a
  measured 1,000-realm/28-day organization-query p95 gate.
- Real Zstandard Parquet interchange with exact Arrow field IDs/types, raw P-256 signed manifests,
  checksum/length/row bounds, idempotent live/backfill convergence and exact-object presigned access limited to
  15 minutes.
- Live Dioxus Analytics drill-down, sibling comparison, policy controls and explicit loading, empty, disabled,
  unsupported, partial, stale and forbidden states. Missing telemetry is rendered unavailable rather than zero.
- Durable Fleet organization/project/environment/connection registry and RBAC; public and realm-initiated
  pairing; source-tagged partial operations; passkey-step-up remote administration; two-phase credential
  rotation/revocation; and correlated realm/Fleet audit.
- Short-lived native Dioxus device sessions with a separate token namespace and desktop/mobile OS-vault
  adapters. Web, desktop and mobile feature builds share the same screens and authorization semantics; native
  targets remain unsupported previews outside the `1.0.0` release artifacts.
- A fail-closed release-evidence record and validator. Tagged releases now require named evidence for the
  independent security/deployment/SableDB/Analytics reviews, real Analytics canary, published-image drills,
  supported-web browser/authenticator matrix, witnessed recovery and final release approval. Native signing
  and device distribution are separately gated post-1.0 work. Evidence must declare the exact
  `server-container-web-ga` scope, and unknown or deprecated native gates are rejected.
- `rustyauth operator list`, `operator find <email>`, `operator promote <user-id> <role>` and
  `operator demote <user-id>`. Promotion is the supported way to create the first Owner: browser bootstrap
  requires an operator email the account has already verified, and nothing can verify one until an operator
  exists to do it. The CLI breaks that cycle and deliberately costs shell access to the deployment rather than
  control of an inbox. It takes a **user id** rather than an address, because any enrolled account can claim
  an unclaimed address through the self-service API — `operator find` shows which accounts hold an address and
  when they claimed it. `operator demote` withdraws a grant; removing an address from `AUTH_OPERATOR_EMAILS`
  does not, because a stored grant is honoured before the allowlist is consulted.
- Response security headers on every response: `Content-Security-Policy` (self-only script, style, font, image
  and connect sources, `frame-ancestors 'none'`, `base-uri 'none'`, `object-src 'none'`),
  `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin` and
  `Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()`.
- `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` in production only. It is withheld
  in development because pinning it from a `http://localhost` origin would hold the browser to HTTPS for that
  host for two years.
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
- Scheduled full-workspace Realm and Fleet backups using compact Postcard encoding, Zstandard compression and
  versioned AES-256-GCM `.rauth` envelopes. New uploads require read-after-write decryption, S3 Versioning,
  compliance-mode Object Lock, configured provider encryption and a valid content manifest. Operator commands
  cover `create`, `list`, durable `status`, `verify` and fail-closed empty-target `restore`; v2 JSON envelopes
  remain restorable.
- A normative backup/disaster-recovery reference and an expanded Astro developer guide covering state scope,
  exclusions, binary layout, key custody, immutable storage, health alerts and monthly clean-room drills.
- A clean-room recovery integration test against two real SableDB instances and MinIO.
- Versioned Connect/gRPC/gRPC-Web services for resumable auth-event streaming and trusted identity reads,
  exact search, profile/contact updates, and passkey metadata operations.
- A generated TypeScript protocol package and dependency-free public client.
- A unified Rust/Dioxus operator dashboard for standalone web and Fleet web, with shared desktop/mobile feature
  targets and a separately deployable stateless dashboard gateway.
- Durable organization, operator and service-account records with one-time credential issuance, revocation and
  short-lived scoped ES256 token exchange.
- RustyAuth public identity, logo lockup and brand guidance.
- Architecture, API, configuration, deployment, security and contribution documentation.
- Apache-2.0 project licence and explicit SableDB attribution.
- `@rustyauth/client`, a dependency-free browser package wrapping the public WebAuthn ceremony, token and
  credential-management endpoints, including the JSON encodings the ceremonies require.
- Runnable `examples/`: a static relying party exercising registration, sign-in and token minting, and a Node
  downstream service verifying issued tokens against JWKS.
- An OpenAPI 3.1 document for the public HTTP API at `docs/openapi.yaml`.
- A tag-triggered release workflow that publishes the container images to `ghcr.io/rusty-auth/rustyauth` and
  `ghcr.io/rusty-auth/sabledb` and the TypeScript packages to JSR, documented in `RELEASING.md`.
- Cached, parallel CI: independent Rust lint/test lanes and a dashboard lane, a dependency layer in the
  Dockerfile so source edits no longer recompile the dependency graph, BuildKit layer caches shared between CI
  and releases, and a cached SableDB image reused by the integration drill instead of a from-source database
  build every run.
- The protobuf module is named `buf.build/rusty-auth/rustyauth` for Buf Schema Registry publication.

### Changed

- API, dashboard and SableDB runtime stages now start from `scratch`. They contain only the required binaries,
  exact shared libraries/configuration/assets and notices; no package manager, shell, Perl, curl or wget ships.
- The dashboard gateway is built from immutable Caddy 2.11.4 source under Go 1.26.5 with fixed `x/text` and
  gRPC modules, rather than inheriting the stale official runtime image.
- The pinned SableDB revision is compiled against the repository-owned `sabledb/Cargo.lock` with `--locked`;
  upstream's missing lockfile can no longer make identical source builds resolve different crates.
- Tagged releases rerun the complete ignored qualification suite against pinned SableDB, MinIO and
  GreptimeDB before publishing. JSR and Buf Schema Registry publication are blocking release dependencies;
  an incomplete package or protocol publish can no longer produce a successful GitHub release.
- Release publication now performs a fail-fast JSR and Buf registry preflight before any container or package
  job starts, and both TypeScript packages receive a publish dry-run during release verification.

- RPC authorization is an exhaustive `METHOD_POLICIES` table naming every method individually, replacing
  suffix matching with a fallback capability. A method with no entry is denied, and a test that reads the
  checked-in `.proto` sources fails until someone assigns it a policy — so a newly generated method can no
  longer become reachable, at whatever capability the `else` branch happened to hold, simply by existing.
- `SetIdentifierVerification` moved from the Support to the Administer capability.
- Operator bootstrap requires a verified email identifier rather than any matching identifier.
- `Cookie` and `x-bootstrap-token` request headers and the `Set-Cookie` response header are now marked
  sensitive by the service itself, alongside `Authorization`. Operator tooling still has to redact them in
  proxy logs, APM collectors, log shippers and support bundles; the service can only protect its own logs.
- `docs/DEPLOYMENT.md` records the platform-side timeout and drain windows a deployment must allow for the new
  request timeout and shutdown grace.

### Removed

- The SolidJS/Vite dashboard and `@rustyauth/connect-solid` package. Dioxus is the only production dashboard
  implementation and CI fails if Solid product sources return.

### Fixed

- Distributed rate-limit transactions now decode Redis `EXEC` tuple responses correctly; the prior scalar
  decode made every shared-counter request fail closed. Snapshot validation also recognizes and excludes the
  new transient counter namespace rather than rejecting backups as an unknown durable key family.
- The Dioxus dashboard uses a hashed external stylesheet and a CSP with `style-src 'self'`; it no longer needs
  inline style permission.
- The dashboard gateway now allowlists every HTTP path and Connect service used by Dioxus, anchors RPC method
  matching, emits the security-header policy on success and error responses, suppresses the Caddy server
  banner, and keeps Caddy state under writable `/tmp` paths for read-only-root deployments.
- Writer-lease renewal now uses the atomic `GETEX` command supported by the pinned SableDB revision and fences
  a replaced owner without relying on the revision's advertised-but-unimplemented `SET IFEQ`/Lua behavior.

- Sessions created by a revoked passkey are no longer accepted. Session validation checks that the session's
  originating credential is still attached to the account and deletes the session when it is not.
- Operator creation runs inside the snapshot gate, so a backup taken concurrently can no longer capture an
  operator record without the `operator.created` event that explains it.
- A `rediss://` datastore URL is accepted instead of being rejected as an unknown scheme.

### Security

- **Passkey revocation is now a containment control.** Previously, revoking a passkey left the sessions it had
  created alive until the absolute session lifetime elapsed — up to seven days at the default
  `AUTH_SESSION_ABSOLUTE_SECONDS`. An operator responding to a lost or stolen authenticator removed the
  credential, watched it disappear from the dashboard, and the thief's browser session kept working. The
  guarantee is now that revoking a passkey ends every session created with it, on that session's next request.
  This is not a revoke-all: other passkeys on the account keep their sessions, and sessions with no
  originating credential (development agent handoffs) are unaffected.
- **Operator bootstrap cannot be claimed with an unverified address.** Every identifier on the self-service
  API is caller-chosen, and production stores new ones unverified. Matching an unverified identifier against
  `AUTH_OPERATOR_EMAILS` let any enrolled account attach an unclaimed operator address to itself and be
  granted Owner on its next dashboard request. Bootstrap now requires the identifier to be verified.
- **`AddIdentifier` can no longer mint a verified identifier.** Honouring `verified: true` let any
  Support-capable caller produce a trusted `email_verified` claim for an address nobody proved control of, and
  — combined with the bootstrap path — create the exact verified operator address that grants Owner. Attaching
  an address and asserting control of it are now separate operations at separate privilege levels.
- **Unknown RPC methods are denied.** Suffix-based authorization resolved any unrecognized method on a known
  service to its fallback capability, so a method added to a `.proto` file became reachable before anyone
  reviewed what it should require.
- **`AUTH_ENV` cannot fail open.** It gates Secure cookies, HTTPS origin validation and identity-verification
  enforcement; defaulting it meant a production deployment that forgot to set it ran with all three relaxed
  while reporting healthy.
- **Placeholder encryption keys are rejected.** The all-zero master key was published in this repository's own
  fixtures. An operator who never replaced it wrapped every stored signing key and every backup envelope under
  a public value, producing encryption at rest that satisfies an inventory question and stops nobody.
- **The bootstrap token is compared in constant time** over SHA-256 digests. String equality short-circuits at
  the first differing byte, which leaks the token to an attacker timing this unauthenticated enrolment
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
