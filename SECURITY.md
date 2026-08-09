# Security policy

RustyAuth handles authentication credentials and bearer sessions. Treat every suspected weakness as
security-sensitive, including weaknesses found in preview clients or development builds.

## Supported versions

| Version | Security support |
| --- | --- |
| `1.0.x` | Supported for the Rust server/control plane, supplied containers and Dioxus web dashboard |
| `main` | Development toward the next supported release; fixes are backported when applicable |
| `< 1.0` | Unsupported |

Desktop, iOS and Android clients are preview-only and are not covered by the `1.0.x` production-support
contract.

## Reporting a vulnerability

Do not open a public issue, discussion or pull request containing vulnerability details, exploit
code, credentials or customer data.

Use the repository's [private vulnerability reporting](https://github.com/rusty-auth/rustyauth/security/advisories/new)
channel. Include:

- the affected commit or version;
- deployment assumptions;
- reproduction steps or a minimal proof of concept;
- expected and observed impact;
- whether credentials or real accounts were involved; and
- any suggested mitigation.

Do not include live session cookies, JWTs, passkey assertions, bootstrap tokens, database URLs or
backup keys. Replace them with unmistakable placeholders.

The maintainers will acknowledge a usable report, coordinate validation and publish remediation information
for supported releases. This project does not currently operate a bug bounty or promise a fixed disclosure
timeline.

## Scope

High-priority reports include:

- WebAuthn origin, RP-ID, ceremony replay or credential-binding bypasses;
- account or tenant crossing;
- session fixation, theft, expiry or revocation failures;
- JWT signature, issuer, audience, key-storage or claim-validation weaknesses;
- bootstrap-token exposure or enrolment bypass;
- operator-role escalation, or any route to a verified identifier the account did not prove control
  of;
- an RPC method reachable at a lower capability than its documented policy;
- SableDB public exposure caused by the supplied deployment;
- leakage of passkey material, bearer tokens or backup secrets;
- unsafe backup encryption or restore behavior; and
- a path that enables the development agent handoff in production.

Reports about missing planned functionality are not vulnerabilities by themselves when the README
already identifies that capability as unimplemented.

## Threat model

RustyAuth assumes:

- TLS is correctly terminated by the deployment platform;
- the configured relying-party browser origin is trusted;
- SableDB and backup buckets are private to the RustyAuth deployment;
- environment secrets are supplied through a protected secret manager;
- the host and container runtime are not already compromised; and
- downstream token consumers validate signatures and all required claims.

RustyAuth defends against unauthenticated remote callers, cross-origin browser requests, replayed
ceremonies, expired sessions, credential/account confusion and accidental exposure through its
default network topology. It does not defend against a malicious deployment administrator with
access to environment secrets and the SableDB volume.

The field-level persistence and exposure boundary is defined in
[Identity data model](docs/IDENTITY_DATA_MODEL.md). In particular, stored WebAuthn credential state,
session metadata and compatibility fields are intentionally narrower than the public HTTP/RPC
identity projections.

## Security invariants

- Production issuer and relying-party origins use HTTPS.
- RP ID exactly equals the configured application-origin host.
- Registration and authentication ceremony state is server-side, five-minute and atomically
  consumed.
- Additional-passkey ceremonies require a recent passkey session and are bound to the exact
  session that created them; initial and additional registration ceremonies are not interchangeable.
- Private endpoints require both exact origin and a valid durable session.
- The production session cookie uses the `__Host-Http-` prefix and is HttpOnly, Secure, SameSite=Strict,
  Path-scoped to `/`, domainless and time bounded.
- `AUTH_ENV` must be set explicitly. It gates Secure cookies, HTTPS origin validation and
  identity-verification enforcement, so no default can be safe in both directions.
- A master or backup encryption key whose 32 bytes are all identical is rejected as a placeholder.
- Agent handoff sessions are read-only for profile, identifier and passkey mutations.
- The final passkey cannot be removed.
- Revoking a passkey invalidates every session created with that passkey on its next use.
- A credential-removal session must be no older than five minutes.
- Every RPC method's authorization is named in an exhaustive table; an unlisted method is denied and
  a test fails until it is assigned a policy. Streaming accepts bearer policies only.
- An identifier cannot be created already verified. Marking one verified requires the administer
  capability, because verification feeds the `email_verified` claim and operator bootstrap.
- Browser operator bootstrap requires a verified allowlisted email; the first Owner is created from
  the host with `operator promote`, which costs shell access rather than control of an inbox.
- The bootstrap token is compared in constant time over fixed-width digests.
- Every response carries CSP, frame denial, cross-origin isolation, a restrictive permissions policy
  and, in production, HSTS.
- Authentication, identity and Fleet responses default to `Cache-Control: no-store`; explicitly public
  artifacts such as JWKS may supply their own bounded cache policy.
- Request duration, request body size and shutdown grace are all bounded.
- `Authorization`, `Cookie`, `x-bootstrap-token` and `Set-Cookie` are marked sensitive before the
  tracing layer observes them.
- Stored accounts must have exactly one primary identifier, unique canonical phone identifiers and
  internally consistent verification state; malformed records and reverse indexes fail closed.
- Non-zero passkey signature counters cannot regress.
- Raw session and handoff tokens are not stored as database keys.
- JWT private key bytes are encrypted at rest under a deployment-provided AES-256 key.
- A replacement signing key is published before activation; retired public keys remain available
  for at least the maximum access-token lifetime plus the JWKS cache allowance.
- Backups use compact versioned binary encoding, Zstandard compression, an authenticated AES-256-GCM
  envelope, a content manifest and tenant-bound object paths. Every new upload is read back and must prove
  content validity. The default immutable profile additionally proves bucket versioning, compliance-mode
  retention and configured server-side encryption; explicit portable deployments do not claim WORM storage.
- Restore accepts only an empty target and invalidates durable sessions by default. An incomplete
  restore marker prevents the service from starting.
- SableDB is private and volume-backed.
- Supplied containers run without root, writable root filesystems, ambient Linux capabilities or privilege
  escalation.
- Production Fleet management endpoints reject literal private, local and metadata targets; production
  infrastructure must additionally deny those destinations at egress to close DNS-rebinding paths.
- Webhook endpoints require HTTPS, reject URL credentials and fragments, and never follow redirects. Deployments
  must constrain webhook egress with an allowlist or proxy when untrusted operators can manage destinations;
  URL validation alone cannot close DNS-rebinding paths or express private-network exceptions safely.
- Missing state or invalid configuration fails closed.
- Logs and events must never contain bearer or credential payloads.

## Known limitations

These are explicit `1.0.0` boundaries and residual risks operators must account for:

- Email sign-in-link delivery remains event-only. Identifier verification challenges are implemented through
  exact signed-webhook subscriptions, and the first Owner can be created with the host CLI.
- Recovery is based on one-time offline recovery codes and passkey re-enrolment. Deployments remain responsible
  for secure code issuance/custody and a witnessed recovery drill.
- Passkey-revocation session invalidation is evaluated when a session is next used. A request
  already in flight when the credential is revoked completes.
- Anyone who can execute a shell in the deployed container can grant themselves the Owner role with
  `operator promote`. Container exec is an operator-equivalent privilege and must be restricted as
  such. `operator demote` withdraws a grant; removing an address from `AUTH_OPERATOR_EMAILS` does
  not, because a stored operator record is honoured before the allowlist is consulted.
- HTTP event polling still uses the bootstrap credential. Private event, identity, metrics and webhook RPCs
  accept short-lived, exact-scope service-account JWTs; legacy static event and identity bearers remain for
  compatibility. Workload identity and mTLS are still deployment responsibilities.
- Stored keys are one configured tenant per instance rather than tenant-prefixed.
- Compound-mutation coordination is process-local; multiple writer replicas are unqualified.
- Authentication, recovery, service-account and Fleet pairing limits use expiring SableDB counters shared
  across process replacement and replicas in the namespace, reinforced by a bounded process-local guard.
  Datastore failure rejects the request instead of falling back to an unmetered path.
- Fleet management endpoint validation cannot by itself prevent DNS rebinding. Production must enforce the
  same private, link-local and metadata denial at the network egress boundary.
- Seeded protocol fuzzing covers Analytics batches, management wire messages and archive manifests locally
  and in the tagged-release workflow. Independent assessment continues as post-GA assurance. Dependency
  auditing is automated across the shipped Rust graphs and Go infrastructure: `cargo-deny` gates the root Rust service
  on every push and tagged release over advisories, licences, bans and sources, while pinned `cargo-audit`
  checks the root, Dioxus console and repository-owned SableDB lockfiles and `govulncheck` checks the Pulumi
  module. The JSR client and generated protocol packages retain pinned dependency resolution in `deno.lock`;
  release publication still requires registry-side provenance and advisory evidence.
- The rate limiter tracks a bounded number of distinct callers and refuses rather than forgets when
  that bound is reached, so a flood from more distinct addresses than it holds degrades to a
  service-wide `429`. Failing closed is deliberate on an authentication surface, but it makes a wide
  distributed flood a denial of service rather than merely an unmetered one.
- Desktop, iOS and Android clients are unsupported previews outside the `1.0.0` artifact and GA support
  contract. Their signing, platform-trust and real-device gates belong to a later native release.
- Browser/OS/authenticator coverage, published-image install/upgrade/rollback, Analytics scale and recovery,
  organization-policy canaries and independent application/deployment/pinned-SableDB/Analytics assessments
  remain continuous assurance programs. Operators must retain deployment-specific evidence for their own
  supported matrix and risk profile.

## Safe verification

Use synthetic accounts and loopback origins. Never test against another person's account or a
deployment you do not own or have explicit permission to assess.

Before a release, run at minimum:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --locked --release
```

The recovery path also has a real-service integration drill:

```sh
docker compose -f compose.integration.yaml up -d --wait source-sabledb destination-sabledb minio
docker compose -f compose.integration.yaml run --rm minio-init
cargo test --locked --test integration_tests clean_room_backup_restore_and_rotation -- --ignored --exact
docker compose -f compose.integration.yaml down --volumes
```

Release qualification additionally requires dependency audit/deny checks, authenticator coverage, negative
protocol tests, deployment isolation verification and regular operator recovery drills. The `1.0.0` artifact
publication state and externally owned evidence are tracked in [Release readiness](docs/RELEASE_READINESS.md).
