<div align="center">
  <img src="assets/rustyauth-lockup.png" width="720" alt="RustyAuth — a copper and graphite R with an integrated passkey aperture" />

  **Built in Rust. Built on SableDB. Built for passkeys.**

  A small, self-hosted Rust identity service for WebAuthn ceremonies, durable browser sessions
  and short-lived ES256 access tokens.

  [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-cb5a19.svg)](LICENSE)
  [![Rust: 1.94.1+](https://img.shields.io/badge/rust-1.94.1%2B-303030.svg)](Cargo.toml)
  [![Status: pre-release](https://img.shields.io/badge/status-pre--release-e2a84a.svg)](#project-status)
  [![Storage: SableDB](https://img.shields.io/badge/storage-SableDB-303030.svg)](https://github.com/sabledb-io/sabledb)

  [Website](https://rustyauth.dev) · [Documentation](https://rustyauth.dev/docs) · [Source](https://github.com/rusty-auth/rustyauth)

  [![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/new/template/rustyauth?utm_medium=integration&utm_source=button&utm_campaign=rustyauth)
</div>

> [!WARNING]
> RustyAuth is pre-release software. Account recovery, abuse controls, multi-writer qualification
> and an independent security assessment are not complete. Do not make it the sole identity system
> for a production service yet.

## What RustyAuth is

RustyAuth is passkey-first authentication built in Rust on SableDB. It is a reusable authentication
boundary for applications that want passkeys without handing
their identity data to a hosted identity provider. The browser talks to a narrow Rust/Axum service;
that service stores durable identity state in a private SableDB instance and issues short-lived JWTs
for downstream APIs.

RustyAuth is not a user-interface framework, authorization engine or general OpenID Provider. It
authenticates an identity and produces claims. Your application remains responsible for roles,
permissions, entitlements and resource ownership.

### Implemented today

- WebAuthn passkey registration and authentication with five-minute, server-side, single-use
  ceremonies;
- persistent users, passkeys and sessions in SableDB using its Valkey-compatible protocol;
- multiple canonical email/phone identifiers and optional given, family and display names per
  stable account UUID;
- HttpOnly, SameSite=Strict sessions with idle and absolute expiry;
- multiple passkeys per account, labels, last-used timestamps and final-credential protection;
- passkey revocation that immediately ends the sessions that passkey created;
- recent-authentication enforcement before credential removal;
- passkey sign-counter regression detection;
- ES256 JWT issuance with issuer, audience, tenant, subject, session and authentication-method
  claims;
- OpenID-style discovery and a public JWKS endpoint;
- ordered, cursor-based authentication-event polling and gRPC streaming;
- private Connect/gRPC identity reads, exact search and controlled mutations;
- a same-origin SolidJS operator dashboard with passkey-only sessions, user search and account
  inspection;
- durable single-organization settings and role-gated operator access;
- scoped service accounts with independently revocable, one-time credentials and short-lived ES256
  token exchange;
- exact-origin CORS and request-origin enforcement;
- browser response hardening with CSP, frame denial, cross-origin isolation, a restrictive
  permissions policy and production HSTS;
- bounded request duration, request body size and shutdown grace;
- liveness, dependency readiness, request IDs and structured JSON logging;
- development-only, one-use agent browser handoffs for an existing account;
- automatic staged signing-key rotation with overlapping JWKS publication; and
- scheduled, authenticated logical backups to S3-compatible storage with verification and
  clean-room restore commands.

See [Project status](#project-status) for functionality that is deliberately not claimed yet.

## Architecture

```mermaid
flowchart LR
    Browser["Browser / relying party"] -->|"WebAuthn + HttpOnly session"| Auth["RustyAuth\nRust + Axum"]
    Auth -->|"private Valkey protocol"| Sable["SableDB\nidentity state"]
    Auth -->|"short-lived ES256 JWT"| API["Application API / SpacetimeDB"]
    API -->|"JWKS verification"| Auth
    Auth -.->|"scheduled AES-256-GCM\nlogical backups"| Bucket["S3-compatible bucket"]
```

Only RustyAuth is public. SableDB must remain private and volume-backed; it is a persistence engine,
not the authorization boundary. A downstream service must verify the JWT signature, `iss`, `aud`,
`exp`, `tenant_id` and the claims relevant to its own policy.

Read [Architecture](docs/ARCHITECTURE.md) for the trust boundaries, data model and complete flows.

## Quick start

Requirements: Docker with Compose and `curl`.

```sh
git clone https://github.com/rusty-auth/rustyauth.git
cd rustyauth
cp .env.example .env
docker compose up --build
```

The default development deployment binds RustyAuth and its bundled operator dashboard to loopback at
`http://localhost:8081` and does not publish SableDB. Open that URL with the `admin@rustyauth.local`
passkey account, or use `?preview=1` to inspect the populated dashboard without mutating SableDB.

```sh
curl --fail http://127.0.0.1:8081/healthz
curl --fail http://127.0.0.1:8081/readyz
curl --fail http://127.0.0.1:8081/.well-known/passkey-auth
```

Stop the containers without deleting identity data:

```sh
docker compose down
```

The `sabledb_data` volume survives container replacement. Add `--volumes` only when you
intentionally want to erase the local identity store.

> [!IMPORTANT]
> The checked-in development key and bootstrap token are public test values. They are only safe on
> loopback. Generate independent secrets before any shared deployment. RustyAuth also refuses a
> 32-byte encryption key whose bytes are all identical, so an unedited `0000…` or `1111…`
> placeholder now stops startup rather than silently protecting nothing.

## Backup, key and operator operations

The same binary provides a small operator CLI. When backup storage is configured, the service
creates a verified logical backup after startup and every six hours by default; signing-key
maintenance is automatic.

```sh
rustyauth doctor
rustyauth backup create
rustyauth backup list
rustyauth backup verify <object-key>
rustyauth keys status
rustyauth keys rotate
rustyauth operator list
rustyauth operator promote <email> <owner|administrator|support|auditor>
```

`operator promote` is the supported way to create the first Owner. Dashboard bootstrap requires an
operator email the account has already **verified**, and verifying an identifier is itself an
operator action — so on a fresh deployment neither can happen first. The CLI breaks that cycle, and
deliberately costs shell access to the deployment rather than control of an inbox. Setting
`AUTH_OPERATOR_EMAILS` alone is no longer enough to become an operator.

Run restore as an offline operation against an empty RustyAuth namespace:

```sh
rustyauth backup restore <object-key>
rustyauth doctor
```

Restore invalidates sessions by default, creates fresh signing-key material and fails closed if its
final security steps do not complete. `--preserve-sessions` exists only for an explicitly reviewed
incident response. See [Configuration](docs/CONFIGURATION.md) for key-overlap settings and
[Deployment](docs/DEPLOYMENT.md) for the clean-room recovery runbook.

## How integration works

Runnable end-to-end material lives in [examples/](examples/README.md): a static relying party
exercising the full ceremony flow and a Node service verifying issued tokens against JWKS. The
[`@rustyauth/client`](packages/client/README.md) package wraps the browser side of these flows,
including the WebAuthn JSON encoding.

### Registration

1. A trusted enrolment controller authorizes a new account with `x-bootstrap-token`.
2. RustyAuth creates WebAuthn registration options and stores the ceremony for five minutes.
3. The browser calls `navigator.credentials.create()` and returns the credential.
4. RustyAuth atomically consumes the ceremony, verifies the credential, creates the user and starts
   a session.

The bootstrap token is an administrative enrolment credential. Never ship it in a production
browser bundle. Replace bootstrap enrolment with your reviewed invitation or provisioning boundary
before production use.

### Sign-in and token exchange

1. The browser requests authentication options for a canonical email address or E.164 phone number.
2. RustyAuth stores a single-use ceremony and returns WebAuthn options.
3. The browser calls `navigator.credentials.get()` and returns the assertion.
4. RustyAuth verifies user presence and verification, advances credential state and creates an
   HttpOnly session.
5. The browser calls `POST /v1/token`; RustyAuth returns a short-lived ES256 access token while the
   durable session remains in its cookie.
6. The downstream service verifies that token against `/.well-known/jwks.json` and applies its own
   authorization.

The access token is returned in JSON and should be held in memory, not local storage. Session tokens
are stored only as SHA-256-derived SableDB keys; the raw bearer value lives in the HttpOnly cookie.

## Public endpoints

| Endpoint | Access | Purpose |
| --- | --- | --- |
| `GET /healthz` | Public | Process liveness |
| `GET /readyz` | Public | SableDB-backed readiness |
| `GET /.well-known/passkey-auth` | Public | Runtime capabilities |
| `GET /.well-known/openid-configuration` | Public | Issuer and token metadata |
| `GET /.well-known/jwks.json` | Public | Active, staged and overlapping ES256 public keys |
| `POST /v1/passkeys/registration/options` | Origin + bootstrap | Start initial registration |
| `POST /v1/passkeys/registration/verify` | Origin + bootstrap | Finish initial registration |
| `POST /v1/passkeys/authentication/options` | Origin | Start passkey sign-in |
| `POST /v1/passkeys/authentication/verify` | Origin | Finish passkey sign-in |
| `POST /v1/token` | Session + origin | Mint a short-lived access token |
| `POST /v1/sign-out` | Origin | Revoke the current session |
| `GET /v1/account` | Session + origin | Read profile and email/phone identifiers |
| `POST /v1/account/profile` | Passkey session + origin | Replace given, family and display names |
| `POST /v1/account/identifiers*` | Recent passkey + origin | Add, remove or select a primary identifier |
| `GET /v1/credentials` | Session + origin | List account passkeys |
| `POST /v1/passkeys/registration/add/*` | Recent passkey + origin | Add another passkey |
| `POST /v1/credentials/rename` | Passkey session + origin | Rename a passkey |
| `POST /v1/credentials/revoke` | Recent passkey + origin | Remove a non-final passkey |
| `GET /v1/events?after=N` | Bootstrap | Poll up to 500 ordered events |
| `POST /v1/email-links` | Origin | Record a sign-in request; delivery is not implemented |

The complete HTTP and private RPC contracts are documented in [API](docs/API.md). The private
`rustyauth.identity.v1` service reads/searches profile, identifier and passkey metadata and applies
controlled identity mutations. `rustyauth.organization.v1` and `rustyauth.service_accounts.v1` are
authorized by passkey operator sessions; service-account credential exchange returns scoped,
short-lived JWTs. `rustyauth.events.v1` provides resumable server streaming. All services support
Connect, gRPC-Web and gRPC.
The API may change before `1.0`; pin a release or commit.

## Configuration and deployment

RustyAuth validates all required configuration at startup and fails closed on an unset `AUTH_ENV`,
placeholder encryption keys with no entropy, partial backup configuration, invalid origins, weak
production bootstrap tokens and plaintext production SableDB addresses outside private networking.

- [Configuration reference](docs/CONFIGURATION.md)
- [Docker and Railway deployment](docs/DEPLOYMENT.md)
- [Security policy and threat model](SECURITY.md)

The intended production topology is one public RustyAuth container, one private persistent SableDB
container and an optional private S3-compatible bucket. Railway is the first packaging target, not a
runtime dependency.

## Project status

RustyAuth is currently `0.1.0` pre-release software.

| Capability | Status |
| --- | --- |
| Passkey registration and authentication | Implemented |
| Multiple email/phone identifiers and basic account profiles | Implemented; external verification delivery required |
| Durable sessions and credential management | Implemented |
| ES256 JWT, JWKS and automatic rotation | Implemented with prepublication and retired-key overlap |
| Ordered HTTP event polling and gRPC event streaming | Implemented |
| Private identity gRPC reads, exact search and mutations | Implemented |
| Passkey-authenticated operator dashboard | Implemented; first owner created with `operator promote`, browser bootstrap requires a verified allowlisted email |
| Organization and operator control plane | Implemented for one organization per instance |
| Service accounts and credential exchange | Implemented with scoped, one-time credentials |
| Email sign-in and verification delivery | Event recording only |
| Account recovery | Not implemented |
| Scheduled encrypted logical backups | Implemented with manifests and read-after-write verification |
| Snapshot restore | Implemented for an empty target; sessions invalidated by default |
| Webhook event delivery | Not implemented |
| Webhook and metrics control plane | Dashboard preview and protobuf contracts only; durable handlers not implemented |
| Multi-tenant runtime isolation | Claims/events are tenant-tagged; one configured tenant per instance |
| Independent security review | Not completed |

Production `1.0` still requires account recovery and abuse controls, event retention/webhook policy,
cross-instance concurrency review, dependency and protocol audits, authenticator coverage and an
independent security assessment. The detailed gate is documented in
[Architecture](docs/ARCHITECTURE.md) and the [Security policy](SECURITY.md).

## Development

Rust `1.94.1` is the minimum declared toolchain. The container currently builds with Rust `1.97`.

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --locked --release
```

Tests cover configuration validation, browser-handoff confinement, credential input validation,
signing-key lifecycle and authenticated backup envelopes. CI also performs a clean-room recovery
drill against real SableDB and S3-compatible MinIO services. Concurrency, authenticator and broader
protocol-negative coverage must expand before production readiness.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and security-sensitive change
requirements.

The website is an Astro and SolidJS workspace managed with Deno:

```sh
deno install
deno task site:dev
deno task site:test
deno task dashboard:check
deno task dashboard:build
```

ConnectRPC contracts and the Solid Query adapter live in `packages/protocol` and
`packages/connect-solid`; the browser client for the public HTTP surface lives in
`packages/client`. Regenerate and verify them with:

```sh
deno task gen
deno task connect:check
deno task connect:test
```

Cloudflare Pages and `rustyauth.dev` are managed in
[`infra/cloudflare`](infra/cloudflare/README.md) with Pulumi. Production credentials are injected
from the maintainers' self-hosted Infisical environment and are never committed or stored in plain
Pulumi configuration.

## Documentation

| Document | Contents |
| --- | --- |
| [Architecture](docs/ARCHITECTURE.md) | Components, flows, state and trust boundaries |
| [Identity data model](docs/IDENTITY_DATA_MODEL.md) | Every persisted identity field, invariant, index and API projection |
| [Dashboard control-plane decision](docs/decisions/0001-dashboard-control-plane.md) | SolidJS, ConnectRPC, Rust, Railway and SableDB trust boundaries |
| [Engineering](docs/ENGINEERING.md) | Module ownership, coding standards and quality gates |
| [HTTP API](docs/API.md) | Endpoints, inputs, responses and access requirements |
| [OpenAPI specification](docs/openapi.yaml) | Machine-readable contract for the public HTTP endpoints |
| [Examples](examples/README.md) | Runnable relying-party and JWT-verification integrations |
| [Releasing](RELEASING.md) | Tagged releases, container image, JSR and BSR publishing |
| [Configuration](docs/CONFIGURATION.md) | Every environment variable and validation rule |
| [Deployment](docs/DEPLOYMENT.md) | Docker, Railway, persistence and operations |
| [Security policy](SECURITY.md) | Reporting, threat model and known limitations |
| [Contributing](CONTRIBUTING.md) | Build, review and pull-request expectations |
| [Code of conduct](CODE_OF_CONDUCT.md) | Community expectations and enforcement |
| [Brand guide](docs/BRAND.md) | Naming, voice, logo and attribution usage |
| [Changelog](CHANGELOG.md) | Release-facing changes and migration notes |
| [Third-party notices](THIRD_PARTY_NOTICES.md) | SableDB and dependency licensing |
| [Third-party licence inventory](THIRD_PARTY_LICENSES.html) | Generated licence texts for the locked Cargo graph |

## Brand and independence

Write the product name as **RustyAuth** with no space. The primary strapline is:

> Built in Rust. Built on SableDB. Built for passkeys.

RustyAuth is an independent project. It is not sponsored, endorsed or maintained by the Rust
Foundation, the Rust Project, SableDB or their contributors. It does not use the Rust cog, Cargo or
Ferris artwork. See [Brand](docs/BRAND.md) and [Trademarks](TRADEMARKS.md).

## Licence

RustyAuth is copyright 2026 Livermore Ledger Ltd and licensed under the
[Apache License 2.0](LICENSE). Contributions submitted for inclusion are licensed on the same terms
unless explicitly agreed otherwise.

RustyAuth builds and distributes SableDB as a separate container under SableDB's BSD three-clause
licence. The upstream notice and disclaimer are reproduced in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and copied into the SableDB image.

The Apache licence covers the source code; it does not grant rights to the RustyAuth name or logos.
See [NOTICE](NOTICE) and [TRADEMARKS.md](TRADEMARKS.md).
