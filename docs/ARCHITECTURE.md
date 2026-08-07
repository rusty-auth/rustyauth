# RustyAuth architecture

This document describes the standalone RustyAuth implementation at version `0.1.0`. Statements
about future functionality are marked explicitly.

## Design goals

RustyAuth keeps the identity boundary small:

- authenticate users with passkeys;
- keep bearer sessions server-side and revocable;
- issue short-lived, audience-bound tokens to downstream services;
- keep durable identity state on private infrastructure; and
- fail closed when configuration, state or authorization is missing.

It intentionally does not decide application roles, subscriptions, entitlements or object ownership.

## Components and trust boundaries

```mermaid
flowchart TB
    subgraph Public["Public boundary"]
      Browser["Relying-party browser"]
      Consumer["Token-consuming API"]
      Auth["RustyAuth HTTP service"]
    end

    subgraph Private["Private deployment network"]
      Sable["SableDB + persistent volume"]
      Bucket["S3-compatible backup bucket"]
      Operator["Trusted RPC consumer"]
    end

    Browser -->|"exact origin, WebAuthn, cookie"| Auth
    Auth -->|"ES256 access token"| Browser
    Consumer -->|"JWKS discovery"| Auth
    Operator -->|"scoped bearer + Connect/gRPC"| Auth
    Auth -->|"Valkey protocol"| Sable
    Auth -.->|"scheduled authenticated snapshots"| Bucket
```

### Browser

The browser performs WebAuthn operations and sends the resulting credential objects to RustyAuth.
It receives an opaque HttpOnly session cookie and a short-lived access JWT in a JSON response. The
intended client stores the JWT only in memory.

### RustyAuth service

One Axum process owns:

- HTTP origin and CORS enforcement;
- WebAuthn relying-party configuration and ceremony verification;
- session creation and validation;
- credential-management policy;
- JWT signing and JWKS publication;
- signing-key lifecycle maintenance;
- logical backup scheduling and recovery commands;
- exact identity discovery and mutations for trusted RPC consumers;
- ordered event creation, polling and streaming; and
- health/readiness reporting.

### SableDB

SableDB is the only online durable store. RustyAuth connects through SableDB's Valkey-compatible
protocol using `redis-rs`. SableDB must have no public endpoint; network reachability is part of the
security boundary.

### Downstream consumer

The consumer validates the token signature and policy-relevant claims. Receiving a valid RustyAuth
token proves authentication under the configured relying party; it does not independently grant
access to an application resource.

### Backup bucket

RustyAuth exports a consistent logical snapshot under a mutation gate, compresses it and protects it
with a versioned AES-256-GCM envelope. The envelope header, derived encryption-key ID and payload are
authenticated together. S3 uploads use a transport checksum and succeed only after read-after-write
decryption and manifest verification.

## Stored state

RustyAuth stores JSON values and indexes under these logical key families:

The complete account, identifier, profile, passkey, session and exposure schema is documented in
[Identity data model](IDENTITY_DATA_MODEL.md). This section describes where those records live and
how they participate in the system lifecycle.

| Key family | Contents | Lifetime |
| --- | --- | --- |
| `auth:user:<uuid>` | Profile, email/phone identifiers, session version and passkeys | Durable |
| `auth:identifier:<type>:<value>` | Canonical email/phone-to-user index | Durable |
| `auth:email:<email>` | Compatibility email-to-user index | Durable |
| `auth:credential:<id>` | Credential-to-user uniqueness index | Durable |
| `auth:registration:<uuid>` | Server-side WebAuthn registration state | Five minutes, single use |
| `auth:authentication:<uuid>` | Server-side WebAuthn authentication state | Five minutes, single use |
| `auth:session:<sha256>` | Session metadata keyed by a digest of the bearer token | Bounded absolute lifetime |
| `auth:jwt:keyset:v1` | Active/staged signing keys, retired public keys and encrypted private material | Durable |
| `auth:event-sequence` | Monotonic event cursor | Durable |
| `auth:event:<sequence>` | Redacted event type, subject and tenant | Durable |
| `auth:agent-handoff:<sha256>` | Development-only one-use handoff | 60 seconds by default |

Raw session and handoff bearer values are not used as database keys. Their SHA-256 digests are.
Passkey credential material is serialized through `webauthn-rs`; passwords are not supported or
stored.

## Registration flow

```mermaid
sequenceDiagram
    participant C as Trusted enrolment client
    participant B as Browser authenticator
    participant R as RustyAuth
    participant S as SableDB

    C->>R: registration/options + exact Origin + bootstrap token
    R->>S: reject existing email or phone identifier
    R->>S: store five-minute ceremony
    R-->>C: ceremonyId + PublicKeyCredentialCreationOptions
    C->>B: navigator.credentials.create()
    B-->>C: attestation response
    C->>R: registration/verify + ceremonyId
    R->>S: GETDEL ceremony
    R->>R: verify WebAuthn response
    R->>S: atomic user + identifier + credential indexes
    R->>S: create session and ordered events
    R-->>C: HttpOnly cookie + short-lived token response
```

Initial registration currently depends on a shared bootstrap token. It is appropriate for controlled
development and provisioning, but it is not a complete public sign-up policy. A production adopter
must place it behind a reviewed invitation or administrative boundary and must never embed it in
public browser code.

## Authentication flow

Authentication is identifier-first. A canonical email or E.164 phone number resolves a stable
account UUID; RustyAuth then loads that account's passkeys, creates a five-minute server-side
ceremony and verifies the returned assertion. Identifiers are discovery and contact records, not
WebAuthn credentials. Verification requires the authenticator to report user verification. A
non-zero signature counter must advance; regression fails as a possible cloned credential.

After success, RustyAuth updates the stored passkey state and last-used time, creates a session and
returns both the session cookie and an access token.

## Session model

Session tokens contain 32 random bytes encoded with unpadded Base64URL. The cookie is:

- `HttpOnly`;
- `SameSite=Strict`;
- scoped to `/`;
- `Secure` in production; and
- bounded by the configured absolute lifetime.

Every authenticated request checks:

1. exact request origin;
2. session existence;
3. absolute expiry;
4. idle expiry;
5. referenced user existence; and
6. equality between the user's and session's `session_version`.

Successful validation advances `last_seen_at`. Sign-out deletes the current session. The data model
supports invalidating sessions by advancing a user's session version, but a public revoke-all
operation is not implemented.

## Credential-management policy

An authenticated account can list passkeys. Adding a passkey requires a recent passkey session and
the resulting ceremony is bound to that exact session. Renaming requires a passkey session;
removing requires one created within the last five minutes and cannot remove the final passkey. The
implementation does not yet provide a separate step-up ceremony; the recency check is based on
session creation time. Agent handoff sessions do not satisfy any identity-mutation requirement.

## Account identity model

An account is anchored by a UUID and may contain up to 20 globally unique email and phone
identifiers plus multiple passkeys. Exactly one identifier is primary. Existing single-email user
records are hydrated into this model on read, and the legacy email index remains supported, so the
change does not invalidate accounts or passkeys already stored by RustyAuth.

Basic profile data consists of optional given, family and display names. It labels WebAuthn
registration but never replaces the UUID user handle. Adding, removing or changing the primary
identifier requires a recent passkey session; updating profile presentation requires a passkey
session. The final identifier cannot be removed.

See [Identity data model](IDENTITY_DATA_MODEL.md) for every stored field, canonicalization rule,
legacy compatibility field, metadata projection and deliberately excluded data class.

## Token model

RustyAuth creates an EC P-256 signing key on first boot. Its PKCS#8 private bytes are encrypted with
AES-256-GCM under `AUTH_MASTER_KEY_HEX` before storage. The public key is exposed as JWK.

JWTs use `alg=ES256`, `typ=JWT` and a `kid`. Claims are:

| Claim | Meaning |
| --- | --- |
| `iss` | Configured RustyAuth issuer |
| `aud` | Configured downstream audience |
| `sub` | RustyAuth user UUID |
| `exp`, `iat` | Expiry and issue time |
| `jti` | Unique token ID |
| `sid` | Durable session UUID |
| `token_type` | `spacetime-access` in the current integration |
| `tenant_id` | Configured instance tenant |
| `amr` | `hwk` for passkey or `agent` for a development handoff |
| `auth_time` | Session creation time |
| `session_version` | User/session invalidation generation |

Email, phone, profile and verification state are returned beside the token but are not JWT claims.
Consumers must not infer authorization from an unverified response field.

Signing keys have a staged, active and retired lifecycle. A replacement public key is published for
at least `AUTH_SIGNING_KEY_PREPUBLISH_SECONDS` before activation. The previous public key remains in
JWKS for `AUTH_SIGNING_KEY_OVERLAP_SECONDS`, which cannot be configured below the maximum access
token lifetime plus the five-minute JWKS cache allowance. Retired private material is discarded.

The maintenance loop rotates automatically and uses a short SableDB lease to avoid duplicate work
across processes. `keys rotate` triggers the same safe staged lifecycle. Master-key rotation is
independent: supplying the new active master key plus the old key in the previous-key list causes
private signing material to be rewrapped without changing its `kid`.

## Backup and restore model

The backup manifest covers sorted durable records, record-family counts, a canonical content digest
and the ordered-event sequence. Validation rejects duplicate or unsupported keys, tenant mismatch,
orphaned user indexes and credentials, malformed expiry policy, missing signing state and event
gaps. Ceremony, agent-handoff, maintenance-lock and restore-marker records are not exported.

Backups run immediately on startup and then on a configurable interval. An in-process operation
lock plus a SableDB lease prevents overlapping snapshots. Restore is an offline command that accepts
only an empty `auth:*` namespace. Sessions are skipped and each user's `session_version` is advanced
unless the operator explicitly supplies `--preserve-sessions`. A durable in-progress marker blocks
normal startup until signing-key rotation and the recovery event both complete.

## Events

Events contain only a sequence, UUID, configured tenant ID, event type, optional user UUID,
timestamp and redacted JSON object. They deliberately exclude passkey assertions, cookies, JWTs,
handoff codes and email-link tokens.

`GET /v1/events?after=N` returns at most 500 subsequent records. It is authenticated by the bootstrap
token. `rustyauth.events.v1.AuthEventService/Subscribe` provides cursor-based replay and follow over
Connect, gRPC-Web and gRPC using the separately scoped event RPC token. Consumers own durable
acknowledgement by committing their sequence after processing. Retention and webhook delivery are
not implemented.

## Private identity RPC

`rustyauth.identity.v1.IdentityService` is the trusted control-plane boundary. It exposes exact
identity search, complete safe account reads, profile replacement, email/phone lifecycle operations,
and passkey rename/revoke operations. It runs on the shared listener but requires its own bearer
credential. Passkey responses are projected through a metadata-only type before protobuf encoding;
stored WebAuthn credentials, public keys and counters never cross the boundary. New credential
material still requires a WebAuthn registration ceremony.

## Tenancy

Version `0.1.0` is one configured tenant per RustyAuth instance. Tokens and events carry
`AUTH_TENANT_ID`, but user/session/database keys are not tenant-prefixed. Do not point multiple
independently trusted tenants at one SableDB namespace.

## Concurrency and scaling

Multi-key user and credential writes use atomic SableDB pipelines. A process-local async mutex
serializes compound mutations within one RustyAuth process. That mutex does not coordinate multiple
replicas. Run one writer instance until cross-instance transaction/locking behavior has dedicated
tests and an explicit design.

## Failure behavior

RustyAuth rejects startup or requests when required state cannot be validated. Examples include:

- invalid or non-HTTPS production origins;
- an RP ID that does not exactly match the application origin host;
- a non-private production SableDB hostname;
- partial backup configuration;
- a backup whose authenticated envelope, manifest or tenant cannot be validated;
- a restore destination that contains auth state or an incomplete restore marker;
- missing, expired or replayed ceremony state;
- missing or expired sessions;
- credential/account mismatches; and
- stored signing material that cannot be decrypted with the configured master key.

Internal errors are logged server-side and returned to callers as a generic fail-closed error.

## Known architectural gaps

See [SECURITY.md](../SECURITY.md) and the README status matrix. The largest gaps are account
recovery policy for lost authenticators, verified email/SMS delivery, revoke-all, cross-instance
writer qualification, event retention/webhook delivery and independent review.
