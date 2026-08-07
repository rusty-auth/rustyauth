# Changelog

All notable RustyAuth changes will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project intends to use semantic versioning
after its public contract stabilises.

## Unreleased

### Added

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

### Security

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
