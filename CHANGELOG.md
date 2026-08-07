# Changelog

All notable RustyAuth changes will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project intends to use semantic
versioning after its public contract stabilises.

## Unreleased

### Added

- RustyAuth public identity, logo lockup and brand guidance.
- Architecture, API, configuration, deployment, security and contribution documentation.
- Apache-2.0 project licence and explicit SableDB attribution.
- A versioned protobuf event service with authenticated Connect, gRPC-Web and native gRPC
  server-streaming delivery.
- A private protobuf identity service for safe account reads, exact search, profile/contact updates
  and passkey metadata operations over Connect, gRPC-Web and native gRPC.
- At-least-once replay from consumer-owned cursors, exact event/tenant filters and idle checkpoints.

### Changed

- Domain mutations and their authentication events now commit in the same atomic SableDB pipeline;
  polling and streaming fail closed on gaps or malformed records.

### Security

- Documented the pre-release threat model, current controls and production blockers.
- Added a dedicated event RPC bearer secret with constant-time verification and redacted event data.
- Added a separately scoped identity RPC bearer secret and metadata-only passkey projections.

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

- No complete email delivery, recovery, scheduled export/restore, key rotation, stable event stream
  or independent security assessment.
