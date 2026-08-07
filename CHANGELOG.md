# Changelog

All notable RustyAuth changes will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project intends to use semantic
versioning after its public contract stabilises.

## Unreleased

### Added

- RustyAuth public identity, logo lockup and brand guidance.
- Architecture, API, configuration, deployment, security and contribution documentation.
- Apache-2.0 project licence and explicit SableDB attribution.

### Security

- Documented the pre-release threat model, current controls and production blockers.

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
