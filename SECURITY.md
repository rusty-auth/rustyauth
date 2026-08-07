# Security policy

RustyAuth handles authentication credentials and bearer sessions. Treat every suspected weakness as
security-sensitive even when it affects only a pre-release build.

## Supported versions

RustyAuth has not reached a production-supported release.

| Version | Security support |
| --- | --- |
| `main` / `0.1.x` | Best-effort fixes during pre-release development |
| `< 0.1` prototypes | Unsupported |

No version is currently approved as the sole identity system for a production service.

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

Do not include live session cookies, JWTs, passkey assertions, bootstrap or RPC tokens,
database URLs or backup keys. Replace them with unmistakable placeholders.

The maintainers will acknowledge a usable report, coordinate validation and publish remediation
information appropriate to the pre-release status. This project does not currently operate a bug
bounty or promise a fixed disclosure timeline.

## Scope

High-priority reports include:

- WebAuthn origin, RP-ID, ceremony replay or credential-binding bypasses;
- account or tenant crossing;
- session fixation, theft, expiry or revocation failures;
- JWT signature, issuer, audience, key-storage or claim-validation weaknesses;
- bootstrap-token or RPC-token exposure, or enrolment/private-RPC authorization bypass;
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

## Security invariants

- Production issuer and relying-party origins use HTTPS.
- RP ID exactly equals the configured application-origin host.
- Registration and authentication ceremony state is server-side, five-minute and atomically
  consumed.
- Private endpoints require both exact origin and a valid durable session.
- The production session cookie is HttpOnly, Secure, SameSite=Strict and time bounded.
- The final passkey cannot be removed.
- A credential-removal session must be no older than five minutes.
- Non-zero passkey signature counters cannot regress.
- Raw session and handoff tokens are not stored as database keys.
- JWT private key bytes are encrypted at rest under a deployment-provided AES-256 key.
- SableDB is private and volume-backed.
- Missing state or invalid configuration fails closed.
- Logs and events must never contain bearer or credential payloads.
- Event streaming requires a dedicated, high-entropy bearer token distinct from the bootstrap token.
- Identity reads and mutations require a second dedicated bearer token. Identity responses expose
  passkey metadata only, never credential/public-key material, counters, sessions or tokens.

## Known limitations

These are explicit reasons RustyAuth is pre-release:

- Production email verification has no delivery/consumption implementation.
- Account recovery is absent.
- There is no public revoke-all-sessions operation.
- Credential removal uses session-creation recency rather than a dedicated fresh step-up ceremony.
- Signing-key rotation and retired-key overlap are absent.
- Backup export, scheduling, manifest verification and restore are absent.
- HTTP event polling still uses the bootstrap token; the streaming token is instance-wide rather
  than scoped per consumer or tenant.
- Stored keys are one configured tenant per instance rather than tenant-prefixed.
- Compound-mutation coordination is process-local; multiple writer replicas are unqualified.
- Automated dependency auditing, protocol fuzzing and an independent assessment are not complete.

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

The production gate additionally requires dependency audit/deny checks, authenticator coverage,
negative protocol tests, deployment isolation verification and a tested recovery drill.
