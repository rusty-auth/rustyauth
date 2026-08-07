# Deploy and Host RustyAuth on Railway

RustyAuth is a small, self-hosted identity service for WebAuthn passkey ceremonies, durable browser sessions,
and short-lived ES256 access tokens. This template deploys the public RustyAuth service alongside a private,
persistent SableDB service in one Railway project. The services communicate over Railway's private network;
only RustyAuth receives a public HTTPS domain. Railway places both services in the template group named
`RustyAuth`.

RustyAuth is pre-release software. Account recovery, abuse controls, multi-writer qualification and an
independent security assessment are not complete. Automatic signing-key rotation and encrypted backup and
restore tooling are implemented. Use this template for evaluation and integration work, and do not make this
release the sole identity system for a production service.

## About Hosting RustyAuth

The template creates RustyAuth and SableDB services from versioned public container images built from the
[`rusty-auth/rustyauth`](https://github.com/rusty-auth/rustyauth) repository. SableDB has no public domain or
TCP proxy and stores identity state on a Railway volume mounted at `/var/lib/sabledb`.

The Railway template must generate `AUTH_MASTER_KEY_HEX`, `BOOTSTRAP_TOKEN`,
`AUTH_EVENT_RPC_TOKEN` and `AUTH_IDENTITY_RPC_TOKEN` independently for every deployment.
`SABLEDB_URL` is assembled from the SableDB service's Railway private-domain reference, so no database
hostname or credential needs to be copied between services.

The RustyAuth container serves its operator dashboard and RPC boundary on the same Railway HTTPS domain.
Set the WebAuthn origin to that public domain and the RP ID to its exact hostname. The template must also ask
for at least one operator email before first sign-in. Other values have safe template defaults but remain
editable during the environment step.

| Variable              | Deployment behavior                                                    |
| --------------------- | ---------------------------------------------------------------------- |
| `WEBAUTHN_RP_ORIGIN`  | Exact HTTPS origin of the public RustyAuth dashboard                    |
| `WEBAUTHN_RP_ID`      | Exact hostname from `WEBAUTHN_RP_ORIGIN`                               |
| `WEBAUTHN_RP_NAME`    | Editable display name; defaults to `RustyAuth`                         |
| `AUTH_OPERATOR_EMAILS` | Required canonical email(s) allowed to bootstrap the owner operator   |
| `SPACETIME_AUDIENCE`  | Editable access-token audience; defaults to `rustyauth`                |
| `AUTH_TENANT_ID`      | Editable tenant claim; defaults to `default`                           |
| `AUTH_ISSUER`         | Automatically references the RustyAuth public Railway domain           |
| `SABLEDB_URL`         | Automatically references SableDB on Railway's private network          |
| `AUTH_MASTER_KEY_HEX` | Automatically generated 256-bit hexadecimal secret                     |
| `BOOTSTRAP_TOKEN`     | Automatically generated 64-character secret                            |
| `AUTH_EVENT_RPC_TOKEN` | Required generated private event-stream credential                     |
| `AUTH_IDENTITY_RPC_TOKEN` | Required generated private identity-control credential              |

Signing-key maintenance runs automatically with prepublication and retired-key overlap. Encrypted scheduled
backups are optional and require the complete S3-compatible `AUTH_BACKUP_*` environment; the base two-service
template does not provision a bucket. Partial backup configuration is rejected at startup.

## Why Deploy RustyAuth on Railway

- Deploy the complete two-service topology as one unit.
- Operate users, organization settings and scoped service accounts from the bundled dashboard.
- Keep SableDB private while exposing RustyAuth through Railway-managed HTTPS.
- Generate high-entropy application secrets automatically for each installation.
- Preserve identity state across SableDB container replacement with a persistent volume.
- Operate automatic signing-key rotation and optional verified backups through one small CLI.
- Use checked-in Docker and health-check configuration from the upstream repository.

## Common Use Cases

- Evaluate passkey-first authentication without adopting a hosted identity provider.
- Add WebAuthn registration, sign-in, sessions, and ES256 tokens to an internal application.
- Prototype a self-hosted authentication boundary for an API or SpacetimeDB application.
- Review RustyAuth's explicit origin, issuer, audience, and tenant trust boundaries.

## Dependencies for RustyAuth Hosting

RustyAuth includes the operator browser application at its HTTPS origin. A downstream API must verify issued
tokens against RustyAuth's JWKS and enforce the configured issuer, audience, tenant, expiry and
application-specific authorization policy.

### Deployment Dependencies

- One Railway service for RustyAuth, with a generated public domain and health check on `/healthz`.
- One private SableDB service on port `6379`.
- One persistent Railway volume for SableDB at `/var/lib/sabledb`.
- A relying-party HTTPS origin whose hostname exactly matches `WEBAUTHN_RP_ID`.

After deployment, check `/healthz` for process liveness and `/readyz` for SableDB-backed readiness. Keep the
generated bootstrap and RPC tokens out of browser bundles. They are independently scoped administrative
credentials; RPC consumers send only the token for their service. Run `passkey-auth-service doctor` after
configuration changes and follow the repository deployment guide for backup verification and clean-room
restore drills.
