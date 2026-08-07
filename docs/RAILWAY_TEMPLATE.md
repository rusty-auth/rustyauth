# Deploy and Host RustyAuth on Railway

RustyAuth is a small, self-hosted identity service for WebAuthn passkey ceremonies, durable browser sessions,
and short-lived ES256 access tokens. This template deploys the public RustyAuth service alongside a private,
persistent SableDB service in one Railway project. The services communicate over Railway's private network;
only RustyAuth receives a public HTTPS domain. Railway places both services in the template group named
`RustyAuth`.

RustyAuth is pre-release software. Recovery, scheduled backup and restore, signing-key rotation, and an
independent security assessment are not complete. Use this template for evaluation and integration work, and
do not make this release the sole identity system for a production service.

## About Hosting RustyAuth

The template creates RustyAuth and SableDB services from versioned public container images built from the
[`rusty-auth/rustyauth`](https://github.com/rusty-auth/rustyauth) repository. SableDB has no public domain or
TCP proxy and stores identity state on a Railway volume mounted at `/var/lib/sabledb`.

Railway generates `AUTH_MASTER_KEY_HEX` and `BOOTSTRAP_TOKEN` independently for every template deployment.
`SABLEDB_URL` is assembled from the SableDB service's Railway private-domain reference, so no database
hostname or credential needs to be copied between services.

The deploy form asks for the browser application's WebAuthn origin and RP ID. The RP ID must exactly match the
hostname in the WebAuthn origin, and production origins must use HTTPS. Other values have safe template
defaults but remain editable during the environment step.

| Variable              | Deployment behavior                                                    |
| --------------------- | ---------------------------------------------------------------------- |
| `WEBAUTHN_RP_ORIGIN`  | Required user input: the exact HTTPS origin of the browser application |
| `WEBAUTHN_RP_ID`      | Required user input: the hostname from `WEBAUTHN_RP_ORIGIN`            |
| `WEBAUTHN_RP_NAME`    | Editable display name; defaults to `RustyAuth`                         |
| `SPACETIME_AUDIENCE`  | Editable access-token audience; defaults to `rustyauth`                |
| `AUTH_TENANT_ID`      | Editable tenant claim; defaults to `default`                           |
| `AUTH_ISSUER`         | Automatically references the RustyAuth public Railway domain           |
| `SABLEDB_URL`         | Automatically references SableDB on Railway's private network          |
| `AUTH_MASTER_KEY_HEX` | Automatically generated 256-bit hexadecimal secret                     |
| `BOOTSTRAP_TOKEN`     | Automatically generated 64-character secret                            |

## Why Deploy RustyAuth on Railway

- Deploy the complete two-service topology as one unit.
- Keep SableDB private while exposing RustyAuth through Railway-managed HTTPS.
- Generate high-entropy application secrets automatically for each installation.
- Preserve identity state across SableDB container replacement with a persistent volume.
- Use checked-in Docker and health-check configuration from the upstream repository.

## Common Use Cases

- Evaluate passkey-first authentication without adopting a hosted identity provider.
- Add WebAuthn registration, sign-in, sessions, and ES256 tokens to an internal application.
- Prototype a self-hosted authentication boundary for an API or SpacetimeDB application.
- Review RustyAuth's explicit origin, issuer, audience, and tenant trust boundaries.

## Dependencies for RustyAuth Hosting

RustyAuth requires a browser application served from the HTTPS origin entered during deployment. That
application performs the WebAuthn browser ceremonies and calls RustyAuth's HTTP API. A downstream API must
verify issued tokens against RustyAuth's JWKS and enforce the configured issuer, audience, tenant, expiry, and
application-specific authorization policy.

### Deployment Dependencies

- One Railway service for RustyAuth, with a generated public domain and health check on `/healthz`.
- One private SableDB service on port `6379`.
- One persistent Railway volume for SableDB at `/var/lib/sabledb`.
- A relying-party HTTPS origin whose hostname exactly matches `WEBAUTHN_RP_ID`.

After deployment, check `/healthz` for process liveness and `/readyz` for SableDB-backed readiness. Keep the
generated bootstrap token out of browser bundles: it is an administrative enrollment and event-polling
credential.
