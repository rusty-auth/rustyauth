# Standalone quick start

Run one complete RustyAuth realm locally: a Dioxus dashboard, private Rust backend and private SableDB. The
launcher generates development secrets and configuration in ignored files; checked-in examples do not contain
working credentials.

RustyAuth is pre-release software. This flow is for development and evaluation.

## Requirements

- Docker with Compose v2
- Git
- OpenSSL
- `curl`
- a browser with WebAuthn support

## Start

```sh
git clone https://github.com/rusty-auth/rustyauth.git
cd rustyauth
scripts/local-stack standalone up
```

The command runs Compose in the foreground. It creates:

- `.env.standalone.local`, containing independent generated local secrets; and
- an ignored local YAML document derived from [`rustyauth.example.yaml`](../rustyauth.example.yaml).

The topology is:

```text
http://localhost:8081
        │
        ▼
Dioxus dashboard ──private──> RustyAuth realm backend ──private──> SableDB volume
```

If port `8081` is occupied, set `STANDALONE_DASHBOARD_PORT` before starting. The launcher keeps the local
issuer and WebAuthn origin aligned with the selected port.

## Verify

In a second terminal:

```sh
curl --fail http://127.0.0.1:8081/healthz
curl --fail http://127.0.0.1:8081/readyz
curl --fail http://127.0.0.1:8081/.well-known/passkey-auth
curl --fail http://127.0.0.1:8081/.well-known/jwks.json
```

- `/healthz` proves the backend process is alive.
- `/readyz` proves the private durable dependency is reachable.
- capability discovery describes supported browser flows.
- JWKS publishes the active, staged and overlapping retired verification keys.

Backup status is intentionally not exposed through public discovery. Use the authenticated operator CLI when
backup storage is configured.

## Explore the dashboard

Open <http://localhost:8081>. The first-run flow registers the allowlisted local account with a passkey. The
generated bootstrap value is in `.env.standalone.local`; it is an administrative development credential, not a
browser secret for production.

Open <http://localhost:8081/?preview=1> to inspect populated sample data without mutating SableDB.

For production, create the first Owner from a deployment shell:

```sh
rustyauth operator find owner@example.com
rustyauth operator promote <user-id> owner
```

An allowlisted email does not grant an operator role by itself.

## Stop or reset

Stop containers while retaining the SableDB volume:

```sh
scripts/local-stack standalone down
```

Delete local identity state only when that is intentional:

```sh
scripts/local-stack standalone down --volumes
```

## Validate configuration

Generate and validate non-secret policy independently of the local launcher:

```sh
rustyauth config example realm > rustyauth.yaml
rustyauth config validate rustyauth.yaml
```

Keep secrets in environment variables, the deployment platform secret store or supported `_FILE` mounts. See
[Configuration](CONFIGURATION.md) for precedence and the production schema.

## Next steps

1. Complete the [application integration guide](INTEGRATION.md).
2. Read the [three-service architecture](ARCHITECTURE.md).
3. Review the [API contract](API.md) and [identity data model](IDENTITY_DATA_MODEL.md).
4. Before hosting, follow [Deployment](DEPLOYMENT.md) and [Security hardening](SECURITY_HARDENING.md).
5. To manage multiple isolated realms, use the [Fleet quick start](FLEET_QUICKSTART.md).
