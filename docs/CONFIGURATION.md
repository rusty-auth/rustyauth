# RustyAuth configuration

RustyAuth reads configuration from environment variables and validates it before binding the HTTP
listener. Missing or invalid required values stop startup.

## Required variables

| Variable | Example | Validation and meaning |
| --- | --- | --- |
| `AUTH_ENV` | `production` | `development` or `production`; defaults to development |
| `AUTH_ISSUER` | `https://auth.example.com` | Public RustyAuth origin with no path/query/fragment; HTTPS in production |
| `WEBAUTHN_RP_ID` | `app.example.com` | Must exactly equal the host of `WEBAUTHN_RP_ORIGIN` |
| `WEBAUTHN_RP_ORIGIN` | `https://app.example.com` | Exact browser application origin; HTTPS in production |
| `WEBAUTHN_RP_NAME` | `Example Account` | Name shown by the authenticator |
| `SABLEDB_URL` | `redis://sabledb.railway.internal:6379` | Valkey-protocol URL; production host must end in `.railway.internal` |
| `AUTH_MASTER_KEY_HEX` | 64 hex characters | 32-byte AES key protecting persisted JWT private material |
| `BOOTSTRAP_TOKEN` | high-entropy secret | Administrative initial-enrolment and HTTP-event-polling credential; at least 32 characters in production |
| `AUTH_EVENT_RPC_TOKEN` | independent high-entropy secret | Bearer credential for Connect/gRPC event subscriptions; at least 32 characters and must differ from `BOOTSTRAP_TOKEN` |
| `SPACETIME_AUDIENCE` | `example-dashboard` | Exact `aud` written into access tokens |

`AUTH_ENV` is logically required even though omission selects development. Set it explicitly in
every deployed environment.

## Optional core variables

| Variable | Default | Allowed range or meaning |
| --- | --- | --- |
| `AUTH_TENANT_ID` | `vtr` | Tenant claim and event tag; one tenant per instance |
| `AUTH_ACCESS_TOKEN_SECONDS` | `300` | 60–900 seconds |
| `AUTH_SESSION_IDLE_SECONDS` | `1800` | 300–86,400 seconds |
| `AUTH_SESSION_ABSOLUTE_SECONDS` | `604800` | 3,600–2,592,000 seconds |
| `BIND_ADDRESS` | `0.0.0.0` | Listener IP address |
| `PORT` | `8080` | Listener port |
| `RUST_LOG` | `passkey_auth_service=info,tower_http=info` | `tracing-subscriber` filter |

Absolute session expiry must be longer than the operational idle policy, but version `0.1.0` does
not validate their relationship. Review both values together.

## Backup variables

Backup configuration is all-or-nothing. Supply all six required values or none:

| Variable | Meaning |
| --- | --- |
| `AUTH_BACKUP_ENDPOINT` | S3-compatible API origin |
| `AUTH_BACKUP_REGION` | SDK signing region |
| `AUTH_BACKUP_BUCKET` | Private destination bucket |
| `AUTH_BACKUP_ACCESS_KEY_ID` | Bucket access identifier |
| `AUTH_BACKUP_SECRET_ACCESS_KEY` | Bucket secret |
| `AUTH_BACKUP_ENCRYPTION_KEY_HEX` | Independent 32-byte AES key encoded as 64 hex characters |

`AUTH_BACKUP_URL_STYLE` is `virtual` by default and may be set to `path` for providers that require
path-style buckets.

Accepted backup configuration only initializes the encrypted upload sink. Scheduled snapshots,
export manifests and restore are not implemented. The capability endpoint reports these separately.

## Secret generation

Generate each secret independently. Example commands:

```sh
openssl rand -hex 32       # AUTH_MASTER_KEY_HEX
openssl rand -base64 48    # BOOTSTRAP_TOKEN
openssl rand -base64 48    # AUTH_EVENT_RPC_TOKEN
openssl rand -hex 32       # AUTH_BACKUP_ENCRYPTION_KEY_HEX
```

Do not reuse keys across purposes, tenants or environments. Keep backup encryption keys outside the
bucket and its provider account; losing that key makes encrypted snapshots unrecoverable.

The development master key, bootstrap token and event RPC token in `.env.example` are public
fixtures. They must not appear in a shared deployment.

## Origin and relying-party rules

RustyAuth deliberately disables RP-ID relaxation:

```text
WEBAUTHN_RP_ID == host(WEBAUTHN_RP_ORIGIN)
```

For example:

```text
WEBAUTHN_RP_ID=app.example.com
WEBAUTHN_RP_ORIGIN=https://app.example.com
```

Changing the RP ID does not merely rename a deployment. Existing WebAuthn credentials are scoped to
the previous RP ID and need an explicit migration/re-enrolment plan.

`AUTH_ISSUER` may be a different origin from the relying-party application. Both must be HTTPS in
production. Browser CORS permits only the configured relying-party origin.

## SableDB boundary

Version `0.1.0` enforces Railway's `.railway.internal` hostname in production. This makes the
included Railway template fail closed, but it also means a non-Railway production deployment cannot
start without a future configurable private-network policy. Do not weaken this check merely to make
a public SableDB endpoint work.

SableDB requires a persistent volume at `/var/lib/sabledb`. RustyAuth assumes the database namespace
belongs to one configured tenant.

## Example production environment

```dotenv
AUTH_ENV=production
AUTH_ISSUER=https://auth.example.com
WEBAUTHN_RP_ID=app.example.com
WEBAUTHN_RP_ORIGIN=https://app.example.com
WEBAUTHN_RP_NAME=Example Account
SABLEDB_URL=redis://sabledb.railway.internal:6379
AUTH_MASTER_KEY_HEX=<64-hex-secret>
BOOTSTRAP_TOKEN=<high-entropy-secret>
AUTH_EVENT_RPC_TOKEN=<independent-high-entropy-secret>
SPACETIME_AUDIENCE=example-dashboard
AUTH_TENANT_ID=example
AUTH_ACCESS_TOKEN_SECONDS=300
AUTH_SESSION_IDLE_SECONDS=1800
AUTH_SESSION_ABSOLUTE_SECONDS=604800
PORT=8080
RUST_LOG=passkey_auth_service=info,tower_http=info
```

This example omits backups rather than pretending that configured storage is a working recovery
system.

## Rotation impact

- Rotating `BOOTSTRAP_TOKEN` affects future enrolment and event polling only.
- Rotating `AUTH_EVENT_RPC_TOKEN` terminates authorization for new subscriptions; reconnect trusted
  consumers with the replacement secret.
- Rotating `AUTH_MASTER_KEY_HEX` without re-encrypting the stored signing key prevents startup.
- Rotating `AUTH_BACKUP_ENCRYPTION_KEY_HEX` makes earlier envelopes unreadable unless old keys are
  retained in a controlled keyring.
- Changing `SPACETIME_AUDIENCE` immediately changes new tokens and requires consumer coordination.
- Changing `AUTH_TENANT_ID` does not migrate existing SableDB keys.

Operational rotation tooling is a production gate, not a completed feature.
