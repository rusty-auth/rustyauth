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
| `BOOTSTRAP_TOKEN` | high-entropy secret | Administrative initial-enrolment and HTTP event-polling credential; at least 32 characters in production |
| `AUTH_EVENT_RPC_TOKEN` | high-entropy secret | Bearer credential for `rustyauth.events.v1`; always at least 32 characters |
| `AUTH_IDENTITY_RPC_TOKEN` | high-entropy secret | Bearer credential for `rustyauth.identity.v1`; always at least 32 characters |
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
| `AUTH_MASTER_PREVIOUS_KEYS_HEX` | empty | Comma-separated previous 32-byte master keys, each encoded as 64 hex characters |
| `AUTH_SIGNING_KEY_ROTATION_SECONDS` | `2592000` | Automatic signing-key lifetime; 3,600–31,536,000 seconds |
| `AUTH_SIGNING_KEY_PREPUBLISH_SECONDS` | `600` | Publish the next public key before activation; 300–86,400 seconds and shorter than the rotation period |
| `AUTH_SIGNING_KEY_OVERLAP_SECONDS` | token lifetime + 300 | Retain retired public keys; minimum is `AUTH_ACCESS_TOKEN_SECONDS + 300`, maximum 86,400 |
| `AUTH_KEY_MAINTENANCE_SECONDS` | `30` | Signing lifecycle check interval; 5–3,600 seconds |

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

Optional backup controls:

| Variable | Default | Meaning |
| --- | --- | --- |
| `AUTH_BACKUP_INTERVAL_SECONDS` | `21600` | Automatic backup interval; 300–604,800 seconds |
| `AUTH_BACKUP_PREVIOUS_KEYS_HEX` | empty | Comma-separated previous 32-byte backup keys, each encoded as 64 hex characters |

When backup configuration is present, RustyAuth creates a verified logical backup at process start
and then at the configured interval. Key IDs are derived automatically; operators never configure
or synchronize separate IDs. Partial configuration fails startup.

## Secret generation

Generate each secret independently. Example commands:

```sh
openssl rand -hex 32       # AUTH_MASTER_KEY_HEX
openssl rand -base64 48    # BOOTSTRAP_TOKEN
openssl rand -base64 48    # AUTH_EVENT_RPC_TOKEN
openssl rand -base64 48    # AUTH_IDENTITY_RPC_TOKEN
openssl rand -hex 32       # AUTH_BACKUP_ENCRYPTION_KEY_HEX
```

Do not reuse keys across purposes, tenants or environments. Keep backup encryption keys outside the
bucket and its provider account; losing that key makes encrypted snapshots unrecoverable.

The zero development master key and `vtr-local-enrolment-only` bootstrap token in `.env.example` are
public fixtures. They must not appear in a shared deployment.

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
AUTH_MASTER_PREVIOUS_KEYS_HEX=
BOOTSTRAP_TOKEN=<high-entropy-secret>
AUTH_EVENT_RPC_TOKEN=<distinct-high-entropy-secret>
AUTH_IDENTITY_RPC_TOKEN=<distinct-high-entropy-secret>
SPACETIME_AUDIENCE=example-dashboard
AUTH_TENANT_ID=example
AUTH_ACCESS_TOKEN_SECONDS=300
AUTH_SESSION_IDLE_SECONDS=1800
AUTH_SESSION_ABSOLUTE_SECONDS=604800
PORT=8080
RUST_LOG=passkey_auth_service=info,tower_http=info
```

Add the six required backup variables to enable scheduled snapshots. Run `passkey-auth-service
doctor` after deploying to validate SableDB, signing material and the bucket connection.

## Rotation impact

- Rotating `BOOTSTRAP_TOKEN` affects future enrolment and HTTP event polling only.
- Rotate `AUTH_EVENT_RPC_TOKEN` and `AUTH_IDENTITY_RPC_TOKEN` independently with coordinated
  consumer restarts. The current static-token transport has no overlap window; use workload
  identity or mTLS at the private edge when the deployment platform supports it.
- To rotate `AUTH_MASTER_KEY_HEX`, put the new key in `AUTH_MASTER_KEY_HEX` and the old key in
  `AUTH_MASTER_PREVIOUS_KEYS_HEX`, then restart. RustyAuth re-encrypts stored private signing
  material under the new key without changing the signing `kid`. Remove the old key only after
  `keys status` succeeds on every running instance.
- To rotate `AUTH_BACKUP_ENCRYPTION_KEY_HEX`, put the new key in the active variable and retain the
  old key in `AUTH_BACKUP_PREVIOUS_KEYS_HEX` until every backup encrypted with it has expired or
  been replaced and a recovery drill has passed.
- `passkey-auth-service keys rotate` safely stages a new signing key. Normal automatic rotation uses
  the same prepublication and overlap lifecycle.
- Changing `SPACETIME_AUDIENCE` immediately changes new tokens and requires consumer coordination.
- Changing `AUTH_TENANT_ID` does not migrate existing SableDB keys.
