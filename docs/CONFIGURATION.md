# RustyAuth configuration

RustyAuth reads configuration from environment variables and validates it before binding the HTTP
listener. Missing or invalid required values stop startup.

## Required variables

| Variable | Example | Validation and meaning |
| --- | --- | --- |
| `AUTH_ENV` | `production` | Exactly `development` or `production`. Required; there is no default and no fallback |
| `AUTH_ISSUER` | `https://auth.example.com` | Public RustyAuth origin with no path/query/fragment; HTTPS in production |
| `WEBAUTHN_RP_ID` | `app.example.com` | Must exactly equal the host of `WEBAUTHN_RP_ORIGIN` |
| `WEBAUTHN_RP_ORIGIN` | `https://app.example.com` | Exact browser application origin; HTTPS in production |
| `WEBAUTHN_RP_NAME` | `Example Account` | Name shown by the authenticator |
| `SABLEDB_URL` | `rediss://sabledb.example.com:6379` | `redis` or `rediss` Valkey-protocol URL. In production a `redis` URL must resolve to a `.railway.internal` host; a `rediss` URL is accepted from any host |
| `AUTH_MASTER_KEY_HEX` | 64 hex characters | 32-byte AES key protecting persisted JWT private material. A key whose 32 bytes are all identical is rejected |
| `BOOTSTRAP_TOKEN` | high-entropy secret | Administrative initial-enrolment and HTTP event-polling credential; at least 32 characters in production |
| `AUTH_EVENT_RPC_TOKEN` | high-entropy secret | Bearer credential for `rustyauth.events.v1`; always at least 32 characters |
| `AUTH_IDENTITY_RPC_TOKEN` | high-entropy secret | Bearer credential for `rustyauth.identity.v1`; always at least 32 characters |
| `AUTH_OPERATOR_EMAILS` | `admin@example.com` | Comma-separated canonical emails permitted to bootstrap the first owner operator **through the browser**, and only when the account has already verified that address. Not sufficient on its own — see [First operator](#first-operator) |
| `SPACETIME_AUDIENCE` | `example-dashboard` | Exact `aud` written into access tokens |

### Why `AUTH_ENV` has no default

`AUTH_ENV` is the switch every other fail-closed check reads. It decides:

- whether the session cookie carries `Secure`;
- whether `AUTH_ISSUER` and `WEBAUTHN_RP_ORIGIN` must be HTTPS;
- whether a plaintext `redis://` datastore URL must sit on private networking;
- whether newly added identifiers are stored unverified rather than trusted immediately; and
- whether the development agent-handoff endpoint is enabled.

A default therefore cannot be safe in both directions. Defaulting to development is what a
misconfigured production deployment would silently inherit: a session cookie sent over cleartext, an
HTTP relying-party origin accepted without complaint, every self-service email or phone number
treated as verified, and the agent-handoff route live. Nothing about that deployment looks wrong —
health and readiness both pass.

Startup now stops with `AUTH_ENV must be set explicitly to development or production`. The failure is
a refusal to boot rather than a weaker deployment that reports healthy.

## Optional core variables

| Variable | Default | Allowed range or meaning |
| --- | --- | --- |
| `AUTH_TENANT_ID` | `vtr` | Tenant claim and event tag; one tenant per instance |
| `AUTH_ACCESS_TOKEN_SECONDS` | `300` | 60–900 seconds |
| `AUTH_SESSION_IDLE_SECONDS` | `1800` | 300–86,400 seconds |
| `AUTH_SESSION_ABSOLUTE_SECONDS` | `604800` | 3,600–2,592,000 seconds |
| `BIND_ADDRESS` | `0.0.0.0` | Listener IP address |
| `PORT` | `8080` | Listener port |
| `RUST_LOG` | `rustyauth=info,tower_http=info` | `tracing-subscriber` filter |
| `AUTH_DASHBOARD_DIR` | `/usr/share/rustyauth/dashboard` | Directory containing the built same-origin SolidJS dashboard |
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
| `AUTH_BACKUP_ENCRYPTION_KEY_HEX` | Independent 32-byte AES key encoded as 64 hex characters; a key whose 32 bytes are all identical is rejected |

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

### Placeholder keys are rejected

`AUTH_MASTER_KEY_HEX` and `AUTH_BACKUP_ENCRYPTION_KEY_HEX` are refused at startup when all 32 bytes
are the same value:

```text
AUTH_MASTER_KEY_HEX is a placeholder with no entropy; generate one with `openssl rand -hex 32`
```

That shape is what an unedited placeholder looks like. The all-zero key was published in this
repository, and `1111…`, `aaaa…` and their relatives are what people substitute when they want the
process to start. Such a key has no entropy and is public, so accepting it would wrap every stored
signing key and every backup envelope under a value an attacker already has — leaving encryption at
rest that satisfies an inventory question and stops nobody.

The rejection applies in development as well as production. Generate every key with:

```sh
openssl rand -hex 32
```

This is a placeholder filter, not a key-quality test. It cannot tell a weak key from a strong one;
it refuses only the specific shape that proves no key was generated. The `AUTH_MASTER_KEY_HEX` in
`.env.example` and `compose.yaml` passes the check but is committed to this repository and therefore
public, as is the `vtr-local-enrolment-only` bootstrap token. Neither may appear in a shared
deployment.

### First operator

`AUTH_OPERATOR_EMAILS` alone no longer makes anyone an operator. Browser bootstrap requires a
passkey session whose account holds a **verified** email identifier listed in that variable, and
production never marks a self-service identifier verified. Nothing can verify one until an operator
exists to do it, so the first Owner is created from the host:

```sh
rustyauth operator promote <email> owner
rustyauth operator list
```

`operator promote` resolves the canonical email to an existing account, writes the operator record,
and marks that address verified so the same account can subsequently bootstrap through the browser.
The account must already exist — promotion does not create one. The cost of this path is deliberate:
it requires shell access to the deployment rather than control of an inbox.

Keep `AUTH_OPERATOR_EMAILS` set anyway. It is what allows a replacement operator to bootstrap from
the browser once their address is verified, and an empty value only disables that browser path —
operator records already stored in SableDB continue to sign in.

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

`SABLEDB_URL` accepts two schemes:

| Scheme | Production rule |
| --- | --- |
| `redis` | Host must end in `.railway.internal`. The link is plaintext, so private networking is the only thing protecting sessions and wrapped signing keys in transit |
| `rediss` | Accepted from any host. TLS protects the link itself, so the hostname check would add nothing |

Development accepts either scheme against any host.

`rediss` exists so a deployment outside Railway can encrypt datastore traffic instead of being
forced onto plaintext. It is not a way to expose SableDB publicly: transport encryption authenticates
and protects the connection, it does not authorize the caller. Keep SableDB unreachable from the
public internet regardless of scheme, and do not switch a `redis` URL off `.railway.internal` to
avoid the check.

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
AUTH_OPERATOR_EMAILS=admin@example.com
AUTH_DASHBOARD_DIR=/usr/share/rustyauth/dashboard
SPACETIME_AUDIENCE=example-dashboard
AUTH_TENANT_ID=example
AUTH_ACCESS_TOKEN_SECONDS=300
AUTH_SESSION_IDLE_SECONDS=1800
AUTH_SESSION_ABSOLUTE_SECONDS=604800
PORT=8080
RUST_LOG=rustyauth=info,tower_http=info
```

Add the six required backup variables to enable scheduled snapshots. Run `rustyauth
doctor` after deploying to validate SableDB, signing material and the bucket connection, then
`rustyauth operator promote <email> owner` once the first account has enrolled.

## Transport limits

These are compiled-in ceilings on the HTTP listener rather than environment variables:

| Limit | Value | Applies to |
| --- | --- | --- |
| Request timeout | 30 seconds | Every request; exceeding it returns `408` |
| Request body limit | 256 KiB | REST handlers, replacing axum's 2 MiB default; exceeding it returns `413` |
| RPC request body limit | 64 KiB | Connect/gRPC/gRPC-Web methods |
| RPC message size limit | 256 KiB | Individual decoded protobuf messages |
| Shutdown grace | 20 seconds | Background signing and backup workers after a shutdown signal |

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
- `rustyauth keys rotate` safely stages a new signing key. Normal automatic rotation uses
  the same prepublication and overlap lifecycle.
- Changing `SPACETIME_AUDIENCE` immediately changes new tokens and requires consumer coordination.
- Changing `AUTH_TENANT_ID` does not migrate existing SableDB keys.
