# RustyAuth configuration

RustyAuth supports one versioned YAML contract for non-secret application policy and retains the original
environment-only contract for backwards compatibility. Both paths are converted into the same internal
configuration and pass through the same fail-closed validation before the HTTP listener binds. Missing,
unknown or invalid values stop startup.

The document configures RustyAuth; it does not create cloud resources. Compose, Railway templates, Terraform,
Pulumi or another platform layer still provisions the container, private network, SableDB volume and backup
bucket, then passes their endpoints to RustyAuth. Users, passkeys, sessions, operator grants and credentials
remain runtime identity state rather than configuration-as-code resources.

| Concern             | Owner               | Examples                                                                 |
| ------------------- | ------------------- | ------------------------------------------------------------------------ |
| RustyAuth policy    | `rustyauth.yaml`    | issuer, relying party, lifetimes, backup schedule, webhook desired state |
| Deployment topology | platform IaC        | image, services, network, volume, bucket, replicas, health checks        |
| Credential material | secret store        | master keys, bootstrap/RPC tokens, datastore credentials, backup keys    |
| Identity state      | RustyAuth + SableDB | users, passkeys, sessions, grants, generated signing material            |

The YAML is authoritative for fields it declares. It is not a seed file that the dashboard may silently
overwrite. When a future resource needs both declarative and interactive creation, its API response carries a
management source so clients can distinguish configuration-managed resources from dashboard-managed ones.

## Recommended YAML contract

Start from the checked-in example and validate it before deployment:

```sh
cp rustyauth.example.yaml rustyauth.yaml
cargo run -- config validate rustyauth.yaml
cargo run -- --config rustyauth.yaml
```

`rustyauth config example realm` and `rustyauth config example fleet` print the current examples without
requiring a repository checkout. The complete production backup example is
[`examples/config/realm-production.yaml`](../examples/config/realm-production.yaml), and
[`schemas/rustyauth-config-v1alpha1.schema.json`](../schemas/rustyauth-config-v1alpha1.schema.json) provides
editor completion and documentation.

The configuration document always describes exactly one running process. A deployment with development,
staging and production therefore keeps one document per environment rather than asking a production process to
choose a branch from a multi-environment file:

```text
deploy/
  development/rustyauth.yaml
  staging/rustyauth.yaml
  production/rustyauth.yaml
```

This keeps security-sensitive changes explicit in review. Shared generation or higher-level workspace tooling
can be added later without changing the runtime schema.

### Configuration source precedence

RustyAuth selects one source in this order:

1. `--config <path>`;
2. multiline YAML in `RUSTYAUTH_CONFIG_YAML`;
3. a path in `RUSTYAUTH_CONFIG_FILE`;
4. an existing `/etc/rustyauth/config.yaml` container mount; or
5. the legacy environment-only contract documented below.

Configure only one of `RUSTYAUTH_CONFIG_YAML` and `RUSTYAUTH_CONFIG_FILE`. An explicit `--config` path wins
over both because it is an operator action on that invocation. In YAML mode, Railway's platform-provided
`PORT` overrides `spec.server.port`; it keeps the container bound to the port Railway routes. `SABLEDB_URL` or
`SABLEDB_URL_FILE` may override `spec.datastore.endpoint` when the connection URL itself contains credentials
or is supplied through a platform service reference. `RUST_LOG` remains process logging configuration rather
than part of the RustyAuth schema.

`apiVersion: rustyauth.dev/v1alpha1` is intentionally explicit. Unknown versions, kinds and fields are
rejected rather than ignored. Durations use readable values such as `30s`, `5m`, `6h`, `7d` and `90d`. Runtime
bounds remain identical to the environment-variable bounds below.

### Containers and Compose

The image automatically reads `/etc/rustyauth/config.yaml`, so no custom entrypoint is required:

```yaml
services:
  auth:
    image: ghcr.io/rusty-auth/rustyauth:v1.0.0
    configs:
      - source: rustyauth
        target: /etc/rustyauth/config.yaml
    environment:
      AUTH_MASTER_KEY_HEX_FILE: /run/secrets/master-key
      BOOTSTRAP_TOKEN_FILE: /run/secrets/bootstrap-token
      AUTH_EVENT_RPC_TOKEN_FILE: /run/secrets/event-rpc-token
      AUTH_IDENTITY_RPC_TOKEN_FILE: /run/secrets/identity-rpc-token
    secrets:
      - master-key
      - bootstrap-token
      - event-rpc-token
      - identity-rpc-token

configs:
  rustyauth:
    file: ./deploy/production/rustyauth.yaml
```

The supplied `compose.yaml` and `compose.fleet.yaml` already use this contract. `scripts/local-stack` derives
an ignored local copy from the checked-in example so overriding `STANDALONE_DASHBOARD_PORT` or
`FLEET_DASHBOARD_PORT` keeps the issuer and WebAuthn origin consistent. Set `STANDALONE_RP_ORIGIN` only when a
separate local relying-party example must be the exact WebAuthn origin.

The same image can validate a document in CI without starting SableDB or receiving secrets:

```sh
docker run --rm -i ghcr.io/rusty-auth/rustyauth:v1.0.0 \
  config validate - < deploy/production/rustyauth.yaml
```

For Kubernetes, put the YAML in a `ConfigMap` mounted at `/etc/rustyauth/config.yaml` and expose credentials
from a `Secret` through the fixed environment names or `_FILE` paths. For ECS, Nomad, Fly.io and similar OCI
platforms, use the mount when available or set `RUSTYAUTH_CONFIG_YAML`; the application schema and validation
behavior do not change with the scheduler.

### Keeping environments consistent

Commit every environment document and validate all of them in pull requests:

```sh
for config in deploy/*/rustyauth.yaml; do
  cargo run --quiet -- config validate "$config"
done
```

Defaults are intentionally encoded in RustyAuth and documented by the JSON Schema; teams need only repeat a
field when they want its value visible in review or different from the default. Security-boundary fields such
as environment, issuer, datastore, RP identity, origin, tenant and realm remain explicit. RustyAuth does not
perform implicit cross-file inheritance because a surprising merge in production is worse than a few visible
lines of duplication.

### Declarative webhooks and ownership

Realm documents may declare webhook desired state under `spec.webhooks`:

```yaml
webhooks:
  - id: application-lifecycle
    name: Application lifecycle
    endpoint: https://api.example.com/hooks/rustyauth
    enabled: true
    eventTypes:
      - identity.created
      - profile.updated
      - session.created
```

The `id` is the stable reconciliation key, not a display name. IDs must be unique, endpoints must use HTTPS,
and each destination needs at least one syntactically valid event type. Fleet control planes reject the field
because realm events originate in realm deployments.

A destination declared here is configuration-managed, not merely seeded. The webhook API contract reports that
management source, and the dashboard labels the destination **Managed by YAML**, renders its controls
read-only and sends operators back to `spec.webhooks` for edits or removal. Dashboard-created destinations
remain dashboard-managed. This avoids two writers silently fighting over the same resource after every
redeploy. Credential rotation and delivery operations are separate from desired-state ownership.

Webhook delivery is implemented on current main. Startup reconciles configuration-managed destinations before
the worker begins sending. The served `WebhookService` manages dashboard destinations and operational actions;
the durable delivery history records attempts, response status and terminal failures. Requests are signed with
HMAC-SHA256 over `timestamp + "." + exact_body`, redirects are disabled, retryable failures use bounded
exponential backoff, and retained source events may be replayed. RustyAuth `1.0.0` is GA for server, container
and web deployments; pin the exact release or image digest you operate.

### Railway and variable-only platforms

Railway accepts multiline service variables, so set `RUSTYAUTH_CONFIG_YAML` to the same validated YAML
document when a filesystem config mount is not available. Keep generated keys and credentials as separate,
preferably sealed, Railway variables. The service's injected `PORT` overrides `spec.server.port`; every other
non-secret setting remains visible in the YAML document. Railway service-reference syntax can be resolved in
the multiline variable before RustyAuth parses it, allowing private service endpoints and bucket metadata to
remain environment-specific.

This does not replace `railway.json`: Railway's config-as-code file owns image build, health checks, replica
count and restart policy, while `rustyauth.yaml` owns the RustyAuth process itself.

See Railway's documentation for [multiline and sealed variables](https://docs.railway.com/variables) and
[platform config as code](https://docs.railway.com/config-as-code).

### Secret input contract

Secrets never have fields in the YAML schema. Supply them through the existing environment name or through a
file path in `<NAME>_FILE`, which works with Docker/Kubernetes secret mounts. Supplying both forms for one
name is rejected. Secret files are read at startup and trailing newlines are removed.

Realm processes require:

- either `AUTH_MASTER_KEY_HEX` or `AUTH_MASTER_KEY_KMS_CIPHERTEXT_B64`, plus the matching optional
  previous-key form;
- `BOOTSTRAP_TOKEN`;
- `AUTH_EVENT_RPC_TOKEN`; and
- `AUTH_IDENTITY_RPC_TOKEN`.

`SABLEDB_URL` is normally visible as the private endpoint in `spec.datastore.endpoint`. If the URL embeds
credentials, inject the complete URL through `SABLEDB_URL`/`SABLEDB_URL_FILE`; it replaces the YAML endpoint
without copying the credential into Git.

Fleet control planes require only their master key and bootstrap token because they do not mount the realm
event or identity services. When YAML enables backups, additionally supply `AUTH_BACKUP_ACCESS_KEY_ID`,
`AUTH_BACKUP_SECRET_ACCESS_KEY`, and either `AUTH_BACKUP_ENCRYPTION_KEY_HEX` or
`AUTH_BACKUP_ENCRYPTION_KEY_KMS_CIPHERTEXT_B64`, plus the matching optional previous-key form.

`rustyauth config validate` deliberately substitutes non-credential validation material, so a pull request can
validate structure and policy without receiving production secrets. Actual secret presence, uniqueness, length
and key material are checked when the service starts.

## Legacy environment-only contract

All existing deployments remain supported. Every variable below also accepts a corresponding `_FILE` form.

## Required variables

| Variable                  | Example                             | Validation and meaning                                                                                                                                                                                                                   |
| ------------------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AUTH_ENV`                | `production`                        | Exactly `development` or `production`. Required; there is no default and no fallback                                                                                                                                                     |
| `AUTH_ISSUER`             | `https://auth.example.com`          | Public RustyAuth origin with no path/query/fragment; HTTPS in production                                                                                                                                                                 |
| `WEBAUTHN_RP_ID`          | `app.example.com`                   | Must exactly equal the host of `WEBAUTHN_RP_ORIGIN`                                                                                                                                                                                      |
| `WEBAUTHN_RP_ORIGIN`      | `https://app.example.com`           | Exact browser application origin; HTTPS in production                                                                                                                                                                                    |
| `WEBAUTHN_RP_NAME`        | `Example Account`                   | Name shown by the authenticator                                                                                                                                                                                                          |
| `SABLEDB_URL`             | `rediss://sabledb.example.com:6379` | `redis` or `rediss` Valkey-protocol URL. In production a `redis` URL must resolve to a `.railway.internal` host; a `rediss` URL is accepted from any host                                                                                |
| `AUTH_MASTER_KEY_HEX`     | 64 hex characters                   | Plaintext-input form of the 32-byte AES key protecting persisted JWT private material. Use either this or `AUTH_MASTER_KEY_KMS_CIPHERTEXT_B64`; a repeated-byte plaintext is rejected                                                    |
| `BOOTSTRAP_TOKEN`         | high-entropy secret                 | Administrative initial-enrolment and HTTP event-polling credential; at least 32 characters in production                                                                                                                                 |
| `AUTH_EVENT_RPC_TOKEN`    | high-entropy secret                 | Realm only: bearer credential for `rustyauth.events.v1`; at least 32 characters                                                                                                                                                          |
| `AUTH_IDENTITY_RPC_TOKEN` | high-entropy secret                 | Realm only: bearer credential for `rustyauth.identity.v1`; at least 32 characters                                                                                                                                                        |
| `AUTH_OPERATOR_EMAILS`    | `admin@example.com`                 | Comma-separated canonical emails permitted to bootstrap the first owner operator **through the browser**, and only when the account has already verified that address. Not sufficient on its own — see [First operator](#first-operator) |
| `AUTH_TRUSTED_PROXY_HOPS` | `1`                                 | Reverse proxies in front of this service. Required in production. `1` when the platform terminates TLS; `0` only when clients reach this process directly                                                                                |
| `SPACETIME_AUDIENCE`      | `example-dashboard`                 | Realm: exact `aud` written into access tokens. Fleet defaults to `rustyauth-fleet-dashboard`                                                                                                                                             |

`AUTH_DEPLOYMENT_ROLE` defaults to `realm`. Set it to `fleet-control-plane` for the central management
service. That role does not mount the realm event or identity services, so their bearer tokens are neither
required nor accepted there.

### Why `AUTH_ENV` has no default

`AUTH_ENV` is the switch every other fail-closed check reads. It decides:

- whether the session cookie carries `Secure`;
- whether `AUTH_ISSUER` and `WEBAUTHN_RP_ORIGIN` must be HTTPS;
- whether a plaintext `redis://` datastore URL must sit on private networking;
- whether newly added identifiers are stored unverified rather than trusted immediately; and
- whether the development agent-handoff endpoint is enabled.

A default therefore cannot be safe in both directions. Defaulting to development is what a misconfigured
production deployment would silently inherit: a session cookie sent over cleartext, an HTTP relying-party
origin accepted without complaint, every self-service email or phone number treated as verified, and the
agent-handoff route live. Nothing about that deployment looks wrong — health and readiness both pass.

Startup now stops with `AUTH_ENV must be set explicitly to development or production`. The failure is a
refusal to boot rather than a weaker deployment that reports healthy.

## Optional core variables

| Variable                                       | Default                          | Allowed range or meaning                                                                                |
| ---------------------------------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `AUTH_TENANT_ID`                               | `vtr`                            | Tenant claim and event tag; one tenant per instance                                                     |
| `AUTH_REALM_ID`                                | `AUTH_TENANT_ID`                 | Durable realm/deployment identifier exposed by the management API and bound into Fleet pairing grants   |
| `AUTH_ACCESS_TOKEN_SECONDS`                    | `300`                            | 60–900 seconds                                                                                          |
| `AUTH_SESSION_IDLE_SECONDS`                    | `1800`                           | 300–86,400 seconds                                                                                      |
| `AUTH_SESSION_ABSOLUTE_SECONDS`                | `604800`                         | 3,600–2,592,000 seconds                                                                                 |
| `BIND_ADDRESS`                                 | `0.0.0.0`                        | Listener IP address                                                                                     |
| `PORT`                                         | `8080`                           | Listener port                                                                                           |
| `RUST_LOG`                                     | `rustyauth=info,tower_http=info` | `tracing-subscriber` filter                                                                             |
| `AUTH_MASTER_PREVIOUS_KEYS_HEX`                | empty                            | Comma-separated previous 32-byte master keys, each encoded as 64 hex characters                         |
| `AUTH_MASTER_KEY_KMS_CIPHERTEXT_B64`           | empty                            | AWS KMS ciphertext for the active raw 32-byte master key; mutually exclusive with `AUTH_MASTER_KEY_HEX` |
| `AUTH_MASTER_PREVIOUS_KEYS_KMS_CIPHERTEXT_B64` | empty                            | Comma-separated AWS KMS ciphertexts for previous raw master keys                                        |
| `AUTH_SIGNING_KEY_ROTATION_SECONDS`            | `2592000`                        | Automatic signing-key lifetime; 3,600–31,536,000 seconds                                                |
| `AUTH_SIGNING_KEY_PREPUBLISH_SECONDS`          | `600`                            | Publish the next public key before activation; 300–86,400 seconds and shorter than the rotation period  |
| `AUTH_SIGNING_KEY_OVERLAP_SECONDS`             | token lifetime + 300             | Retain retired public keys; minimum is `AUTH_ACCESS_TOKEN_SECONDS + 300`, maximum 86,400                |
| `AUTH_KEY_MAINTENANCE_SECONDS`                 | `30`                             | Signing lifecycle check interval; 5–3,600 seconds                                                       |

Absolute session expiry must be longer than the operational idle policy. Startup rejects equality or an
absolute lifetime shorter than the idle lifetime so an invalid policy cannot silently reach production.

## Backup variables

This section defines configuration inputs. The complete data scope, binary envelope, S3 object contract,
health model and restore runbook are documented in [Backups and disaster recovery](BACKUPS.md).

Backup configuration is all-or-nothing. Supply all six required values or none:

| Variable                         | Meaning                                                                                                                                                           |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AUTH_BACKUP_ENDPOINT`           | S3-compatible API origin. Must be HTTPS in production: snapshots carry every account and the wrapped signing keys, and the SigV4 header carries the access key id |
| `AUTH_BACKUP_REGION`             | SDK signing region                                                                                                                                                |
| `AUTH_BACKUP_BUCKET`             | Private destination bucket                                                                                                                                        |
| `AUTH_BACKUP_ACCESS_KEY_ID`      | Bucket access identifier                                                                                                                                          |
| `AUTH_BACKUP_SECRET_ACCESS_KEY`  | Bucket secret                                                                                                                                                     |
| `AUTH_BACKUP_ENCRYPTION_KEY_HEX` | Plaintext-input form of the independent 32-byte application backup key; use either this or `AUTH_BACKUP_ENCRYPTION_KEY_KMS_CIPHERTEXT_B64`                        |

`AUTH_BACKUP_URL_STYLE` is `virtual` by default and may be set to `path` for providers that require path-style
buckets.

Optional backup controls:

| Variable                                        | Default         | Meaning                                                                                                                                             |
| ----------------------------------------------- | --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AUTH_BACKUP_INTERVAL_SECONDS`                  | `21600`         | Automatic backup interval; 300–604,800 seconds                                                                                                      |
| `AUTH_BACKUP_RPO_SECONDS`                       | backup interval | Maximum acceptable age of the last successful recovery point; cannot be shorter than the interval                                                   |
| `AUTH_BACKUP_RETENTION_DAYS`                    | `90`            | Minimum compliance-mode Object Lock duration required on every new object; 1–3,650 days                                                             |
| `AUTH_BACKUP_ALERT_AFTER_FAILURES`              | `2`             | Consecutive failures that put backup health into alerting state; 1–100                                                                              |
| `AUTH_BACKUP_SSE`                               | `aws:kms`       | Required provider-side encryption reported for new objects: `aws:kms`, `AES256`, or `provider` for a compatible service that owns encryption policy |
| `AUTH_BACKUP_SSE_KMS_KEY_ID`                    | empty           | Exact customer-managed KMS key ARN expected on every new object; requires `AUTH_BACKUP_SSE=aws:kms`                                                 |
| `AUTH_BACKUP_PREVIOUS_KEYS_HEX`                 | empty           | Comma-separated previous 32-byte backup keys, each encoded as 64 hex characters                                                                     |
| `AUTH_BACKUP_ENCRYPTION_KEY_KMS_CIPHERTEXT_B64` | empty           | AWS KMS ciphertext for the active raw 32-byte application backup key; mutually exclusive with the plaintext form                                    |
| `AUTH_BACKUP_PREVIOUS_KEYS_KMS_CIPHERTEXT_B64`  | empty           | Comma-separated AWS KMS ciphertexts for previous raw backup keys                                                                                    |

When backup configuration is present, RustyAuth creates a verified logical backup at process start and then at
the configured interval. New v3 objects contain a compact Postcard binary snapshot, Zstandard compression and
an authenticated AES-256-GCM envelope. Upload succeeds only when the read-back proves a version ID,
compliance-mode Object Lock for at least the configured retention, the configured provider-side encryption,
successful decryption and a valid content manifest. Existing v2 compressed-JSON envelopes remain restorable.
Key IDs are derived automatically; operators never configure or synchronize separate IDs.

The bucket must have Versioning and a default compliance-mode Object Lock rule before RustyAuth writes to it.
On AWS, use the checked-in `infra/aws/backup-bucket.yaml` stack, which also configures bucket-default SSE-KMS
and blocks application deletion. The RustyAuth principal needs only `s3:ListBucket`, `s3:GetObject` and
`s3:PutObject`; do not grant delete, retention changes or governance bypass.

### AWS KMS envelope-key input

Production can keep the master and portable backup data-encryption keys out of deployment variables. Generate
each as 32 raw random bytes, encrypt it with a customer-managed symmetric AWS KMS key, then supply only the
standard-base64 `CiphertextBlob`. RustyAuth calls `Decrypt` at startup and holds the plaintext only in its
zeroizing in-process key ring. The ciphertext is bound to its purpose and tenant with mandatory encryption
context, so a master-key ciphertext cannot be substituted for a backup key or moved to another tenant.

```sh
umask 077
openssl rand 32 > master-key.raw
aws kms encrypt \
  --key-id alias/rustyauth-production \
  --plaintext fileb://master-key.raw \
  --encryption-context rustyauth-purpose=master,rustyauth-tenant=payments \
  --query CiphertextBlob --output text
```

Use `rustyauth-purpose=backup` for the application backup key. `AWS_REGION` and the standard AWS workload
credential chain select KMS; do not place long-lived AWS access keys in the image. Grant only `kms:Decrypt` on
the selected key and constrain the IAM statement to both encryption-context pairs. Ciphertexts may also use
their `_FILE` inputs. Never provide a plaintext and KMS form for the same active or previous ring; startup
rejects the ambiguity. Retain encrypted previous keys until the rotation and recovery windows below close.

Scheduler status survives process restarts in an excluded operational SableDB key. Run
`rustyauth backup
status` or `rustyauth doctor` from the host: both exit non-zero when the RPO is overdue or
the failure threshold is reached, so the platform check must page the operator. The scheduler also emits the
structured log field `backup_health_alert=true`, but the exit-status check is the required alert path rather
than relying on log collection alone.

Backup configuration is all-or-nothing in both directions. Supplying some of the six required values fails
startup, and so does supplying any of the optional controls above — including `AUTH_BACKUP_INTERVAL_SECONDS` —
while the six are absent. Setting a backup interval on a deployment with no backup sink is the shape of a
deployment that believes it has backups and does not, so it is refused rather than ignored.

## Secret generation

Generate each secret independently. Example commands:

```sh
openssl rand -hex 32       # AUTH_MASTER_KEY_HEX
openssl rand -base64 48    # BOOTSTRAP_TOKEN
openssl rand -base64 48    # AUTH_EVENT_RPC_TOKEN
openssl rand -base64 48    # AUTH_IDENTITY_RPC_TOKEN
openssl rand -hex 32       # AUTH_BACKUP_ENCRYPTION_KEY_HEX
```

Do not reuse keys across purposes, tenants or environments. Keep backup encryption keys outside the bucket and
its provider account; losing that key makes encrypted snapshots unrecoverable. Escrow the active and retained
previous keys in a separately administered recovery vault, and test access to that escrow during every
clean-room drill. The S3 KMS key is defence in depth and cannot replace the portable application key.

### Placeholder keys are rejected

`AUTH_MASTER_KEY_HEX` and `AUTH_BACKUP_ENCRYPTION_KEY_HEX` are refused at startup when all 32 bytes are the
same value:

```text
AUTH_MASTER_KEY_HEX is a placeholder with no entropy; generate one with `openssl rand -hex 32`
```

That shape is what an unedited placeholder looks like. The all-zero key was published in this repository, and
`1111…`, `aaaa…` and their relatives are what people substitute when they want the process to start. Such a
key has no entropy and is public, so accepting it would wrap every stored signing key and every backup
envelope under a value an attacker already has — leaving encryption at rest that satisfies an inventory
question and stops nobody.

The rejection applies in development as well as production. Generate every key with:

```sh
openssl rand -hex 32
```

This is a placeholder filter, not a key-quality test. It cannot tell a weak key from a strong one, and it
cannot tell a generated key from one that has been published — it refuses only the specific shape that proves
no key was generated at all.

That limit is why no secret ships with a value. `.env.example` leaves every one blank and `compose.yaml`
refuses to substitute a default, so a missing value stops startup by name instead of falling back to something
readable in the repository. Generate each one, including for local work.

### First operator

`AUTH_OPERATOR_EMAILS` alone no longer makes anyone an operator. Browser bootstrap requires a passkey session
whose account holds a **verified** email identifier listed in that variable, and production never marks a
self-service identifier verified. Nothing can verify one until an operator exists to do it, so the first Owner
is created from the host:

```sh
rustyauth operator promote <user-id> owner
rustyauth operator list
```

`operator promote` takes a **user id**, not an address, and it does not mark anything verified. Both are
deliberate. Any enrolled account can attach an unclaimed address to itself through the self-service API, so
resolving an address here would promote whichever account claimed it first — handing Owner to an attacker by
the administrator's own hand. Run `operator find <email>` first: it prints every account holding that address
with `claimedAt` and `verified`, so an address claimed recently by an account nobody recognises is visible
before anything is granted.

Production registration is invitation-only. Create the initial identifier-bound invitation from the host,
complete passkey registration, inspect the resulting account and then promote its UUID:

```sh
rustyauth invitation create email owner@example.com 30m
rustyauth operator find owner@example.com
rustyauth operator promote <user-id> owner
```

The invitation code is returned once and only its digest is stored. The account must exist before promotion;
promotion does not create one. The cost of this path is deliberate: it requires privileged command-execution
access to the deployment (the production image has no shell) rather than control of an inbox.

Development deployments also expose a dashboard setup screen that creates the first local Owner with the
bootstrap token. That path is disabled in production; do not distribute a production bootstrap token to a
browser operator.

`operator demote <user-id>` removes a grant. Taking an address out of `AUTH_OPERATOR_EMAILS` does **not**
revoke anything, because a stored operator record is honoured before the allowlist is consulted; demotion is
the only way to withdraw one.

Keep `AUTH_OPERATOR_EMAILS` set anyway. It is what allows a replacement operator to bootstrap from the browser
once their address is verified, and an empty value only disables that browser path — operator records already
stored in SableDB continue to sign in.

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

Changing the RP ID does not merely rename a deployment. Existing WebAuthn credentials are scoped to the
previous RP ID and need an explicit migration/re-enrolment plan.

`AUTH_ISSUER` may be a different origin from the relying-party application. Both must be HTTPS in production.
Browser CORS permits only the configured relying-party origin.

## SableDB boundary

`SABLEDB_URL` accepts two schemes:

| Scheme   | Production rule                                                                                                                                              |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `redis`  | Host must end in `.railway.internal` or `.svc.cluster.local`. The link is plaintext, so private networking is the only thing protecting sessions and wrapped signing keys in transit |
| `rediss` | Accepted from any host. TLS protects the link itself, so the hostname check would add nothing                                                                |

Development accepts either scheme against any host.

The Kubernetes allowance requires a fully qualified Service name such as
`sabledb.identity.svc.cluster.local`; a short name such as `sabledb` is rejected in production. `rediss`
exists so a deployment outside these private platform networks can encrypt datastore traffic instead of
being forced onto plaintext. It is not a way to expose SableDB publicly: transport encryption authenticates
and protects the connection, it does not authorize the caller. Keep SableDB unreachable from the public
internet regardless of scheme.

SableDB requires a persistent volume at `/var/lib/sabledb`. RustyAuth assumes the database namespace belongs
to one configured tenant.

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
SPACETIME_AUDIENCE=example-dashboard
AUTH_TENANT_ID=example
AUTH_REALM_ID=example-production
AUTH_ACCESS_TOKEN_SECONDS=300
AUTH_SESSION_IDLE_SECONDS=1800
AUTH_SESSION_ABSOLUTE_SECONDS=604800
PORT=8080
RUST_LOG=rustyauth=info,tower_http=info
```

Add the six required backup variables to enable scheduled snapshots. Run `rustyauth
doctor` after deploying to
validate SableDB, signing material and the bucket connection, then
`rustyauth operator promote <user-id> owner` once the first account has enrolled.

After an Owner or Administrator exists on a realm, create a one-use Fleet pairing code from that realm's host:

```sh
rustyauth fleet pairing-code https://fleet.example.com <operator-user-id>
```

The command is realm-only, requires an active Owner or Administrator, binds the code to the exact
control-plane origin and expires it after the configured pairing window. Paste the returned code into the
Fleet dashboard; the browser never receives the resulting long-lived realm credential.

## Transport limits

These are compiled-in ceilings on the HTTP listener rather than environment variables:

| Limit                  | Value      | Applies to                                                                |
| ---------------------- | ---------- | ------------------------------------------------------------------------- |
| Request timeout        | 30 seconds | Every request; exceeding it returns `408`                                 |
| Request body limit     | 256 KiB    | REST handlers, replacing axum's 2 MiB default; exceeding it returns `413` |
| RPC request body limit | 64 KiB     | Connect/gRPC/gRPC-Web methods                                             |
| RPC message size limit | 256 KiB    | Individual decoded protobuf messages                                      |
| Shutdown grace         | 20 seconds | Background signing and backup workers after a shutdown signal             |

## Rotation impact

- Rotating `BOOTSTRAP_TOKEN` affects future enrolment and HTTP event polling only.
- Rotate `AUTH_EVENT_RPC_TOKEN` and `AUTH_IDENTITY_RPC_TOKEN` independently with coordinated consumer
  restarts. The current static-token transport has no overlap window; use workload identity or mTLS at the
  private edge when the deployment platform supports it.
- To rotate `AUTH_MASTER_KEY_HEX`, put the new key in `AUTH_MASTER_KEY_HEX` and the old key in
  `AUTH_MASTER_PREVIOUS_KEYS_HEX`, then restart. RustyAuth re-encrypts stored private signing material under
  the new key without changing the signing `kid`. Remove the old key only after `keys status` succeeds on
  every running instance.
- With AWS KMS input, perform the same overlap using `AUTH_MASTER_KEY_KMS_CIPHERTEXT_B64` and
  `AUTH_MASTER_PREVIOUS_KEYS_KMS_CIPHERTEXT_B64`. After a control-plane compromise, revoke the affected
  workload identity, issue a new KMS-enveloped master key, restart to rewrap signing material, rotate every
  Fleet connection credential, revoke active operator sessions, and retain the former ciphertext only in the
  separately controlled recovery path until a clean-room restore succeeds.
- To rotate `AUTH_BACKUP_ENCRYPTION_KEY_HEX`, put the new key in the active variable and retain the old key in
  `AUTH_BACKUP_PREVIOUS_KEYS_HEX` until every backup encrypted with it has expired or been replaced and a
  recovery drill has passed.
- `rustyauth keys rotate` safely stages a new signing key. Normal automatic rotation uses the same
  prepublication and overlap lifecycle.
- Changing `SPACETIME_AUDIENCE` immediately changes new tokens and requires consumer coordination.
- Changing `AUTH_TENANT_ID` does not migrate existing SableDB keys.
