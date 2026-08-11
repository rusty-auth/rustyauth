# Railway deployment templates

**Status:** Supported `1.0.0` deployment topology. `railway.template.json` is the canonical standalone
marketplace graph, and the successful production workflow publishes its three verified image digests to the
existing `rustyauth` template slug after every current-main rollout.

GitHub environment `railway-production` keeps the project-scoped rollout credential in `RAILWAY_TOKEN` and the
workspace-owner template credential in `RAILWAY_TEMPLATE_TOKEN`; separating them prevents ordinary service
deployment from acquiring marketplace publication authority.

RustyAuth uses separate Railway services so the user interface, policy services and stateful stores have
independent deploy, scaling, health and recovery boundaries. SableDB is always private and always attached to
a persistent volume.

## Template A: standalone realm

The standalone template contains three services:

```text
rustyauth-dashboard  ->  rustyauth-backend  ->  realm-sabledb
public HTTPS             private API*           private + volume
```

`rustyauth-dashboard` serves the Dioxus web release and forwards only bounded authentication and ConnectRPC
paths to the backend over Railway private networking. This keeps the browser same-origin for passkey sessions
without combining the processes. The backend remains the only authorization and mutation boundary.

`rustyauth-backend` may also have a public application-authentication domain when relying-party applications
call it directly. The dashboard gateway is for operator browser traffic, not a general-purpose open proxy.

| Service               | Image                                 | Public exposure                 | Persistent state   | Initial replicas   |
| --------------------- | ------------------------------------- | ------------------------------- | ------------------ | ------------------ |
| `rustyauth-dashboard` | `ghcr.io/rusty-auth/dashboard:v1.0.0` | HTTPS                           | None               | 1 or more          |
| `rustyauth-backend`   | `ghcr.io/rusty-auth/rustyauth:v1.0.0` | Optional application API domain | None               | 1                  |
| `realm-sabledb`       | `ghcr.io/rusty-auth/sabledb:v1.0.0`   | None                            | `/var/lib/sabledb` | 1 stateful service |

## Template B: Fleet control plane

The central Fleet template also contains three services:

```text
rustyauth-dashboard  ->  rustyauth-control-plane  ->  fleet-sabledb
public HTTPS             private web API*             private + volume
                                                        |
                                                        +-> fleet-backups bucket
```

The control plane owns Fleet operator identities, organizations, projects, environments, memberships, role
bindings, connection metadata, bounded projections and central audit records. It does not serve customer
authentication and does not connect to realm databases.

Desktop and mobile clients require a public native API domain on `rustyauth-control-plane`. That endpoint uses
short-lived device credentials, not browser cookies. The browser continues through the same-origin dashboard
gateway.

| Service                   | Image                                     | Public exposure            | Persistent state   | Initial replicas   |
| ------------------------- | ----------------------------------------- | -------------------------- | ------------------ | ------------------ |
| `rustyauth-dashboard`     | `ghcr.io/rusty-auth/dashboard:v1.0.0`     | HTTPS                      | None               | 1 or more          |
| `rustyauth-control-plane` | `ghcr.io/rusty-auth/control-plane:v1.0.0` | Optional native API domain | None               | 1                  |
| `fleet-sabledb`           | `ghcr.io/rusty-auth/sabledb:v1.0.0`       | None                       | `/var/lib/sabledb` | 1 stateful service |

`fleet-backups` is an encrypted S3-compatible Railway bucket resource rather than a running service. The
control-plane process schedules backups initially. A separate `fleet-worker` service is added when connector,
projection or backup work needs independent horizontal scaling.

Each managed application environment lives in its own Railway project or environment and adds a
`rustyauth-backend` plus a private `realm-sabledb`. Public HTTPS management or an outbound connector links the
realm to Fleet; the Fleet project never receives `SABLEDB_URL` for a realm.

## Template C: all-in-one evaluation

The evaluation template combines one Fleet control plane and one local realm:

```text
rustyauth-dashboard
rustyauth-control-plane
fleet-sabledb
rustyauth-backend
realm-sabledb
```

This is five independently deployable services. The dashboard can switch between Fleet and the local realm
through explicit configured routes. The two SableDB services must remain separate: one holds Fleet metadata
and Fleet operator state; the other holds the realm's users, passkeys, sessions, signing state and backups.

An outbound connector gateway becomes an optional sixth service only when long-lived connection volume needs
an independent scaling boundary. The first implementation keeps it inside the control-plane service.

The combined template also provisions separate `fleet-backups` and optional realm-backup buckets. Backups
never cross state boundaries: restoring Fleet does not restore a realm, and restoring a realm does not restore
Fleet.

Railway's native buckets currently lack S3 Versioning, Object Lock and server-side-encryption metadata. The
production automation therefore configures RustyAuth's explicit `portable` storage profile and verifies a
fresh application-encrypted recovery point before each API rollout. Use the repository's AWS immutable-bucket
stack when provider-enforced WORM retention is required.

## Dashboard gateway contract

The dashboard service is stateless. It may know only:

- the private API upstream;
- the exact public dashboard origin;
- allowed RPC path prefixes;
- request and response size limits; and
- health/build metadata.

It must not contain a database URL, realm-management credential, bootstrap token, signing key or master key.
It forwards `Origin`, `Cookie`, `Set-Cookie`, request IDs, content type and Connect/gRPC-Web headers without
inventing identity or scope headers. The upstream service performs all authentication, authorization,
validation, rate limiting and auditing.

Suggested dashboard variables:

| Variable                 | Purpose                                              |
| ------------------------ | ---------------------------------------------------- |
| `RUSTYAUTH_API_UPSTREAM` | Railway private URL for the backend or control plane |
| `PORT`                   | Dashboard service port                               |

The same stateless image serves standalone and Fleet deployments; the upstream deployment role determines
which API surface is mounted. Public origin and WebAuthn policy remain backend configuration, not dashboard
state.

## Backend configuration and secrets

The recommended template creates one multiline `RUSTYAUTH_CONFIG_YAML` service variable from the validated
`rustyauth.dev/v1alpha1` schema. It contains the deployment role, environment, issuer, relying-party policy,
private SableDB endpoint, token/session/key timings, operator allowlist and optional backup destination and
schedule. Realm documents may also carry deployment-owned webhook destinations. Railway supplies `PORT`, which
RustyAuth treats as the single non-secret platform override.

This application document complements `railway.realm.json` and `railway.control-plane.json`: those files own
Railway build, health, restart and replica policy; the YAML value owns RustyAuth runtime behavior. Existing
templates using the environment-only contract remain compatible during migration.

Every realm receives independent generated values for:

- `AUTH_MASTER_KEY_HEX`, or an AWS KMS-enveloped `AUTH_MASTER_KEY_KMS_CIPHERTEXT_B64` when the service has a
  scoped workload identity;
- `BOOTSTRAP_TOKEN`;
- `AUTH_EVENT_RPC_TOKEN`;
- `AUTH_IDENTITY_RPC_TOKEN`;
- optional plaintext or KMS-enveloped backup encryption and S3 credentials.

The template wires `SABLEDB_URL` from `realm-sabledb` through a Railway private service reference; it safely
overrides the YAML's `spec.datastore.endpoint` placeholder and is never copied to the dashboard or control
plane. Bucket credentials likewise use Railway service references or sealed variables because they are
intentionally absent from the YAML schema.

The SableDB service sets `SABLEDB_BLOCK_CACHE_SIZE=256MB` for Railway's realm shape. The container validates
this value and materializes a private runtime configuration before dropping privileges. The image default
remains 128 MB so the 512 MiB k3s/Helm profile retains sufficient headroom for memtables, compaction and
process overhead; larger dedicated datastore tiers may raise the override after measuring resident memory.

Production YAML requires exact issuer, relying-party, audience, proxy and operator settings documented in
[Configuration](CONFIGURATION.md). The backend refuses to start with development defaults in production.

## Control-plane variables

The Fleet control plane receives independent generated values for:

- its operator-session and master keys;
- device-token signing material;
- pairing and connector signing material;
- `FLEET_INSTANCE_ID`; and
- optional backup encryption and object-storage credentials.

`FLEET_SABLEDB_URL` references only `fleet-sabledb`. Realm connection credentials are encrypted with a
Fleet-specific key or stored through an approved external secret provider; ordinary connection records contain
only an opaque credential reference.

Fleet logical backups include operator credentials and session metadata, the resource hierarchy, role
bindings, connection metadata, idempotency state and central audit events. Ephemeral health caches and expired
pairing attempts may be omitted under an explicit retention policy. Backup encryption keys are escrowed
outside the Fleet project and outside the bucket provider account.

## SableDB services

Both SableDB services use the pinned RustyAuth image, have no public domain or TCP proxy, expose port `6379`
only on Railway private networking, and mount a volume at `/var/lib/sabledb`. The image prepares a newly
attached root-owned Railway volume, clears supplementary groups, drops to UID/GID `10002`, and only then
executes SableDB; clean-template qualification covers first boot and restart.

SableDB is a stateful service. “Scale independently” means its CPU, memory, volume and maintenance lifecycle
are separate; it does not mean increasing a replica slider. Replication or failover requires a separately
qualified topology.

## Scaling rules

- Dashboard: horizontally scalable immediately because it is stateless.
- Control plane: one writer replica until distributed idempotency, locking, session coordination and audit
  sequencing pass; read/connector workers may split later.
- Realm backend: one writer replica until cross-process locking and event sequencing pass.
- SableDB: one stateful service with a persistent volume in the initial supported topology.

Railway services are still independently deployable and vertically scalable from day one. The replica limits
protect correctness; they do not require combining services.

## Health and routing

| Service       | Liveness         | Readiness                                                       |
| ------------- | ---------------- | --------------------------------------------------------------- |
| Dashboard     | `/healthz`       | `/readyz` verifies the configured private upstream is reachable |
| Control plane | `/healthz`       | `/readyz` requires Fleet SableDB and policy initialization      |
| Realm backend | `/healthz`       | `/readyz` requires realm SableDB and signing readiness          |
| SableDB       | TCP health check | Durable volume mounted and accepting commands                   |

Railway drain and platform timeouts must exceed each service's internal timeout and shutdown grace. A queued
deployment is not success; template release verification waits for terminal `SUCCESS` and then exercises the
readiness endpoint and one binary RPC.

## Security invariants

- No SableDB service has a public domain or TCP proxy.
- The dashboard has no backend or database credential.
- The control plane never receives a realm database URL.
- Each realm has unique secrets, credentials, issuer, RP policy and persistent state.
- Fleet failure does not interrupt realm registration, authentication, session validation, token issuance,
  JWKS, backups or local administration.
- Pairing uses a short-lived single-use code and produces a revocable environment-scoped relationship.
- Published images are pinned by version and eventually signed with provenance and SBOMs.
