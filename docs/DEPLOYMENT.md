# Deploying RustyAuth

RustyAuth `1.0.0` builds three independently deployable services:

- a public, stateless Dioxus dashboard and bounded same-origin Connect gateway;
- a Rust/Axum authentication realm backend; and
- a private, persistent SableDB service.

The Fleet template uses the same three-service shape with the realm backend replaced by a distinct Fleet
control-plane service. See [Railway deployment templates](RAILWAY_TEMPLATE.md).

An optional S3-compatible bucket enables scheduled encrypted logical backups and clean-room restore.

## Local Docker Compose

From this directory:

```sh
scripts/local-stack standalone up
```

No secret ships with a value. `.env.example` leaves every one blank and `compose.yaml` refuses to substitute a
default, so an unpopulated `.env` stops the stack with a named missing variable rather than starting on
something an attacker could read in the repository. A committed default is a published default, and the
entropy check in `config.rs` cannot tell a generated key from one that has been published — so generating is
the only path, including locally.

Non-secret settings come from the versioned YAML contract. The launcher derives an ignored local file from
`rustyauth.example.yaml`; the auth container receives it at `/etc/rustyauth/config.yaml` through a read-only
Compose config. This keeps the deployed process configuration inspectable without putting credentials in it.

Compose publishes only the Dioxus gateway at `127.0.0.1:8081`. The Rust API and SableDB share an internal
network and have no host ports. The named SableDB volume survives service replacement. Override the public
port with `STANDALONE_DASHBOARD_PORT`; the local issuer and WebAuthn origin follow it automatically.

Use `scripts/local-stack fleet up` for the equivalent dashboard/control-plane/Fleet-SableDB stack on port
`5196`. Its state and secret file are independent from the standalone realm.

Check both probes:

```sh
curl --fail http://127.0.0.1:8081/healthz
curl --fail http://127.0.0.1:8081/readyz
```

`/healthz` proves that the process can answer HTTP. `/readyz` additionally requires a SableDB `PONG`. Route
traffic based on readiness; use liveness for process restart decisions.

### Lifecycle commands

```sh
scripts/local-stack standalone logs auth sabledb
scripts/local-stack standalone down
scripts/local-stack standalone up --detach
```

`scripts/local-stack standalone down --volumes` permanently deletes local identity state. Do not include
`--volumes` in routine restart or upgrade automation.

## Railway topology

The target standalone template creates three core services in one project and preferred region. An optional
backup bucket is a project resource rather than a running service:

| Resource          | Exposure                                              | Persistent resource           |
| ----------------- | ----------------------------------------------------- | ----------------------------- |
| Dashboard         | Public HTTPS                                          | None                          |
| RustyAuth backend | Private operator API; optional public application API | None                          |
| Realm SableDB     | Railway private network only, port `6379`             | Volume at `/var/lib/sabledb`  |
| AuthBackups       | Private credentials only                              | Optional S3-compatible bucket |

The bucket remains optional, but any deployment claiming recovery must configure it and complete a restore
drill.

### Automatic maintained-template upgrades

The maintained Railway production/template-source project follows successful merges to `main` through
`.github/workflows/railway-production.yml`. The workflow starts only after the repository's `CI` workflow has
completed successfully for the current `main` tip. A later merge makes an older successful result stale, so
the older result is recorded as skipped rather than being allowed to roll production backwards.

Each merge publishes separate API, dashboard and SableDB images under a full-commit tag. The images include
SBOM and provenance attestations and are signed by GitHub OIDC. Railway is updated to that exact tag, and the
rollout sends Railway a digest reference rather than a tag and accepts success only when Railway reports that
digest in a terminal `SUCCESS` deployment. Mutable `latest` tags are never used by this path.

Rollouts are serialized across the state boundaries:

1. The realm API runs the target image's `rustyauth doctor` as a Railway pre-deploy command, then reaches
   `/healthz` and `/readyz` on the application API origin.
2. The stateless dashboard deploys and reaches both probes through its public origin, including its private
   upstream readiness check.
3. Private SableDB is replaced without recreating its volume, after which both API and dashboard readiness
   are checked again.

Before the first mutation, the workflow records the active deployment and browser-origin configuration. A
later deployment or readiness failure restores every completed service in reverse order, restores the prior
issuer and relying-party values, and retains both forward and rollback receipts. If a newly introduced service
had no prior deployment, rollback removes only that service's latest deployment; it never deletes the service
or a datastore volume. A rollback failure keeps the workflow red and requires operator repair.

The GitHub `railway-production` environment owns the workspace-scoped `RAILWAY_API_TOKEN` and non-secret
target IDs/URLs. The token is restricted to the Railway workspace containing this project; project-scoped
tokens are preferred when the workspace permits their creation. The environment must define
`RAILWAY_PROJECT_ID`, `RAILWAY_ENVIRONMENT_ID`, `RAILWAY_API_SERVICE_ID`,
`RAILWAY_DASHBOARD_SERVICE_ID`, `RAILWAY_SABLEDB_SERVICE_ID`, `RAILWAY_API_URL` and
`RAILWAY_DASHBOARD_URL`. The job aligns the issuer and WebAuthn relying-party settings to the dashboard origin
without printing their existing values. Every successful or failed run retains per-service deployment
receipts for 90 days.

A manual dispatch defaults to the current `main` tip. Selecting an older full SHA additionally requires the
explicit `allow_non_tip` rollback input, and the workflow still rejects commits that are not ancestors of
`main`. Customer projects cloned from the public template remain independently owned and are never mutated by
RustyAuth's repository credentials; operators choose when to adopt a newer pinned release.

### RustyAuth service

Use the repository root as the source root and `Dockerfile` as the builder. Set:

- healthcheck path `/healthz`;
- one replica until multi-writer operation is qualified;
- `RUSTYAUTH_CONFIG_YAML` to a validated production document from [Configuration](CONFIGURATION.md); and
- every required credential as a separate sealed variable.

Railway supplies `PORT`; it deliberately overrides `spec.server.port` so public routing and the process
listener agree. Wire `SABLEDB_URL` through a private service reference; it overrides the document's
`spec.datastore.endpoint` placeholder and keeps any credential-bearing URL out of the YAML value. The YAML
document may be a multiline Railway variable; it is the same schema used by Docker and other platforms rather
than a Railway-specific configuration dialect.

`spec.environment` has no default. A deployment that omits it fails to start rather than falling back to
development settings, which would drop `Secure` from the session cookie, accept an HTTP relying-party origin
and treat self-service identifiers as verified. Set it to `production`.

The target dashboard service forwards operator authentication and RPC paths over the private network so the
browser remains on one public origin. Configure the operator origin to the dashboard HTTPS origin and keep the
realm's relying-party policy explicit. The backend, not the gateway, validates the session, origin and method
policy.

Readiness should also be monitored separately at `/readyz`. A liveness-only deploy can be running while unable
to authenticate users.

### First operator

`AUTH_OPERATOR_EMAILS` is no longer sufficient to become an operator. Browser bootstrap requires the account
to hold a **verified** email identifier from that list, and production never marks a self-service identifier
verified — so on a fresh deployment nothing can verify one, because verifying an identifier is itself an
operator action. Create the first Owner by executing the RustyAuth binary in the deployed container (the
scratch image deliberately has no shell):

```sh
rustyauth operator find founder@example.com
rustyauth operator promote <user-id> owner
rustyauth operator list
```

Promotion takes a user id, not an address, and `operator find` is how you get one. Any enrolled account can
attach an unclaimed address to itself through the self-service API, so a command that resolved an address
would promote whoever claimed it first — an attacker who claims your operator address before you run the
promotion would receive Owner from your own hand. `operator find` prints every account holding the address
with `claimedAt` and `verified`; promote the id you recognise, and treat an unfamiliar recent claim on an
operator address as an incident.

Roles are `owner`, `administrator`, `support` and `auditor`. The account must already exist — enrol it through
the normal bootstrap-token registration flow first.

This deliberately costs command-execution access to the deployment rather than control of an inbox. Treat the
ability to run `operator promote` as equivalent to Owner: anyone who can execute the binary in the container can grant themselves
the control plane. Restrict container exec the way you restrict the master key.

`operator demote <user-id>` removes a grant. Removing an address from `AUTH_OPERATOR_EMAILS` does **not**
revoke an existing operator — a stored record is honoured before the allowlist is consulted — so demotion is
the only way to withdraw one. Include it in your offboarding runbook.

`operator list` prints every stored operator with role, primary email and last authentication time. Review it
after any promotion and as part of routine access review.

### SableDB service

Use the repository root as the source root and `sabledb/Dockerfile` as the builder. The Docker build checks out
the immutable SableDB revision declared by `SABLEDB_REVISION`, currently
`8bebc4a60dee404e95608b40ec5c58799e7fa820`. That upstream revision does not commit a lockfile, so the image
copies RustyAuth's reviewed `sabledb/Cargo.lock` before compiling with `--locked`.

Requirements:

- no public domain;
- no TCP proxy;
- private port `6379` only;
- persistent volume at `/var/lib/sabledb`; and
- health check before RustyAuth receives traffic.

Railway private networking and RustyAuth's exclusive reachability are the access-control boundary; SableDB
itself is not being presented as the public authentication layer.

### Backup bucket

This section covers placement in the deployment topology. Use [Backups and disaster recovery](BACKUPS.md) for
the complete snapshot scope, `.rauth` format, provider contract, monitoring behavior, key rotation and
clean-room restore procedure.

Inject bucket credentials into RustyAuth through Railway resource references. Do not expose them to the
relying-party browser. Use a backup encryption key generated and escrowed outside Railway and outside the
bucket provider account.

RustyAuth creates a backup immediately after startup and at `spec.backups.schedule.interval`. Each object
contains the complete server-side namespace for that deployment. A realm object includes its durable users,
identifiers, passkeys, sessions, signing state, organization settings, operator grants, service accounts,
credential locators and ordered events. A Fleet object includes its central organizations, projects,
environments, realm registrations, slug indexes, scoped roles, idempotency records and audit trail; it never
reaches into paired realm databases. The dashboard has no durable browser-local state; its compiled assets
come from the release image. Short-lived WebAuthn ceremonies, agent handoffs, leases and health counters are
deliberately excluded. An unknown future durable key family fails snapshot creation rather than silently
producing an incomplete backup.

New objects are compact binary, compressed with Zstandard and protected with application-level AES-256-GCM.
The destination must additionally provide Versioning, a default compliance-mode Object Lock rule and the
configured server-side encryption. Upload succeeds only after a read-after-write decrypt, manifest check,
version-ID check, retention check and server-side-encryption check. For AWS, deploy
`infra/aws/backup-bucket.yaml`; its application policy permits only list/get/put and explicitly denies delete
and retention bypass.

The release image and runtime environment are part of the recovery plan but not the data backup. Retain the
deployed image digest, non-secret configuration inventory and independently escrowed master/backup keys in a
separate operator-controlled system. Putting the only decryption key inside the bucket it decrypts is not a
recoverable workspace.

Use the binary inside the deployed container for operator checks:

```sh
rustyauth doctor
rustyauth backup create
rustyauth backup list
rustyauth backup status
rustyauth backup verify <object-key>
rustyauth operator list
rustyauth operator find <email>
rustyauth operator promote <user-id> <owner|administrator|support|auditor>
rustyauth operator demote <user-id>
```

## Container properties

The RustyAuth runtime image:

- starts from `scratch` and contains the release binary, its exact dynamic libraries, CA roots, configuration
  mount point and licence notices only;
- contains no dashboard or JavaScript runtime;
- runs as non-root UID/GID `10001`;
- has no shell, package manager or writable application directory;
- exposes port `8080`; and
- includes project and third-party licence notices.

Tagged releases publish separate `dashboard`, `control-plane`, `rustyauth` and `sabledb` images. Neither Rust
API image contains a JavaScript dashboard runtime.

The dashboard is also scratch-based. It contains the Dioxus assets, a statically built source-pinned Caddy
gateway and a dependency-free health probe; it has no Alpine userspace, shell, curl or package manager.

The SableDB image is scratch-based, runs as non-root UID/GID `10002`, and stores data under
`/var/lib/sabledb`. Its dedicated probe sends Redis `PING` and requires the exact `PONG` response; the image
does not carry a shell merely to open a TCP socket.

The API, SableDB and Dioxus WebAssembly release builds embed `cargo-auditable` dependency metadata. Compatible
artifact scanners therefore recover the Cargo graph from the shipped binary instead of inferring it from a
builder layer that is absent from the scratch image. CI separately audits the root, console and SableDB
lockfiles and requires zero HIGH/CRITICAL findings from the checksum-pinned runtime-image scanner.

The supplied Compose files additionally make every service root filesystem read-only, mount a bounded `noexec`
temporary filesystem, drop all Linux capabilities, enable `no-new-privileges` and cap the process count.
Preserve equivalent controls in Railway or any other production platform. They are runtime policy, not image
properties, so publishing the same image does not automatically apply them.

Run `scripts/qualify-runtime-images.sh` against the exact candidate tags before promotion. It creates an
isolated temporary topology, proves the runtime controls and bounded gateway behavior, crosses repeated lease
renewals, then removes only its uniquely named containers, networks and volume. The tagged-release workflow
executes the same drill before live integration qualification.

Fleet realm-management URLs and configured webhook destinations are outbound request targets. Production Fleet
validation rejects literal private, loopback, link-local, metadata and local-name endpoints; webhook
validation requires HTTPS, rejects URL credentials and fragments, and disables redirects. Before each
public-endpoint RPC, Fleet resolves the hostname under a deadline, rejects the entire answer set if any
address is non-public, and pins that answer set into a redirect-disabled TLS client so connection
establishment cannot resolve a different address. Still enforce an egress allowlist or proxy at the
infrastructure boundary and deny cloud metadata and unreviewed private address ranges there as independent
defence in depth.

See [Security hardening and qualification](SECURITY_HARDENING.md) for the release verification matrix and
continuous production-assurance program.

## TLS and proxying

RustyAuth expects the deployment platform to terminate TLS. `AUTH_ISSUER` and `WEBAUTHN_RP_ORIGIN` must
describe the public HTTPS origins, not internal container URLs. Do not rewrite browser `Origin` headers to
bypass exact-origin enforcement.

Preserve `Set-Cookie`, `Origin`, `Content-Type` and request IDs through any proxy. Do not cache token,
credential or session responses.

### Response headers

RustyAuth sets these on every response it serves, including dashboard assets. Each is applied only when the
header is absent, so a proxy that already sets one wins:

| Header                         | Value                                                                                                                                                                                                | Applies         |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| `Content-Security-Policy`      | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'` | Always          |
| `X-Frame-Options`              | `DENY`                                                                                                                                                                                               | Always          |
| `Cross-Origin-Opener-Policy`   | `same-origin`                                                                                                                                                                                        | Always          |
| `Cross-Origin-Resource-Policy` | `same-origin`                                                                                                                                                                                        | Always          |
| `Permissions-Policy`           | `geolocation=(), camera=(), microphone=(), payment=()`                                                                                                                                               | Always          |
| `X-Content-Type-Options`       | `nosniff`                                                                                                                                                                                            | Always          |
| `Cache-Control`                | `no-store` unless a public artifact such as JWKS sets a narrower explicit policy                                                                                                                     | Default         |
| `Referrer-Policy`              | `no-referrer`                                                                                                                                                                                        | Always          |
| `Strict-Transport-Security`    | `max-age=63072000; includeSubDomains; preload`                                                                                                                                                       | Production only |

HSTS is withheld outside production on purpose. Emitting it from a `http://localhost` development origin pins
the browser to HTTPS for that host for two years, well past the session that caused it.

Do not add a proxy-level CSP that loosens these directives to make a third-party script, analytics tag or
embedded frame work on the dashboard. The dashboard loads no third-party code; the policy is strict so an
injected script has nowhere to execute and nowhere to send what it reads.

If you front RustyAuth with a proxy that strips unknown response headers, allowlist the table above.

### Request limits

| Limit            | Value      | Behaviour                                                                                                                |
| ---------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------ |
| Request timeout  | 30 seconds | Returns `408`. Bounds slow-body clients, which the size limits alone cannot                                              |
| Request body     | 256 KiB    | Returns `413`. Applies to the REST handlers                                                                              |
| RPC request body | 64 KiB     | Applies to Connect, gRPC and gRPC-Web methods                                                                            |
| Shutdown grace   | 20 seconds | Background signing and backup workers get this long to finish after a shutdown signal, then the process exits regardless |

Set the platform's own request timeout and drain window above 30 and 20 seconds respectively, so RustyAuth's
bounded shutdown completes rather than being killed mid-write.

## Upgrade procedure

There is not yet a formal storage migration framework. Until one exists:

1. Read the release changelog and persisted-data notes.
2. Verify that the target release can read current user, passkey, session and signing-key records.
3. Run `backup create`, retain its JSON receipt and run `backup verify <object-key>`.
4. Deploy RustyAuth first only when it remains compatible with the current SableDB data.
5. Confirm `/healthz`, `/readyz`, discovery, JWKS and an end-to-end passkey sign-in.
6. Retain the previous image and recovery material until verification completes.

Never delete or recreate the SableDB volume as an upgrade shortcut.

## Scaling

Run one RustyAuth writer replica in version `1.0.0`. At startup every serving process must acquire the
namespace's SableDB writer lease. It renews the 60-second lease every 10 seconds and shuts down if renewal
fails or the ownership token changes. Multi-key operations use SableDB atomic pipelines and compound mutations
also use a process-local mutex; active/active mutation has not been qualified and is unsupported.

`railway.json` pins `numReplicas: 1` and `overlapSeconds: 0` so a scale-up or a rolling deploy cannot silently
start a second writer. This narrows the window rather than removing it: `drainingSeconds` (25) is the time the
outgoing process has between `SIGTERM` and `SIGKILL`, and for that period the old process is still finishing
in-flight requests while the new one is live. It stops accepting new work at `SIGTERM`, so the overlap covers
requests already in progress, not new mutations — but it is not zero. Treat a deploy as a short window in
which the outgoing process may still be draining. The replacement cannot serve while the old process retains
the writer lease; the platform may therefore need to wait up to the lease TTL before the new instance starts.
Avoid deploying during a bulk migration and configure health/restart policy to tolerate that bounded wait.

Raising `numReplicas` above 1 is not supported in this version. A second process using the same namespace
fails startup while the lease is owned, and a process that loses ownership stops the server. The lease is a
fence for the supported one-writer topology, not a claim that the data model is safe for active/active writes.

## Observability

RustyAuth writes structured JSON logs and propagates or creates `x-request-id`. The default filter is:

```text
rustyauth=info,tower_http=info
```

Never enable body logging for WebAuthn credentials, cookies, JWTs, bootstrap tokens or backup secrets.

RustyAuth marks four headers sensitive before its own tracing layer sees them, so their values never reach the
structured log:

| Header              | Direction | Carries                                           |
| ------------------- | --------- | ------------------------------------------------- |
| `Authorization`     | Request   | RPC bearer credentials and service-account tokens |
| `Cookie`            | Request   | The operator and end-user session bearer          |
| `x-bootstrap-token` | Request   | The enrolment and event-polling credential        |
| `Set-Cookie`        | Response  | A newly issued session bearer                     |

That covers RustyAuth's own logs only. It has no effect on anything upstream or downstream of the process, so
operators must still redact the same four headers in:

- reverse proxy, ingress and load-balancer access logs;
- platform request logs and any HTTP tracing or APM collector;
- log shippers and aggregation search indexes; and
- support bundles, `curl -v` transcripts and browser HAR captures attached to tickets.

A HAR file from an authenticated dashboard session contains a live session cookie. Treat one as a credential
until the session's absolute lifetime has passed.

Monitor at least:

- process restarts;
- liveness and readiness separately;
- SableDB volume usage and persistence;
- authentication failure rate without storing credential payloads;
- signing-key maintenance failures and `keys status`;
- `operator.created` and `operator.promoted` events, and the output of `operator list`;
- backup freshness and failure count from `rustyauth doctor`; it exits non-zero while alerting, so this
  host-side or scheduled check must page the operator independently of log collection;
- `backup_health_alert=true`, Object Lock retention and SSE-KMS posture as supporting telemetry;
- a monthly clean-room restore job whose non-zero exit pages the operator; and
- event-consumer cursor lag.

## Clean-room recovery

The authoritative step-by-step procedure, including prerequisites, failure handling and drill evidence, is in
[Backups and disaster recovery](BACKUPS.md#clean-room-restore). The condensed commands below are retained for
incident use.

Restore never overwrites a live namespace. Provision a new, empty SableDB volume and run the same RustyAuth
release with the original tenant ID, active master key plus any required previous master keys, and active
backup key plus any required previous backup keys:

```sh
rustyauth backup list
rustyauth backup verify <object-key>
rustyauth backup restore <object-key>
rustyauth doctor
```

The restore command validates the authenticated envelope, tenant, manifest, signing keyset, index references
and event continuity before writing. It invalidates all snapshotted sessions by default, activates a new
signing key, appends `recovery.restored`, and clears its in-progress marker only when the full operation
succeeds. If interrupted, normal service startup fails closed until the empty target is recreated and the
restore is retried.

`--preserve-sessions` exists for an explicitly reviewed incident response. Omitting it is the safe default and
the recommended procedure. After recovery, validate discovery/JWKS, enrol a synthetic account, sign in with a
real authenticator and preserve the command receipts with the incident log.

## One-click template status

The public
[RustyAuth Railway template](https://railway.com/new/template/rustyauth?utm_medium=integration&utm_source=button&utm_campaign=rustyauth)
is available for `1.0.0` deployments. Its clean-room deployment and storage-survival checks pass:
all three services become healthy, generated secrets are applied, the private SableDB reference resolves, and
signing state survives SableDB container replacement.

Do not treat template availability or backup configuration alone as production readiness. Schedule and retain
evidence from clean-room drills appropriate to the deployment's recovery objective.
