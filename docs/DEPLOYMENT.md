# Deploying RustyAuth

RustyAuth ships as two containers:

- a public Rust/Axum authentication service; and
- a private, persistent SableDB service.

An optional S3-compatible bucket enables scheduled encrypted logical backups and clean-room restore.

## Local Docker Compose

From this directory:

```sh
cp .env.example .env
# The secrets in .env.example are intentionally blank; generate real ones.
printf 'AUTH_MASTER_KEY_HEX=%s\n'     "$(openssl rand -hex 32)"    >> .env
printf 'BOOTSTRAP_TOKEN=%s\n'         "$(openssl rand -base64 48)" >> .env
printf 'AUTH_EVENT_RPC_TOKEN=%s\n'    "$(openssl rand -base64 48)" >> .env
printf 'AUTH_IDENTITY_RPC_TOKEN=%s\n' "$(openssl rand -base64 48)" >> .env
docker compose up --build
```

No secret ships with a value. `.env.example` leaves every one blank and `compose.yaml` refuses to
substitute a default, so an unpopulated `.env` stops the stack with a named missing variable rather than
starting on something an attacker could read in the repository. A committed default is a published default,
and the entropy check in `config.rs` cannot tell a generated key from one that has been published — so
generating is the only path, including locally.

The Compose topology publishes only `127.0.0.1:8081` for RustyAuth. SableDB joins an internal Docker network
and has no host port. Its named volume is `sabledb_data`. The same Rust container serves the built operator
dashboard at `http://localhost:8081`; `?preview=1` opens realistic local preview data.

Check both probes:

```sh
curl --fail http://127.0.0.1:8081/healthz
curl --fail http://127.0.0.1:8081/readyz
```

`/healthz` proves that the process can answer HTTP. `/readyz` additionally requires a SableDB `PONG`. Route
traffic based on readiness; use liveness for process restart decisions.

### Lifecycle commands

```sh
docker compose logs -f auth sabledb
docker compose down
docker compose up --build -d
```

`docker compose down --volumes` permanently deletes local identity state. Do not include `--volumes` in
routine restart or upgrade automation.

## Railway topology

Create three resources in one project and preferred region:

| Resource    | Exposure                                  | Persistent resource          |
| ----------- | ----------------------------------------- | ---------------------------- |
| RustyAuth   | Public HTTPS, container port `8080`       | None                         |
| SableDB     | Railway private network only, port `6379` | Volume at `/var/lib/sabledb` |
| AuthBackups | Private credentials only                  | S3-compatible bucket         |

The bucket remains optional, but any deployment claiming recovery must configure it and complete a restore
drill.

### RustyAuth service

Use the repository root as the source root and `Dockerfile` as the builder. Set:

- healthcheck path `/healthz`;
- public port `8080`;
- all production variables in [Configuration](CONFIGURATION.md); and
- `SABLEDB_URL` through a Railway private-domain resource reference.

`AUTH_ENV` has no default. A deployment that omits it fails to start rather than falling back to development
settings, which would drop `Secure` from the session cookie, accept an HTTP relying-party origin and treat
self-service identifiers as verified. Set `AUTH_ENV=production`.

The container serves the dashboard and RPC APIs from the same public origin. Configure `WEBAUTHN_RP_ORIGIN` to
that Railway HTTPS origin, set `WEBAUTHN_RP_ID` to its exact hostname and set `AUTH_OPERATOR_EMAILS` before
the first operator signs in.

Readiness should also be monitored separately at `/readyz`. A liveness-only deploy can be running while unable
to authenticate users.

### First operator

`AUTH_OPERATOR_EMAILS` is no longer sufficient to become an operator. Browser bootstrap requires the account
to hold a **verified** email identifier from that list, and production never marks a self-service identifier
verified — so on a fresh deployment nothing can verify one, because verifying an identifier is itself an
operator action. Create the first Owner from a shell on the deployed container:

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

Roles are `owner`, `administrator`, `support` and `auditor`. The account must already exist — enrol it
through the normal bootstrap-token registration flow first.

This deliberately costs shell access to the deployment rather than control of an inbox. Treat the ability to
run `operator promote` as equivalent to Owner: anyone who can execute in the container can grant themselves
the control plane. Restrict container exec the way you restrict the master key.

`operator demote <user-id>` removes a grant. Removing an address from `AUTH_OPERATOR_EMAILS` does **not**
revoke an existing operator — a stored record is honoured before the allowlist is consulted — so demotion is
the only way to withdraw one. Include it in your offboarding runbook.

`operator list` prints every stored operator with role, primary email and last authentication time. Review it
after any promotion and as part of routine access review.

### SableDB service

Use `sabledb` as its source root. The Docker build checks out the immutable SableDB revision declared by
`SABLEDB_REVISION`, currently `8bebc4a60dee404e95608b40ec5c58799e7fa820`.

Requirements:

- no public domain;
- no TCP proxy;
- private port `6379` only;
- persistent volume at `/var/lib/sabledb`; and
- health check before RustyAuth receives traffic.

Railway private networking and RustyAuth's exclusive reachability are the access-control boundary; SableDB
itself is not being presented as the public authentication layer.

### Backup bucket

Inject bucket credentials into RustyAuth through Railway resource references. Do not expose them to the
relying-party browser. Use a backup encryption key generated and escrowed outside Railway and outside the
bucket provider account.

RustyAuth creates a backup immediately after startup and at `AUTH_BACKUP_INTERVAL_SECONDS`. Each object
contains durable users, identifiers, passkeys, sessions, signing state, organization, operators, service
accounts, credential locators and ordered events; short-lived WebAuthn ceremonies and agent handoffs are
deliberately excluded. Upload succeeds only after a read-after-write decrypt and manifest check.

Use the binary inside the deployed container for operator checks:

```sh
rustyauth doctor
rustyauth backup create
rustyauth backup list
rustyauth backup verify <object-key>
rustyauth operator list
rustyauth operator find <email>
rustyauth operator promote <user-id> <owner|administrator|support|auditor>
rustyauth operator demote <user-id>
```

## Container properties

The RustyAuth runtime image:

- contains the release binary and CA certificates only;
- contains the compiled SolidJS dashboard under `/usr/share/rustyauth/dashboard`;
- runs as non-root UID/GID `10001`;
- has no shell-owned writable application directory;
- exposes port `8080`; and
- includes project and third-party licence notices.

The SableDB image runs as non-root UID/GID `10002` and stores data under `/var/lib/sabledb`.

## TLS and proxying

RustyAuth expects the deployment platform to terminate TLS. `AUTH_ISSUER` and `WEBAUTHN_RP_ORIGIN` must
describe the public HTTPS origins, not internal container URLs. Do not rewrite browser `Origin` headers to
bypass exact-origin enforcement.

Preserve `Set-Cookie`, `Origin`, `Content-Type` and request IDs through any proxy. Do not cache token,
credential or session responses.

### Response headers

RustyAuth sets these on every response it serves, including dashboard assets. Each is applied only when the
header is absent, so a proxy that already sets one wins:

| Header | Value | Applies |
| --- | --- | --- |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'` | Always |
| `X-Frame-Options` | `DENY` | Always |
| `Cross-Origin-Opener-Policy` | `same-origin` | Always |
| `Cross-Origin-Resource-Policy` | `same-origin` | Always |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=(), payment=()` | Always |
| `X-Content-Type-Options` | `nosniff` | Always |
| `Referrer-Policy` | `no-referrer` | Always |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Production only |

HSTS is withheld outside production on purpose. Emitting it from a `http://localhost` development origin
pins the browser to HTTPS for that host for two years, well past the session that caused it.

Do not add a proxy-level CSP that loosens these directives to make a third-party script, analytics tag or
embedded frame work on the dashboard. The dashboard loads no third-party code; the policy is strict so an
injected script has nowhere to execute and nowhere to send what it reads.

If you front RustyAuth with a proxy that strips unknown response headers, allowlist the table above.

### Request limits

| Limit | Value | Behaviour |
| --- | --- | --- |
| Request timeout | 30 seconds | Returns `408`. Bounds slow-body clients, which the size limits alone cannot |
| Request body | 256 KiB | Returns `413`. Applies to the REST handlers |
| RPC request body | 64 KiB | Applies to Connect, gRPC and gRPC-Web methods |
| Shutdown grace | 20 seconds | Background signing and backup workers get this long to finish after a shutdown signal, then the process exits regardless |

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

Run one RustyAuth writer replica in version `0.1.0`. Multi-key operations use SableDB atomic pipelines, but
compound mutations are additionally protected only by a process-local mutex. Cross-replica registration and
credential mutation have not been qualified.

`railway.json` pins `numReplicas: 1` and `overlapSeconds: 0` so a scale-up or a rolling deploy cannot
silently start a second writer. This narrows the window rather than removing it: `drainingSeconds`
(25) is the time the outgoing process has between `SIGTERM` and `SIGKILL`, and for that period the old
process is still finishing in-flight requests while the new one is live. It stops accepting new work at
`SIGTERM`, so the overlap covers requests already in progress, not new mutations — but it is not zero.
Treat a deploy as a short window in which the single-writer invariant is weakest, and avoid deploying
during a bulk migration.

Raising `numReplicas` above 1 is not supported in this version. Nothing in the process detects a second
writer; the event-sequence counter is read-then-written without a compare-and-set, so a concurrent
writer silently overwrites audit events.

## Observability

RustyAuth writes structured JSON logs and propagates or creates `x-request-id`. The default filter is:

```text
rustyauth=info,tower_http=info
```

Never enable body logging for WebAuthn credentials, cookies, JWTs, bootstrap tokens or backup secrets.

RustyAuth marks four headers sensitive before its own tracing layer sees them, so their values never reach
the structured log:

| Header | Direction | Carries |
| --- | --- | --- |
| `Authorization` | Request | RPC bearer credentials and service-account tokens |
| `Cookie` | Request | The operator and end-user session bearer |
| `x-bootstrap-token` | Request | The enrolment and event-polling credential |
| `Set-Cookie` | Response | A newly issued session bearer |

That covers RustyAuth's own logs only. It has no effect on anything upstream or downstream of the process,
so operators must still redact the same four headers in:

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
- backup freshness and failure count from `rustyauth doctor` (the public metadata endpoint no longer
  reports them, so this check must run on the host or in a scheduled job);
- backup scheduler errors and bucket retention; and
- event-consumer cursor lag.

## Clean-room recovery

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
is available for evaluation and integration work. Its clean-room deployment and storage-survival checks pass:
both services become healthy, generated secrets are applied, the private SableDB reference resolves, and
signing state survives SableDB container replacement.

Do not treat template availability or backup configuration alone as production readiness. Schedule and retain
evidence from clean-room drills appropriate to the deployment's recovery objective.
