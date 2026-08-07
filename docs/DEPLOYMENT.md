# Deploying RustyAuth

RustyAuth ships as two containers:

- a public Rust/Axum authentication service; and
- a private, persistent SableDB service.

An optional S3-compatible bucket enables scheduled encrypted logical backups and clean-room restore.

## Local Docker Compose

From this directory:

```sh
cp .env.example .env
docker compose up --build
```

The Compose topology publishes only `127.0.0.1:8081` for RustyAuth. SableDB joins an internal Docker
network and has no host port. Its named volume is `sabledb_data`.

Check both probes:

```sh
curl --fail http://127.0.0.1:8081/healthz
curl --fail http://127.0.0.1:8081/readyz
```

`/healthz` proves that the process can answer HTTP. `/readyz` additionally requires a SableDB
`PONG`. Route traffic based on readiness; use liveness for process restart decisions.

### Lifecycle commands

```sh
docker compose logs -f auth sabledb
docker compose down
docker compose up --build -d
```

`docker compose down --volumes` permanently deletes local identity state. Do not include `--volumes`
in routine restart or upgrade automation.

## Railway topology

Create three resources in one project and preferred region:

| Resource | Exposure | Persistent resource |
| --- | --- | --- |
| RustyAuth | Public HTTPS, container port `8080` | None |
| SableDB | Railway private network only, port `6379` | Volume at `/var/lib/sabledb` |
| AuthBackups | Private credentials only | S3-compatible bucket |

The bucket remains optional, but any deployment claiming recovery must configure it and complete a
restore drill.

### RustyAuth service

Use the repository root as the source root and `Dockerfile` as the builder. Set:

- healthcheck path `/healthz`;
- public port `8080`;
- all production variables in [Configuration](CONFIGURATION.md); and
- `SABLEDB_URL` through a Railway private-domain resource reference.

Readiness should also be monitored separately at `/readyz`. A liveness-only deploy can be running
while unable to authenticate users.

### SableDB service

Use `sabledb` as its source root. The Docker build checks out the immutable
SableDB revision declared by `SABLEDB_REVISION`, currently
`8bebc4a60dee404e95608b40ec5c58799e7fa820`.

Requirements:

- no public domain;
- no TCP proxy;
- private port `6379` only;
- persistent volume at `/var/lib/sabledb`; and
- health check before RustyAuth receives traffic.

Railway private networking and RustyAuth's exclusive reachability are the access-control boundary;
SableDB itself is not being presented as the public authentication layer.

### Backup bucket

Inject bucket credentials into RustyAuth through Railway resource references. Do not expose them to
the relying-party browser. Use a backup encryption key generated and escrowed outside Railway and
outside the bucket provider account.

RustyAuth creates a backup immediately after startup and at `AUTH_BACKUP_INTERVAL_SECONDS`. Each
object contains durable users, identifiers, passkeys, sessions, signing state and ordered events;
short-lived WebAuthn ceremonies and agent handoffs are deliberately excluded. Upload succeeds only
after a read-after-write decrypt and manifest check.

Use the binary inside the deployed container for operator checks:

```sh
passkey-auth-service doctor
passkey-auth-service backup create
passkey-auth-service backup list
passkey-auth-service backup verify <object-key>
```

## Container properties

The RustyAuth runtime image:

- contains the release binary and CA certificates only;
- runs as non-root UID/GID `10001`;
- has no shell-owned writable application directory;
- exposes port `8080`; and
- includes project and third-party licence notices.

The SableDB image runs as non-root UID/GID `10002` and stores data under `/var/lib/sabledb`.

## TLS and proxying

RustyAuth expects the deployment platform to terminate TLS. `AUTH_ISSUER` and
`WEBAUTHN_RP_ORIGIN` must describe the public HTTPS origins, not internal container URLs. Do not
rewrite browser `Origin` headers to bypass exact-origin enforcement.

Preserve `Set-Cookie`, `Origin`, `Content-Type` and request IDs through any proxy. Do not cache token,
credential or session responses.

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

Run one RustyAuth writer replica in version `0.1.0`. Multi-key operations use SableDB atomic
pipelines, but compound mutations are additionally protected only by a process-local mutex.
Cross-replica registration and credential mutation have not been qualified.

## Observability

RustyAuth writes structured JSON logs and propagates or creates `x-request-id`. The default filter is:

```text
passkey_auth_service=info,tower_http=info
```

Never enable body logging for WebAuthn credentials, cookies, JWTs, bootstrap tokens or backup
secrets. The application marks the RPC `Authorization` request header as sensitive; operational tooling
must also redact `Cookie`, `Set-Cookie` and `x-bootstrap-token`.

Monitor at least:

- process restarts;
- liveness and readiness separately;
- SableDB volume usage and persistence;
- authentication failure rate without storing credential payloads;
- signing-key maintenance failures and `keys status`;
- `last_backup_at` and `backup_healthy` from `/.well-known/passkey-auth`;
- backup scheduler errors and bucket retention; and
- event-consumer cursor lag.

## Clean-room recovery

Restore never overwrites a live namespace. Provision a new, empty SableDB volume and run the same
RustyAuth release with the original tenant ID, active master key plus any required previous master
keys, and active backup key plus any required previous backup keys:

```sh
passkey-auth-service backup list
passkey-auth-service backup verify <object-key>
passkey-auth-service backup restore <object-key>
passkey-auth-service doctor
```

The restore command validates the authenticated envelope, tenant, manifest, signing keyset, index
references and event continuity before writing. It invalidates all snapshotted sessions by default,
activates a new signing key, appends `recovery.restored`, and clears its in-progress marker only when
the full operation succeeds. If interrupted, normal service startup fails closed until the empty
target is recreated and the restore is retried.

`--preserve-sessions` exists for an explicitly reviewed incident response. Omitting it is the safe
default and the recommended procedure. After recovery, validate discovery/JWKS, enrol a synthetic
account, sign in with a real authenticator and preserve the command receipts with the incident log.

## One-click template status

The public
[RustyAuth Railway template](https://railway.com/new/template/rustyauth?utm_medium=integration&utm_source=button&utm_campaign=rustyauth)
is available for evaluation and integration work. Its clean-room deployment and storage-survival
checks pass: both services become healthy, generated secrets are applied, the private SableDB
reference resolves, and signing state survives SableDB container replacement.

Do not treat template availability or backup configuration alone as production readiness. Schedule
and retain evidence from clean-room drills appropriate to the deployment's recovery objective.
