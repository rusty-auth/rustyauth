# Fleet quick start

Fleet is a separate management plane for isolated RustyAuth deployments. It provides one Dioxus dashboard for
organizations, projects and environments while every managed realm keeps its own backend, SableDB, users,
keys, sessions and recovery boundary.

Fleet management and Fleet Analytics V1 are supported in the `1.0.0` server/container/web GA scope. This local
flow uses generated development credentials and is not a production topology.

## Start the central project

Requirements are the same as the [standalone quick start](QUICKSTART.md): Docker Compose v2, Git, OpenSSL,
`curl` and a WebAuthn-capable browser.

```sh
git clone https://github.com/rusty-auth/rustyauth.git
cd rustyauth
scripts/local-stack fleet up
```

The launcher generates ignored local secrets and configuration, then starts:

```text
http://localhost:5196
        │
        ▼
Dioxus Fleet dashboard ──private──> Fleet control-plane API ──private──> Fleet SableDB
```

If port `5196` is occupied, set `FLEET_DASHBOARD_PORT` before starting.

## Verify

Open <http://localhost:5196>. Use the first-run passkey flow for the local operator, or add `?preview=1` to
inspect the populated product surface without relying on live realm data.

The central datastore owns:

- organizations, projects and environments;
- realm registrations and immutable realm identity;
- scoped operator role bindings;
- encrypted realm management credentials;
- central audit and bounded health/analytics projections; and
- its own signing and recovery state.

It does not own identities, passkeys, sessions or signing keys from managed realms.

## Start a realm to manage

In another checkout or with non-conflicting ports, run the standalone topology:

```sh
STANDALONE_DASHBOARD_PORT=8082 scripts/local-stack standalone up
```

In a deployed environment, the realm can live in a different Railway project, provider, region or cloud. Fleet
needs a narrowly scoped realm management endpoint, not a SableDB URL.

## Pair the realm

The product flow is:

1. create or select an organization;
2. create a project for the application;
3. create an environment such as development, staging or production;
4. ask the realm to issue a short-lived, single-use pairing token;
5. enter the realm management endpoint and token in Fleet;
6. allow Fleet to validate TLS, capabilities and immutable realm identity;
7. confirm the new realm, credential scope and durable audit receipt.

New pairings include the `telemetry.export` scope and assignment epoch. The realm then projects closed
five-minute aggregates, retains at most 288 snapshots (24 hours) in its own SableDB and initiates the native
gRPC telemetry stream to Fleet. Fleet stores a trusted hierarchy-stamped acceptance record before returning an
exact-revision acknowledgement. No user, identifier, credential, session or token value crosses this path.

This completes reliable realm export. When private Analytics storage is configured and organization policy is
explicitly enabled, Dioxus uses the delegated realm/environment/project/organization/Fleet AnalyticsService,
including coverage, sibling comparison and bounded failure contribution. New organizations default disabled.

Never paste a realm SableDB connection string into the dashboard. Fleet communicates with the realm's
authorized management API. Direct database access would bypass realm policy and collapse the isolation
boundary.

## Test isolation

For each paired realm, verify:

- an operator cannot see a project or environment outside their assigned scope;
- losing Fleet does not stop realm passkey sign-in or local JWT verification;
- losing one realm does not make another realm unavailable;
- revoking a pairing credential stops central management without deleting realm state; and
- Fleet backup and realm backup restore independently.

## Stop without deleting state

```sh
scripts/local-stack fleet down
```

Pass `--volumes` only to intentionally erase the local Fleet datastore.

## Deployment model

Deploy the central project as three independently scalable services: Dioxus Fleet dashboard, Fleet
control-plane API and private Fleet SableDB. Give the central datastore its own durable volume, encrypted
backup policy and clean-room restore drill. Each managed environment is a separate realm deployment with the
same responsibilities.

Continue with [Fleet control-plane architecture](FLEET_CONTROL_PLANE.md),
[Railway topology](RAILWAY_TEMPLATE.md), [Fleet Analytics](FLEET_ANALYTICS.md) and
[Security hardening](SECURITY_HARDENING.md).
