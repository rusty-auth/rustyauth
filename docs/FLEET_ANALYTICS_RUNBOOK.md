# Fleet Analytics operations and recovery runbook

**Applies to:** `rustyauth.analytics.v1`, pinned GreptimeDB 1.1.4 and V1 Zstandard Parquet.

**Last qualified:** 9 August 2026 (local pinned integration topology; production canary pending).

Fleet Analytics is optional. During any analytics incident, preserve realm authentication first. Disabling
organization export or removing the central Analytics configuration must not change issuer, RP ID, signing
keys, sessions, realm databases or the Fleet hierarchy.

## Service objectives

| Objective | Target | Measurement |
| --- | ---: | --- |
| Acknowledged closed-bucket durability | No acknowledged loss | Accepted revision ledger, Greptime mirror result and replay/recovery comparison. |
| Healthy central acceptance p95 | <= 2 minutes after send | Connector close/send timestamp to accepted ledger timestamp. |
| Healthy event-to-dashboard delay | <= one five-minute bucket plus close grace | Realm bucket start/closure to latest complete API window. |
| Medium 24-hour environment/project query p95 | <= 500 ms | `rustyauth.analytics.query` duration by scope class and range. |
| Medium 28-day organization query p95 | <= 2 seconds | Same trace event; qualification test enforces the ceiling. |
| Coverage truth | Exact registry snapshot | Expected/reporting/stale/disabled/unsupported counts returned with every result. |
| Realm authentication impact | No measurable added latency | Realm auth SLO comparison with exporter healthy, saturated, panicked and central services unavailable. |

The measured medium gate loaded 1,000 realms × 28 days (8,064,000 canonical rows) in 89.78 seconds. Twenty
hourly organization queries had a 239.5325 ms p95 on the pinned local standalone GreptimeDB topology. This is
qualification evidence for that artifact/topology, not a capacity promise for unrelated hardware.

## Required topology and controls

1. Configure GreptimeDB only on a private service network. Do not publish its SQL, dashboard or gRPC ports.
2. Set `AUTH_ANALYTICS_ENDPOINT`, `AUTH_ANALYTICS_DATABASE`, `AUTH_ANALYTICS_USERNAME` and
   `AUTH_ANALYTICS_PASSWORD` together from the secret manager. Use a credential dedicated to RustyAuth.
3. Keep Fleet SableDB and GreptimeDB in separate recovery plans. SableDB owns hierarchy, policy, accepted
   revisions, coverage and manifests; GreptimeDB owns canonical/derived numerical serving data.
4. Leave new organizations disabled until a reviewed canary explicitly enables Analytics.
5. Permit object import only from an approved HTTPS bucket origin using a presigned URL whose exact object and
   lifetime (maximum 15 minutes) match the signed manifest.
6. Route structured logs/traces to the deployment's approved monitoring system with authorization headers,
   URLs and query strings redacted.

Hourly and daily Flow names include the configured Analytics database, preventing test/environment collision.
Canonical rows retain at most 35 days; hourly and daily sinks are derived from canonical rows and policy-driven
purge reduces all three stores together.

## Monitoring and alerts

The `rustyauth.analytics.query` event contains only scope class, step, source, record count, coverage counts and
duration. It deliberately omits organization, project, environment, connection, realm and object identifiers.
Ingestion audit records contain trusted organization/connection UUIDs but never bucket payloads or credentials.

Create alerts for:

- query p95 above 500 ms for medium 24-hour environment/project views or 2 seconds for 28-day organizations
  over two consecutive five-minute windows;
- acceptance p95 above two minutes, any rejected/quarantined spike, or quota rejection sustained for 10
  minutes;
- an expected realm stale for three complete buckets, with disabled and unsupported realms excluded;
- any Greptime mirror failure before acknowledgement, Flow flush failure or manifest stuck pending beyond 15
  minutes;
- backup recovery-point objective risk, failed clean-room drill or missing pinned image/manifest evidence;
- attempted cross-organization scope comparison, assignment mismatch, manifest substitution, private/metadata
  object origin or unsupported schema version; and
- any measurable realm authentication latency/error change correlated with Analytics failure.

## Triage

1. Confirm realm authentication health independently. If degraded, disable the Analytics runtime/export path
   and treat authentication as the primary incident.
2. Determine the failed boundary: realm projection/outbox, connector, Fleet SableDB acceptance, Greptime mirror,
   Flow materialization, archive access or Analytics RPC.
3. Compare registry coverage with accepted-ledger freshness. Never convert unavailable sources to zero.
4. Preserve redacted audit records, request IDs, image digests, configuration hashes and the last known good
   backup/manifest set. Do not copy connector proofs, presigned URLs or database credentials into tickets.
5. Keep organization policy disabled if integrity or isolation is uncertain.

## Incident procedures

### GreptimeDB unavailable

- Do not acknowledge a new bucket whose accepted revision cannot be mirrored.
- Realms retain/retry the bounded outbox; authentication continues.
- Restore network/service health, verify credentials privately, initialize schemas/Flows, then replay pending
  connector batches. Compare accepted ledger and canonical results before clearing the incident.

### Fleet SableDB unavailable

- Reject/defer ingestion; GreptimeDB must not become the acceptance or authorization authority.
- Restore Fleet from its own encrypted backup. Validate hierarchy, policies, assignments, manifests and accepted
  revision records before replaying any realm or archive data.

### Stale or partial coverage

- Check capability, connection state, organization policy and the realm outbox in that order.
- A disabled/unsupported realm is not an outage. A stale expected realm remains visible as stale.
- Repair connector access or replay the outbox; do not insert synthetic zero buckets.

### Poisoning, schema or clock-skew quarantine

- Disable the affected organization policy or revoke the connection if compromise is suspected.
- Preserve the quarantine hash/reason and correlated local/central audit events.
- Verify realm identity, assignment epoch, clock and deployment version. Purge/re-pair only after the root cause
  is understood; never rewrite trusted hierarchy from the submitted payload.

### Archive/object failure

- Treat redirect, origin/path mismatch, excessive lifetime, missing/incorrect length, digest mismatch, wrong
  signature, schema mismatch, truncation and expired credentials as hard failures.
- Issue a new short-lived exact-object URL only after verifying the immutable signed manifest. Never persist or
  log the URL. A retry with the same manifest is idempotent; a changed object under the same manifest ID is a
  security incident.

### Suspected cross-organization disclosure

- Disable Analytics process-wide, preserve authorization/audit evidence and rotate Greptime/service credentials.
- Do not use GreptimeDB permissions as evidence that service-layer scope isolation held.
- Engage the security/privacy incident process and assess notification duties before re-enabling any tenant.

## Clean-room recovery

1. Provision empty Fleet SableDB and private GreptimeDB from pinned images/configuration. Keep Analytics policy
   disabled.
2. Restore Fleet SableDB from its independently retained encrypted backup and validate the hierarchy,
   assignments, policies, acceptance ledger, manifests and audits.
3. Initialize the canonical table and database-namespaced hourly/daily Flows.
4. Obtain only approved signed manifests and short-lived exact-object access. Verify signature, realm assignment,
   schema, digest, byte/row limits and time/sequence bounds before import.
5. Import manifests oldest-first while live connector ingestion continues. Revision fencing makes archive/live
   delivery converge without double-counting.
6. Flush materializations, then compare canonical, hourly and daily ratio-of-sums/histogram results with the
   retained fixture and acceptance ledger for the supported window.
7. Exercise organization, project, environment and realm queries plus a cross-organization negative query.
8. Record recovery duration, record counts, last complete window, image/database versions and discrepancies.
   Enable only the reviewed canary organization after all checks pass.

## Retention, disconnect and purge

An Analytics policy update enforces the requested 1–35 day boundary before persisting the new policy and writes
a redacted maintenance outcome. Revoking a Fleet connection purges that trusted organization/connection from
canonical, hourly and daily stores; a mismatched organization ID deletes nothing. Failed cleanup returns an
error after the revocation and is safe to retry with the same mutation request.

Organization-wide purge is an internal low-level primitive and must be invoked only through an authorized,
human-reasoned workflow that records a maintenance outcome. Immutable customer-owned archives are not deleted
by a central database purge; their owner applies the approved object-retention/deletion process.

## Qualification commands

Fast and full repository gates are documented in [Engineering](ENGINEERING.md). With the pinned integration
services running, execute ignored tests serially and include the explicit medium gate:

```sh
RUSTYAUTH_TEST_SOURCE_SABLEDB_URL=redis://127.0.0.1:16379 \
RUSTYAUTH_TEST_DESTINATION_SABLEDB_URL=redis://127.0.0.1:16380 \
RUSTYAUTH_TEST_S3_ENDPOINT=http://127.0.0.1:19000 \
RUSTYAUTH_TEST_S3_BUCKET=rustyauth-integration \
RUSTYAUTH_TEST_S3_ACCESS_KEY=rustyauth-test \
RUSTYAUTH_TEST_S3_SECRET_KEY=rustyauth-test-secret \
RUSTYAUTH_TEST_GREPTIME_URL=http://127.0.0.1:14000 \
cargo test --locked -- --ignored --nocapture --test-threads=1

RUSTYAUTH_TEST_GREPTIME_URL=http://127.0.0.1:14000 \
RUSTYAUTH_RUN_MEDIUM_ANALYTICS_QUALIFICATION=1 \
cargo test --locked \
  analytics_store::tests::medium_tier_organization_query_meets_the_two_second_p95_target \
  -- --ignored --nocapture --test-threads=1
```

Do not promote solely from local evidence. Production release also requires signed images/SBOM/provenance,
upgrade/downgrade and clean-room drills, an independent assessment, and a successful organization canary.
