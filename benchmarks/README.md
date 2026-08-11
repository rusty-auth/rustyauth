# RustyAuth benchmark control

This directory contains the reproducible workloads for the separate **RustyAuth Benchmarks** Railway project.
Nothing here is referenced by `railway.template.json`; customer and demo deployments receive only the
supported dashboard, API, SableDB and backup resources.

## Starter baseline

The first single-realm baseline uses:

- one RustyAuth API replica capped at 1 vCPU and 500 MB;
- one SableDB replica capped at 1 vCPU and 1 GB;
- 10,000 cryptographically valid synthetic passkey accounts and 10,000 valid sessions;
- an external k6 runner calling the API's public Railway domain;
- authenticated-read steps at 25, 50, 100, 200, 400 and 800 arrivals per second; and
- 30 complete passkey sign-ins over five minutes.

The passkey rate deliberately stays below the production policy of ten identifier probes per source address
per minute. Benchmarking must not weaken or bypass the shipped brute-force controls. The authenticated-read
ladder measures the scalable signed-in workload; passkey sign-in records end-to-end user latency separately.
`run-passkey-companion.sh` repeats only the passkey workload when capacity and soak traffic are already in
progress. Synthetic authenticator counters advance monotonically between retained runs, so the harness never
asks the server to accept a replayed credential counter.

The highest ladder step that satisfies every latency, failure, dropped-iteration, readiness, restart and
resource gate is the measured sustainable rate. The full-product operating rate is the lower of 70% of that
rate and the highest background rate at which the passkey companion also clears its ceremony gates. Published
active-user estimates use that operating rate:

```text
operating RPS = min(sustainable authenticated RPS × 0.70,
                    passkey-qualified background RPS)
supported active users = operating RPS × 60
                         ÷ requests per user per minute
```

## Enterprise product journey

`run-enterprise-profile.sh` adds a high-traffic product workload after the simple capacity floor is known. It
supports a named-phase exploratory ladder for locating the likely boundary, then exact fixed-rate windows for
the passing and first-failing targets. This prevents an exploratory generator limit or nearby phase from
contaminating the reviewed boundary. Its deterministic traffic mix is 60% session-backed account reads, 20%
user-token minting, 15% passkey inventory reads and 5% signing-key discovery.

The runner authenticates a separate timing header with the realm's benchmark-only secret. RustyAuth then emits
a standard `Server-Timing` response only for that authorized request. Every Redis command and pipeline issued
by the API is measured below the store abstraction, allowing the run to split:

- total public runner-to-Railway response time;
- external edge, transport and runner overhead (`end-to-end - app`);
- API application time;
- accumulated API-to-SableDB round-trip time and round-trip count; and
- non-datastore application work (`app - SableDB`).

Ordinary callers receive no internal timing header. The installable Railway template does not contain the
runner, fixture keys or benchmark secret.

Enterprise qualification uses explicit fixed-rate targets to bracket the first strict latency or reliability
failure. A separate one-hour soak then runs at 70% of the highest passing target. A short breakpoint run is
never promoted as a soak result, and a higher read-only result is never presented as mixed-journey capacity.

The retained 11 August 2026 enterprise run demonstrates why this gate is fail-closed. Its exact two-minute
2,400 RPS boundary passed and its exact 3,200 RPS run was the first tested failure, but the 1,680 RPS soak was
stopped after 37 minutes 40.7 seconds and never reached recovery. The 1,680 RPS figure is therefore a candidate
headroom calculation, not a published operating rate. Raw final-run artifacts, partial Railway telemetry and
the resource wind-down record are retained under
`release-evidence/benchmarks/enterprise-20260811T132328Z/`.

The isolated Railway project is intentionally dormant: all five services have zero running replicas, every
benchmark volume is pending deletion and the runner's GitHub source is disconnected so a push to `main` cannot
wake it. A future run requires explicit owner authorization, a fresh runner source connection, fresh volumes
and reseeding; there is no always-on or scheduled Railway benchmark workload.

Methodology v2 requires less than 0.1% unexpected failures, zero unplanned 5xx responses, end-to-end latency
below 300 ms p95 / 750 ms p99, API application latency below 150 ms p95 / 400 ms p99 and accumulated
API-to-SableDB latency below 150 ms p95 / 250 ms p99. An initial 100 ms SableDB p95 candidate gate was
withdrawn before qualification, not relaxed after a passing publication: exact 100 and 350 RPS trials both
reported a roughly 140–145 ms tail while their SableDB medians remained below 1 ms. That non-monotonic fixed
tail did not identify capacity. The raw failed trials remain in the reviewed evidence, and the independent
application, end-to-end, p99, failure and dropped-iteration gates remain binding.

## Realm-cell extrapolation

A realm is an independent capacity cell. If a pinned shape has a full-product operating rate of `O` requests
per second, `N` identically sized, independently sharded realms provide an initial planning model of `N × O`.
Capacity is additive: one-to-two realms doubles the total; adding a third to two increases it by 50%.

This arithmetic is labelled **extrapolated**, not measured. It assumes balanced routing, comparable datasets
and no shared Fleet, network or regional bottleneck. Facebook-scale claims require separate multi-realm,
Fleet-cardinality, global-routing and failure-domain tests; a large multiplication of one-realm results is not
that proof.

## Isolation and safety

`rustyauth-benchmark` is compiled only with the `benchmark-tools` Cargo feature. Its data-mutating command
refuses to run unless `BENCHMARK_PROJECT_ID` is the dedicated project ID. Fixture private keys and session
tokens remain on the benchmark runner volume and are never committed, logged or added to a report.

Preparation verifies every synthetic WebAuthn registration locally, then persists accounts, lookup indexes,
sessions and gap-free auth events in bounded atomic batches of 25. This keeps the generated realm identical to
the production storage contract without turning 10,000-account preparation into tens of thousands of separate
durability barriers. Seeding refuses to run when identity/event records or an active writer lease are present,
and verifies the final account/session cardinalities before the fixture set can be used by k6.

Each reviewed run rewrites every deterministic session with a fresh absolute TTL, removes its separate
deferred-activity key and validates the first and last fixtures through the production session model. The
refresher staggers `last_seen_at` across the production touch interval minus the unmeasured settle window. For
the retained 30-minute idle policy, that means a 300-second touch interval, a 60-second settle and a
240-second distribution: sessions become due gradually after measurement begins instead of all producing a
write at the same instant. This preserves the expensive account and passkey dataset between monthly runs
without hiding the durable write load of a genuinely active population.

A future-dated or malformed activity record fails closed instead of extending a fixture session. The refresher
prunes only superseded sessions owned by deterministic benchmark accounts. The runner's
`BENCHMARK_SESSION_IDLE_SECONDS` must exactly match the realm's `AUTH_SESSION_IDLE_SECONDS`. If an earlier
preflight caused the API to delete an idle-expired synthetic session, the runner reconstructs only that
deterministic session from its persisted account and single registered passkey and records the repair count.
The 60-second settle keeps the 10,000-session preparation burst outside the smoke gate and measured profile.
Adjacent exploratory steps may set `BENCHMARK_REFRESH_SESSIONS=false` to retain still-valid fixtures and skip
the settle window, but a reviewed boundary or soak may not use that shortcut.

The runner image is built from `Dockerfile.benchmark`, stays private, has no public domain and connects to
SableDB through Railway private networking. k6 alone calls the public target domain so gateway latency is
included. Raw run evidence is downloaded, sanitised, checksummed and reviewed before the catalogue is changed.

## Reproduction

Inside the private runner:

```sh
rustyauth-benchmark seed
RUN_ID=starter-YYYYMMDDTHHMMSSZ /opt/rustyauth/benchmarks/run-starter-baseline.sh
RUN_ID=passkey-YYYYMMDDTHHMMSSZ /opt/rustyauth/benchmarks/run-passkey-companion.sh
```

Resetting an interrupted synthetic preparation is a separate, fail-closed action. It requires both the exact
benchmark Railway project ID and `BENCHMARK_RESET_CONFIRM=reset-synthetic-benchmark-data`; the command deletes
keys in bounded batches and succeeds only after a fresh scan reports zero remaining RustyAuth-owned `auth:*`
keys. The receipt also records SableDB's total key count so datastore-internal accounting remains visible
without being mistaken for live realm data.

The runner writes one directory under `/data/runs/<run-id>` containing dataset cardinalities, each k6 summary,
human-readable k6 output, exit codes and `SHA256SUMS`. Railway CPU, memory, HTTP, network, volume and
deployment evidence is collected for the same UTC interval by benchmark control before a candidate report is
generated.

## Datastore path diagnosis

`diagnose-sable-path.sh` issues sequential direct SableDB reads for one deterministic session and account from
inside the private runner. It prints only combined microsecond durations; fixture tokens, derived keys and
values never leave the runner. Use it only when the public timing waterfall points to SableDB, and never while
a k6 process is active:

```sh
SABLEDB_DIAGNOSTIC_ITERATIONS=200 \
  /opt/rustyauth/benchmarks/diagnose-sable-path.sh > /data/runs/<run-id>/sable-direct-get-micros.txt
```

Supported SableDB images also expose cumulative command-execution, lock-acquisition and RocksDB I/O timing in
`INFO`. Capture deltas around the diagnostic window. The three layers distinguish datastore command or lock
queuing from storage-engine I/O without adding customer identifiers or enabling verbose request logs.

`inspect-sable-cursors.sh` prints only the numeric event-log boundary, local analytics cursor and their lag.
Run it before a qualification window so analytics replay from an earlier failed test cannot be mistaken for
steady-state datastore capacity.
