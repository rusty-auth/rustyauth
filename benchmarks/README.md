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

The highest ladder step that satisfies every latency, failure, dropped-iteration, readiness, restart and
resource gate is the measured sustainable rate. Published active-user estimates use only 70% of that rate,
retaining 30% headroom:

```text
supported active users = sustainable authenticated RPS × 60 × 0.70
                         ÷ requests per user per minute
```

## Isolation and safety

`rustyauth-benchmark` is compiled only with the `benchmark-tools` Cargo feature. Its data-mutating command
refuses to run unless `BENCHMARK_PROJECT_ID` is the dedicated project ID. Fixture private keys and session
tokens remain on the benchmark runner volume and are never committed, logged or added to a report.

Preparation verifies every synthetic WebAuthn registration locally, then persists accounts, lookup indexes,
sessions and gap-free auth events in bounded atomic batches of 25. This keeps the generated realm identical to
the production storage contract without turning 10,000-account preparation into tens of thousands of separate
durability barriers. Seeding refuses to run when identity/event records or an active writer lease are present,
and verifies the final account/session cardinalities before the fixture set can be used by k6.

Each run renews only the synthetic sessions' idle and absolute boundaries before preflight, then validates the
first and last fixtures through the production session model. This preserves the expensive account and passkey
dataset between monthly runs without accepting expired session keys as valid workload fixtures. The runner's
`BENCHMARK_SESSION_IDLE_SECONDS` must exactly match the realm's `AUTH_SESSION_IDLE_SECONDS`. If an earlier
preflight caused the API to delete an idle-expired synthetic session, the runner reconstructs only that
deterministic session from its persisted account and single registered passkey and records the repair count.

The runner image is built from `Dockerfile.benchmark`, stays private, has no public domain and connects to
SableDB through Railway private networking. k6 alone calls the public target domain so gateway latency is
included. Raw run evidence is downloaded, sanitised, checksummed and reviewed before the catalogue is changed.

## Reproduction

Inside the private runner:

```sh
rustyauth-benchmark seed
RUN_ID=starter-YYYYMMDDTHHMMSSZ /opt/rustyauth/benchmarks/run-starter-baseline.sh
```

Resetting an interrupted synthetic preparation is a separate, fail-closed action. It requires both the exact
benchmark Railway project ID and `BENCHMARK_RESET_CONFIRM=reset-synthetic-benchmark-data`; the command deletes
keys in bounded batches and succeeds only after the isolated database reports zero remaining keys.

The runner writes one directory under `/data/runs/<run-id>` containing dataset cardinalities, each k6 summary,
human-readable k6 output, exit codes and `SHA256SUMS`. Railway CPU, memory, HTTP, network, volume and
deployment evidence is collected for the same UTC interval by benchmark control before a candidate report is
generated.
