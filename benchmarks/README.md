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

The runner image is built from `Dockerfile.benchmark`, stays private, has no public domain and connects to
SableDB through Railway private networking. k6 alone calls the public target domain so gateway latency is
included. Raw run evidence is downloaded, sanitised, checksummed and reviewed before the catalogue is changed.

## Reproduction

Inside the private runner:

```sh
rustyauth-benchmark seed
RUN_ID=starter-YYYYMMDDTHHMMSSZ /opt/rustyauth/benchmarks/run-starter-baseline.sh
```

The runner writes one directory under `/data/runs/<run-id>` containing dataset cardinalities, each k6 summary,
human-readable k6 output, exit codes and `SHA256SUMS`. Railway CPU, memory, HTTP, network, volume and
deployment evidence is collected for the same UTC interval by benchmark control before a candidate report is
generated.
