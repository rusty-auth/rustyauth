# Benchmarks and capacity evidence

RustyAuth publishes performance evidence from a dedicated synthetic Railway project. Benchmark infrastructure
is not a product dependency and is never added to `railway.template.json`, the Helm charts, Compose topology
or customer installations.

The public catalogue is [available on the marketing site](https://rustyauth.dev/benchmarks/) and as
[machine-readable JSON](https://rustyauth.dev/benchmarks/catalog.json). The Dioxus dashboard embeds the same
validated catalogue under **Operator menu → Release benchmarks**, allowing an administrator or developer to
inspect the evidence associated with the installed dashboard image without granting it access to benchmark
infrastructure.

## Isolation boundary

The maintained template and benchmark system have different responsibilities:

| Boundary                 | Contains                                                                                 | Must not contain                                                               |
| ------------------------ | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Installable template     | Dashboard, RustyAuth API, private SableDB and backup bucket                              | Load generators, synthetic identities, benchmark credentials or report storage |
| Benchmark target project | A clean installation of the public template using release-candidate image digests        | Production or customer data                                                    |
| Benchmark control        | Ephemeral load generators, seed tooling, Railway metric collection and evidence assembly | Customer installation credentials                                              |
| Public catalogue         | Sanitised aggregate results and immutable provenance                                     | Secrets, raw identity records, source addresses or unbounded logs              |

A release or monthly run creates or refreshes the benchmark target from the maintained public template.
Control automation then adds benchmark-only resources to that project after template installation. Those
additions are never synchronized back into the template. Load generation runs outside the target service
boundary so public gateway and regional latency remain measurable.

## Publication contract

`benchmarks/catalog.json` is the reviewed, Git-versioned publication source. `deno task benchmark:check`
validates it before either product surface builds. A passed single-realm capacity report is rejected unless it
contains all of the following:

- registered-account and valid-session dataset sizes;
- sustainable authenticated request and sign-in throughput;
- typical-active-user extrapolation and sign-in p95;
- a full-product operating rate, the first tested failing rate and the external/API/SableDB latency split for
  enterprise methodology reports;
- a machine-readable realm-cell model that permits exactly one measured realm and states its extrapolation
  assumptions;
- API, dashboard and SableDB immutable image digests;
- release commit, resource tier, environment, methodology version and observation time; and
- at least one retained HTTPS evidence location.

Failed and informational runs may be retained, but cannot satisfy a passed capacity claim. The marketing site
continues to say `awaiting-baseline` until the first complete run is reviewed; after publication it selects
the newest passed report by observation time.

Benchmark control is required to assemble a candidate report and retained evidence; a maintainer then opens
or updates the review pull request. Merging the reviewed catalogue update publishes the marketing page and
causes the next dashboard image to embed the same evidence. Benchmark infrastructure must never push an
unreviewed capacity claim directly to `main`.

Enterprise methodology v2 binds the mixed journey to less than 0.1% unexpected failures, zero unplanned 5xx
responses, 300 ms p95 / 750 ms p99 end-to-end latency, 150 ms p95 / 400 ms p99 API application latency and 150
ms p95 / 250 ms p99 accumulated API-to-SableDB latency. The initial 100 ms datastore p95 candidate was
withdrawn before qualification after exact 100 and 350 RPS runs produced the same approximately 140–145 ms
tail with sub-millisecond medians. Because it was non-monotonic, it could not identify load saturation. Those
failed candidate-gate runs remain in the evidence; the independent application, end-to-end, p99, reliability
and dropped-iteration gates still fail closed.

The maintained runner, synthetic fixture boundary and exact Starter ladder are documented in
[`benchmarks/README.md`](../benchmarks/README.md). The runner is a fourth service only in the dedicated
benchmark project; it is intentionally absent from the installable Railway template.

## User-capacity model

An idle authenticated session and an actively requesting user are different capacity dimensions. Reports
retain both. The operating rate is the lower of the 30%-reserved mixed-workload rate and the highest
background rate at which the passkey companion clears its full-ceremony latency gates:

```text
operating RPS = min(sustainable authenticated RPS × 0.70,
                    passkey-qualified background RPS)
supported active users = operating RPS × 60
                         ÷ requests per user per minute
```

The catalogue defines light, typical and heavy profiles. The headline single-realm figure uses the typical
profile; all three remain visible so an integrator can map the result to its own traffic. Sign-in throughput
is reported independently from session-backed API throughput.

## Realm-cell scaling model

Each supported realm is an independent deployment cell with its own API process, SableDB process and durable
data. If a qualified resource tier sustains `C` authenticated requests per second, `N` equally sized and
independently deployed realms have an initial planning envelope based on the published operating rate `O`:

```text
fleet qualified-workload envelope = N × O
```

`O` already includes the 30% throughput reserve and any stricter passkey-journey constraint. Adding an
equivalent realm therefore adds approximately one realm's qualified envelope; it does not make an existing
realm multi-writer and does not increase the capacity of shared ingress, Fleet routing, observability, backup
storage or a Railway region. Those shared layers require their own load tests and limits. Reports show both
the linear realm-cell projection and these unqualified shared boundaries so the projection cannot be presented
as evidence of arbitrary global or hyperscale operation.

## What “50,000 users” means

Four different numbers are often collapsed into one:

- **registered accounts** are durable records and determine dataset size, indexes, backup volume and recovery
  time;
- **valid sessions** are durable session records, including sessions that are currently idle;
- **monthly active users (MAU/MRU)** are billing or audience measures and say little about peak traffic by
  themselves; and
- **simultaneously active users** consume request capacity and must be translated through a disclosed activity
  model.

The current enterprise run contains 10,000 registered accounts and 10,000 valid sessions. It therefore does
not prove that a single realm stores 50,000 or 100,000 accounts with the same latency, backup duration or
recovery time. Those dataset sizes are the next qualification tiers.

For live traffic, divide peak request demand by a fully qualified full-product operating rate. At the typical
six-requests-per-minute profile, 50,000 users continuously active at once generate 5,000 RPS and 100,000
generate 10,000 RPS. The incomplete enterprise run's 1,680 RPS headroom calculation must not be used as a
support commitment. A product with 50,000 or 100,000 monthly users usually has a much smaller active fraction,
but the decision still requires a completed operating-rate soak, measured peak RPS and the separately
qualified stored-account tier—not the MAU headline.

## Public market context

The benchmark page links each row to first-party evidence and dates the comparison. It is intentionally not a
leaderboard:

- [Keycloak regularly tests 300 RPS with one million users](https://www.keycloak.org/high-availability/single-cluster/introduction)
  on a three-pod, multi-AZ Aurora reference topology, and documents much larger scale on far larger hardware.
  That is stronger large-dataset and HA evidence than the current RustyAuth run, but it is not the same
  workload or resource shape.
- [Rauthy publishes a 35–65 MB small-deployment footprint](https://github.com/sebadob/rauthy#fast-and-efficient)
  and describes million-user scale, but does not publish a directly comparable retained RPS/latency run. It is
  not defensible to rank either Rust implementation faster from those claims.
- [Clerk limits its production Backend API to 1,000 requests per 10 seconds](https://clerk.com/docs/guides/how-clerk-works/system-limits).
  Browser authentication and local session-token verification use different paths, so this is a service limit,
  not a matching benchmark.
- [Auth0 documents Private Cloud tiers from 100 to 10,000 RPS](https://auth0.com/docs/deploy-monitor/deploy-private-cloud/private-cloud-on-aws),
  while actual flow and endpoint limits vary by subscription. These are contracted rate envelopes without a
  matching public dataset, workload mix and latency trace.

The retained RustyAuth result is promising for its disclosed hardware: the mixed journey passed an exact
two-minute boundary at 2,400 RPS, and 3,200 RPS was the first tested failure. The planned 1,680 RPS soak was
stopped after 37 minutes 40.7 seconds, did not run recovery and recorded 548 ms Railway API-edge p95 in the
partial window. The honest conclusion is “competitive short-window throughput evidence on a small
single-writer dataset,” not a qualified production operating rate or “faster than every identity provider.”
Keycloak still has materially stronger million-account, multi-pod and availability evidence.

## Railway cost model

[Railway currently charges](https://docs.railway.com/pricing/plans) $20 per consumed vCPU-month, $10 per
consumed GB-month of memory, $0.15 per stored GB-month and $0.05 per GB of public egress. The Pro plan has a
$20 monthly minimum that counts toward resource usage. Private API-to-SableDB traffic does not incur public
egress.

The enterprise benchmark caps the API at 1 vCPU / 1 GB and SableDB at 4 vCPU / 4 GB. Caps are safety ceilings,
not the bill: Railway bills measured consumption. Permanently consuming both caps would cost about $150/month
before the lightweight dashboard, stored volume and public egress. The retained partial-window telemetry is
diagnostic only and does not publish a monthly production or egress estimate. An idle or ordinary-traffic
realm must not be priced from a configured-cap or incomplete saturated-run estimate.

The published v1 read-only baseline used a smaller 1 vCPU / 500 MB API and 1 vCPU / 1 GB SableDB. Full-time
consumption of those two ceilings is $55/month; it is a conservative cap envelope, not an observed average.
A lightly used Railway Pro realm can remain near the $20 plan minimum while a continuously busy realm moves
toward the report's observed-resource and public-egress run-rate.

The 1 GB API ceiling is also a recovery requirement for this dataset: a 535,229-record encrypted backup was
created and read-back verified on that tier, while the same pre-deploy operation was killed at the 500 MB
ceiling. Serving-path memory is much lower, but a supported large-realm shape must include enough headroom for
backup and recovery instead of sizing only for steady-state requests.

For purchasing context, [Clerk Pro includes 50,000 monthly retained users](https://clerk.com/pricing) for
$20/month billed annually ($25 monthly) and then publishes per-user overages; 100,000 fully retained users are
about $1,025/month before add-ons. [Auth0 includes 25,000 MAU on its free tier](https://auth0.com/pricing),
while paid feature/user tiers and enterprise capacity rise separately. Keycloak and Rauthy have no software
licence fee, but their infrastructure, upgrades, monitoring, incident response and compliance work still
belong in total cost. These are different billing units and service boundaries, so they must not be presented
as a raw “cost per user” ranking.

For a bounded self-hosting illustration, Keycloak's
[published sizing guidance](https://www.keycloak.org/high-availability/multi-cluster/concepts-memory-and-cpu-sizing)
starts at 1.25 GB of memory per pod and its availability architecture uses three pods. Illustrating those pods
at 1 vCPU each against Railway's full-consumption rates produces a $97.50/month application-only cap before
PostgreSQL/Aurora, storage, egress or operations. That is not an observed Keycloak Railway bill. Rauthy's
published 35–65 MB application footprint is smaller, but without a matching retained Railway run its actual
CPU, database and reliability cost cannot be ranked against RustyAuth. A future competitor harness should run
the same dataset, journey, region, availability target and evidence gates before publishing a cost/performance
leaderboard.

## Cadence

- Merges continue to run correctness and deployment probes, not load benchmarks.
- Every release runs a fixed-rate regression against a clean template installation.
- The monthly cadence is a manual operating target, not an always-on Railway job. The isolated benchmark
  project remains stopped and volume-free between authorized runs.
- Authentication, gateway, datastore or deployment changes may trigger a manual run.

Every report retains k6 latency/throughput output, Railway CPU/memory/network/volume series, deployment and
image identifiers, readiness/restart evidence, dataset cardinalities and the generated sanitised report.
Railway infrastructure metrics and application-level request metrics are collected separately and correlated
by run ID.

The 11 August 2026 wind-down disconnected the benchmark runner from GitHub, stopped all five services and
submitted every volume for deletion. Resuming requires explicit authorization, fresh storage and a fresh
synthetic seed; ordinary pushes and merges cannot restart benchmark compute.

## Current limitation

RustyAuth `1.0.0` supports one active writer. Published realm results therefore qualify explicit vertical
resource tiers. They must not be extrapolated to multiple API writers or described as horizontal scaling until
the multi-writer model has separate correctness and performance qualification.
