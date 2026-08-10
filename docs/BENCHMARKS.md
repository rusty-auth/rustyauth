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
- API, dashboard and SableDB immutable image digests;
- release commit, resource tier, environment, methodology version and observation time; and
- at least one retained HTTPS evidence location.

Failed and informational runs may be retained, but cannot satisfy a passed capacity claim. The catalogue
starts the Railway single-realm programme in `awaiting-baseline`; the marketing site must say so until the
first complete run is reviewed.

The benchmark runner is required to write a candidate report and open a pull request. Merging the reviewed
catalogue update publishes the marketing page and causes the next dashboard image to embed the same evidence.
A runner must never push an unreviewed capacity claim directly to `main`; the single-realm programme remains
`awaiting-baseline` until that runner and its first report have both passed review.

The maintained runner, synthetic fixture boundary and exact Starter ladder are documented in
[`benchmarks/README.md`](../benchmarks/README.md). The runner is a fourth service only in the dedicated
benchmark project; it is intentionally absent from the installable Railway template.

## User-capacity model

An idle authenticated session and an actively requesting user are different capacity dimensions. Reports
retain both. Active-user estimates use an explicit request profile and 30% headroom:

```text
supported active users = sustainable authenticated RPS × 60 × 0.70
                         ÷ requests per user per minute
```

The catalogue defines light, typical and heavy profiles. The headline single-realm figure uses the typical
profile; all three remain visible so an integrator can map the result to its own traffic. Sign-in throughput
is reported independently from session-backed API throughput.

## Realm-cell scaling model

Each supported realm is an independent deployment cell with its own API process, SableDB process and durable
data. If a qualified resource tier sustains `C` authenticated requests per second, `N` equally sized and
independently deployed realms have an initial planning envelope of:

```text
fleet authenticated request envelope = N × C × 0.70
```

The 30% factor is operating headroom, not additional measured capacity. Adding an equivalent realm therefore
adds approximately one realm's qualified envelope; it does not make an existing realm multi-writer and does
not increase the capacity of shared ingress, Fleet routing, observability, backup storage or a Railway region.
Those shared layers require their own load tests and limits. Reports show both the linear realm-cell projection
and these unqualified shared boundaries so the projection cannot be presented as evidence of arbitrary global
or hyperscale operation.

## Cadence

- Merges continue to run correctness and deployment probes, not load benchmarks.
- Every release runs a fixed-rate regression against a clean template installation.
- The monthly job runs the breakpoint ladder and a one-hour soak.
- Authentication, gateway, datastore or deployment changes may trigger a manual run.

Every report retains k6 latency/throughput output, Railway CPU/memory/network/volume series, deployment and
image identifiers, readiness/restart evidence, dataset cardinalities and the generated sanitised report.
Railway infrastructure metrics and application-level request metrics are collected separately and correlated
by run ID.

## Current limitation

RustyAuth `1.0.0` supports one active writer. Published realm results therefore qualify explicit vertical
resource tiers. They must not be extrapolated to multiple API writers or described as horizontal scaling until
the multi-writer model has separate correctness and performance qualification.
