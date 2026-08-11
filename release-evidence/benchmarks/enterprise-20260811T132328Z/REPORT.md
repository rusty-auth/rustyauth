# RustyAuth 1.0.0 enterprise single-realm boundary

Status: **informational — boundary retained; one-hour qualification incomplete**\
Qualification window: `qualification-final-2400-20260811T1323Z`\
First-failure window: `qualification-final-3200-20260811T1330Z`\
Operating-rate soak: `soak-final-1680-20260811T1335Z`\
Passkey companion: `passkey-final-under-1680-20260811T1336Z`

## Decision result

One single-writer Railway realm with 10,000 synthetic registered accounts and 10,000 valid sessions qualified
an exact **2,400 mixed authenticated requests per second** for two measured minutes. It completed 288,140
measured requests at 173.293 ms p95 and 251.554 ms p99 end-to-end latency. Ninety-four requests (0.032623%)
ended as HTTP/2 client transport cancellations, below the 0.1% reliability gate. The API returned zero
unplanned 5xx responses. Connection establishment dropped 1,386 iterations during the separate unmeasured
warm-up, but the measured phase still exceeded its required 288,000 arrivals; the warm-up drops remain in the
raw summary rather than being hidden.

The exact **3,200 RPS** test is the first retained failure. It completed 383,850 of the required 384,000
measured requests and missed 150 scheduled arrivals. End-to-end p95 reached 295.904 ms, while application and
accumulated SableDB p95 reached 236.740 ms and 236.641 ms, above their strict 150 ms gates. The API still
returned zero unplanned 5xx responses. The result is therefore a controlled capacity boundary, not a crash.

The planned **1,680 RPS** production operating rate was not qualified. At the owner's request, the Railway
benchmark environment was wound down after 37 minutes 40.7 seconds of the one-hour soak phase. The retained
terminal log records 3,802,109 completed iterations including the one-minute warm-up, zero interrupted
iterations and no completed recovery phase. It contains 284 HTTP/2 `CANCEL` warning lines and no matching
server-5xx line; because k6 did not produce its terminal JSON summary, those log observations are diagnostic,
not a final failure-rate measurement. Railway's API-edge telemetry for the retained partial window reports
3,695,306 2xx responses, zero 5xx responses and 548 ms p95, above the intended 300 ms gate.

The companion passkey run remains valid: while the partial soak was active, 30 complete synthetic passkey
ceremonies ran at six per minute with zero failures, 221.1 ms p95 and 310.75 ms p99 ceremony latency. The
exact two-minute 2,400 RPS boundary also remains valid. Neither result substitutes for the missing one-hour
soak and recovery gate.

Applying 30% planning headroom to the short-window boundary produces a **candidate** 1,680 RPS rate. At six
authenticated requests per user per minute that candidate would represent 16,800 simultaneously active
users; it would represent 50,400 at two requests/minute and 5,040 at twenty requests/minute. These are
unqualified planning calculations, not supported-capacity or stored-account claims. The retained dataset is
10,000, so 50,000 and 100,000 stored accounts remain unqualified.

## Latency waterfall at 2,400 RPS

| Layer                 |        p95 |        p99 | Reading                                                  |
| --------------------- | ---------: | ---------: | -------------------------------------------------------- |
| Public end to end     | 173.293 ms | 251.554 ms | k6 through the Railway public edge                       |
| External path         |  55.297 ms |  89.789 ms | runner, edge and network time separated from server work |
| RustyAuth application | 142.095 ms | 205.104 ms | secret-gated aggregate `Server-Timing`                   |
| Accumulated SableDB   | 142.019 ms | 204.988 ms | all private datastore commands/pipelines in one request  |

The normal store-backed journey used an average of 1.9 SableDB round trips. The operation mix was 60% account
reads, 20% access-token minting, 15% passkey-inventory reads and 5% public signing-key discovery. Access-token
responses were consumed rather than discarded so the client behaves like a relying party.

## Railway shape and cost

The measured realm used a 1 vCPU / 1 GB RustyAuth API and a 4 vCPU / 4 GB SableDB ceiling, one public Railway
edge, one private-network datastore path and one active SableDB volume. The dashboard was pinned and healthy
but was not in the benchmark request path. Configured ceilings are safety limits; Railway bills observed CPU,
memory, volume and public egress.

The retained partial-window metrics record API, SableDB, dashboard and load-generator CPU and memory, but the
incomplete soak cannot support a monthly production run-rate or egress claim. The load generator itself
averaged 1.55 vCPU and 1.57 GB RAM during the retained window and is excluded from customer-install cost
models. No production cost figure is published from this run.

## Comparison boundary

This run demonstrates competitive throughput and latency on a compact single-writer dataset. It does not prove
that RustyAuth is faster than Keycloak, Rauthy, Clerk or Auth0 because their public figures use different
datasets, endpoints and availability shapes. Keycloak publishes materially stronger million-account and
multi-pod HA evidence. Rauthy publishes a smaller application-memory claim but no matching retained throughput
trace. Clerk publishes a Backend API service limit, and Auth0 publishes contracted Private Cloud capacity
tiers; neither is the same workload as this run.

The report therefore supports a purchasing decision about this exact self-hosted realm shape. A speed or cost
leaderboard requires the same workload, dataset, region, availability target and retained evidence for every
provider.

## Reproduction and retained artifacts

The API source reference was built from `10b19eb48dc22e6271acea046c3da1ebaec7ad63`. Immutable source and
deployed-image digests, deployment IDs, UTC intervals, Railway metrics and dataset cardinalities are retained
in `reviewed-evidence.json`. `raw-runs/` contains the original k6 JSON, terminal output, exit codes and
runner-generated checksums for the passing boundary, first failure, incomplete soak and passkey companion.
`railway-metrics/` contains the captured Railway telemetry. `CAPTURE-SHA256SUMS` covers the retained evidence
files. Fixture session tokens, passkey private keys and timing secrets are intentionally excluded.

The load generator was a separate private Railway service with no public domain. It is not part of the
installable RustyAuth template.

## Railway wind-down

After evidence export, all five services in the isolated `RustyAuth Benchmarks` project were stopped. All five
volumes were submitted for deletion, including two superseded volumes containing approximately 50 GB each.
Railway reported zero active volumes and 103,883.72 MB pending deletion. The project and service definitions
remain available for a future explicitly authorized, freshly seeded run. See `WIND_DOWN.md` for the resource
identifiers and verification snapshot.
