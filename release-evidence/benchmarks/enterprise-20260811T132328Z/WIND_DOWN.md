# Railway benchmark wind-down

Captured at `2026-08-11T14:21:08Z` for Railway project `RustyAuth Benchmarks`
(`3da0030b-006f-4198-a8e7-f8f18da4a8e0`), environment `production`
(`6f24c06b-b008-4d74-bc7e-5759575e2f8b`).

## Compute

The benchmark runner, RustyAuth API, dashboard, original SableDB service and fresh SableDB service were shut
down with Railway's deployment removal operation. The final read-back showed no deployable SableDB instances;
the runner, API and dashboard records were marked stopped, and all five services reported zero running
replicas. The runner's `rusty-auth/rustyauth` GitHub source was disconnected after shutdown so a future push to
`main` cannot automatically redeploy it. No production or public-template project was changed.

| Service | Railway service ID | Final reading |
| --- | --- | --- |
| benchmark-runner | `e0d03bd6-31ea-4575-9026-b825ffff24e2` | stopped |
| RustyAuth | `77212d56-8d31-4df9-8f50-3c8e421dde67` | stopped |
| rustyauth-dashboard | `d31040a4-944d-45de-8595-57407aaf1ce8` | stopped |
| SableDB | `242a1e2a-2f43-4afd-ba7a-1d47e4e0f287` | no deployment |
| SableDB-fresh | `cd0175fa-351e-40ef-be2d-5e0c455f2e6f` | no deployment |

The pinned-image API, dashboard and SableDB source definitions remain in the project, but none has a running
deployment. Resumption requires an explicit redeploy; the benchmark runner additionally requires reconnecting
its source.

## Storage

Every volume is pending deletion. The read-back returned zero active volumes and 103,883.72 MB pending
deletion. The 50,000 MB values are Railway capacity ceilings; `currentSizeMB` is the stored-data observation at
the deletion request.

Railway documents volume usage as billed per GB per minute and says a deleted volume is queued for permanent
deletion within 48 hours. Compute spend stopped with the deployments; the final storage charge cannot be
treated as zero until Railway finishes that deletion queue. See Railway's
[volume reference](https://docs.railway.com/volumes/reference).

| Volume | Railway volume ID | Stored data | State |
| --- | --- | ---: | --- |
| sabledb-volume-lfqQ | `b50eccb0-7529-4fe9-9e8d-cefe5ad0cdfe` | 1,598.41 MB | pending deletion |
| sabledb-replacement-volume | `00e37791-c1da-46cf-9af8-2ecb131c463a` | 50,192.15 MB | pending deletion |
| benchmark-runner-volume | `b3287232-ec56-4c0e-8f98-d4eea960cca7` | 903.73 MB | pending deletion |
| sabledb-fresh-volume | `c548a63e-d00d-4ab1-8854-b288848aec13` | 992.36 MB | pending deletion |
| sabledb-volume | `8be9ba87-bc45-45f8-9de1-217b6a2d910a` | 50,197.07 MB | pending deletion |

The database fixtures and incomplete soak state are intentionally unrecoverable from Railway after deletion.
The report, raw final-run artifacts, partial-window Railway metrics and their checksums were exported first.

## Incomplete soak

The 1,680 RPS soak was stopped after 37 minutes 40.7 seconds of its planned one-hour phase. The last retained
terminal update recorded 3,802,109 completed iterations including warm-up, zero interrupted iterations, 284
HTTP/2 `CANCEL` warning lines and no completed recovery phase. There is no final k6 JSON summary or run
checksum, so this run does not qualify an operating rate.

Railway API telemetry for `2026-08-11T13:36:08Z` through `2026-08-11T14:12:49Z` retained 3,695,306 2xx
responses, zero 5xx responses and 548 ms p95 edge latency. These are partial-window diagnostic measurements,
not a completed benchmark result.
