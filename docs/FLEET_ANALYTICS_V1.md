# Fleet Analytics V1 semantic contract

**Status:** Active and normative for M9+

**Version:** `rustyauth.analytics.v1` / metric schema V1

**Updated:** 9 August 2026

**Developer reference:**
[Fleet Analytics V1](https://rustyauth.dev/docs/fleet-analytics-v1)

This document fixes the meaning of the data that may cross a realm boundary for Fleet Analytics. The
[Protobuf contract](../proto/rustyauth/analytics/v1/analytics.proto),
[Parquet schema](../packages/protocol/schemas/analytics/v1/metric-bucket-v1.parquet.schema.json), and
[compatibility fixtures](../packages/protocol/fixtures/analytics/v1/) are executable parts of this contract.
Database tables, connector framing and GreptimeDB SQL are internal adapters and may change without changing
metric meaning.

## Compatibility identity

V1 has independently versioned layers:

| Layer            | V1 identity                    | Purpose                                 |
| ---------------- | ------------------------------ | --------------------------------------- |
| Protobuf package | `rustyauth.analytics.v1`       | Message and enum compatibility          |
| Batch envelope   | `transport_schema_version = 1` | Batch limits and delivery framing       |
| Metric snapshot  | `METRIC_SCHEMA_VERSION_V1`     | Names, units, dimensions and arithmetic |
| Parquet rows     | `rustyauth-metric-bucket-v1`   | Portable archive and repair             |
| Archive manifest | `manifest_schema_version = 1`  | Object integrity and import idempotency |

A release must reject an unknown version. It must not reinterpret an unknown value as V1, accept unknown V1
fields, or infer a version from deployment metadata.

## Window and correction contract

- A V1 bucket is exactly five minutes, aligned to UTC epoch boundaries.
- The interval is left-closed and right-open: `[bucket_start, bucket_start + 5m)`.
- Event time selects the bucket. A receiver never rewrites it to receipt time.
- V1 exports closed buckets only. There are no provisional open buckets.
- The default realm close grace is two minutes. The first expected delivery is therefore within seven minutes
  of a window start, before network and ingestion allowance.
- The first snapshot revision is `1`. A correction increments the revision and resends the complete snapshot.
- A retry reuses the exact bucket key and revision. It never sends a counter delta.
- `first_event_sequence` and `last_event_sequence` are both zero when no durable event contributes. Otherwise
  they form an ordered positive range.
- One batch contains at most 288 buckets, representing a maximum 24-hour replay unit, and encodes to at most
  256 KiB.

The canonical key is:

```text
(realm_id, assignment_epoch, bucket_start_unix_milliseconds,
 bucket_width_seconds, metric_schema_version)
```

`revision` chooses the accepted value for that key. The ingestion coordinator, not this stateless contract,
enforces revision and sequence monotonicity across batches.

## Metric families and units

An optional family message means unsupported or unavailable. A present family containing zeros means the realm
supports the family and observed zero. Every customer-facing query combines the analytical facts with
registry-backed coverage so those states remain distinct.

| Family                 | V1 facts                                                                   | Unit and aggregation                                                                        |
| ---------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Authentication         | attempts, successes, failures, denials, active account observations        | Integer counts; sum. Success rate is `sum(successes) / sum(attempts)`                       |
| Authentication latency | count, sum and fixed cumulative histogram                                  | Milliseconds; merge cumulative counts before calculating quantiles                          |
| Registration           | options started, ceremonies opened, responses returned, completed, expired | Integer counts; sum each stage independently                                                |
| Sessions and tokens    | sessions created/revoked, user/service tokens issued                       | Integer counts; sum                                                                         |
| Service accounts       | calls, successes, failures, denials, credential rotations                  | Integer counts; sum                                                                         |
| Webhooks               | deliveries, successes, failures, latency, latest backlog                   | Events sum; histograms merge; select the latest backlog per realm before summing realms     |
| Platform               | API requests/errors/latency and SableDB operations/errors/latency          | Counts sum; histograms merge                                                                |
| Realm health           | serving state, backup age, signing-key age, connector lag                  | Latest observation per realm; derive scope state and coverage from those realm observations |

`active_account_observations` counts distinct realm accounts within one five-minute bucket. Its sum is an
account-window observation count, not active users or unique humans; the same account may contribute once per
bucket and the same person may hold accounts in multiple realms.

## Outcome invariants

Every producer and receiver enforces:

```text
authentication attempts = successes + failures + denials
service-account calls    = successes + failures + denials
webhook deliveries       = successes + failures
```

Authentication flow rows must exactly reproduce the headline authentication totals. Authentication failure
classes must exactly reproduce `failures + denials`. A registration funnel must satisfy:

```text
options_started >= ceremonies_opened >= responses_returned >= registrations_completed
```

Expired challenges are not included in that ordering because a challenge expiring in one window may have
started in an earlier window.

Each counter is limited to 1,000,000,000 per realm bucket. Sums use checked arithmetic. Impossible
relationships, duplicate breakdown enum values and unknown enum values fail closed.

## Histogram profiles

Histograms contain cumulative counts for every fixed upper bound and one final `+Inf` count. The final count
must equal `count`; all preceding values must be monotonic and no greater than `count`.

`HISTOGRAM_PROFILE_INTERACTIVE_MILLISECONDS_V1`:

```text
5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, +Inf
```

Used for authentication, API and SableDB latency.

`HISTOGRAM_PROFILE_DELIVERY_MILLISECONDS_V1`:

```text
10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, +Inf
```

Used for webhook delivery latency. A percentile is the upper bound of the first merged cumulative bucket
meeting the nearest-rank threshold. A value falling only in `+Inf` has no finite upper bound.

## Allowed dimensions

V1 has no label map and accepts no caller-named dimension. The only dimensions a realm may send are closed
Protobuf enums:

- authentication flow: passkey, email link or recovery;
- authentication failure class: invalid credential, challenge expired, origin rejected, policy denied, rate
  limited, store unavailable, upstream unavailable, internal or bounded other;
- metric family, histogram profile, serving state, acknowledgement status and rejection reason; and
- the stable realm ID and assignment epoch required to identify the source snapshot.

Organization, project and environment are not realm-supplied dimensions. The central gateway resolves and
stamps them from the authenticated connection and Fleet registry.

The following values are prohibited anywhere in a metric, dimension, manifest or acknowledgement:

- user, subject, account, credential, challenge, session, token or request IDs;
- email addresses, phone numbers, names, IP addresses or user-agent strings;
- RP assertions, public keys, cookies, secrets or secret hints;
- arbitrary paths, webhook URLs, error messages or caller-defined labels; and
- presigned URLs or object-store credentials.

`realm_id` uses the same stable 1–64 character ASCII identifier accepted by realm configuration and Fleet
pairing; it is not required to be a UUID. `batch_id` and `manifest_id` are canonical transport/idempotency
UUIDs, not analytical dimensions. Event sequences are watermarks, not query dimensions.

## Coverage arithmetic

Coverage is calculated from Fleet registry authority and accepted analytical facts:

```text
expected_realms = reporting_realms + stale_realms
total_realms    = expected_realms + disabled_realms + unsupported_realms
partial         = reporting_realms < expected_realms
```

Coverage is metric-family-specific. A realm can report authentication while lacking webhook capability. The
last complete window is zero when no complete common window exists; otherwise it is a UTC-aligned five-minute
instant.

## Archive contract

V1 Parquet archives contain one row per complete bucket snapshot at one revision and use Zstandard
compression. The golden logical-row fixture pins values, enum numbers and nesting; physical Parquet file bytes
are not compared because writer metadata and page layout are not semantic. An object is immutable after its
signed manifest is published. The manifest contains:

- exact manifest and metric schema versions;
- manifest UUID, realm UUID and assignment epoch;
- a credential-free key relative to a separately approved bucket binding;
- SHA-256 digest, byte length, row count and Zstandard compression;
- minimum and maximum bucket start, event sequence range and creation time; and
- signing-key ID plus a raw 64-byte P-256 signature over the canonical unsigned manifest.

The exact signature input is the ASCII domain `rustyauth.analytics.metric-bucket-manifest.v1`, one NUL byte,
then the deterministic Protobuf encoding of `MetricBucketArchiveManifest` with `signature` unset. The golden
signing-payload fixture pins those bytes across languages and releases.

The importer verifies the binding, signature, digest, size, row count, time range and sequence range before
reading a row. It records the manifest ID and digest before accepting a retry. The current schema permits no
raw event or subject-level row.

## Deterministic aggregation

Every numerical scope derives from canonical realm buckets for the requested assignment epochs. It must not
cascade rounded environment, project or organization values.

- Counts: checked sum.
- Success and conversion rates: ratio of summed numerator to summed denominator.
- Latency percentiles: merge compatible cumulative histograms, then calculate.
- Gauges: select the latest accepted value per realm before summing or classifying.
- Serving health: classify each realm from its latest observation and report source coverage separately.
- Corrections: recompute the affected canonical time range from the highest accepted bucket revisions.

The golden authentication fixture intentionally combines unequal realm volumes so an implementation that
averages child success rates produces the wrong result.

## Change policy

Adding an enum value is additive at the Protobuf layer but requires a new metric schema version before a realm
may emit it. Changing a unit, boundary, aggregation rule, invariant, Parquet field meaning or privacy rule is
always a new metric schema version. Field numbers and Parquet field IDs are never reused.

CI must continue to prove:

1. the golden batch encodes to the committed wire bytes and decodes under strict limits;
2. the archive manifest round-trips through canonical ProtoJSON;
3. Parquet field IDs and paths are unique and stable;
4. aggregate fixtures produce the same ratio and merged-histogram result; and
5. unknown versions, unknown fields, duplicate dimensions and resource-limit violations fail closed.
