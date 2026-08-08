# 0004: Federated Fleet Analytics with trusted rollup ingestion

**Status:** Proposed; activation is gated on completion of the main Fleet roadmap through M8

**Date:** 8 August 2026

## Context

After Fleet is fully delivered, operators need to understand authentication health across organizations,
projects, environments, clouds and customer networks. Querying every realm synchronously cannot produce
reliable historical charts when connections are slow or offline, and it makes a fleet-wide view depend on the
least available realm.

Centralizing realm databases would violate Fleet's isolation model. Sending complete identity events to a
shared analytics service by default would also expand residency, retention, breach and authorization scope far
beyond what bounded operational metrics require.

RustyAuth already has the right control-plane primitives: stable realm identity, an authoritative hierarchy
registry, environment-scoped credentials, outbound mTLS connectors, source-tagged read models and a rule that
missing realms remain visibly stale rather than becoming zero. The analytics feature should extend those
boundaries rather than create a parallel connection system.

GreptimeDB is a Rust time-series and observability database with SQL/PromQL, object-storage support,
deduplicating time-series keys, external Parquet tables and continuous Flow aggregations. It is a better fit
for central time-series serving than SableDB's key-value model. Its File Engine can read external Parquet, but
product-serving queries across many foreign buckets would inherit credential sprawl, file-listing latency,
schema drift and cross-cloud availability.

## Decision

### Activate only after Fleet is shipped

Federated Fleet Analytics is a post-Fleet program. Production implementation begins only after M8 of the main
roadmap passes and Fleet is described as shipped in the README and release notes. Planning and non-customer
benchmarks may occur earlier, but no realm emits central telemetry merely to prepare for the feature.

### Project bounded rollups locally

Each realm projects request and durable-event signals into UTC-aligned five-minute bucket snapshots. Metric
names, units, dimensions, histogram boundaries and error classes are closed, versioned protocol enums. User,
identifier, credential, session, IP, arbitrary path and arbitrary error values are prohibited.

Realms send complete snapshots with a monotonic bucket revision and source sequence watermark. At-least-once
transport can therefore retry without adding a delta twice. Local projection and the export outbox live behind
the realm's existing storage and failure boundary; exporter failure never blocks authentication.

### Ingest through the Fleet trust boundary

The normal hot path uses the existing realm-initiated management connection or a dedicated streaming service
with the same mTLS identity, realm binding, limits and interceptors. A realm never writes to GreptimeDB.

The Fleet ingestion gateway resolves organization, project and environment from the authenticated realm and
Fleet registry. It stamps those IDs and an assignment epoch on accepted facts. Hierarchy fields supplied by
the realm are non-authoritative. Fleet SableDB retains hierarchy, policy, expected-source state, accepted
revisions, cursors, manifests and audit; GreptimeDB retains analytical facts.

### Keep one canonical realm grain

The canonical analytical fact is one realm bucket plus bounded breakdown dimensions. Environment, project,
organization and fleet results derive from that same canonical grain. Rates are ratios of summed components;
histogram percentiles are computed after merging buckets; gauges use the latest realm sample.

Higher-level aggregates never form a cascading arithmetic chain. A fleet value is not a sum or average of
already rounded organization rates. Hourly and daily materializations are disposable products of canonical
realm facts and can be rebuilt.

### Use GreptimeDB behind an internal port

GreptimeDB is the preferred central store, subject to post-Fleet benchmark, recovery, security and deployment
qualification. RustyAuth owns an internal `AnalyticsStore` boundary so public Protobufs, metric semantics and
Parquet formats do not depend on GreptimeDB SQL or physical schemas.

Only the Fleet ingestion/analytics services can reach GreptimeDB. Dioxus calls a bounded, role-authorized
Fleet Analytics RPC; it never sends SQL or receives database credentials. GreptimeDB's own dashboard is not a
product or authorization surface.

### Use Parquet for portability and repair

Versioned metric-bucket Parquet is the cold recovery and backfill format. A customer/project bucket may retain
it under local policy. A signed manifest names the realm, assignment epoch, sequence range, schema, row count,
time bounds, object identity and content hash.

The central importer consumes explicit manifests with short-lived prefix access, a presigned transfer or
approved replication. It verifies and imports data into canonical tables. Routine queries do not introspect
every foreign bucket, and GreptimeDB Flow does not run over foreign external tables.

Optional raw redacted-event archives are disabled by default and separately governed. They are not required to
produce Fleet metrics.

### Make coverage part of every result

GreptimeDB knows which facts arrived; the Fleet registry knows which realms were expected. The Rust control
plane combines both and returns expected, reporting, stale, unsupported and disabled counts with every
aggregate. Missing data never silently becomes zero.

### Preserve historical attribution

Changing a realm's environment creates a new assignment epoch. New buckets use the new hierarchy; historical
facts retain the old attribution. Retroactive movement is an explicit audited repair, not a side effect of
editing Fleet inventory.

## Security properties

- A realm credential can contribute only to its authenticated realm.
- A realm cannot select an organization, project, environment or global scope.
- Central metrics contain no user or credential dimensions.
- All-organization queries require a distinct Fleet-platform permission.
- Organization-facing queries and caches are keyed and authorized by stored scope.
- Cardinality, batch size, revisions, clock skew and schema are bounded before database ingestion.
- Customer object-store access is short-lived and prefix-scoped; static cross-cloud credentials are not placed
  in Dioxus or realm configuration.
- Analytics availability is absent from registration, authentication, token, session, JWKS and recovery paths.
- Disconnect and policy disable stop new export without central cooperation in local authentication.

## Consequences

- Fleet dashboards remain useful through partial realm failure and show the incompleteness honestly.
- A new private stateful service and analytics worker increase central operational scope and require their own
  backup, restore, upgrade, monitoring and threat assessment.
- Complete snapshots consume slightly more bandwidth than deltas but make at-least-once delivery and repair
  substantially safer.
- Five-minute realm buckets limit central volume and personal-data exposure while retaining useful drill-down.
- External Parquet remains portable without becoming the latency and availability boundary for live views.
- Metric semantics, not the database engine, become the durable compatibility surface.
- Unique-human analytics across realms and customer benchmarking remain unavailable until separately decided.

## Rejected alternatives

### Query every realm live for every dashboard request

Rejected because offline and slow realms make historical and fleet-wide results unreliable, expensive and
impossible to reproduce.

### Let realms write directly to GreptimeDB

Rejected because it lets an external deployment choose tags, exercise the database protocol, amplify
cardinality and potentially target another organization's series. The Fleet gateway must authenticate, bound
and stamp every fact.

### Make GreptimeDB scan every foreign bucket continuously

Rejected as the normal serving path because it couples dashboard correctness to foreign credentials, object
listing, network latency, egress, schema consistency and bucket availability. External tables remain useful
for controlled exploration and repair.

### Store all central analytics in Fleet SableDB

Rejected as the long-term design because high-retention time windows, histograms, cross-scope aggregation and
analytical scans are not SableDB's intended workload. SableDB remains the coordination and authority store.

### Embed h5i-db in the control-plane service

Rejected for the central serving path because an embedded local-filesystem database constrains horizontal
service topology, expands the control-plane process and has a much shorter production history. Its versioned
Parquet model may inform offline tooling but is not the Fleet analytics boundary.

### Send metric deltas

Rejected because an acknowledgement lost after a durable central write makes retry ambiguous and duplicates a
delta. Full bucket snapshots plus revisions are idempotent.

### Cascade environment, project, organization and fleet arithmetic

Rejected because rates, percentiles, gauges, late corrections and hierarchy changes do not compose safely
through rounded child aggregates. All numerical levels derive from canonical realm facts.

### Centralize raw events by default

Rejected because operational charts do not require subject-level event history and the resulting residency,
retention and breach scope would be disproportionate. Raw redacted archives are optional and separately
governed.

## Rollback

Disable organization export policy and the central analytics capability. Realms retain local metrics and
continue every authentication function. Fleet hides Analytics RPCs through capability discovery. Central
history follows configured retention or an audited purge. Removing the analytics services does not change
realm identity, issuer, RP ID, keys, users, sessions, databases, Fleet hierarchy or management connections.

## Follow-up

The complete activation, milestones, metric model, storage plan, test matrix and definition of done live in
[Federated Fleet Analytics delivery program](../FLEET_ANALYTICS.md).
