# Fleet Analytics security and privacy assessment

**Assessment status:** internal engineering review complete for V1; independent security and privacy review
remains a production-release gate.

**Reviewed:** 9 August 2026

This assessment covers the optional `rustyauth.analytics.v1` plane: realm projection, authenticated connector
delivery, the Fleet acceptance ledger, GreptimeDB canonical and derived tables, signed Parquet recovery,
hierarchical RPCs and the Dioxus Analytics screen. It does not broaden RustyAuth's authentication trust
boundary. Disabling or removing Analytics leaves realm authentication and Fleet management available.

## Data inventory and purpose

Fleet Analytics processes closed five-minute numerical rollups for authentication, registration, sessions and
tokens, service accounts, webhooks, bounded platform observations and realm health. Dimensions are fixed to
trusted organization, project, environment, connection, realm assignment, time, schema version and bounded
catalogue enums. Its purpose is operational reliability and security monitoring within one customer's
authorized hierarchy.

The V1 validator rejects subject IDs, emails, phone numbers, usernames, IP addresses, credential material,
cookies, tokens, WebAuthn payloads, arbitrary labels, free-form error text and unknown dimensions. There is no
cross-customer cohort or unique-human metric. An aggregate can still be commercially sensitive, especially for
small realms, so authorization, residency, retention and deletion controls apply even though rows are designed
not to identify an account.

## Trust boundaries and assets

| Boundary | Security property |
| --- | --- |
| Realm projector -> durable realm outbox | Authentication writes never wait for export; only validated closed buckets enter the outbox. |
| Realm -> Fleet connector | Pairing-derived, connection-scoped proof signs the exact frame; assignment and capability state come from the authenticated connection. |
| Fleet ingress -> SableDB ledger | Organization hierarchy is stamped from the registry; revisions, sequences, quotas, policy, quarantine and audit are authoritative here. |
| Fleet worker -> GreptimeDB | Only trusted accepted records are mirrored; the database is private and never an authorization boundary. |
| Archive origin -> importer | P-256 manifest signature, exact object binding, SHA-256, length, row count and Arrow schema all fail closed. |
| Dioxus -> AnalyticsService | Server-side Fleet authorization resolves every scope; clients receive neither SQL nor database/object credentials. |

Protected assets include hierarchy confidentiality, aggregate integrity, freshness/coverage truth, manifest
signing keys, pairing-derived connector credentials, GreptimeDB credentials and the availability independence
of the realm authentication path.

## Threat review

| Threat | Required control and evidence |
| --- | --- |
| Realm forges another organization or realm | Ingress ignores untrusted hierarchy fields and stamps the authenticated `FleetConnectionRecord`; cross-organization and assignment-negative tests fail closed. |
| Duplicate, reordered or corrected buckets double-count | Exact bucket key, monotonic revision and source-sequence fencing live in SableDB; Greptime primary-key replacement and Flow correction tests prove convergence. |
| Policy bypass or ingestion flood | Analytics defaults disabled, requires explicit organization administration, uses per-realm minute quotas, bounded batches and crash-bounded idempotency markers. |
| High-cardinality or identity exfiltration | V1 uses a fixed Protobuf/Parquet schema and allowlisted enums; semantic and golden-fixture tests reject unknown/high-cardinality input. |
| Cross-organization query inference | Every scope is resolved and authorized before any store query; comparison is limited to siblings in one organization; no caller-supplied SQL exists. |
| Missing data rendered as zero | Registry-backed coverage reports reporting, stale, disabled and unsupported realms; Dioxus state tests render missing metrics as unavailable. |
| GreptimeDB or Fleet outage affects sign-in | Projection/export are background work with a bounded outbox; the 24-hour outage/restart/replay test proves authentication durability remains independent. |
| Malicious or substituted Parquet | Manifest signature, exact realm assignment, immutable object key hash, digest, byte/row limits, exact field IDs/types and decompression bounds are verified before acceptance. |
| Presigned URL SSRF or credential leakage | The URL is secret-held, redirect-free, exact-origin/exact-path, HTTPS-only, limited to 15 minutes and never logged. Infrastructure must still deny private, link-local and metadata egress after DNS resolution. |
| Retention or disconnect leaves undeclared copies | Policy updates enforce the requested organization retention in canonical/hourly/daily tables; connection revocation purges that connection and records a redacted success/failure audit. |
| Analytics database compromise exposes identity secrets | The schema contains no identity/credential payload; GreptimeDB is private with a separate credential. Aggregate operational data remains sensitive and is treated as customer data. |
| Control-plane compromise rewrites history | Signed realm delivery, accepted-revision records, manifest hashes and immutable backups provide evidence, but a fully privileged Fleet compromise remains able to read or delete central aggregates. Recovery and credential rotation are required. |

## Privacy assessment

- **Minimization:** V1 exports aggregate counters and mergeable histograms only. Raw authentication events are
  not an Analytics input.
- **Purpose limitation:** data supports availability, failure and adoption analysis inside the customer's own
  hierarchy. Advertising, employee monitoring, identity profiling and cross-customer benchmarking are outside
  the contract.
- **Retention:** canonical retention is organization-controlled from 1–35 days. Derived data is purged to the
  same reduced boundary by the product workflow. Approved immutable archives follow the customer's separately
  documented object-retention policy.
- **Residency:** policy selects rollups-only, customer-owned archive or central-landing archive. A manifest
  never grants access by itself; object access is short-lived and exact-prefix/object bound.
- **Access:** Fleet roles and parent-child authorization apply. GreptimeDB users and its dashboard are not
  customer authorization surfaces.
- **Deletion and data-subject requests:** V1 should contain no account-level identifier and therefore cannot
  locate one person. Organization/connection deletion is supported; if a customer maps a small aggregate to a
  person using outside information, that customer must include the aggregate and any immutable archive in its
  own request/retention process.
- **International transfer and subprocessors:** deployment owners select regions and object-store providers.
  RustyAuth code cannot establish a lawful transfer mechanism or processor agreement; those remain deployment
  responsibilities.

## Residual risks and release decisions

Open-source GreptimeDB basic authentication is defense in depth, not row-level customer isolation. Supported
production topology therefore requires private networking, service-only credentials and one RustyAuth
authorization layer; higher-assurance hosted deployments should use database-per-organization or an approved
managed isolation control. DNS rebinding must be blocked by infrastructure egress policy. Very small aggregates
can reveal business activity even without identity fields.

The internal review does not satisfy the roadmap's independent-assessment gate. Before a production `1.0.0`
claim, an assessor independent of implementation must review the application, deployment, SableDB, connector,
GreptimeDB and archive boundaries; findings need owners, severity and closure evidence. An organization-policy
canary must also run without cross-organization, privacy, latency or availability regressions.

## Verification map

- Contract and privacy validation: `src/analytics.rs` and protocol fixtures.
- Trusted ingestion, quota, quarantine and audit: `src/store/fleet_analytics.rs` and
  `src/store/fleet_analytics_control.rs`.
- Canonical/materialized correction, isolation purge and scale: `src/analytics_store.rs`.
- Signed Parquet and short-lived object access: `src/analytics_archive.rs`.
- Scope authorization and coverage: `src/analytics_rpc.rs`.
- Missing/partial/stale/forbidden presentation: `console/src/app.rs`.
- Recovery and incident procedure: [Fleet Analytics operations runbook](FLEET_ANALYTICS_RUNBOOK.md).
