# RustyAuth 1.0.0 release readiness

**Decision:** NO-GO

**Last updated:** 9 August 2026

RustyAuth's in-repository implementation is release-candidate complete and the recorded repository gates pass.
Production qualification is not complete. The project must remain at `0.1.0` and must not create a `v1.0.0`
tag until every externally owned gate below has evidence and the machine-readable release record passes
`deno task release:check 1.0.0`.

## Qualified in this repository

The following evidence passed on the pinned local integration topology on 9 August 2026:

- the full fast gate: Rust and Dioxus formatting, Clippy with warnings denied, Deno formatting/lint/type checks,
  Astro diagnostics, documentation links, gateway-route coverage, 25 TypeScript client tests, 9 rendered-site
  tests, 2 release-evidence tests, 186 non-ignored Rust library tests, 3 binary tests, 60 separately exercised
  Rust doctests, the container-healthcheck Go tests and the Cloudflare Go tests;
- all 12 ignored live module tests and all 4 ignored end-to-end tests against the pinned SableDB, MinIO and
  GreptimeDB services;
- clean-room backup restore and key rotation, 24-hour telemetry outage/restart/exact replay, cross-organization
  hierarchy isolation, restart-safe remote-mutation replay fencing, authenticated realm connector operation,
  pinned-SableDB writer-lease renewal and stale-owner fencing, canonical correction replacement, signed
  Parquet import and product-query convergence;
- the explicit medium Analytics gate with 1,000 realms and 8,064,000 five-minute rows: 20 organization
  queries over 28 days completed with a measured p95 of 239.5325 ms against the 2-second ceiling;
- `cargo audit` of the root, console and repository-owned SableDB lockfiles, locked `cargo deny`
  advisories/bans/licences/sources, `govulncheck`, Buf lint/format and the Buf breaking-change comparison against
  `main`; the console and SableDB audits found zero known vulnerabilities and reported 14 and 6 upstream
  maintenance/unsoundness warnings respectively, including desktop-Linux GTK bindings and a build-only
  `rand 0.7` path, which remain visible to the independent native/SableDB reviews;
- three seeded protocol fuzz targets completed 1,000 runs each, covering Analytics batches, management wire
  messages and archive manifests;
- a local macOS preview `.app` package built successfully and passed strict ad-hoc hardened-runtime
  code-signing verification. This is informational preview evidence, not a `1.0.0` artifact or GA gate;
- scratch release builds of the Rust API, Dioxus dashboard and pinned SableDB images. Auditable Rust metadata
  made the shipped API and SableDB graphs directly inspectable; checksum-pinned Trivy reported zero HIGH or
  CRITICAL findings across 337 API Cargo components, 160 dashboard Go components, 208 SableDB Cargo components
  and both dependency-free Go probes; and
- the codified `scripts/qualify-runtime-images.sh` drill proved non-root execution, shell-free/read-only roots,
  bounded capabilities/processes, private API/datastore networking, loopback-only publication, health,
  discovery, bounded gateway routing, external hashed CSS, correct JS/WASM MIME types, strict CSP/security
  headers and operation across repeated writer-lease renewals. The tagged-release workflow repeats this drill.

These results qualify the checked-out source and local images. They do not substitute for published-artifact,
platform, independent-review or real-organization evidence.

## External release gates

Every item is required for `1.0.0`; none may be self-certified by the implementer.

- [ ] Independent application security assessment completed, findings resolved or explicitly accepted.
- [ ] Independent deployment/topology assessment completed against the production ingress, egress, secret,
      datastore and backup configuration.
- [ ] Independent review of the pinned SableDB revision and RustyAuth's concurrency/atomicity assumptions.
- [ ] Independent Fleet Analytics threat and privacy assessment completed.
- [ ] Fleet Analytics completes its pinned production scale, soak, chaos, upgrade, downgrade, cost and
      clean-room recovery matrix, with retained measurements against the published SLOs and supported tiers.
- [ ] A real organization-policy Analytics canary meets the published SLOs and exercises disable/rollback,
      purge, partial/stale behavior and incident alerts.
- [ ] Published API, control-plane, dashboard and SableDB images are pulled anonymously by digest, signatures,
      provenance and SBOMs verify, and clean install plus supported upgrade/rollback drills pass.
- [ ] The [web GA browser/authenticator matrix](WEB_GA_QUALIFICATION.md) passes real registration, sign-in,
      step-up, recovery and revocation on every supported browser/OS/authenticator combination using the exact
      release-candidate image digests.
- [ ] An operator other than the implementer witnesses the clean-room Realm and Fleet recovery drill from
      retained artifacts and escrowed keys.
- [ ] A release owner records the final go decision and evidence for every gate in
      `release-evidence/v1.0.0.json`.

Current `1.0.0` blockers are external reviewers, a supported web browser/authenticator matrix, real canary
traffic and published-artifact/recovery evidence. A Railway production project exists, but it runs an older
template image; repurposing or replacing it for the RC canary and destructive upgrade/rollback matrix requires
explicit deployment authority. Mutating production infrastructure and approving risk require owner authority.

The 9 August 2026 publication preflight also found that `@rustyauth/client` and `@rustyauth/protocol` do not
yet exist on JSR and `buf.build/rusty-auth/rustyauth` does not yet exist in the Buf Schema Registry. The GitHub
repository exposes no repository-level `BUF_TOKEN`; an organization-level secret, if one exists, is not visible
to the current operator. Provision and link the JSR packages, create the Buf module, and confirm a push-scoped
`BUF_TOKEN` before any release-candidate tag. The workflow now verifies these destinations before any image or
package publication begins.

Xcode licence acceptance, Apple/Windows signing identities, notarization credentials, Android SDK/NDK tooling
and mobile keystores are explicitly outside the server/container/web `1.0.0` contract. They remain mandatory
before a later native preview can be promoted, but they do not block this GA release.

## Promotion procedure

1. Close every external gate and retain stable evidence URLs or repository paths.
2. Copy `release-evidence/TEMPLATE.json` to `release-evidence/v1.0.0.json`, set the version and decision, and
   retain `scope: "server-container-web-ga"`. Record at least two distinct named reviewers plus evidence for
   every required gate. Unknown or deprecated native gates are rejected.
3. Run `deno task release:check 1.0.0`; the tag workflow repeats this check and fails closed if any gate is
   missing.
4. Follow [Releasing RustyAuth](../RELEASING.md), including the full source gate and reviewed version changes.
5. Push `v1.0.0` only after the release commit is on `main`. The workflow reruns the live pinned-service
   qualification before it publishes any artifact.

If any post-publication verification fails, do not describe the release as complete: stop promotion, preserve
the failing evidence, revoke or de-list affected artifacts where supported, fix forward under a new version,
and follow the relevant incident/recovery runbook.
