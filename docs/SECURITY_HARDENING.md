# Security hardening and qualification

This document records the controls in the supplied RustyAuth and Fleet deployments, the checks that qualify
them, and the remaining production gates. It complements the trust model in [SECURITY.md](../SECURITY.md);
it is not a claim that the pre-release product has completed an independent security assessment.

## Hardened deployment baseline

The supplied Compose topologies apply the same runtime policy to the dashboard, Rust API and SableDB:

- a read-only root filesystem with a small `noexec`, `nosuid`, `nodev` `/tmp`;
- all Linux capabilities dropped and `no-new-privileges` enabled;
- an init process and a 256-process limit;
- fixed non-root identities (`10001` for RustyAuth/dashboard and `10002` for SableDB);
- no host port for either Rust service or SableDB; and
- an internal-only network between the public dashboard gateway and private services.

Only the named dashboard routes are proxied. An arbitrary path cannot be used as a generic reverse proxy to
the control plane. The dashboard receives no datastore URL, master key, bootstrap token or Fleet connection
credential.

Production sessions use a `__Host-Http-` cookie with `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/` and no
`Domain`. Development retains a separate unprefixed cookie so an HTTP localhost session can never shadow the
production cookie name.

Fleet encrypts a paired realm credential before persistence and moves plaintext into zeroizing memory while
doing so. Pairing exchange is single-use, expiring and rate limited. In production, a realm management URL
must be HTTPS; a literal IP must be public, and a hostname cannot use an obviously local or metadata
namespace. DNS is not trusted by this application check; see the egress requirement below.

## Supply-chain baseline

- Rust and runtime base images are pinned by digest.
- The bundled SableDB image builds the pinned upstream commit recorded in `sabledb/Dockerfile`.
- `Cargo.lock` is enforced in builds and CI.
- `cargo-deny` gates advisories, duplicate/version policy, licences and registry/git sources with no active
  advisory exceptions.
- Release images publish BuildKit provenance and SPDX-compatible SBOM attestations.
- The release workflow and third-party actions are pinned by commit.

An SBOM or provenance statement proves what was built; it does not prove that the contents are safe. Review
both the RustyAuth dependency graph and the pinned SableDB source whenever either lock or revision changes.

## Production infrastructure requirements

The application cannot enforce these properties by itself:

1. Terminate TLS at a trusted ingress and preserve the exact browser `Origin`, cookie and request-ID headers.
2. Allow the dashboard to reach only the private Rust API. Allow the Rust API to reach only SableDB, the
   configured backup endpoint and explicitly approved realm management endpoints.
3. Deny loopback, RFC1918/ULA, link-local and cloud-instance metadata destinations at the network layer. DNS
   may change after validation, so this egress rule is required to close DNS-rebinding and redirect-based
   SSRF paths.
4. Keep SableDB private with no public domain or TCP proxy. Encrypt its volume using the platform's storage
   controls.
5. Supply master, backup and bootstrap material from a secret manager. Restrict container exec as an
   Owner-equivalent privilege and redact authorization/cookie headers upstream of RustyAuth.
6. Back up Fleet control-plane state independently from every realm. Retain image digests, non-secret
   configuration and escrowed keys outside the failure domain of the datastore they recover.
7. Keep a single writer replica until distributed mutation coordination and rate limiting are qualified.

## Verification matrix

Run the fast gate for every change:

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo audit
cargo deny --all-features check advisories bans licenses sources
deno task console:check
docker compose --env-file .env.standalone.local config --quiet
docker compose -f compose.fleet.yaml --env-file .env.fleet.local config --quiet
```

For every release candidate, additionally:

- build both Compose topologies from a clean cache and wait for all health checks;
- assert container user IDs, read-only roots, dropped capabilities, `no-new-privileges` and process limits
  with `docker inspect`;
- prove a root-filesystem write fails and a `/tmp` write succeeds in every container;
- verify only the loopback dashboard port is published and no database port is published;
- test malformed, oversized, unauthenticated, wrong-origin and unknown gateway requests;
- run real-SableDB ignored tests and the clean-room backup/restore/rotation drill;
- exercise pairing-code reuse, expiry, revocation, unreachable realm and private/metadata endpoint rejection;
- inspect image SBOMs and scan all three runtime images for known OS and application vulnerabilities; and
- test a full passkey registration, sign-in, sign-out, Owner bootstrap and Fleet create/pair/disconnect flow
  with synthetic accounts.

At least quarterly, restore Fleet and a realm into clean infrastructure using only the retained runbook,
artifacts and escrowed keys. A backup that has not passed that drill is not a recovery capability.

## Remaining production gates

The following work remains deliberately visible rather than being hidden behind a generic “secure” claim:

- dedicated recent-passkey step-up and human reason for sensitive production Fleet mutations;
- workload identity or mutually authenticated outbound realm connectors instead of bearer-only management
  credentials;
- a KMS/HSM envelope-key provider and documented credential rotation after control-plane compromise;
- distributed rate limiting and mutation coordination before horizontal control-plane writers;
- durable allowlisted DNS resolution plus infrastructure egress enforcement for realm endpoints;
- role-dominance rules preventing a lower operator role from disrupting a higher role;
- removal of CSP `style-src 'unsafe-inline'` after Dioxus inline styles are replaced by static classes;
- protocol fuzzing, version-skew and fault-injection suites; and
- independent application, deployment and SableDB assessments before production support.

These gates are tracked in the [roadmap](ROADMAP.md). Until they are closed, RustyAuth remains pre-release and
must not be the sole identity system for a production service.
