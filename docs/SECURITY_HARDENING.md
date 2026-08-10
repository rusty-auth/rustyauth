# Security hardening and qualification

This document records the controls in the supplied RustyAuth and Fleet deployments, the checks that qualify
them, and the continuous assurance program. It complements the trust model in [SECURITY.md](../SECURITY.md);
GA status is not a claim that every deployment has completed an independent security assessment.

## Hardened deployment baseline

The supplied Compose topologies apply the same runtime policy to the dashboard, Rust API and SableDB:

- scratch-based production images with no shell, package manager or general-purpose operating-system tools;
- a read-only root filesystem with a small `noexec`, `nosuid`, `nodev` `/tmp`;
- all Linux capabilities dropped and `no-new-privileges` enabled for the API and dashboard; the SableDB
  bootstrap receives only `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID` and `SETUID` until it drops to 10002;
- an init process for API/dashboard, direct SableDB PID 1 after privilege drop, and a 256-process limit;
- fixed non-root application identities (`10001` for RustyAuth/dashboard and `10002` for the SableDB process);
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

- Rust and build-tool images are pinned by digest; all three final runtime stages start from `scratch`.
- The bundled SableDB image builds the pinned `vendor/sabledb` gitlink from the public RustyAuth fork. The
  parent commit records the exact reviewed source revision instead of downloading a moving branch during the
  build. Because that SableDB revision has no lockfile, RustyAuth owns `sabledb/Cargo.lock` and the build uses
  it with `--locked`.
- Its static entrypoint rejects symlinked volume paths, prepares only `/var/lib/sabledb`, `data` and `conf`,
  clears supplementary groups, drops to UID/GID 10002 and then replaces itself with SableDB. Kubernetes may
  instead start it directly as 10002 after applying `fsGroup`.
- The dashboard gateway builds the immutable Caddy 2.11.4 source revision under Go 1.26.5 with the fixed
  `x/text` and gRPC module versions. Selected command/HTTP packages and the in-image health probe are tested
  before the static binary enters the scratch image.
- Root, console and SableDB `Cargo.lock` files are enforced in builds and audited in CI.
- `cargo-deny` gates advisories, duplicate/version policy, licences and registry/git sources with no active
  advisory exceptions.
- API, SableDB and Dioxus WebAssembly release builds use checksum-locked `cargo-auditable 0.7.5`, embedding the
  precise runtime Cargo graph into the artifact for compatible vulnerability scanners and SBOM generators.
- CI installs a checksum-pinned Trivy binary and rejects any HIGH or CRITICAL finding in the API, dashboard or
  SableDB runtime image. The scanner database remains current even though the scanner executable is pinned.
- Release images publish BuildKit provenance and SPDX-compatible SBOM attestations.
- The release workflow and third-party actions are pinned by commit.

An SBOM or provenance statement proves what was built; it does not prove that the contents are safe. Review
both the RustyAuth dependency graph and the pinned SableDB source whenever either lock or revision changes.

## Production infrastructure requirements

The application cannot enforce these properties by itself:

1. Terminate TLS at a trusted ingress and preserve the exact browser `Origin`, cookie and request-ID headers.
2. Allow the dashboard to reach only the private Rust API. Allow the Rust API to reach only SableDB, the
   configured backup endpoint and explicitly approved realm management endpoints.
3. Deny loopback, RFC1918/ULA, link-local and cloud-instance metadata destinations at the network layer. Fleet
   already validates, resolves and pins every public management endpoint with redirects disabled; the egress
   rule is an independent containment layer if the application or resolver is compromised.
4. Keep SableDB private with no public domain or TCP proxy. Encrypt its volume using the platform's storage
   controls.
5. Supply bootstrap and bearer material from a secret manager. Prefer the native AWS KMS envelope-key inputs
   for master and portable backup keys so deployment variables contain only ciphertext. Restrict container
   exec as an Owner-equivalent privilege and redact authorization/cookie headers upstream of RustyAuth.
6. Back up Fleet control-plane state independently from every realm. Retain image digests, non-secret
   configuration and escrowed keys outside the failure domain of the datastore they recover.
7. Keep exactly one active writer replica. A SableDB writer lease fences a second writer and shared SableDB
   rate-limit counters survive process replacement; horizontal active/active writers are outside the 1.0
   support contract.

## Verification matrix

Run the fast gate for every change:

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo audit
cargo audit --file console/Cargo.lock
cargo audit --file sabledb/Cargo.lock
cargo deny --all-features --locked check advisories bans licenses sources
go -C container-healthcheck test ./...
deno task console:check
docker compose --env-file .env.standalone.local config --quiet
docker compose -f compose.fleet.yaml --env-file .env.fleet.local config --quiet
```

For every release candidate, additionally:

- build both Compose topologies from a clean cache and wait for all health checks;
- assert container user IDs, read-only roots, dropped capabilities, `no-new-privileges` and process limits
  with `docker inspect`;
- prove the read-only root and writable `/tmp` policy through inspection and live application/health probes;
- verify only the loopback dashboard port is published and no database port is published;
- test malformed, oversized, unauthenticated, wrong-origin and unknown gateway requests;
- run real-SableDB ignored tests and the clean-room backup/restore/rotation drill;
- exercise pairing-code reuse, expiry, revocation, unreachable realm and private/metadata endpoint rejection;
- inspect image SBOMs and use the checksum-pinned scanner to require zero HIGH/CRITICAL findings in all three
  runtime images;
- run `scripts/qualify-runtime-images.sh` against the exact release-candidate tags;
- run `scripts/qualify-sabledb-image.sh` to exercise a fresh Railway-style root-owned volume and a
  Kubernetes-style `fsGroup` volume across restarts; and
- test a full passkey registration, sign-in, sign-out, Owner bootstrap and Fleet create/pair/disconnect flow
  with synthetic accounts.

At least quarterly, restore Fleet and a realm into clean infrastructure using only the retained runbook,
artifacts and escrowed keys. A backup that has not passed that drill is not a recovery capability.

## Continuous production assurance

The following work remains deliberately visible rather than being hidden behind a generic “secure” claim:

- horizontal active/active mutation coordination (1.0 deliberately supports one fenced writer only);
- production infrastructure egress enforcement for realm endpoints (application DNS answers are validated and
  pinned);
- real supported-web browser/OS/authenticator qualification;
- published-image install, upgrade and rollback drills in the production topology;
- the pinned Fleet Analytics scale, soak, chaos, upgrade/downgrade, cost and recovery matrix;
- a real organization-policy Analytics canary; and
- independent application, deployment, pinned-SableDB and Analytics threat/privacy assessments.

Desktop, iOS and Android clients remain unsupported previews and are not `1.0.0` artifacts. Their signing,
notarization/platform trust, update and real-device matrices are separately gated post-1.0 work.

Recent-passkey step-up with mandatory human reasons, pairing-derived outbound connector proof, credential
rotation/revocation and operator-role dominance are implemented and covered by the repository tests. The
assurance program is tracked in the [roadmap](ROADMAP.md), while exact artifact-publication evidence lives in
the [1.0.0 release-readiness record](RELEASE_READINESS.md). Operators remain responsible for qualifying their
own ingress, egress, secret management, browser/authenticator matrix and recovery process.
