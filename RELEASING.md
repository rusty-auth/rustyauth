# Releasing RustyAuth

A release is triggered by pushing a `v*` tag. The [release workflow](.github/workflows/release.yml) verifies
the tag and reviewed release-evidence record, runs the ordinary and pinned-service qualification suites,
publishes the RustyAuth backend, Dioxus dashboard and SableDB container images to GHCR, publishes the active
TypeScript packages to JSR, pushes the Protobuf module to the Buf Schema Registry, packages the three Helm
charts and creates the GitHub release. Artifact publication is fail-closed: no GitHub release is created after
a partial publish.

The image builds share BuildKit layer caches with CI (`type=gha` scopes `rustyauth-image`, `dashboard-image`
and `sabledb-image`), so a release normally reuses dependency layers CI already built. RustyAuth recompiles
only when workspace inputs change, and SableDB rebuilds only when `SABLEDB_REVISION` in
[sabledb/Dockerfile](sabledb/Dockerfile) changes.

## One-time setup

These exist per organization, not per release. All three are required before the first release delivers
everything the workflow promises.

1. **GHCR** needs nothing in advance. The first workflow run creates `ghcr.io/rusty-auth/rustyauth`,
   `ghcr.io/rusty-auth/control-plane`, `ghcr.io/rusty-auth/dashboard` and `ghcr.io/rusty-auth/sabledb`;
   afterwards, set each package's visibility to public in the GitHub package settings so consumers can pull
   without authentication.
2. **JSR**: create the `@rustyauth` scope at <https://jsr.io>, create the `protocol` and `client` packages
   inside it, and link each package to the `rusty-auth/rustyauth` GitHub repository so the workflow's OIDC
   token is accepted. Verify this before tagging; either failed publish blocks the release.
3. **Buf Schema Registry**: create the `buf.build/rusty-auth/rustyauth` repository named in
   [buf.yaml](buf.yaml), create a scoped token that can push that module, and save it as the repository's
   `BUF_TOKEN` Actions secret. A failed schema push blocks the release.

The release workflow checks both JSR package records, target-version availability, the Buf login and the Buf
module before any publication job can start. Keep this preflight dependency intact: it prevents a registry
setup error from leaving only some of the promised artifacts published.

Desktop, iOS and Android applications are not `1.0.0` artifacts. Their preview workflow is independent of GA
tags; a later native release must add authorized signing identities, platform distribution channels and its
own machine-readable evidence gates. Native credentials never belong in the repository.

## Cutting a release

1. Close the [release-readiness checklist](docs/RELEASE_READINESS.md). Copy
   `release-evidence/TEMPLATE.json` to `release-evidence/v<version>.json`, record stable evidence and named
   reviewers for every gate, retain `scope: "server-container-web-ga"`, set `decision` to `go`, then run
   `deno task release:check <version>`. The validator rejects deprecated native-distribution gates.
2. Move the `Unreleased` section of [CHANGELOG.md](CHANGELOG.md) under a new `## <version> - <date>` heading.
   Breaking changes anywhere in the section require a major-version bump; additive features use a minor bump
   and compatible fixes use a patch bump.
3. Set the same version in [Cargo.toml](Cargo.toml), `console/Cargo.toml`,
   `packages/protocol/deno.json`, `packages/client/deno.json`, `site/package.json` and every `charts/*/Chart.yaml`
   `version` and `appVersion`. Set each chart image `tag` to `v<version>`. Package versions move in lockstep
   with the server so every tagged package version is new and publication is deterministic.
4. Refresh both Rust lockfiles and run the full gate:

   ```sh
   cargo check --workspace --offline
   cargo check --manifest-path console/Cargo.toml --offline
   deno task check
   deno task test
   deno task connect:publish-dry
   deno task release:check <version>
   scripts/check-helm.sh
   ```

5. Review and commit the exact release scope, including new files, before tagging:

   ```sh
   git status --short
   git add Cargo.toml Cargo.lock console/Cargo.toml console/Cargo.lock \
     packages/protocol/deno.json packages/client/deno.json site/package.json \
     charts CHANGELOG.md docs/RELEASE_READINESS.md release-evidence/v<version>.json
   git diff --cached --check
   git commit -m "release: v<version>"
   git tag v<version>
   git push origin main v<version>
   ```

Do not tag from a dirty tree or bypass the release-evidence check. The workflow publishes the Protobuf module
after the source and pinned-service gates pass.

## After the workflow finishes

- `docker pull ghcr.io/rusty-auth/rustyauth:v<version>`, `docker pull ghcr.io/rusty-auth/dashboard:v<version>`
  and `docker pull ghcr.io/rusty-auth/sabledb:v<version>` succeed from a logged-out Docker client. The backend
  image is also published as `ghcr.io/rusty-auth/control-plane:v<version>` for the Fleet role.
- The GitHub release exists and links the changelog section.
- The GitHub release contains `rustyauth-integrated-<version>.tgz`, `rustyauth-fleet-<version>.tgz`,
  `rustyauth-realm-<version>.tgz` and `SHA256SUMS`.
- `deno add jsr:@rustyauth/client` resolves the new version, as does `jsr:@rustyauth/protocol`.
- `buf.build/rusty-auth/rustyauth` exposes the release tag's schema commit.
- The [README](README.md) quick start and [deployment docs](docs/DEPLOYMENT.md) still match the released
  behaviour.
