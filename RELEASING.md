# Releasing RustyAuth

A release is triggered by pushing a `v*` tag. The [release workflow](.github/workflows/release.yml)
verifies the tag, runs the Rust test suite, publishes the RustyAuth and SableDB container images to
GHCR, publishes the TypeScript packages to JSR and creates the GitHub release. Protobuf contracts
are pushed to the Buf Schema Registry manually.

Both image builds share BuildKit layer caches with CI (`type=gha` scopes `rustyauth-image` and
`sabledb-image`), so a release normally reuses the dependency layers CI already built: only the
RustyAuth workspace code compiles at release time, and SableDB rebuilds only when
`SABLEDB_REVISION` in [sabledb/Dockerfile](sabledb/Dockerfile) changes.

## One-time setup

These exist per organization, not per release. All three are required before the first release
delivers everything the workflow promises.

1. **GHCR** needs nothing in advance. The first workflow run creates
   `ghcr.io/rusty-auth/rustyauth` and `ghcr.io/rusty-auth/sabledb`; afterwards, set both packages'
   visibility to public in the GitHub package settings so consumers can pull without
   authentication.
2. **JSR**: create the `@rustyauth` scope at <https://jsr.io>, create the `protocol`,
   `connect-solid` and `client` packages inside it, and link each package to the
   `rusty-auth/rustyauth` GitHub repository so the workflow's OIDC token is accepted. Until the
   packages are linked, the `jsr` job's publishes fail (they are `continue-on-error` and will not
   block the release).
3. **Buf Schema Registry**: create the `buf.build/rusty-auth/rustyauth` repository named in
   [buf.yaml](buf.yaml), then authenticate locally with `buf registry login`.

## Cutting a release

1. Move the `Unreleased` section of [CHANGELOG.md](CHANGELOG.md) under a new
   `## <version> - <date>` heading. Breaking changes anywhere in the section mean a minor bump
   while the project is pre-`1.0`.
2. Set the same version in [Cargo.toml](Cargo.toml), `packages/protocol/deno.json`,
   `packages/connect-solid/deno.json` and `packages/client/deno.json`. The package versions move in
   lockstep with the server until the contracts stabilise; a package with no changes simply skips
   publishing (the registry rejects the duplicate version and the workflow continues).
3. Refresh the lockfile entry and run the full gate:

   ```sh
   cargo update --workspace --offline
   deno task check
   deno task test
   ```

4. Commit, tag and push:

   ```sh
   git commit -am "release: v<version>"
   git tag v<version>
   git push origin main v<version>
   ```

5. Push the protobuf contracts to the BSR:

   ```sh
   buf push
   ```

## After the workflow finishes

- `docker pull ghcr.io/rusty-auth/rustyauth:v<version>` and
  `docker pull ghcr.io/rusty-auth/sabledb:v<version>` succeed from a logged-out Docker client.
- The GitHub release exists and links the changelog section.
- `deno add jsr:@rustyauth/client` resolves the new version (likewise `protocol` and
  `connect-solid`).
- The [README](README.md) quick start and [deployment docs](docs/DEPLOYMENT.md) still match the
  released behaviour.
