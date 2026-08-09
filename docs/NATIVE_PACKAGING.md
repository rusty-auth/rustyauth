# Native preview packaging and future distribution qualification

RustyAuth uses the shared Dioxus console for web, desktop and mobile feature builds. Native compilation is not
distribution: a package becomes a release artifact only after the platform publisher has signed it, the
platform trust service accepts it, and the clean-install/update matrix passes on a supported device.

Native applications are explicitly preview-only in RustyAuth `1.0.0`. The GA release contains the server,
hardened container images and Dioxus web dashboard; it does not publish or support desktop, iOS or Android
packages. Native signing and real-device distribution are separately gated post-1.0 work.

## Desktop package matrix

The `Native preview qualification` workflow builds host-native, unsigned preview artifacts on separate
runners for manual or pull-request qualification:

| Host runner  | Qualification output | Distribution proof still required                                     |
| ------------ | -------------------- | --------------------------------------------------------------------- |
| macOS 14     | `.app` bundle        | Developer ID signature, hardened runtime, notarization and stapling   |
| Windows 2025 | `.msi` installer     | Authenticode publisher signature and RFC 3161 timestamp               |
| Ubuntu 24.04 | `.deb` package       | Release checksum/provenance and signature in the supported repository |

The bundle identifier is `dev.rustyauth.console`. Publisher identities, certificate thumbprints, private keys,
notarization credentials and mobile signing material must be injected by authorized future release
infrastructure and must never be committed. Preview artifacts are clearly named `preview-unsigned`, expire
after seven days and are never built from, attached to or allowed to block GA release tags.

## Local macOS evidence

On 9 August 2026, Dioxus CLI 0.7.10 built the release `.app` on Apple silicon with Rust 1.94.1. The generated
bundle passed these repository-controlled checks:

- `Info.plist` parses and contains the expected identifier, `0.1.0` candidate version, Developer Tools
  category, icon, executable and macOS 12 deployment floor;
- the executable is an arm64 Mach-O with only system framework and library dependencies;
- the stylesheet and icon are inside sealed bundle resources;
- a local ad-hoc signing drill with hardened-runtime flags passes `codesign --verify --deep --strict`; and
- the application remains running without a startup panic during a bounded native launch smoke.

The untouched Dioxus output carries only a linker ad-hoc signature and fails strict bundle verification. The
locally re-signed drill still fails Gatekeeper assessment because it has no Developer ID identity or Apple
notarization ticket. Both failures are expected and are evidence that local packaging has not bypassed the
distribution gate.

## Release verification

For macOS, verify the final downloaded artifact with `codesign --verify --deep --strict`, `spctl --assess`,
`stapler validate` and a clean install/update on every supported architecture. For Windows, verify the final
download's Authenticode status, publisher chain and timestamp before a clean install, upgrade, rollback and
uninstall drill. For Linux, verify the repository/package signature and digest before clean install, upgrade,
rollback and removal.

iOS and Android remain separate post-1.0 release gates. iOS requires an authorized operator to accept the Xcode
licence, configure an Apple team/profile and exercise passkeys plus device-token vault storage on real
hardware. Android requires a pinned NDK, authorized keystore and the same real-device flows. Feature-only
compilation does not satisfy either distribution gate.

See [1.0.0 release readiness](RELEASE_READINESS.md) for the server/container/web GA evidence. A future native
release must add its own machine-readable signing, platform trust, clean-install/update and real-device gates
before any preview channel is promoted.
