# RustyAuth cross-platform console

`console/` is the sole dashboard implementation target for RustyAuth standalone and Fleet deployments. Its web
release is deployed as a separate stateless service from the control plane and realm backend. It currently
provides a faithful, responsive clone of the embedded SolidJS dashboard's Overview, Users, Organization,
Service accounts, Webhooks and Metrics screens, plus both operator sign-in presentations from the embedded
dashboard.

The web target supports live browser passkey registration and authentication, an HttpOnly operator session,
binary Connect/Protobuf calls, Fleet hierarchy CRUD and single-use realm pairing. `Open populated preview`
keeps the visual product tour available through typed Rust fixtures without pretending those records are
durable. Native device tokens are stored through platform vault adapters. Signed desktop distribution and
real-device mobile passkey qualification remain explicit post-1.0 native-release gates because they require
publisher credentials and authorized devices outside the repository. They do not block the supported web GA.

## Targets

The shared application and screen components compile behind explicit platform features:

- `web`: browser-hosted console;
- `desktop`: macOS, Windows and Linux packages through the Dioxus desktop renderer; and
- `mobile`: the shared foundation for future iOS and Android packages.

Platform integrations such as secure credential storage, deep links, notifications and window controls should
be added behind adapters. Screens and fleet models should remain platform-neutral.

## Development

Install Rust `1.94.1`, the `wasm32-unknown-unknown` target and Dioxus CLI `0.7.10`, then run from the
repository root:

```sh
rustup target add wasm32-unknown-unknown
cargo install dioxus-cli --version 0.7.10 --locked
deno task console:dev
```

Verification commands:

```sh
deno task console:check
deno task console:check:desktop
deno task console:check:mobile
deno task console:build:web
dx bundle --desktop --release --features bundle --package-types macos
```

`dx serve --desktop` runs the same application in a native window. `Dioxus.toml` fixes the application
identifier, publisher, icon, descriptions, macOS deployment floor/hardened runtime and Windows SHA-256
timestamp policy. Dioxus bundles only the host platform, so CI must use macOS, Windows and Linux runners;
desktop and mobile outputs remain unsupported previews outside the `1.0.0` GA artifacts. The
[native preview qualification](../docs/NATIVE_PACKAGING.md) records the host matrix, local `.app` evidence and
the separate post-1.0 distribution gates. Preview packages are unsigned, short-lived CI artifacts and must not
be redistributed as releases.

The web client mirrors the embedded dashboard's routes:

- `/` opens the classic operator sign-in;
- `/?login=aperture` opens the darker Aperture sign-in presentation; and
- `/?preview=1` opens the populated local preview.

Inside preview, `Connect live`, the sidebar operator control and every `Exit preview` action return to the
classic operator sign-in. A successful web passkey flow opens the live Fleet workspace; organization, project,
environment and connection mutations use the control-plane API and persist in Fleet SableDB. The same
transitions are state-driven on desktop and mobile, where browser URLs do not apply and platform credential
adapters are still required.

## Visual architecture

The console loads `assets/styles.css` through Dioxus's static-asset pipeline and uses the real RustyAuth
lockup from `site/public/brand`. The stylesheet and the bounded same-origin gateway configuration are owned by
the Dioxus package. `dx_icons_tabler` supplies the Tabler icon family established by the original dashboard.

Use Dioxus-native state and semantic controls for core interactions. First-party Dioxus component primitives
are preferred when they improve accessibility without changing the visual target. Rust/UI registry components
may be selectively vendored after checking accessibility, cross-platform behavior and browser-only script
dependencies; the registry is a reference library, not an all-or-nothing application dependency.

See [ADR 0003](../docs/decisions/0003-unified-dioxus-fleet-control-plane.md) and the
[Fleet control-plane architecture](../docs/FLEET_CONTROL_PLANE.md). Start the complete local central project
with `scripts/local-stack fleet up`; the [Fleet quick start](../docs/FLEET_QUICKSTART.md) explains how its
three services relate to managed realms.
