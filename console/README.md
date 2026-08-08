# RustyAuth cross-platform console

`console/` is the sole dashboard implementation target for RustyAuth standalone and Fleet deployments. Its web
release is deployed as a separate stateless service from the control plane and realm backend. It currently provides
a faithful, responsive clone of the embedded SolidJS dashboard's Overview, Users, Organization, Service
accounts, Webhooks and Metrics screens, plus both operator sign-in presentations from the embedded dashboard.

This is a preview client, not a shipped fleet management service. The data comes from typed Rust fixtures.
Pairing, a fleet registry, operator authorization and remote realm APIs still belong to later roadmap phases.
The sign-in forms deliberately stop at the live RustyAuth boundary until the client adapter is implemented;
`Open populated preview` exercises the complete local navigation flow without pretending a passkey was verified.

## Targets

The shared application and screen components compile behind explicit platform features:

- `web`: browser-hosted console;
- `desktop`: macOS, Windows and Linux packages through the Dioxus desktop renderer; and
- `mobile`: the shared foundation for future iOS and Android packages.

Platform integrations such as secure credential storage, deep links, notifications and window controls should
be added behind adapters. Screens and fleet models should remain platform-neutral.

## Development

Install Rust `1.94.1`, the `wasm32-unknown-unknown` target and Dioxus CLI `0.7.10`, then run from the repository
root:

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
```

`dx serve --desktop` runs the same application in a native window. iOS and Android packaging will be added
when the fleet connection flow and platform credential-storage policy are defined.

The web client mirrors the embedded dashboard's routes:

- `/` opens the classic operator sign-in;
- `/?login=aperture` opens the darker Aperture sign-in presentation; and
- `/?preview=1` opens the populated local preview.

Inside the preview, `Connect live`, the sidebar operator control and every `Exit preview` action return to the
classic operator sign-in. The same transitions are state-driven on desktop and mobile, where browser URLs do
not apply.

## Visual architecture

The console embeds `dashboard/src/styles.css` at compile time and uses the real RustyAuth lockup from
`site/public/brand`. That keeps the first clone aligned with the existing product instead of creating a second
design system during the port. `dx_icons_tabler` supplies the same Tabler icon family used by the SolidJS
dashboard.

Use Dioxus-native state and semantic controls for core interactions. First-party Dioxus component primitives
are preferred when they improve accessibility without changing the visual target. Rust/UI registry components
may be selectively vendored after checking accessibility, cross-platform behavior and browser-only script
dependencies; the registry is a reference library, not an all-or-nothing application dependency.

See [ADR 0003](../docs/decisions/0003-unified-dioxus-fleet-control-plane.md) and the
[fleet control-plane direction](../docs/FLEET_CONTROL_PLANE.md).
