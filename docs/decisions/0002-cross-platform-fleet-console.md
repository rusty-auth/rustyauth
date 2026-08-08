# 0002: Dioxus for the cross-platform fleet console

**Status:** Superseded by ADR 0003

**Date:** 8 August 2026

## Context

RustyAuth needs to preserve a small same-origin dashboard for standalone and break-glass administration while
eventually offering one fleet surface across organizations, projects, environments and isolated auth realms.
The fleet client should be available on the web and desktop, with a credible path to iOS and Android, without
forking its information architecture and interaction logic by platform.

The existing SolidJS dashboard is implemented and remains the visual and behavioral source of truth. Replacing
it before the single-tenant service is production-ready would add migration risk to the local administrative
boundary.

## Decision at the time

Keep `dashboard/` as the embedded same-origin SolidJS client for one RustyAuth realm. Build `console/` as a
separate Dioxus application for the future fleet control plane.

The Dioxus application will:

- share Rust screens, models and state transitions across web, desktop and later mobile targets;
- use explicit Cargo features for platform renderers;
- reproduce the embedded dashboard before introducing fleet hierarchy screens;
- keep platform services behind adapters;
- call an authorized control-plane API rather than remote realm databases; and
- begin read-only when real fleet connections are introduced.

The first slice contains native Dioxus implementations of all six current dashboard screens, both operator
sign-in presentations, the sign-in-to-preview return journey, responsive mobile navigation, charts,
search/filtering, forms, drawers and modals. It uses typed preview fixtures. It does not implement pairing,
connection storage, a fleet operator session or remote mutations.

## Component policy

The first clone reuses the established CSS and Tabler icon family because pixel parity is the acceptance
criterion. First-party Dioxus accessible primitives are the preferred long-term behavior layer when they can
preserve that visual contract.

The Rust/UI Dioxus registry is useful as a source of patterns and selectively vendored components. It is not a
blanket dependency: components that inject browser-only scripts, couple charts to JavaScript runtimes or do not
meet keyboard and screen-reader requirements require an adapter or a native implementation.

## Consequences

- Standalone deployments retain local administration when the fleet control plane is unavailable.
- The Dioxus console can be deployed separately without moving identity authority out of each realm.
- Visual changes must be checked against both clients until a shared design-token/component package replaces
  the compile-time stylesheet bridge.
- Desktop and mobile packaging do not broaden authorization: credentials and realm routing remain server-side.
- Two clients exist during the transition, so parity checks and explicit capability discovery are required.

## Rejected alternatives

### Replace the SolidJS dashboard immediately

Rejected because it changes the supported local administrative surface before the Dioxus client has live API,
security and packaging evidence.

### One JavaScript web application wrapped for desktop and mobile

Rejected as the primary direction because it does not provide the shared Rust client foundation chosen for the
fleet product and would make native integrations a wrapper-specific boundary.

### Connect the Dioxus client directly to each database

Rejected because it bypasses RustyAuth authorization, redaction, auditing and storage-version boundaries and
would distribute high-impact database credentials to clients.

## Supersession

[ADR 0003](0003-unified-dioxus-fleet-control-plane.md) replaces the temporary two-client strategy. Dioxus is now
the sole dashboard implementation target for standalone, Fleet web, desktop and future mobile surfaces. The
local break-glass capability remains; only its SolidJS implementation is retired.
