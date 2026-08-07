# Engineering guide

RustyAuth is security infrastructure. The repository optimizes for auditable boundaries, explicit
failure behavior and a small operational surface—not framework novelty or speculative abstraction.

## Repository boundaries

| Path | Responsibility | Must not own |
| --- | --- | --- |
| `src/main.rs` | Process lifecycle and dependency composition | Authentication policy or storage keys |
| `src/app_state.rs` | Initialized capabilities shared by handlers | Request-scoped or mutable global data |
| `src/auth.rs` | HTTP contract, origin policy and response mapping | Direct SableDB commands or key custody |
| `src/store.rs` | Durable records, key layout and atomic mutations | HTTP status codes or browser policy |
| `src/identity_rpc.rs` | Safe identity projection and private control-plane RPC | WebAuthn material exposure or storage keys |
| `src/event_rpc.rs` | Ordered replay/follow event projection | Event mutation or consumer checkpoints |
| `src/operator_auth.rs` | Exact-origin passkey operator sessions and role capabilities | RPC persistence or browser state |
| `src/organization_rpc.rs` | Single-organization and operator RPC projection | Session policy or storage keys |
| `src/service_account_rpc.rs` | Service principal policy, credentials and token exchange | Secret persistence or signing-key custody |
| `src/rpc.rs` | RPC composition, limits and scoped service authentication | Identity persistence policy |
| `src/jwt.rs` | Signing-key custody and token issuance | Session validation or application authorization |
| `src/config.rs` | Typed configuration and deployment validation | Runtime defaults that weaken production |
| `src/backup.rs` | Logical snapshot validation, authenticated envelopes and S3 backup operations | HTTP policy or storage mutations outside the snapshot boundary |
| `site/src` | Static public site and documentation UI | Product secrets or service-side auth logic |
| `dashboard/src` | SolidJS operator experience and safe RPC projections | Authorization policy or raw credential persistence |
| `infra/cloudflare` | Cloudflare Pages and DNS control plane | Application deployment or secret values |

The current service is intentionally a single binary. New modules should represent a real security,
protocol, persistence or operational boundary. Do not create layers whose only purpose is to rename a
function call.

## Identity persistence changes

[Identity data model](IDENTITY_DATA_MODEL.md) is the canonical persisted-identity contract. A change
to `User`, `AccountIdentifier`, `AccountProfile`, `StoredPasskey`, `Session`, identity indexes or
identity events must update that reference in the same pull request.

Review the complete data path: stored record and indexes → backup validation and restore behavior →
safe HTTP/RPC projection → event metadata → documentation. New durable fields require backwards-
compatible deserialization or an explicit migration, bounded validation, backup coverage and a
decision about whether they belong in JWTs, API responses and administrative search. Do not expose
opaque WebAuthn credential state merely because it exists inside the aggregate.

## Rust rules

- Use typed configuration and validate it before opening the listener.
- Keep secret values in `SecretString` or fixed-size key buffers; zeroize owned key material after use.
- Never log bearer tokens, cookies, WebAuthn responses, private keys or handoff codes.
- Keep persistence keys and serialization inside `store`.
- Consume one-time state atomically. A read followed by a delete is not replay-safe.
- Map internal failures to a generic response and retain precise context only in server logs.
- Add rejection-path tests whenever a trust boundary changes.
- `unsafe` code requires a written design rationale and independent review.

## TypeScript, dashboard and site rules

- Deno is the workspace runtime and task runner; dependency versions are pinned in `package.json` and
  resolved by the committed `deno.lock`.
- Astro owns document structure and static routing. Solid islands are reserved for real client-side
  behavior, not static markup.
- The SolidJS dashboard consumes only generated protobuf descriptors through
  `@rustyauth/connect-solid`; Rust remains authoritative for every permission and mutation.
- Service credential values may appear only in the one-time creation dialog and must never enter
  query caches, preview fixtures, logs or persistent browser storage.
- Browser-only resources must be created in lifecycle hooks and completely disposed during cleanup.
  The Three.js scene tracks GPU resources through `scene-primitives.ts` for this reason.
- Prefer semantic HTML and CSS over JavaScript layout logic. All animation must respect reduced-motion
  preferences.
- Marketing copy must distinguish shipped behavior from roadmap work.

## Infrastructure rules

- Pulumi code declares resources; it never contains credentials or copies secret values into stack
  configuration.
- Cloudflare tokens are injected at execution time from the approved secret manager.
- The `.dev` site and its DNS are the only resources owned by `infra/cloudflare`. RustyAuth service
  hosting remains a separate deployment concern.
- Preview infrastructure changes before applying them. Review resource replacement and DNS deletion
  as destructive operations.

## Quality gates

Run the same aggregate gates as CI from the repository root:

```sh
deno task check
deno task test
```

`check` enforces Rust formatting and Clippy, Deno formatting and linting, Astro and dashboard type
checks, Go formatting and `go vet`. `test` builds the dashboard, builds and tests the static site,
runs Rust tests with the lockfile, and runs the Cloudflare Pulumi unit/compile checks.

For release candidates, also run:

```sh
cargo build --locked --release
docker build --tag rustyauth:local .
```

Changes to persistence, signing or recovery must also pass the real-service clean-room drill in
`compose.integration.yaml`. It proves encrypted upload, previous-key decryption, empty-target
restore, default session invalidation, signing-key replacement and ordered-event continuity against
two SableDB instances and MinIO.

## Change design

Open an architecture decision record before adding a new public protocol, online data store,
authentication factor, recovery mechanism, token class or multi-writer strategy. A decision should
record the security property being added, rejected alternatives, migration compatibility and rollback
behavior.

Code review should be able to answer four questions without inference:

1. Which trust boundary changed?
2. What invalid input now fails closed?
3. What durable or public contract changed?
4. Which automated check proves the intended behavior?
