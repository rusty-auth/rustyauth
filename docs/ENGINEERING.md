# Engineering guide

RustyAuth is security infrastructure. The repository optimizes for auditable boundaries, explicit failure
behavior and a small operational surface—not framework novelty or speculative abstraction.

## Repository boundaries

| Path                                                     | Responsibility                                                                | Must not own                                                        |
| -------------------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `src/main.rs`                                            | Process lifecycle and dependency composition                                  | Authentication policy or storage keys                               |
| `src/cli.rs`                                             | Operator CLI parsing and doctor/backup/keys/operator commands                 | Server routing or request handling                                  |
| `src/lib.rs`                                             | Library crate root declaring the service modules                              | Runtime logic or process lifecycle                                  |
| `src/app_state.rs`                                       | Initialized capabilities shared by handlers                                   | Request-scoped or mutable global data                               |
| `src/auth.rs`, `src/auth/`                               | HTTP contract, origin policy and response mapping                             | Direct SableDB commands or key custody                              |
| `src/store.rs`, `src/store/`                             | Durable records, key layout and atomic mutations                              | HTTP status codes or browser policy                                 |
| `src/identity_rpc.rs`, `src/identity_rpc/`               | Safe identity projection and private control-plane RPC                        | WebAuthn material exposure or storage keys                          |
| `src/event_rpc.rs`                                       | Ordered replay/follow event projection                                        | Event mutation or consumer checkpoints                              |
| `src/operator_auth.rs`                                   | Exact-origin passkey operator sessions and role capabilities                  | RPC persistence or browser state                                    |
| `src/organization_rpc.rs`                                | Single-organization and operator RPC projection                               | Session policy or storage keys                                      |
| `src/service_account_rpc.rs`, `src/service_account_rpc/` | Service principal policy, credentials and token exchange                      | Secret persistence or signing-key custody                           |
| `src/fleet_rpc.rs`, `src/management_rpc.rs`              | Fleet hierarchy, scoped authorization and realm-management protocol           | Direct realm database access or client-held connection credentials  |
| `src/rpc.rs`                                             | RPC composition, limits and scoped service authentication                     | Identity persistence policy                                         |
| `src/jwt.rs`, `src/jwt/`                                 | Signing-key custody and token issuance                                        | Session validation or application authorization                     |
| `src/config.rs`, `src/config/file.rs`                    | Env/secret inputs, versioned YAML and deployment validation                    | Runtime defaults that weaken production                             |
| `src/backup.rs`, `src/backup/`                           | Logical snapshot validation, authenticated envelopes and S3 backup operations | HTTP policy or storage mutations outside the snapshot boundary      |
| `tests/`                                                 | Integration coverage against the real compose services                        | Unit tests, which live beside their modules                         |
| `site/src`                                               | Static public site and documentation UI                                       | Product secrets or service-side auth logic                          |
| `console/src`                                            | Dioxus web/desktop/mobile presentation and generated Protobuf client          | Authorization policy, database access or reusable realm credentials |
| `console/assets/styles.css`                              | Dioxus dashboard visual tokens and component styling                           | Product behavior or authorization policy                            |
| `infra/cloudflare`                                       | Cloudflare Pages and DNS control plane                                        | Application deployment or secret values                             |

The current service is intentionally a single binary. New modules should represent a real security, protocol,
persistence or operational boundary. Do not create layers whose only purpose is to rename a function call.

## Module layout

A module that grows past roughly 800 lines is split into `<name>.rs` plus a `<name>/` directory of domain
submodules, the pattern `store`, `auth`, `jwt` and the RPC services already follow. The rules that keep a
split auditable:

- **The facade file owns the contract.** `<name>.rs` declares the submodules, re-exports their items so every
  existing `crate::<name>::X` path keeps resolving, and holds only glue genuinely shared by all submodules.
  Callers never change in a split commit.
- **Boundaries follow domains, not line counts.** Split by resource, lifecycle or protocol concern — the way
  an auditor would ask questions — never into `part1.rs`/`part2.rs` chunks that merely hit a number.
- **Every submodule states its single responsibility** in a one- or two-line `//!` header comment.
- **A split commit is structural only.** Code, comments and tests move verbatim; behavior, error mapping and
  cryptographic constructions do not change in the same commit. Unit tests move beside the code they exercise.
- **Visibility widens only as far as the split requires.** Prefer `pub(super)` and `pub(crate)`; items become
  `pub` only when the binary or `tests/` genuinely consumes them.

## Identity persistence changes

[Identity data model](IDENTITY_DATA_MODEL.md) is the canonical persisted-identity contract. A change to
`User`, `AccountIdentifier`, `AccountProfile`, `StoredPasskey`, `Session`, identity indexes or identity events
must update that reference in the same pull request.

Review the complete data path: stored record and indexes → backup validation and restore behavior → safe
HTTP/RPC projection → event metadata → documentation. New durable fields require backwards- compatible
deserialization or an explicit migration, bounded validation, backup coverage and a decision about whether
they belong in JWTs, API responses and administrative search. Do not expose opaque WebAuthn credential state
merely because it exists inside the aggregate.

## Backup changes

[Backups and disaster recovery](BACKUPS.md) is the canonical backup contract. Any change to a managed
SableDB key family, snapshot DTO, manifest validation, envelope magic, compression/encryption order, key-ID
derivation, S3 metadata or posture check, scheduler health, receipt field or restore behavior must update that
document and `site/src/pages/docs/recovery.astro` in the same pull request.

When adding durable `auth:*` or `fleet:*` state, make an explicit include/exclude decision in
`src/store/snapshot.rs`, add semantic validation in `src/backup/snapshot.rs`, and add a failure-path test. An
unknown key family is intentionally a backup error; broadening the exporter without ownership validation
weakens the full-workspace recovery claim. Format changes must remain backwards-readable or receive a new
envelope magic and stable DTO.

## Rust rules

- Use typed configuration and validate it before opening the listener.
- Keep secret values in `SecretString` or fixed-size key buffers; zeroize owned key material after use.
- Never log bearer tokens, cookies, WebAuthn responses, private keys or handoff codes.
- Keep persistence keys and serialization inside `store`.
- Consume one-time state atomically. A read followed by a delete is not replay-safe.
- Map internal failures to a generic response and retain precise context only in server logs.
- Add rejection-path tests whenever a trust boundary changes.
- `unsafe` code requires a written design rationale and independent review.

## Dioxus dashboard and site rules

- Deno is the workspace runtime and task runner; dependency versions are pinned in `package.json` and resolved
  by the committed `deno.lock`.
- Astro owns the marketing-site document structure and static routing.
- Dioxus consumes generated Protobuf types and sends binary Connect requests. Rust services remain
  authoritative for every permission, route, secret and mutation.
- Service credential values may appear only in the one-time creation dialog and must never enter query caches,
  preview fixtures, logs or persistent browser storage.
- Browser-only resources must be created in lifecycle hooks and completely disposed during cleanup. The
  Three.js scene tracks GPU resources through `scene-primitives.ts` for this reason.
- Prefer semantic HTML and CSS over JavaScript layout logic. All animation must respect reduced-motion
  preferences.
- Marketing copy must distinguish shipped behavior from roadmap work.

## Infrastructure rules

- Pulumi code declares resources; it never contains credentials or copies secret values into stack
  configuration.
- Cloudflare tokens are injected at execution time from the approved secret manager.
- The `.dev` site and its DNS are the only resources owned by `infra/cloudflare`. RustyAuth service hosting
  remains a separate deployment concern.
- Preview infrastructure changes before applying them. Review resource replacement and DNS deletion as
  destructive operations.

## Quality gates

Run the same aggregate gates as CI from the repository root:

```sh
deno task check
deno task test
```

`check` enforces Rust/Dioxus formatting and Clippy, Deno formatting and linting, Astro type checks, Go
formatting and `go vet`. `test` builds and tests the static site, runs Rust tests with the lockfile, and runs
the Cloudflare Pulumi unit/compile checks.

For release candidates, also run:

```sh
cargo build --locked --release
docker build --tag rustyauth:local .
docker build --file Dockerfile.dashboard --tag rustyauth-dashboard:local .
```

Changes to persistence, signing or recovery must also pass the real-service clean-room drill in
`compose.integration.yaml`. It proves encrypted upload, previous-key decryption, empty-target restore, default
session invalidation, signing-key replacement and ordered-event continuity against two SableDB instances and
MinIO.

## Change design

Open an architecture decision record before adding a new public protocol, online data store, authentication
factor, recovery mechanism, token class or multi-writer strategy. A decision should record the security
property being added, rejected alternatives, migration compatibility and rollback behavior.

Code review should be able to answer four questions without inference:

1. Which trust boundary changed?
2. What invalid input now fails closed?
3. What durable or public contract changed?
4. Which automated check proves the intended behavior?
