# Contributing to RustyAuth

Thank you for helping improve RustyAuth. Authentication code has a larger blast radius than an ordinary
application feature, so changes are reviewed for failure behavior as well as the happy path.

## Before you start

- Search existing issues and pull requests.
- For a new public endpoint, stored record, token claim, authentication method or recovery path, open a design
  issue first.
- Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).
- Never include credentials, cookies, passkey assertions, real account data or private deployment addresses in
  an issue, fixture, commit or test output.

## Development setup

Clone the repository with its pinned SableDB source:

```sh
git clone --recurse-submodules https://github.com/rusty-auth/rustyauth.git
cd rustyauth
```

For an existing clone, run `git submodule update --init --recursive`. See [Vendored source](vendor/README.md)
when changing SableDB itself; the submodule's `origin` is the RustyAuth fork, while RustyAuth's gitlink keeps
every parent commit reproducible.

Requirements:

- Rust `1.94.1`;
- Deno `2.9.3`;
- Go `1.25` for the Cloudflare control plane;
- Docker with Compose; and
- `curl` for health checks.

Run the service and its private SableDB dependency:

```sh
cargo run -- config validate rustyauth.example.yaml
scripts/local-stack standalone up
```

The launcher generates ignored local secrets and configuration, then starts the Dioxus dashboard, private Rust
backend and private SableDB. Use `scripts/local-stack fleet up` for the central Fleet topology. See the
[documentation index](docs/README.md) for the correct guide by task.

Run Rust checks directly:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --locked --release
```

Run the complete repository gates before opening a pull request:

```sh
deno install --frozen
deno task check
deno task test
```

`deno task docs:check` validates local Markdown links. The static-site tests separately prove that every
documented site route renders.

See [Engineering](docs/ENGINEERING.md) for module ownership and review rules.

The VTR integration can be exercised from the repository root with `deno task dev:v2`. That path must remain
independent of the legacy Go/PostgreSQL application.

## Design rules

1. **Fail closed.** Missing identity, ceremony, session, credential, tenant, authorization or configuration is
   an error.
2. **Keep bearer material out of durable output.** Never log or emit cookies, assertions, JWTs, handoff codes,
   backup keys or bootstrap tokens.
3. **The browser is not an authorization boundary.** Enforce access in RustyAuth or the downstream service.
4. **Preserve exact origin policy.** Do not relax RP ID or origin checks to solve deployment convenience.
5. **Keep SableDB private.** A public database port is not an acceptable configuration workaround.
6. **Make one-time state atomically one-time.** Ceremony and handoff consumption must resist replay.
7. **Document persistence changes.** Stored-record or key-layout changes need compatibility and rollback
   notes.
8. **Do not overclaim.** A primitive is not a complete recovery, email or streaming system.
9. **Keep docs and contracts atomic.** Update OpenAPI, Protobuf, configuration schemas and the closest
   normative guide in the same pull request as behavior changes.

## Tests expected by change type

| Change                    | Minimum additional coverage                                              |
| ------------------------- | ------------------------------------------------------------------------ |
| Ceremony or WebAuthn flow | success, expiry, replay, origin and account mismatch                     |
| Session behavior          | fixation, idle expiry, absolute expiry, logout and invalidation          |
| Credential management     | wrong account, duplicate, final credential and recent-auth requirement   |
| Token or key behavior     | signature, `kid`, issuer, audience, expiry and rotation compatibility    |
| Tenant/event behavior     | cross-tenant denial, cursor resume, redaction and ordering               |
| Storage change            | atomicity, existing-record compatibility and failed partial write        |
| Backup/recovery           | corruption, wrong key, wrong tenant, interrupted upload and full restore |

Use table-driven tests where they improve reviewability. A test that proves a security boundary rejects
invalid input is usually more valuable than another happy-path assertion.

## Pull requests

Keep pull requests focused and explain:

- the user or threat-model problem;
- the security invariants affected;
- public API, token or persistence changes;
- tests performed; and
- rollout, compatibility and rollback considerations.

Use conventional commit subjects such as `feat(auth):`, `fix(session):`, `docs:` and `security:`.

Generated or formatted changes should be reproducible. Do not commit local `.env` files, database volumes,
build targets or real credentials.

## Licence of contributions

Unless you explicitly state otherwise before submission, an intentional contribution submitted for inclusion
in RustyAuth is provided under the Apache License 2.0, consistent with section 5 of the project licence. The
project does not currently require a separate contributor licence agreement.

The Apache licence covers code and documentation. It does not grant rights to the RustyAuth name or logos; see
[TRADEMARKS.md](TRADEMARKS.md).
