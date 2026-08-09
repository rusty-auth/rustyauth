## Summary

Describe the problem and the resulting behavior.

## Verification

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --locked --all-targets --all-features -- -D warnings`
- [ ] `cargo test --locked`
- [ ] `deno task docs:check`
- [ ] API/OpenAPI, Protobuf, schema and normative docs updated with behavior changes
- [ ] Developer-site journey, project status and licence inventory updated when applicable

## Security review

Describe changes to WebAuthn ceremonies, sessions, tokens, tenant boundaries, storage, secrets or
deployment assumptions. Write “None” only when none of these boundaries changed.
