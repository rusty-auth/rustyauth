# RustyAuth configuration examples

These files contain non-secret runtime configuration for one RustyAuth process. They are intended to be
committed next to deployment code and supplied through a read-only mount or the multiline
`RUSTYAUTH_CONFIG_YAML` variable.

- `../../rustyauth.example.yaml` is a local standalone realm and is the default used by `compose.yaml`.
- `../../rustyauth.fleet.example.yaml` is a local Fleet control plane and is the default used by
  `compose.fleet.yaml`.
- `realm-production.yaml` demonstrates production HTTPS, private SableDB networking, key lifecycle, an
  IaC-managed webhook and a complete S3-compatible backup policy.

Validate an example without supplying credentials:

```sh
cargo run -- config validate examples/config/realm-production.yaml
```

At runtime, inject the required secrets through environment variables or their `_FILE` companions. Never add
secret values to these YAML documents.
