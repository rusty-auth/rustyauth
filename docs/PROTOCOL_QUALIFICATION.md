# Protocol compatibility and fault qualification

RustyAuth 1.0 treats stored data, Protobuf messages, Connect/gRPC behavior, Fleet capability negotiation and
backup envelopes as versioned compatibility boundaries. A deployment must reject an unknown incompatible
version before it mutates durable state; additive capabilities may be recorded but are used only when their
exact supported version is advertised.

## Supported-version policy

| Boundary                   | 1.0 policy                                                                                                   | Executable gate                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| Fleet management protocol  | Exactly `1`; `0`, `2`, partial and empty versions fail before pairing                                        | `telemetry::tests::protocol_version_skew_is_explicit_and_additive_capabilities_are_safe` |
| Fleet capabilities         | Unknown names/versions are retained as additive metadata; each operation requires its exact V1 capability    | Fleet and connector service tests                                                        |
| Analytics transport/schema | Transport and metric schema V1 only; unknown fields, enum values and high-cardinality dimensions fail closed | `analytics::tests` plus golden fixtures                                                  |
| Backup envelope            | Writes V3; restores V3 and retained V2 JSON envelopes; rejects the pre-snapshot legacy marker                | `backup::envelope::tests`                                                                |
| Signing-key storage        | Reads and rewrites the legacy single-key record without changing its signing key ID                          | `jwt::keyset::tests`                                                                     |
| Operator records           | A pre-revocation-field record loads as a live grant; explicit revocation never falls through to bootstrap    | `store::organization::tests`                                                             |
| Browser sessions           | Missing credential/step-up fields load without inventing revocation binding or user-verification assurance   | `store::sessions::tests`                                                                 |

There is no claim that an arbitrary future major version is forwards compatible. A realm with a management
protocol other than `1` must be upgraded or connected through a deliberately implemented bridge. Within
protocol V1, an unknown capability is harmless until RustyAuth implements and explicitly selects its version.

## Fuzzing

The standalone `fuzz/` package pins three libFuzzer targets and its own dependency lock:

- `analytics_batch` exercises bounded Protobuf decode plus every Analytics semantic validator;
- `management_wire` exercises discovery, connector, remote-mutation, operational-snapshot, pairing and
  acknowledgement wire decoders, and asserts successful messages round-trip without semantic change; and
- `archive_manifest_json` exercises JSON decoding, manifest validation and canonical signing-payload creation.

Run a bounded local qualification with a pinned nightly and cargo-fuzz version:

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2026-08-01 fuzz run analytics_batch -- -max_total_time=30 -timeout=10
cargo +nightly-2026-08-01 fuzz run management_wire -- -max_total_time=30 -timeout=10
cargo +nightly-2026-08-01 fuzz run archive_manifest_json -- -max_total_time=30 -timeout=10
```

The dedicated workflow repeats these targets on protocol changes and weekly. The release workflow runs all
three before any container or package publisher can start. Crashing inputs are release blockers and must be
retained as regression corpus entries after minimization.

## Fault and recovery matrix

| Injected condition                                  | Required result                                                  | Evidence                                |
| --------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------- |
| Connector payload/signature mutation                | Authentication error; no command execution                       | Connector signature unit test           |
| Duplicate or unsolicited response ID                | Rejected; an in-flight request completes at most once            | Connector hub tests                     |
| Exporter panic                                      | Background task fails without terminating authentication         | Telemetry panic-confinement test        |
| 24-hour Fleet outage and realm restart              | Authentication remains durable; exact telemetry replay converges | Ignored live integration drill          |
| Duplicate remote mutation across restart            | One durable result; changed-data replay rejected                 | Ignored live integration drill          |
| SableDB writer replacement                          | Stale writer loses lease and fences itself                       | Ignored pinned-SableDB lease drill      |
| Process replacement during an attack                | Shared rate-limit budget continues rather than resetting         | Ignored pinned-SableDB rate-limit drill |
| DNS answer containing a private or metadata address | Entire resolution set rejected and no connection attempted       | Fleet endpoint tests                    |

## Upgrade and rollback rule

Upgrade in place only when the new image passes the current fixture, legacy-record and clean-room restore
gates. Keep the prior image digest, configuration and key rings until the new image has served successfully
and a post-upgrade backup has been verified. Rollback is supported only while the prior image can read every
durable record and envelope written by the new image. If a release introduces a non-additive stored schema, it
must provide an explicit downgrade procedure or declare rollback unavailable before publication; replacing or
deleting the SableDB volume is never a rollback mechanism.

The published-artifact install/upgrade/rollback drill remains a production release-evidence item because it
requires registry artifacts and the target topology. Repository compatibility tests are necessary but do not
substitute for that drill.
