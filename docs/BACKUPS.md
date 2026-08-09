# Backups and disaster recovery

This document is the normative reference for RustyAuth logical backups. It describes what a backup contains,
how the `.rauth` object is produced and validated, what the storage provider must guarantee, how backup health
is surfaced, and how to perform a clean-room restore.

Backups are implemented for both deployment roles:

- a **Realm backup** protects the complete server-side identity workspace for one realm; and
- a **Fleet backup** protects the complete central control-plane workspace.

They are separate recovery boundaries. A Fleet backup never connects to a managed realm's SableDB, and a Realm
backup never contains the central Fleet hierarchy.

## Recovery contract

RustyAuth backups are logical exports of the managed `auth:*` and `fleet:*` keyspaces. They are not SableDB
filesystem copies, block-device snapshots, continuous replication or point-in-time transaction logs.

One successful backup run performs this pipeline:

```mermaid
flowchart LR
    Trigger["Startup, schedule or CLI"] --> Lease["Acquire single-flight lease"]
    Lease --> Capture["Capture sorted SableDB records"]
    Capture --> Validate["Validate manifest and relationships"]
    Validate --> Encode["Postcard binary encoding"]
    Encode --> Compress["Zstandard level 3"]
    Compress --> Seal["AES-256-GCM envelope"]
    Seal --> Put["S3 PutObject with SHA-256 checksum"]
    Put --> ReadBack["GetObject and decrypt read-back"]
    ReadBack --> Posture["Verify version, retention and SSE"]
    Posture --> Receipt["Persist success and emit receipt"]
```

A `PutObject` response alone is not success. RustyAuth reports success only after the stored object has been
read back, decrypted, validated against its manifest and checked against the configured storage profile.

## What is recoverable

### Realm state

A Realm snapshot includes:

| State                    | Stored families                                                                          | Recovery purpose                                                                         |
| ------------------------ | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Accounts and credentials | users, identifier/email indexes, credential indexes and passkey state                    | Preserve account UUIDs, profiles, identifiers and registered authenticators              |
| Sessions                 | session records and absolute expiries                                                    | Available only for an explicitly approved session-preserving restore; skipped by default |
| Signing state            | the wrapped ES256 signing keyset                                                         | Prove the snapshot is internally recoverable before upload and restore                   |
| Dashboard administration | organization settings, operator grants, service accounts and service-credential locators | Recover durable settings and operator control-plane state                                |
| Realm-to-Fleet trust     | Fleet grants and live credential-digest locators                                         | Recover scoped central-management relationships without exposing raw bearer values       |
| Audit history            | ordered events and the event-sequence record                                             | Preserve the contiguous realm event history                                              |

### Fleet state

A Fleet snapshot includes:

| State               | Stored families                                                | Recovery purpose                                                        |
| ------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Workspace hierarchy | organizations, projects, environments and their slug indexes   | Reconstruct the complete central workspace and lookup paths             |
| Realm registrations | environment connections and their encrypted scoped credentials | Reconnect the control plane to registered realms after recovery         |
| Authorization       | role bindings and reverse subject indexes                      | Preserve operator scope across organizations, projects and environments |
| Mutation history    | idempotency records and audit records                          | Prevent replay ambiguity and retain the central audit trail             |

The exporter scans both managed prefixes for either deployment role, so a Fleet snapshot also retains every
applicable central `auth:*` record—for example its signing keyset and operator identity state—in addition to
the Fleet-specific families above. The tables describe role-specific state, not mutually exclusive filters.

Fleet connection credentials are already encrypted under the Fleet deployment's master-key ring before they
enter SableDB. The backup envelope adds an independent encryption layer around the whole snapshot.

### Deliberately excluded state

The exporter has an explicit allowlist. It excludes short-lived or operational records that should not be
replayed:

- WebAuthn registration and authentication ceremonies;
- local-agent handoffs and Fleet pairing codes;
- in-progress Fleet connection attempts;
- backup lease and persisted backup-health records;
- signing-key and operator-seen maintenance locks; and
- the restore-in-progress sentinel.

An unknown `auth:*` or `fleet:*` family fails backup creation. RustyAuth does not silently skip a future
durable record type and claim that the resulting object is a complete workspace backup.

### Recovery material outside the object

The following artifacts are required for a full deployment recovery but are intentionally not embedded in the
data object:

| Artifact                                       | Why it remains external                                                                              |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Pinned RustyAuth and Dioxus image digests      | Dashboard assets and binaries are release artifacts, not database state                              |
| Validated non-secret YAML configuration        | Infrastructure and runtime policy must be independently reproducible and reviewable                  |
| Active and previous master keys                | Required to unwrap the signing keyset and encrypted Fleet connection credentials                     |
| Active and previous backup keys                | Required to open the portable `.rauth` envelope                                                      |
| Bucket, Object Lock, IAM and KMS configuration | These controls form the storage recovery boundary itself                                             |
| Downstream application data                    | RustyAuth authenticates identities; it does not back up an application's roles, billing or resources |

Browser navigation, filters and query state are transient. Durable dashboard settings are already represented
by the Realm or Fleet records above. Keep image digests, configuration and escrowed keys in a separately
administered recovery system; storing the only decryption key in the bucket it decrypts is not a recovery
plan.

## Snapshot capture and consistency

The exporter takes the process-local mutation gate in write mode, records the capture time and scans the
managed `auth:*` and `fleet:*` keyspaces. Each included value and its TTL are read together through one
pipeline, and TTLs are converted to absolute Unix expiry timestamps so time spent uploading does not extend a
session.

Records are sorted lexicographically by key before manifest creation. The exporter enforces these safety
ceilings:

| Limit                 |     Value |
| --------------------- | --------: |
| Managed keys          | 1,000,000 |
| One stored value      |     8 MiB |
| Decompressed snapshot |   512 MiB |
| Encrypted S3 object   |   256 MiB |

The mutation gate blocks writers in the same RustyAuth process. The SableDB backup lease prevents two
RustyAuth processes from running backups simultaneously, but it does not turn a multi-writer deployment into a
datastore-wide snapshot transaction. RustyAuth `1.0.0` therefore retains the documented one-writer
qualification boundary.

## Manifest and semantic validation

Every snapshot records:

- a random snapshot UUID;
- the configured tenant identifier;
- capture time in Unix seconds;
- uniquely sorted key/value/expiry records;
- total record count;
- a SHA-256 digest of the canonical record list;
- counts by known key family; and
- the last ordered-event sequence.

Validation happens before upload and again after download. It rejects:

- a snapshot for a different tenant;
- unsupported snapshot or envelope versions;
- duplicate, unsorted or unknown keys;
- a record-count, family-count or content-digest mismatch;
- missing or multiple signing keysets;
- malformed TTL policy or a durable record carrying an expiry unexpectedly;
- gaps or tenant mismatches in the ordered event stream;
- missing, orphaned or incorrectly owned email, identifier and credential indexes;
- sessions or operator grants for unknown users;
- service credentials that are absent from their service account;
- invalid live or revoked Realm-to-Fleet credential locators;
- Fleet slugs, projects, environments or connections that cross workspace ownership boundaries;
- Fleet role bindings whose reverse indexes or target resources disagree; and
- Fleet audit/idempotency pairs whose action, resource or ownership metadata disagree.

The wrapped signing keyset is also checked using the configured active and previous master keys. RustyAuth
will not upload a snapshot whose signing material cannot be recovered by the current key ring.

## Binary `.rauth` format

New objects use the `RAUTHBK3` format. The logical snapshot is encoded with a dedicated, stable Postcard DTO,
compressed with Zstandard level 3, and then encrypted with AES-256-GCM. Compression happens before encryption
because encrypted data is intentionally incompressible.

The envelope layout is:

| Field              |     Size | Authentication                        |
| ------------------ | -------: | ------------------------------------- |
| Magic `RAUTHBK3`   |  8 bytes | AES-GCM additional authenticated data |
| Key-ID length      |   1 byte | AES-GCM additional authenticated data |
| UTF-8 key ID       | variable | AES-GCM additional authenticated data |
| Random nonce       | 12 bytes | AES-GCM additional authenticated data |
| Ciphertext         | variable | AES-GCM ciphertext                    |
| Authentication tag | 16 bytes | Appended by AES-GCM                   |

The key ID is derived as `backup-` plus the first 12 bytes of SHA-256 over the 32-byte key, encoded as hex.
The ID selects an active or previous key without storing the key itself. Header tampering, ciphertext
tampering, truncation or use of the wrong key fails authentication before decompression or record parsing.
Decoded record values are zeroized when the snapshot is dropped.

Compatibility rules:

- `RAUTHBK3` Postcard objects are created and restored;
- existing `RAUTHBK2` compressed-JSON objects remain listable, verifiable and restorable; and
- legacy `PAUTHBK1` payloads predate restorable snapshots and are rejected.

The envelope version and logical snapshot version are independent. An incompatible future binary layout must
receive a new envelope magic and DTO rather than silently changing the bytes behind `RAUTHBK3`.

## S3 object contract

New objects are written under:

```text
rustyauth-backups/v3/<tenant-id>/<RFC3339-capture-time>-<snapshot-uuid>.rauth
```

Colons in the timestamp are replaced with hyphens. The upload uses content type
`application/vnd.rustyauth.backup.v3`, sends the envelope's SHA-256 checksum, and records this non-secret
metadata:

- `snapshot-id`;
- `key-id`;
- `format-version=3`; and
- `scope=complete-server-workspace`.

Object-key validation confines reads to the configured tenant's v2 or v3 prefix, requires the `.rauth` suffix,
and rejects traversal or control characters. Listing is paginated and combines the v3 and legacy v2 prefixes.

### Storage profiles and provider posture

The default `immutable` profile requires every new v3 object to prove all of the following on `GetObject`:

1. a non-empty object version ID;
2. Object Lock mode `COMPLIANCE`;
3. a retain-until time at least `capturedAt + configured retention`, allowing five minutes of clock skew;
4. the configured server-side encryption mode; and
5. when configured, the exact SSE-KMS key ID reported by the provider.

The application does not set per-object retention or encryption headers. The bucket's default policy owns
those controls, which allows the RustyAuth S3 principal to remain limited to:

- `s3:ListBucket` on `rustyauth-backups/*`;
- `s3:GetObject`; and
- `s3:PutObject`.

Do not grant object deletion, version deletion, legal-hold changes, retention changes or governance bypass.
When SSE-KMS is used, the KMS policy separately permits the application principal to use that key only through
S3. The checked-in [AWS template](../infra/aws/backup-bucket.yaml) provisions Versioning, compliance-mode
Object Lock, bucket-default SSE-KMS, key rotation, public-access blocking, TLS enforcement and the
least-privilege bucket policy. Deployment instructions are in [infra/aws/README.md](../infra/aws/README.md).

`serverSideEncryption.mode: provider` is for a compatible provider that owns its encryption policy and does
not return an AWS-style SSE value. In the immutable profile it skips only the exact SSE-header comparison;
application AES encryption, version IDs and compliance-mode retention remain mandatory.

The explicit `portable` profile supports S3-compatible providers that do not implement Versioning, Object
Lock or AWS-style server-side encryption metadata. It keeps unique tenant-scoped object keys, the authenticated
AES-256-GCM application envelope, SHA-256 upload checksum, bounded download, manifest validation and
read-after-write decryption. It does not claim WORM retention: a provider administrator can still delete an
object. Use it only when that reduced recovery boundary is understood, and migrate production recovery points
to `immutable` storage when a compatible bucket is available.

Legacy v2 objects remain recoverable even if they predate the v3 storage-posture checks. Treat that as a
compatibility path, not evidence that an old object has WORM protection.

## Configuration

Non-secret policy belongs in `spec.backups`:

```yaml
spec:
  backups:
    enabled: true
    destination:
      endpoint: https://s3.eu-west-2.amazonaws.com
      region: eu-west-2
      bucket: example-rustyauth-backups
      urlStyle: virtual
      storageProfile: immutable
      serverSideEncryption:
        mode: aws-kms
        kmsKeyId: arn:aws:kms:eu-west-2:123456789012:key/00000000-0000-0000-0000-000000000000
    schedule:
      interval: 6h
      recoveryPointObjective: 6h
    retention: 90d
    alertAfterFailures: 2
```

Provide credential material separately through the secret store or corresponding `_FILE` inputs:

```sh
AUTH_BACKUP_ACCESS_KEY_ID=<access-id>
AUTH_BACKUP_SECRET_ACCESS_KEY=<secret>
AUTH_BACKUP_ENCRYPTION_KEY_HEX=<64-hex-character-key>
AUTH_BACKUP_PREVIOUS_KEYS_HEX=<comma-separated-old-keys>
```

The previous-key variable is optional. Generate the application key independently with `openssl rand -hex 32`;
do not reuse the master key, the KMS key or a backup key from another deployment. The parser rejects partial
backup configuration and repeated-byte placeholder keys.

Defaults and bounds are:

| Policy                            |   Default | Bound                             |
| --------------------------------- | --------: | --------------------------------- |
| Interval                          |   6 hours | 5 minutes–7 days                  |
| Recovery point objective          |  interval | interval–30 days                  |
| Immutable retention               |   90 days | 1–3,650 whole days                |
| Consecutive failures before alert |         2 | 1–100                             |
| Storage profile                    | `immutable` | `immutable` or explicit `portable` |
| Server-side encryption            | `aws-kms` | `aws-kms`, `aes256` or `provider` |

Production S3 endpoints must use HTTPS. Path-style addressing is available for compatible providers through
`urlStyle: path`. The [configuration reference](CONFIGURATION.md) documents source precedence and the legacy
environment-only equivalents.

## Scheduling, leases and shutdown

When backups are enabled, the server starts one scheduler task. Tokio's first interval tick is immediate, so
the process attempts a backup after startup and then at the configured interval. Missed ticks use delay
semantics instead of launching a burst of catch-up jobs.

Two single-flight controls apply:

- an in-process mutex serializes manual and scheduled operations in one process; and
- a one-hour SableDB lease prevents two RustyAuth processes from creating backups concurrently.

Lease release is an atomic compare-and-delete. SableDB uses `DELIFEQ`; compatible Valkey/Redis servers fall
back to an equivalent Lua script. Panics are converted into backup failures so the lease can be released and
health status updated.

On shutdown, the scheduler receives the shared shutdown signal. The server waits up to the global 20-second
grace period for signing and backup workers, then exits so a stuck provider cannot block deployment forever.

## Receipts and commands

All operator commands use the same configured bucket and key rings as the server:

| Command                                 | Writes data          | Purpose                                                                                                |
| --------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------ |
| `rustyauth backup create`               | S3 and backup status | Capture, upload, read back and return a verified receipt                                               |
| `rustyauth backup list`                 | No                   | List v3 and legacy v2 objects under the configured tenant prefix                                       |
| `rustyauth backup status`               | No                   | Print persisted health; exit non-zero while alerting                                                   |
| `rustyauth backup verify <object-key>`  | No                   | Download, check S3 posture, decrypt, validate the manifest and prove the signing keyset is recoverable |
| `rustyauth backup restore <object-key>` | Empty SableDB target | Perform the fail-closed restore workflow                                                               |
| `rustyauth doctor`                      | No                   | Check SableDB, signing state, bucket reachability, object count and backup health                      |

A create or verify receipt contains:

```json
{
  "formatVersion": 3,
  "snapshotId": "<uuid>",
  "objectKey": "rustyauth-backups/v3/<tenant>/<timestamp>-<uuid>.rauth",
  "capturedAt": 0,
  "recordCount": 0,
  "envelopeBytes": 0,
  "encryptionKeyId": "backup-<derived-id>",
  "storageProfile": "immutable",
  "objectVersionId": "<provider-version>",
  "retainedUntil": 0,
  "serverSideEncryption": "aws:kms"
}
```

Retain receipts with deployment and restore-drill evidence. They contain identifiers and storage metadata, not
encryption keys.

## Health and alerting

Scheduler health is persisted under `auth:backup:status` so a process restart cannot erase the failure
history. That operational key is excluded from snapshots. Status includes:

- whether a backup is running;
- last attempt and last success times;
- last successful object key;
- consecutive failures;
- configured RPO and retention;
- whether the last recovery point is overdue; and
- whether the deployment is alerting.

The alerting state becomes true when the last success is older than the RPO or the consecutive-failure
threshold is reached. Success resets the failure count. The scheduler emits `backup_health_alert=true` as
supporting structured telemetry.

Logging is not the alert path. Run `rustyauth backup status` or `rustyauth doctor` from an authenticated
host-side scheduled check and page on a non-zero exit. Backup health is deliberately absent from public
discovery and readiness endpoints because it reveals a deployment's recovery posture to unauthenticated
callers.

## Backup-key rotation

Application envelope keys, master keys and provider KMS keys protect different layers:

| Key                   | Protects                                                                           | Must be available during restore                        |
| --------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Backup encryption key | Portable compressed `.rauth` payload                                               | Yes, active or previous key selected by envelope key ID |
| RustyAuth master key  | Wrapped signing material and encrypted Fleet connection credentials inside records | Yes, active or previous key as appropriate              |
| Provider KMS key      | The provider's stored S3 object                                                    | Yes through the provider's recovery/IAM process         |

To rotate the application backup key:

1. Generate a new independent 32-byte key.
2. Make it `AUTH_BACKUP_ENCRYPTION_KEY_HEX`.
3. Add the former active key to `AUTH_BACKUP_PREVIOUS_KEYS_HEX`.
4. Restart all instances and create and verify a new backup.
5. Complete a clean-room restore using the new recovery point.
6. Keep each previous key until every immutable object encrypted with it has expired and the drill evidence is
   retained.

The AWS KMS envelope-input form follows the same lifecycle with
`AUTH_BACKUP_ENCRYPTION_KEY_KMS_CIPHERTEXT_B64` and `AUTH_BACKUP_PREVIOUS_KEYS_KMS_CIPHERTEXT_B64`. This KMS
layer protects the application key presented to the process; it is separate from the bucket's SSE-KMS key and
uses encryption context `rustyauth-purpose=backup,rustyauth-tenant=<tenant-id>`.

Do not use S3 lifecycle expiry as the sole signal for destroying an escrowed key: versioned and replicated
copies may have a longer provider-specific lifetime.

## Clean-room restore

### Prerequisites

Collect these before starting:

- the selected object key and its retained receipt;
- an image version capable of reading that envelope version;
- configuration with the exact expected tenant/deployment role;
- the active or previous backup key named by the envelope;
- the master-key ring required by the snapshot's wrapped signing state;
- access to the bucket and provider KMS key; and
- a new private SableDB volume with no managed `auth:*` or `fleet:*` records.

Do not restore over a live namespace. The supported response to a failed partial restore is to discard the new
volume and start again.

### Procedure

1. Provision an isolated target using the pinned image and validated configuration. Do not route production
   traffic to it.
2. List and select the intended recovery point:

   ```sh
   rustyauth backup list
   ```

3. Verify the object without writing to SableDB:

   ```sh
   rustyauth backup verify <object-key>
   ```

4. Restore into the empty target:

   ```sh
   rustyauth backup restore <object-key>
   ```

5. Run host-side health checks:

   ```sh
   rustyauth doctor
   rustyauth keys status
   rustyauth operator list
   ```

6. Start the recovered service without exposing it publicly. Verify readiness, discovery, JWKS and a real
   synthetic passkey sign-in.
7. For a Realm, verify identities, organization settings, operators, service accounts, events and any Fleet
   registration. For Fleet, verify hierarchy, realm connections, scoped roles and audit history.
8. Record the object version, receipt, restored record count, new active signing key and drill result before
   promoting the target.

Restore writes a sentinel before the first record. Records are written in atomic pipelines of at most 250.
Expired TTL records are skipped. By default all stored sessions are skipped and every user's `session_version`
is incremented. RustyAuth then loads the restored signing state, forces a fresh signing-key rotation, appends
`recovery.restored` and removes the sentinel only after those security steps succeed.

Normal startup refuses a volume that still contains the sentinel. Do not manually delete it: discard the
volume, correct the failure and restore again so no partially written workspace can serve traffic.

`--preserve-sessions` preserves session records and user session generations. It exists for an explicitly
reviewed incident where continuity outweighs the risk of carrying pre-incident sessions into the recovered
system. It is not the normal disaster-recovery path.

## Recovery objectives and drills

The recommended starting policy is:

- six-hour backup interval and six-hour RPO;
- 90 days of compliance-mode immutable retention;
- alert after two consecutive failures; and
- one monthly clean-room restore using a real retained object.

Adapt these values to the business recovery objective and the rate of identity or Fleet mutations. Keep the
interval no longer than the RPO. Retention must cover detection time, incident investigation, rebuild time and
at least one successful drill cycle.

A drill passes only when the object is downloaded from the real provider, both encryption layers are opened,
the workspace is restored to a new volume, `doctor` succeeds and an end-to-end passkey operation succeeds. A
unit test, a successful upload or a visible object in the bucket is not recovery evidence. Run the drill as a
scheduled external job and page on its non-zero exit; the production process cannot truthfully attest that an
isolated restore job ran elsewhere.

The repository integration drill exercises the same lifecycle against real SableDB and MinIO services:

```sh
docker compose -f compose.integration.yaml up -d --wait source-sabledb destination-sabledb minio
docker compose -f compose.integration.yaml run --rm minio-init
cargo test --locked --test integration_tests clean_room_backup_restore_and_rotation -- --ignored --exact
docker compose -f compose.integration.yaml down --volumes
```

## Implementation map

| Area                                   | Source                                |
| -------------------------------------- | ------------------------------------- |
| Configuration and key rings            | `src/config.rs`, `src/config/file.rs` |
| Snapshot capture and restore           | `src/store/snapshot.rs`               |
| Manifest and workspace validation      | `src/backup/snapshot.rs`              |
| Binary compression/encryption envelope | `src/backup/envelope.rs`              |
| S3 operations and posture verification | `src/backup/object.rs`                |
| Scheduling, health and alerts          | `src/backup/scheduler.rs`             |
| Operator commands                      | `src/cli.rs`                          |
| AWS immutable bucket                   | `infra/aws/backup-bucket.yaml`        |
| Real-service recovery drill            | `tests/integration_tests.rs`          |

Any change to an included key family, snapshot validation, envelope encoding, key selection, object posture,
restore behavior or operator command must update this document and the Astro developer guide at
`site/src/pages/docs/recovery.astro` in the same change.
