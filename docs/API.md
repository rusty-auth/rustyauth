# RustyAuth API

This is the pre-`1.0` contract implemented by the Rust service. All JSON request bodies use
`Content-Type: application/json`. Error responses have the form:

```json
{ "error": "authentication required" }
```

Internal failures intentionally return the generic message `authentication service failed closed`.

## Access controls

The endpoint tables use these terms:

- **Origin** — the `Origin` header exactly equals `WEBAUTHN_RP_ORIGIN` without a trailing slash.
- **Bootstrap** — `x-bootstrap-token` exactly matches `BOOTSTRAP_TOKEN`.
- **Session** — a valid `passkey_auth_session` HttpOnly cookie plus the exact origin.
- **Recent session** — the valid session was created no more than five minutes ago.
- **Event RPC** — `Authorization: Bearer <AUTH_EVENT_RPC_TOKEN>` on the event service.
- **Identity RPC** — `Authorization: Bearer <AUTH_IDENTITY_RPC_TOKEN>` on the identity service.

The bootstrap and RPC tokens are administrative service secrets, not end-user browser credentials.
Each RPC token is scoped to one service, compared in constant time and rejected if it reuses another
administrative token.

## Health and discovery

### `GET /healthz`

Returns `200` when the HTTP process is live:

```json
{ "status": "ok" }
```

### `GET /readyz`

Pings SableDB. Returns `200` with `{"status":"ready"}` or `503` with
`{"status":"not_ready"}`.

### `GET /.well-known/passkey-auth`

Returns runtime capability metadata:

```json
{
  "issuer": "https://auth.example.com",
  "passkeys": true,
  "event_protocols": ["http-poll", "connect", "grpc-web", "grpc"],
  "identity_protocols": ["connect", "grpc-web", "grpc"],
  "backup_sink_configured": false,
  "scheduled_backups": false
}
```

`backup_sink_configured` means credentials and an encryption key were accepted. It does not mean
exports are scheduled.

### `GET /.well-known/openid-configuration`

Returns issuer, JWKS URL, token URL, `ES256` and public subject metadata. This resembles OpenID
discovery but RustyAuth is not claiming full OpenID Provider conformance.

### `GET /.well-known/jwks.json`

Returns the active public P-256 signing key:

```json
{ "keys": [{ "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "…" }] }
```

## Initial registration

### `POST /v1/passkeys/registration/options`

Access: Origin + Bootstrap.

Request:

```json
{ "email": "person@example.com" }
```

The email is trimmed and lowercased. Superficial format and 320-byte length checks are applied; this
is not mail-delivery verification. Existing emails return `409`.

Response `200`:

```json
{
  "ceremonyId": "4b4dbd0e-21c4-4e3a-92a0-190701d10fed",
  "options": {}
}
```

`options` is the `webauthn-rs` `CreationChallengeResponse` consumed by a WebAuthn browser adapter.

### `POST /v1/passkeys/registration/verify`

Access: Origin + Bootstrap.

Request:

```json
{
  "ceremonyId": "4b4dbd0e-21c4-4e3a-92a0-190701d10fed",
  "response": {}
}
```

The response is a browser `RegisterPublicKeyCredential`. The ceremony is atomically consumed before
verification, so a failed or replayed submission must begin again.

Response `201` sets the session cookie and returns a [token response](#token-response).

## Authentication

### `POST /v1/passkeys/authentication/options`

Access: Origin.

Request:

```json
{ "email": "person@example.com" }
```

An absent user returns the same `401 passkey authentication is unavailable` class as unavailable
authentication state.

Response `200` contains a five-minute `ceremonyId` and WebAuthn request `options`.

### `POST /v1/passkeys/authentication/verify`

Access: Origin.

Request:

```json
{
  "ceremonyId": "4b4dbd0e-21c4-4e3a-92a0-190701d10fed",
  "response": {}
}
```

The response is a browser `PublicKeyCredential`. RustyAuth requires user verification, validates the
stored credential, rejects a regressing non-zero sign counter, updates last-used state and creates a
session.

Response `200` sets the session cookie and returns a token response.

### `POST /v1/token`

Access: Session.

Returns a fresh short-lived token for the existing durable session and refreshes session activity.

### Token response

```json
{
  "email": "person@example.com",
  "emailVerified": false,
  "token": "eyJ…",
  "expiresIn": 300
}
```

In development, the response reports `emailVerified: true` so local use does not require a mail
provider. Production preserves stored verification state. Email is not embedded in the JWT.

### `POST /v1/sign-out`

Access: Origin.

Deletes the current session when present, expires the cookie and returns `204`. The operation is
idempotent.

## Credential management

### `GET /v1/credentials`

Access: Session.

Response:

```json
{
  "credentials": [
    {
      "id": "base64url-credential-id",
      "label": "Primary passkey",
      "createdAt": "2026-08-07T10:00:00Z",
      "lastUsedAt": "2026-08-07T10:05:00Z",
      "authenticator": "Passkey",
      "current": true
    }
  ]
}
```

`lastUsedAt` is an empty string before first use. `current` identifies the credential used to create
the current passkey session.

### `POST /v1/passkeys/registration/add/options`

Access: Session.

```json
{ "label": "YubiKey 5" }
```

Labels are trimmed, contain 1–80 characters and may not contain control characters. The response is
the same ceremony/options shape as initial registration.

### `POST /v1/passkeys/registration/add/verify`

Access: Session.

Uses the registration verification body. The ceremony must belong to the authenticated account.
Returns `204`; duplicate credentials return `409`.

### `POST /v1/credentials/rename`

Access: Session.

```json
{ "credentialId": "base64url-credential-id", "label": "Office security key" }
```

Returns `204` or `400` when the credential is not linked to the account.

### `POST /v1/credentials/revoke`

Access: Recent session.

```json
{ "credentialId": "base64url-credential-id" }
```

Returns `204`. RustyAuth rejects removal of the final passkey with `409`. Version `0.1.0` measures
recency from session creation; it does not run a separate step-up ceremony.

## Events and email hooks

### `POST /v1/email-links`

Access: Origin.

```json
{ "email": "person@example.com" }
```

Always returns `202` after appending `email.sign_in.requested`; the event may have no subject for an
unknown email. No token is created and no email is delivered in version `0.1.0`.

### `GET /v1/events?after=<sequence>`

Access: Bootstrap.

Returns at most 500 events strictly after the supplied cursor:

```json
{
  "events": [
    {
      "sequence": 42,
      "id": "7e47c38e-a471-4d44-9508-c12853afe64c",
      "tenantId": "vtr",
      "type": "session.created",
      "subject": "3e706d6b-091d-4dc5-a885-5de9ccbf89e8",
      "occurredAt": 1786096800,
      "data": {
        "authMethod": "passkey",
        "credentialId": "base64url-credential-id"
      }
    }
  ]
}
```

Known event types include:

- `identity.created`;
- `email.verification.requested`;
- `email.sign_in.requested`;
- `credential.created`, `credential.renamed`, `credential.revoked`;
- `session.created`; and
- `agent.handoff.created`.

HTTP polling remains available for bootstrap and diagnostics. New durable consumers should use the
streaming RPC below. No retention or compaction policy is implemented yet.

## Event streaming RPC

### `rustyauth.events.v1.AuthEventService/Subscribe`

Access: `Authorization: Bearer <AUTH_EVENT_RPC_TOKEN>`.

The server exposes one protobuf server-streaming RPC on the same port as the HTTP API:

```protobuf
rpc Subscribe(SubscribeRequest) returns (stream SubscribeResponse);
```

The canonical schema is
[`proto/rustyauth/events/v1/events.proto`](../proto/rustyauth/events/v1/events.proto). The route is
`/rustyauth.events.v1.AuthEventService/Subscribe` and accepts Connect, gRPC-Web and native gRPC.

`SubscribeRequest` fields:

| Field | Meaning |
| --- | --- |
| `after_sequence` | Last sequence durably processed; zero starts from the beginning |
| `event_types` | Up to 50 exact event types; empty selects all |
| `checkpoint_interval_seconds` | Zero selects 15 seconds, otherwise 5–60 |
| `tenant_ids` | Up to 50 exact tenant IDs; empty selects all events in this instance |

Each response is either an `AuthEvent` or an idle `AuthEventCheckpoint`. Events contain sequence,
event UUID, type, optional subject UUID, RFC 3339 timestamp, tenant ID and `data_json`. The latter is
a UTF-8 JSON object with redacted event-specific fields. It can still contain personal data such as
an email address or a credential identifier, so consumers must protect it accordingly. Assertions,
cookies, JWTs, session tokens and handoff codes are never included.

Delivery is at least once. A consumer must commit its own work and the received event sequence in
one durable operation, then reconnect with that value as `after_sequence`. Filtered events still
advance the server's internal scan cursor; checkpoint `latest_sequence` is the latest global cursor,
including events excluded by filters.

For a local native-gRPC smoke test:

```sh
grpcurl -plaintext \
  -import-path proto \
  -proto rustyauth/events/v1/events.proto \
  -H "authorization: Bearer ${AUTH_EVENT_RPC_TOKEN}" \
  -d '{"afterSequence":"0","checkpointIntervalSeconds":15}' \
  127.0.0.1:8081 \
  rustyauth.events.v1.AuthEventService/Subscribe
```

Invalid cursors or filters return `INVALID_ARGUMENT`; missing or invalid credentials return
`UNAUTHENTICATED`; exhausted stream capacity returns `RESOURCE_EXHAUSTED`; a non-contiguous or
malformed event log returns `DATA_LOSS`; and a storage failure returns `UNAVAILABLE`. One process
accepts at most 32 concurrent subscriptions.

## Private identity RPC

### `rustyauth.identity.v1.IdentityService`

Access: `Authorization: Bearer <AUTH_IDENTITY_RPC_TOKEN>`.

RustyAuth serves the following unary methods over Connect, gRPC-Web and native gRPC on the same
listener as HTTP:

| RPC | Purpose |
| --- | --- |
| `GetUser` | Read one user by stable UUID |
| `SearchUsers` | Find users by exact UUID, canonical email/phone, passkey credential ID or label, and profile names |
| `UpdateProfile` | Replace given, family and display names; empty values clear fields |
| `AddIdentifier` | Add a canonical email or E.164 phone with an explicit trusted verification state |
| `RemoveIdentifier` | Remove a non-final linked identifier |
| `SetPrimaryIdentifier` | Select the account's primary identifier |
| `SetIdentifierVerification` | Set or clear trusted verification state and timestamp |
| `RenamePasskey` | Change passkey display metadata |
| `RevokePasskey` | Remove a non-final passkey |

`SearchUsers` combines populated criteria with AND and rejects an empty search. Results are ordered
by user UUID and use opaque page tokens; the default page size is 25 and the maximum is 100. Email
and phone values are canonicalized before exact lookup. Name and passkey-label filters are also
exact, privileged administrative filters rather than public directory search.

Responses contain profile values, identifier verification metadata and passkey credential ID,
label, creation and last-used timestamps. They never contain stored WebAuthn credentials/public
keys, authenticator counters, assertions, sessions, JWTs or bearer tokens. Passkey cryptographic
material can only be registered through a WebAuthn ceremony, not written through this service.

The canonical schema is
[`proto/rustyauth/identity/v1/identity.proto`](../proto/rustyauth/identity/v1/identity.proto).

## Development-only agent handoff

`GET /v1/local-agent-handoff?code=…` exists only when `AUTH_ENV=development`. Codes are created by
the local CLI for an existing account, expire after 60 seconds, are atomically consumed and redirect
only to a hash route on the configured `localhost` application origin. The resulting agent session
lasts one hour.

The endpoint is disabled in production and is not a general login or impersonation API.

## Status codes

| Status | Meaning |
| --- | --- |
| `200` | Successful read, options creation or sign-in/token response |
| `201` | Account and initial session created |
| `202` | Email request event accepted; delivery not promised |
| `204` | Successful mutation with no body |
| `303` | Development handoff consumed and redirected |
| `400` | Invalid caller input or account/credential relationship |
| `401` | Missing/invalid origin, bootstrap, session, ceremony or WebAuthn verification |
| `409` | Existing email/credential or prohibited final-passkey removal |
| `500` | Internal dependency/state failure, reported generically |
| `503` | SableDB readiness failure |
