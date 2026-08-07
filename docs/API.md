# RustyAuth HTTP API

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

The bootstrap token is an administrative secret, not an end-user browser credential.

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
  "event_protocols": ["http-poll"],
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
      "occurredAt": 1786096800
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

There is no retention, acknowledgement or stable streaming contract yet.

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
