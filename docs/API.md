# RustyAuth HTTP and private RPC API

This is the stable `1.0.0` contract implemented by the Rust service. Incompatible changes require a new major
version. The public HTTP surface is also available as a machine-readable [OpenAPI 3.1 document](openapi.yaml).
All JSON request bodies use
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
- **Passkey session** — a session created by WebAuthn, rather than a local agent handoff.
- **Recent passkey** — the valid session was created by a passkey no more than five minutes ago.
- **Event RPC** — the legacy `AUTH_EVENT_RPC_TOKEN` or a service-account JWT carrying `events.read`.
- **Identity read/write** — the legacy `AUTH_IDENTITY_RPC_TOKEN` or a service-account JWT carrying the exact
  `identity.read` or `identity.write` scope required by the method.
- **Scoped service account** — a short-lived ES256 token from `ExchangeCredential`; aggregate metrics require
  `metrics.read` and every WebhookService operation requires `webhooks.manage`.
- **Operator read** — an exact-origin passkey session belonging to any stored operator role.
- **Operator support** — an owner, administrator or support operator passkey session.
- **Operator administer** — an owner or administrator passkey session.

The bootstrap and legacy RPC tokens are administrative service secrets, not end-user browser credentials. They
are independently scoped and configuration rejects reuse between them. Prefer short-lived scoped
service-account tokens for new trusted integrations. The bootstrap token is compared in constant time over
SHA-256 digests, so a wrong value takes the same time to reject whatever its length or leading bytes.

Browser operator bootstrap requires a passkey-authenticated account holding a **verified** email identifier
listed in `AUTH_OPERATOR_EMAILS`. An unverified match is refused: every identifier on the self-service API is
caller-chosen and unverified in production, so trusting one would let any enrolled account claim an unclaimed
operator address. Because production has no way to verify an identifier before an operator exists, the first
Owner is created with `rustyauth operator promote <user-id> owner` from the host. Local-agent sessions are
deliberately rejected by every operator RPC.

For the authoritative field-by-field persistence contract—including internal fields deliberately excluded from
these APIs—see [Identity data model](IDENTITY_DATA_MODEL.md).

## Private RPC boundary

RustyAuth serves Connect, gRPC-Web and native gRPC on the same listener as HTTP. The versioned protobuf
sources are in `proto/rustyauth`. These methods are intended for trusted back-office and service-to-service
consumers; browser WebAuthn ceremonies remain on the HTTP API.

Authorization is a table naming every method one by one, not a match on the service prefix. A method that is
not in the table is rejected with `unauthenticated`, so a newly generated proto method is unreachable until
someone assigns it a policy. Streaming accepts only bearer-authenticated methods; any method needing an
operator session must stay unary.

### `rustyauth.identity.v1.IdentityService`

| RPC                         | Access                                        | Purpose                                                                                            |
| --------------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `GetUser`                   | Identity read or operator read                | Read one user by stable UUID                                                                       |
| `ListUsers`                 | Identity read or operator read                | Page through users ordered by stable UUID                                                          |
| `SearchUsers`               | Identity read or operator read                | Find users by exact UUID, canonical email/phone, passkey credential ID or label, and profile names |
| `UpdateProfile`             | Identity write or operator support            | Replace given, family and display names; empty values clear fields                                 |
| `AddIdentifier`             | Identity write or operator support            | Add a canonical email or E.164 phone. Always stored unverified                                     |
| `RemoveIdentifier`          | Identity write or operator support            | Remove a non-final linked identifier                                                               |
| `SetPrimaryIdentifier`      | Identity write or operator support            | Select the account's primary identifier                                                            |
| `SetIdentifierVerification` | Operator administer **only** — no bearer path | Set or clear trusted verification state and timestamp                                              |
| `RenamePasskey`             | Identity write or operator support            | Change passkey display metadata                                                                    |
| `RevokePasskey`             | Identity write or operator support            | Remove a non-final passkey and end the sessions it created                                         |

#### Identifier verification is a separate, higher privilege

`AddIdentifier` **rejects** a request with `verified: true` and returns `invalid_argument`:

```json
{
  "code": "invalid_argument",
  "message": "verified may not be set when adding an identifier; use SetIdentifierVerification"
}
```

Attaching an address to an account and asserting that the account controls it are two different decisions.
Honouring `verified` on the add path let any Support-capable caller create a trusted address in one step,
which produces an `email_verified` claim for an address nobody proved they own and, in the same motion, an
identifier that satisfies operator bootstrap.

The verification decision now lives only in `SetIdentifierVerification`, which requires **operator
administer** and accepts no bearer token at all. That exclusion is the point: the interceptor accepts the
service token before it consults the capability, so leaving this method on the shared bearer path would make
`AUTH_IDENTITY_RPC_TOKEN` equivalent to Owner — attach an allowlisted operator address to any account, mark it
verified, and browser bootstrap mints the role. A caller that needs to add and then verify makes two calls at
two privilege levels, and only a human operator session can make the second.

`SearchUsers` combines every populated criterion with AND and rejects an empty search. Email and phone
searches use their canonical exact indexes. Name and passkey-label filters are exact, privileged
administrative filters. Results are ordered by user UUID with opaque pagination tokens; the default page is 25
and the maximum is 100.

The returned `User` contains profile fields, identifier verification metadata, and passkey ID, label, creation
and last-used timestamps. It never contains the stored WebAuthn credential, public key, authenticator counter,
assertion data, sessions or tokens. Passkey cryptographic material can only be registered through a WebAuthn
ceremony, not written through gRPC.

### `rustyauth.events.v1.AuthEventService`

`Subscribe` replays the durable event log after `after_sequence` and then follows new events. It supports
exact event-type and tenant filters plus periodic checkpoints. Delivery is at least once: consumers must
persist their cursor only after their own work commits. A missing or malformed sequence terminates the stream
with `DATA_LOSS` instead of silently skipping the event. Authentication accepts the legacy event RPC token or
a short-lived service-account JWT carrying `events.read`.

### `rustyauth.organization.v1.OrganizationService`

| RPC                       | Access                               | Purpose                                            |
| ------------------------- | ------------------------------------ | -------------------------------------------------- |
| `GetOrganization`         | Operator read                        | Read the deployment's durable organization         |
| `GetCurrentOperator`      | Operator read                        | Resolve the current passkey session to an operator |
| `UpdateOrganization`      | Operator administer                  | Replace the organization display name              |
| `ListOperators`           | Operator read                        | Page through durable operator records              |
| `CreateAccountInvitation` | Operator administer + recent passkey | Issue an identifier-bound code returned once       |
| `ListAccountInvitations`  | Operator read                        | Page through redacted invitation state             |
| `RevokeAccountInvitation` | Operator administer + recent passkey | Revoke an unused invitation                        |

Version `1.0.0` supports one organization per SableDB namespace. The explicit resource and stable UUID allow a
future migration without claiming multi-tenant isolation today.

### `rustyauth.service_accounts.v1.ServiceAccountService`

| RPC                    | Access              | Purpose                                                      |
| ---------------------- | ------------------- | ------------------------------------------------------------ |
| `ListServiceAccounts`  | Operator read       | Search and page through non-human principals                 |
| `GetServiceAccount`    | Operator read       | Read one principal and redacted credential metadata          |
| `CreateServiceAccount` | Operator administer | Create an active principal with allowed scopes               |
| `UpdateServiceAccount` | Operator administer | Change metadata, status and granted scopes                   |
| `CreateCredential`     | Operator administer | Issue a high-entropy credential shown exactly once           |
| `RevokeCredential`     | Operator administer | Permanently revoke one credential                            |
| `ExchangeCredential`   | Service credential  | Exchange the credential for a short-lived ES256 bearer token |

Allowed scopes are `events.read`, `identity.read`, `identity.write`, `metrics.read` and `webhooks.manage`. An
exchange may request only a subset of the stored grant; omitting requested scopes returns the full grant. Raw
credentials use a random `rsa_` value, are indexed by SHA-256 and never appear in list or get responses.
Disabled accounts, expired credentials, revoked credentials and scope escalation fail closed.

### `rustyauth.webhooks.v1.WebhookService`

Every method accepts an appropriately privileged operator session or a short-lived service-account JWT
carrying `webhooks.manage`. The scope deliberately covers both desired-state changes and operational actions;
grant it only to automation that is allowed to create, rotate, test, replay and delete dashboard-managed
destinations.

The Protobuf contract covers destination CRUD, one-time signing-secret creation and rotation, test delivery,
delivery history and replay. Each `Webhook` carries `management_source`:

- `WEBHOOK_MANAGEMENT_SOURCE_CONFIGURATION` means the desired state came from `spec.webhooks`. Clients render
  destination fields read-only; updates and deletes must be made in YAML and deployed through the normal IaC
  path.
- `WEBHOOK_MANAGEMENT_SOURCE_DASHBOARD` means an authorized operator created the destination interactively and
  may update or delete it through the service.

Operational actions such as testing, delivery inspection and signing-secret rotation remain separate from
desired-state ownership. Deliveries are durable, signed with HMAC-SHA256 over the exact body and timestamp,
retried with bounded exponential backoff, and replayable while their source event remains retained. Redirects
are disabled. A destination cursor advances only after success or terminal failure, giving at-least-once
delivery without silently skipping events.

### `rustyauth.metrics.v1.MetricsService`

The standalone realm serves bounded aggregate metrics to an authenticated operator session:

| RPC                       | Purpose                                                                   |
| ------------------------- | ------------------------------------------------------------------------- |
| `GetOverview`             | Aggregate users, authentication, webhook and backup health                |
| `QuerySeries`             | Bounded time series for an allowed metric, granularity and filter set     |
| `GetAuthenticationFunnel` | Registration and authentication starts, completions and expired challenge |
| `GetFailureBreakdown`     | Bounded aggregate error-class counts                                      |

These responses never include user, email, phone, IP address, credential or webhook URL dimensions. This is
the per-realm runtime service. The same durable projector feeds the M10 outbound Fleet telemetry path.

### `rustyauth.analytics.v1` Fleet Analytics

The analytics package defines the realm interchange and the dedicated, served Fleet product API:

| Message boundary                | Purpose                                                                    |
| ------------------------------- | -------------------------------------------------------------------------- |
| `TelemetryBucketBatch`          | Bounded complete snapshots for authenticated, retryable realm export       |
| `TelemetryBatchAcknowledgement` | Exact per-bucket revision acceptance or typed rejection                    |
| `ReportingCoverage`             | Expected, reporting, stale, disabled and unsupported source accounting     |
| `MetricBucketArchiveManifest`   | Signed, credential-free identity and integrity metadata for Parquet import |
| `AnalyticsService`              | Bounded hierarchy reads, comparison, coverage and organization policy      |

The realm projector, bounded outbox and `telemetry.rollups.v1` connector are mounted in M10. Fleet
authenticates the connection, validates the batch, stamps its stored organization/project/environment
assignment and commits an exact-revision acceptance record before acknowledging. `AnalyticsService` serves
`GetAnalyticsOverview`, `QueryMetricSeries`, `GetAuthenticationFunnel`, `GetFailureBreakdown`,
`GetReportingCoverage`, `CompareScopes`, `GetAnalyticsPolicy` and `UpdateAnalyticsPolicy`. It supports
authorized Fleet, organization, project, environment and realm scopes, caps ranges at 28 days, reports every
metric family's coverage and never accepts SQL. Numerical serving uses private GreptimeDB
canonical/hourly/daily tables when configured; the trusted Fleet ledger remains the bounded fallback and
authority for hierarchy, acceptance, coverage and policy.

Every producer and importer must follow the [Fleet Analytics V1 semantic contract](FLEET_ANALYTICS_V1.md),
including five-minute closed buckets, full-snapshot revisions, fixed histogram profiles, prohibited identity
dimensions, trusted central hierarchy stamping and explicit coverage. The shorter
[developer reference](https://rustyauth.dev/docs/fleet-analytics-v1) mirrors those boundaries.

## Health and discovery

### `GET /healthz`

Returns `200` when the HTTP process is live:

```json
{ "status": "ok" }
```

### `GET /readyz`

Pings SableDB. Returns `200` with `{"status":"ready"}` or `503` with `{"status":"not_ready"}`.

### `GET /.well-known/passkey-auth`

Returns runtime capability metadata:

```json
{
  "issuer": "https://auth.example.com",
  "passkeys": true,
  "event_protocols": ["http-poll", "connect", "grpc-web", "grpc"],
  "identity_protocols": ["connect", "grpc-web", "grpc"]
}
```

This endpoint is unauthenticated and deliberately says nothing about backups. Reporting whether backups exist,
when the last one succeeded, or whether they are currently failing tells an attacker how recoverable the
deployment is before they attempt anything destructive. Backup posture is available to an operator on the host
through `rustyauth doctor`, which reports `lastAttemptAt`, `lastSuccessAt` and `consecutiveFailures` alongside
object count and reachability.

### `GET /.well-known/openid-configuration`

Returns issuer, JWKS URL, token URL, `ES256` and public subject metadata. This resembles OpenID discovery but
RustyAuth is not claiming full OpenID Provider conformance.

### `GET /.well-known/jwks.json`

Returns the public P-256 signing keyset:

```json
{ "keys": [{ "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "…" }] }
```

The set contains the active key, any prepublished staged key and unexpired retired keys needed to verify
existing access tokens. Responses are publicly cacheable for five minutes.

## Initial registration

### `POST /v1/passkeys/registration/options`

Access: Origin + invitation in production; Origin + Bootstrap in development.

Request:

```json
{
  "identifier": { "type": "phone", "value": "+44 7700 900123" },
  "invitationCode": "rinv_…",
  "givenName": "Ada",
  "familyName": "Lovelace",
  "displayName": "Ada Lovelace"
}
```

Exactly one identifier is required. Production also requires a one-time operator-issued invitation bound to
the canonical identifier. Only the invitation digest is stored; it is consumed atomically in the same SableDB
transaction that creates the account and first passkey. Development uses the bootstrap header instead. New
clients can supply an explicit `identifier` with type `email` or `phone`; `{ "email": "person@example.com" }`
remains supported, and `{ "phone":
"+447700900123" }` is shorthand for a phone identifier. Emails are trimmed,
lowercased and must use the supported ASCII dot-atom address form. Phone numbers are normalized to
international E.164 form and must contain 8–15 digits. Existing identifiers return `409`.

The three profile names are optional. Given and family names contain at most 100 characters; display names
contain at most 200. Values are trimmed; control and invisible directional-formatting characters are rejected.
The display name, or the joined given and family names, becomes the WebAuthn display label. The stable
RustyAuth user UUID remains the WebAuthn user handle.

Response `200`:

```json
{
  "ceremonyId": "4b4dbd0e-21c4-4e3a-92a0-190701d10fed",
  "options": {}
}
```

`options` is the `webauthn-rs` `CreationChallengeResponse` consumed by a WebAuthn browser adapter.

### `POST /v1/passkeys/registration/verify`

Access: Origin + invitation ceremony in production; Origin + Bootstrap in development.

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
{ "phone": "+44 7700 900123" }
```

The request accepts the same explicit identifier and email/phone shorthand shapes as registration. An absent
user returns the same `401 passkey authentication is unavailable` class as unavailable authentication state.
RustyAuth loads every passkey attached to the resolved account; identifiers are account discovery keys, not
passkey credentials.

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

The response is a browser `PublicKeyCredential`. RustyAuth requires user verification, validates the stored
credential, rejects a regressing non-zero sign counter, updates last-used state and creates a session.

Response `200` sets the session cookie and returns a token response.

### `POST /v1/token`

Access: Session.

Returns a fresh short-lived token for the existing durable session and refreshes session activity.

### Token response

```json
{
  "email": "person@example.com",
  "emailVerified": true,
  "phoneNumber": "+447700900123",
  "phoneNumberVerified": false,
  "profile": {
    "givenName": "Ada",
    "familyName": "Lovelace",
    "displayName": "Ada Lovelace"
  },
  "token": "eyJ…",
  "expiresIn": 300
}
```

`email` and `phoneNumber` are nullable when an account does not have that identifier type. In development,
present identifiers report as verified so local use does not require delivery providers. Production preserves
stored verification state. Contact details and profile fields are not embedded in the JWT.

### `POST /v1/sign-out`

Access: Origin.

Deletes the current session when present, expires the cookie and returns `204`. The operation is idempotent.

### `POST /v1/passkeys/step-up/options` and `/verify`

Access: Passkey session. Runs a dedicated user-verifying assertion bound to the current account and session.
Successful verification starts a five-minute assurance window. A fresh user-verifying passkey sign-in starts
the same window; refreshing or merely using the session does not extend it.

### `POST /v1/sessions/revoke-all`

Access: Recently stepped-up passkey session. Increments the account's durable session version, invalidating
every browser session including the current one, clears the session cookie and returns `204`.

## Account profile and identifiers

Passkeys, identifiers and the basic profile belong to the stable account UUID. Changing a contact address or
number never changes the WebAuthn user handle and does not require re-registering the account's passkeys.

### `GET /v1/account`

Access: Session.

```json
{
  "id": "3e706d6b-091d-4dc5-a885-5de9ccbf89e8",
  "profile": {
    "givenName": "Ada",
    "familyName": "Lovelace",
    "displayName": "Ada Lovelace"
  },
  "identifiers": [
    {
      "type": "email",
      "value": "person@example.com",
      "verified": true,
      "verifiedAt": "2026-08-07T10:00:00Z",
      "primary": true,
      "createdAt": "2026-08-07T10:00:00Z"
    }
  ],
  "createdAt": "2026-08-07T10:00:00Z"
}
```

`verifiedAt` may be `null` for a verified email migrated from the original single-email record, because that
format stored verification state without its timestamp.

### `POST /v1/account/profile`

Access: Passkey session. Replaces the small profile and returns the account response. Omitted or blank fields
clear their current values. Local agent sessions remain read-only for identity data.

```json
{ "givenName": "Ada", "familyName": "Lovelace", "displayName": "Ada" }
```

### `POST /v1/account/identifiers`

Access: Recent passkey.

```json
{ "type": "phone", "value": "+44 7700 900123" }
```

Adds a globally unique identifier and returns `201` with the account response. An account may hold at most 20
identifiers. Development marks the identifier verified immediately. Production stores it unverified and
requires the verification endpoints below.

### `POST /v1/account/identifiers/verification/request`

Access: Session. Creates a single-use 15-minute challenge and delivers its raw code only through an explicitly
subscribed `identifier.email.verification` or `identifier.phone.verification` signed webhook. Wildcard
subscriptions do not receive verification codes. Only a domain-separated digest is persisted; the code is
never written to the auth event log or webhook-delivery metadata. Production returns `503` and deletes the
challenge when no delivery succeeds. Development returns `developmentCode` for local testing.

### `POST /v1/account/identifiers/verification/verify`

Access: Session. Atomically consumes `{ "challengeId": "…", "code": "…" }`, verifies that it belongs to the
current account and linked identifier, marks the identifier verified and returns `204`.

### `POST /v1/account/identifiers/primary`

Access: Recent passkey. Makes the linked identifier primary and returns the account response.

```json
{ "type": "email", "value": "person@example.com" }
```

### `POST /v1/account/identifiers/remove`

Access: Recent passkey. Removes the linked identifier and returns the account response. Removing the final
identifier returns `409`; when the primary identifier is removed, the oldest remaining identifier becomes
primary.

```json
{ "type": "phone", "value": "+447700900123" }
```

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

`lastUsedAt` is an empty string before first use. `current` identifies the credential used to create the
current passkey session.

### `POST /v1/passkeys/registration/add/options`

Access: Recent passkey.

```json
{ "label": "YubiKey 5" }
```

Labels are trimmed, contain 1–80 characters and may not contain control or invisible directional- formatting
characters. The response is the same ceremony/options shape as initial registration.

### `POST /v1/passkeys/registration/add/verify`

Access: Recent passkey.

Uses the registration verification body. The ceremony must belong to the authenticated account and the exact
passkey session that started it. Returns `204`; duplicate credentials return `409`.

### `POST /v1/credentials/rename`

Access: Passkey session.

```json
{ "credentialId": "base64url-credential-id", "label": "Office security key" }
```

Returns `204` or `400` when the credential is not linked to the account.

### `POST /v1/credentials/revoke`

Access: Recent passkey.

```json
{ "credentialId": "base64url-credential-id" }
```

Returns `204`. RustyAuth rejects removal of the final passkey with `409`. Recency is measured from the latest
user-verifying passkey sign-in or dedicated step-up, never from a passive session refresh or request.

Revoking a passkey also ends every session that passkey created. The next request presenting such a session
finds that its `current_credential_id` is no longer attached to the account; the session record is deleted and
the request is rejected as unauthenticated. This applies to the HTTP API and to
`rustyauth.identity.v1.IdentityService/RevokePasskey` equally, because both paths validate sessions through
the same check.

Sessions with no originating credential — development agent handoffs — are unaffected, since there is no
passkey to revoke.

## Offline account recovery

### `POST /v1/account/recovery-codes`

Access: Recently stepped-up passkey session. Invalidates the old set and returns ten new high-entropy `rrc_`
codes exactly once. Only domain-separated SHA-256 digests are persisted. Operators should instruct the user to
store these offline; the codes cannot be displayed again.

### `POST /v1/passkeys/recovery/options` and `/verify`

Access: Origin. The options request supplies an identifier, one recovery code and a label for the replacement
passkey. A valid code is atomically consumed before the WebAuthn ceremony begins. Successful verification adds
the replacement passkey, increments the durable session version to revoke all prior sessions, clears every
remaining recovery code and creates a new passkey session. Responses deliberately collapse lookup, code and
account-state failures into `401 account recovery is unavailable`.

## Events and email hooks

### `POST /v1/email-links`

Access: Origin.

```json
{ "email": "person@example.com" }
```

Always returns `202` after appending `email.sign_in.requested`; the event may have no subject for an unknown
email. This privacy-preserving application hook deliberately creates no authentication token and RustyAuth
does not send email. Known-account consumers may use the subject with an independently authorized identity
lookup and the durable signed-webhook delivery path; the endpoint is not an authentication factor.

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
      "data": {}
    }
  ]
}
```

Known event types include:

- `identity.created`;
- `email.verification.requested` and `phone.verification.requested`;
- `email.sign_in.requested`;
- `identifier.added`, `identifier.removed`, `identifier.primary_changed`, `identifier.verified`,
  `identifier.unverified` and `profile.updated`;
- `credential.created`, `credential.renamed`, `credential.revoked`;
- `session.created`;
- `operator.created` and `operator.promoted`; and
- `agent.handoff.created`.

`operator.promoted` records a role granted with `rustyauth operator promote`. Because that command is the only
way to create the first Owner, treat an unexplained `operator.promoted` as a privilege-escalation signal.

There is no retention or server-side acknowledgement record. The private event RPC provides at-least-once
replay/follow streaming; consumers persist their own sequence after processing.

## Development-only agent handoff

`GET /v1/local-agent-handoff?code=…` exists only when `AUTH_ENV=development`. Codes are created by the local
CLI for an existing account, expire after 60 seconds, are atomically consumed and redirect only to a hash
route on the configured `localhost` application origin. The resulting agent session lasts one hour.

The endpoint is disabled in production and is not a general login or impersonation API.

## Response headers and limits

Every response carries `Content-Security-Policy`, `X-Frame-Options: DENY`,
`Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Permissions-Policy`,
`X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. `Strict-Transport-Security` is added in
production only. The exact values are in [Deployment](DEPLOYMENT.md#response-headers).

`Cross-Origin-Resource-Policy: same-origin` means a cross-origin page cannot embed RustyAuth responses as
subresources. It does not affect the CORS-authorized `WEBAUTHN_RP_ORIGIN` fetches the browser client makes,
which remain governed by the exact-origin CORS policy.

Requests are bounded at 30 seconds, a 256 KiB REST body and a 64 KiB RPC body.

Unauthenticated endpoints are rate limited per caller address over a fixed 60-second window, so enumeration is
not free while a person retrying a failed passkey tap is not throttled under normal load. A refused request
returns `429` with a `Retry-After` header giving the seconds until the window resets.

The limiter tracks a bounded number of distinct callers. A flood from more distinct addresses than it can hold
makes it refuse rather than forget, so a wide distributed flood degrades to a service-wide `429` instead of an
unmetered authentication surface. That is the deliberate direction to fail, but it means such a flood is a
denial of service; see the limitations in SECURITY.md.

| Class               | Endpoints                                                         | Budget per minute |
| ------------------- | ----------------------------------------------------------------- | ----------------- |
| Identifier probe    | Registration and authentication options, `POST /v1/email-links`   | 10                |
| Ceremony            | Registration and authentication verification, development handoff | 30                |
| Credential exchange | Service-account token exchange                                    | 60                |

## Status codes

| Status | Meaning                                                                       |
| ------ | ----------------------------------------------------------------------------- |
| `200`  | Successful read, options creation or sign-in/token response                   |
| `201`  | Account and initial session created                                           |
| `202`  | Email request event accepted; delivery not promised                           |
| `204`  | Successful mutation with no body                                              |
| `303`  | Development handoff consumed and redirected                                   |
| `400`  | Invalid caller input or account/credential relationship                       |
| `401`  | Missing/invalid origin, bootstrap, session, ceremony or WebAuthn verification |
| `408`  | Request exceeded the 30-second ceiling                                        |
| `409`  | Existing identifier/credential, identifier limit, or prohibited final removal |
| `413`  | Request body exceeded 256 KiB                                                 |
| `429`  | Rate-limit budget exhausted; retry after the `Retry-After` interval           |
| `500`  | Internal dependency/state failure, reported generically                       |
| `503`  | SableDB readiness failure                                                     |
