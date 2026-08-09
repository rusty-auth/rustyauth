# Identity data model

This document is the canonical developer reference for identity data persisted by RustyAuth
`0.1.0`. It describes the authoritative account aggregate, supporting indexes and lifecycle records,
what crosses each API boundary, and what RustyAuth deliberately does not store.

RustyAuth uses **account**, **user** and **identity** for the same durable subject. Every subject is
anchored by one stable UUID. Email addresses, phone numbers, profile names and passkeys are mutable
properties of that UUID; none of them is the account key.

## Persistence map

| Data | Storage | Lifetime | Included in backup |
| --- | --- | --- | --- |
| Account aggregate | `auth:user:<uuid>` | Durable | Yes |
| Email/phone lookup index | `auth:identifier:<type>:<canonical-value>` | Durable | Yes |
| Legacy email lookup index | `auth:email:<canonical-email>` | Durable compatibility record | Yes |
| Passkey uniqueness index | `auth:credential:<credential-id>` | Durable | Yes |
| Browser session metadata | `auth:session:<sha256-of-token>` | Idle and absolute expiry | Yes; skipped on restore by default |
| Registration ceremony | `auth:registration:<uuid>` | Five minutes, single use | No |
| Authentication ceremony | `auth:authentication:<uuid>` | Five minutes, single use | No |
| Development agent handoff | `auth:agent-handoff:<sha256-of-code>` | Normally 60 seconds, single use | No |
| Identity event | `auth:event:<sequence>` | Durable; no retention policy yet | Yes |
| Event cursor | `auth:event-sequence` | Durable | Yes |

All timestamps inside JSON records are unsigned Unix seconds. HTTP and RPC projections render
timestamps as RFC 3339 strings. SableDB TTL controls expiring records.

## The account aggregate

`auth:user:<uuid>` is the authoritative identity record. Multi-key mutations write the aggregate and
its indexes in an atomic SableDB pipeline.

| Field | Type | Meaning and rules | Public exposure |
| --- | --- | --- | --- |
| `id` | UUID | Stable account ID and WebAuthn user handle. Never changes when contact details or names change. | HTTP account response, RPC `User`, JWT `sub` |
| `profile` | object | Optional given, family and display names. See [Profile](#profile). | HTTP account/token response and RPC `User`; not in JWT claims |
| `identifiers` | array | One to 20 email/phone records. Exactly one record is primary. | HTTP account response and RPC `User`; selected contact projections accompany token responses |
| `passkeys` | array | WebAuthn credentials plus private authentication metadata. At least one passkey must remain. | Metadata-only HTTP/RPC projections; credential material never leaves the service |
| `session_version` | integer | Internal revocation generation copied into sessions and JWTs. A mismatch invalidates a session. | JWT claim only; not an identity-management input |
| `created_at` | Unix seconds | Account creation time. | HTTP account response and RPC `User` |
| `email` | string | Compatibility mirror of the preferred stored email. Not the source of truth for new code. | Never exposed as a raw storage field |
| `email_verified` | boolean | Compatibility mirror of that email's verification state. | Never exposed as a raw storage field |

The legacy email fields remain on disk so accounts written before the multi-identifier model still
load without changing their UUID or passkeys. A legacy email-only record is hydrated into one
primary identifier on read. New integrations must use `identifiers`.

Every account read validates the aggregate. Missing identifiers, more than 20 identifiers,
duplicates, zero or multiple primaries, unsafe profile text, non-canonical phones and inconsistent
verification timestamps fail closed instead of being silently accepted.

## Identifiers

An identifier is a discovery and contact record, not an authenticator. A passkey account can have
any mix of email and phone identifiers, including a phone-only or email-only account.

| Field | Type | Meaning |
| --- | --- | --- |
| `type` | `email` or `phone` | Identifier namespace. Type and value form the global uniqueness key. |
| `value` | string | Canonical value used for exact lookup. |
| `verified` | boolean | Whether a trusted verification workflow has confirmed control of the identifier. |
| `verifiedAt` | nullable timestamp | Time verification became true. Clearing verification also clears this value. Legacy verified emails may have no timestamp. |
| `primary` | boolean | Exactly one identifier per account is primary. |
| `createdAt` | timestamp | Time the identifier was linked to the account. |

### Canonical forms

- Email is trimmed, ASCII-lowercased and validated as the supported ASCII dot-atom form. The local
  part is at most 64 bytes, the domain at most 253 bytes and the complete value at most 320 bytes.
  Quoted local parts and internationalized addresses are not accepted in `0.1.0`.
- Phone input must start with `+`. Spaces, parentheses, hyphens and dots are accepted as input
  formatting and removed. The stored E.164 value contains 8–15 digits and cannot begin with zero.
- Identifier lookup is exact after canonicalization. There is no fuzzy, prefix or case-insensitive
  scan over stored data.

Each canonical identifier is globally unique inside the configured RustyAuth instance. The final
identifier cannot be removed. Removing the primary promotes the first remaining identifier. Making
an identifier primary does not make it verified.

For token responses, RustyAuth separately projects a preferred email and preferred phone when those
types exist. The account-wide primary wins when it has that type; otherwise the oldest identifier of
the requested type is returned. Consumers must always inspect the accompanying verification boolean.

### Verification ownership

Development mode marks browser-added identifiers verified so local work does not depend on a
delivery provider. Production registration and browser-added identifiers are unverified and emit an
`email.verification.requested` or `phone.verification.requested` event. One-time production challenges are
delivered only to exact signed-webhook subscriptions, expire, are rate limited and are atomically consumed;
codes are not retained in delivery metadata.

The private `IdentityService` cannot create a verified identifier in one step. `AddIdentifier`
rejects `verified: true` with `invalid_argument` and always stores the new identifier unverified;
`SetIdentifierVerification` is the only way to set or clear the flag, and it requires the administer
capability rather than support.

The split exists because `verified` is load-bearing in two places at once: it feeds the
`email_verified` claim downstream consumers act on, and it is what browser operator bootstrap
matches against `AUTH_OPERATOR_EMAILS`. Writing it is an identity-proofing decision, so it is priced
as one. Treat that RPC as a control-plane authority; never expose its bearer credential to a
browser.

## Profile

The profile is deliberately small. Updating it replaces all three fields; omitted or blank values
clear the corresponding field.

| Field | Required | Maximum | Use |
| --- | --- | --- | --- |
| `givenName` | No | 100 Unicode characters | Human-readable given/first name |
| `familyName` | No | 100 Unicode characters | Human-readable family/last name |
| `displayName` | No | 200 Unicode characters | Preferred presentation name |

Values are trimmed. Control characters, zero-width space, byte-order mark and Unicode directional
formatting/isolation characters are rejected to reduce UI spoofing risk. RustyAuth preserves case
and other Unicode characters; it does not split, infer or reorder names.

During passkey registration, the WebAuthn display label uses `displayName`, then joined given and
family names, then the primary identifier. The stable UUID—not a name or identifier—remains the
WebAuthn user handle.

RustyAuth does not currently persist title, middle name, pronouns, date of birth, postal address,
locale, time zone, avatar, organization role or arbitrary custom attributes.

## Passkeys

Every stored passkey belongs to exactly one account. The account aggregate stores:

| Field | Meaning |
| --- | --- |
| `id` | Unpadded Base64URL credential ID and global uniqueness key |
| `label` | User-facing label, trimmed to 1–80 characters with unsafe formatting characters rejected |
| `counter` | Last accepted authenticator signature counter |
| `created_at` | Registration time |
| `last_used_at` | Last successful authentication time, or absent before first use |
| `passkey` | Opaque `webauthn-rs` credential containing the public-key authentication state required to verify assertions |

The HTTP and private RPC APIs expose only credential ID, label and timestamps. They do not expose the
stored WebAuthn credential, public key, counter, registration state or assertion data. Passkey
material can only be created by a successful WebAuthn ceremony; the identity RPC cannot write it.

RustyAuth has no configured passkey-count limit in `0.1.0`, but it prevents duplicate credential IDs
and refuses to revoke the final passkey. A non-zero signature counter must advance; regression fails
authentication as a possible cloned credential.

## Sessions

A successful passkey authentication or development agent handoff creates a separate session record:

| Field | Meaning |
| --- | --- |
| `id` | Stable session UUID, also emitted as JWT `sid` |
| `user_id` | Owning account UUID |
| `auth_method` | `passkey` or development-only `agent` |
| `current_credential_id` | Passkey used to create the session, when applicable |
| `session_version` | Copy of the account revocation generation |
| `created_at` | Authentication time and JWT `auth_time` source |
| `last_seen_at` | Sliding idle-expiry activity time |
| `absolute_expires_at` | Non-extendable session deadline |

The cookie contains a random bearer token. RustyAuth stores only its SHA-256 digest in the SableDB
key, never the raw token. Successful authenticated requests advance `last_seen_at`. Expired,
orphaned or version-mismatched sessions are deleted and rejected.

`current_credential_id` is also an authorization input, not just metadata. When it names a passkey
that is no longer in the account's `passkeys` list, the session is deleted and rejected on its next
use. Revoking a passkey therefore ends the sessions created with it immediately, rather than leaving
them alive until `absolute_expires_at`. Sessions with no `current_credential_id` — development agent
handoffs — are unaffected.

Agent sessions can read account and credential metadata but cannot mutate profile, identifiers or
passkeys. Sensitive identifier and credential changes require a passkey session created within five
minutes. Profile and passkey-label changes require a passkey-authenticated session.

Sessions appear in logical backups so an operator can explicitly preserve them, but restore skips
them and increments every account's `session_version` by default.

## One-time WebAuthn state

Registration and authentication ceremonies are server-side records with five-minute TTLs. They
contain the challenge/state objects required by `webauthn-rs`, their account/identifier context and
an expiry. Submission uses atomic `GETDEL`, so success, invalid verification and replay all consume
the ceremony.

Additional-passkey registration also records `purpose=addCredential` and the initiating session UUID.
It cannot be confused with initial registration or completed from a different valid session. These
records are transient and excluded from backups.

## Indexes and consistency

Indexes contain only the owning account UUID:

- `auth:identifier:email:<canonical-email>` and `auth:identifier:phone:<e164>` resolve sign-in and
  enforce identifier uniqueness;
- `auth:email:<canonical-email>` preserves compatibility with the original email-only model; and
- `auth:credential:<credential-id>` resolves ownership and enforces passkey uniqueness.

Account/index writes are atomic. Backup validation checks both directions: every aggregate member
must have the expected index, and every index must point to an existing account that actually owns
the identifier or credential. A malformed or orphaned index prevents restore.

## Durable identity events

Identity mutations append ordered, tenant-tagged events. Each event persists sequence, event UUID,
type, optional account UUID in `subject`, occurrence time and a redacted JSON object. Current events
do not contain profile values, identifier values, bearer tokens, JWTs, passkey material or challenge
payloads.

Identity-related event types are:

- `identity.created`;
- `email.verification.requested`, `phone.verification.requested` and `email.sign_in.requested`;
- `identifier.added`, `identifier.removed`, `identifier.primary_changed`,
  `identifier.verified` and `identifier.unverified`;
- `profile.updated`;
- `credential.created`, `credential.renamed` and `credential.revoked`;
- `session.created`; and
- `agent.handoff.created`.

Events have no retention or acknowledgement record in `0.1.0`. Polling and streaming consumers own
their checkpoint outside RustyAuth.

## Exposure by boundary

| Boundary | Identity data returned | Deliberately excluded |
| --- | --- | --- |
| `GET /v1/account` | UUID, profile, identifiers and account creation time | Passkeys, sessions, internal generation, legacy fields |
| `GET /v1/credentials` | Passkey ID, label, timestamps, authenticator label and whether it created the current session | WebAuthn credential, public key and counter |
| Token response | Preferred email/phone with verification booleans, profile and short-lived JWT | Full identifier list and passkey/session records |
| JWT | UUID, session/tenant/authentication metadata and standard token claims | Email, phone, names, verification and passkey metadata |
| Private `IdentityService` | UUID, profile, identifiers, passkey metadata and account creation time | Stored WebAuthn credential, counter, sessions, tokens and legacy fields |
| Event APIs | Sequence, type, optional subject UUID, tenant, timestamp and redacted data | Contact/profile values and all bearer or credential payloads |
| Logical backup | Complete durable aggregate, indexes, signing state, events and optionally restorable session metadata | Ceremonies, handoffs, raw tokens and transient locks |

## What RustyAuth does not persist

RustyAuth does not store passwords, password hashes, recovery codes, raw session cookies, raw agent
handoff codes, issued JWT strings, WebAuthn assertion/attestation payloads after verification, email
or SMS verification tokens, application roles, permissions, entitlements, billing state, resource
ownership or arbitrary custom claims.

If an application needs additional person or customer data, keep it in the application's own data
model keyed by the RustyAuth UUID. Adding a new authentication factor, secret, custom identity field
or durable record family requires an explicit schema/security design, migration and backup policy;
do not hide application data inside passkey labels, profile names or event payloads.

## Integration checklist

- Store the RustyAuth UUID as the foreign identity key in downstream systems.
- Treat identifiers as mutable and verification state as independent from primary selection.
- Never use email, phone or display name as an authorization key.
- Validate JWT signature, issuer, audience, expiry, tenant and required authentication claims.
- Keep the identity RPC token in a trusted service; browser clients use the HTTP account surface.
- Persist event cursors only after downstream processing commits, because delivery is at least once.
- Issue and escrow offline recovery codes, and qualify the exact signed verification-webhook path before
  production adoption.
