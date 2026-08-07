# Identity data model

RustyAuth keeps authentication state and the safe identity projection in one durable user record.
This document is the field and exposure contract for the private identity RPC.

## User

| Field | Persisted | Identity RPC | Searchable | Mutable by identity RPC |
| --- | --- | --- | --- | --- |
| Stable UUID | Yes | Yes | Exact | No |
| Given, family and display names | Yes | Yes | Exact | Replace/clear |
| Email identifiers | Yes | Yes | Canonical exact | Add/remove/primary/verification |
| Phone identifiers | Yes | Yes | Canonical exact | Add/remove/primary/verification |
| Passkey credential ID | Yes | Yes | Exact | Revoke only |
| Passkey label | Yes | Yes | Exact | Rename |
| Passkey created/last-used timestamps | Yes | Yes | No | No |
| WebAuthn credential/public key | Yes | No | No | No |
| Authenticator counter | Yes | No | No | No |
| Session version, sessions and tokens | Yes | No | No | No |

The legacy `email` and `emailVerified` fields remain on disk for compatibility. The identifier list
is authoritative for new code; reading a legacy account creates an in-memory primary email
identifier without changing the user UUID.

## Invariants

- A user has one to 20 identifiers and exactly one is primary.
- Email identifiers are lowercase canonical addresses; phone identifiers are canonical E.164.
- An identifier maps to at most one user through `auth:identifier:<type>:<value>`.
- `verifiedAt` is present only when `verified` is true.
- A user retains at least one passkey and one identifier.
- Profile fields are optional, trimmed and bounded to 100/100/200 Unicode characters.
- Profile and passkey labels reject control, zero-width and bidirectional-formatting characters.

Mutations serialize through the store's single-writer guard and write the user/index changes and
ordered event in one atomic SableDB pipeline. Exact profile and label search scans bounded user keys;
indexed UUID, identifier and credential-ID criteria take a direct lookup path.
