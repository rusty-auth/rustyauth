# 0006: Private realms use a realm-initiated, proof-bound Fleet connector

**Status:** Accepted

**Date:** 9 August 2026

## Context

Fleet must manage realms inside private networks without exposing SableDB, accepting inbound database access or
placing a permanent central credential in customer infrastructure. The connection also carries bounded
operational reads, controlled mutations and anonymous telemetry, so message identity and exact correlation are
security boundaries rather than transport conveniences.

## Decision

A private realm creates a high-entropy, short-lived, single-use pairing code and stores only its domain-separated
digest. Fleet redeems it for one opaque connection identity and assignment epoch. The realm then establishes an
outbound HTTP/2 gRPC stream over TLS. Each direction uses a separately derived proof from the pairing credential;
signed frames bind connection ID, command ID, operation, payload, deadline and correlation fields.

Fleet resolves hierarchy and authorization from the authenticated connection record. A realm never supplies an
authoritative organization, project or environment. Commands are typed, bounded, expiring and idempotent;
responses must match the exact outstanding command. Credentials rotate through a two-phase staged protocol so a
crash can retry with either the old or staged secret and converge. The realm can revoke the grant locally without
central cooperation.

## Threat review

- Pairing replay fails because redemption atomically consumes a digest-bound code.
- Cross-realm substitution fails because proofs, frames and grants bind the opaque connection and realm.
- Reordered, duplicate or fabricated responses fail exact command correlation and request binding.
- A compromised Fleet dashboard never receives connector credentials, database URLs or raw pairing secrets.
- Deadline, payload, queue and response limits bound memory and stale-command execution.
- Telemetry hierarchy poisoning fails because Fleet stamps registry IDs and assignment epoch after authentication.
- Credential rotation survives acknowledgement loss without making two permanent active credentials.
- Connector or control-plane failure has no dependency path into registration, authentication, sessions or JWKS.

Production deployments may add ingress mTLS workload identity, but mTLS does not replace the application proof
or hierarchy checks.

## Consequences

Private realms need only outbound connectivity to Fleet. The connector becomes a long-running operational
component with heartbeat, retry, rotation and audit obligations, while the realm remains the authority for its
identity data and local revocation.

## Rejected alternatives

- Fleet-to-SableDB access was rejected because the database is not an authorization boundary.
- An inbound realm management port was rejected as the only topology because many customer networks cannot
  expose one safely.
- Unsigned multiplexed commands were rejected because TLS alone does not bind application correlation after a
  gateway or process compromise.
- One shared credential for all realms was rejected because compromise would cross tenant boundaries.

## Rollback

Revoke the realm grant or remove the connector capability. Realm authentication continues locally; cached Fleet
read models remain visibly stale until retention removes them.
