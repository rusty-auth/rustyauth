# 0005: Native device sessions use a distinct keychain-bound token class

**Status:** Accepted

**Date:** 9 August 2026

## Context

The Dioxus console targets web, desktop, iOS and Android from one Rust codebase. RustyAuth `1.0.0` supports the
web client; native targets are previews pending their own distribution release. Browser sessions can rely on
an origin-bound Secure, HttpOnly, SameSite cookie, but native webviews cannot safely or consistently use that
cookie as durable application storage. Reusing bearer access tokens would also blur API authorization with
interactive operator-session lifecycle.

## Decision

Native clients exchange a successful passkey session for a separately namespaced `rdt_` device-session token.
The server stores only its digest, binds it to the account, originating passkey, session version, idle limit and
absolute limit, and accepts it only in the operator-session authentication path. Browser cookie, native device
token and service-account bearer namespaces are mutually exclusive.

The client stores the raw token only in the operating-system credential vault. It is never written to local
storage, configuration, logs or crash metadata. Sign-out deletes both server state and the local vault entry.
Passkey revocation, account-wide revoke-all, recovery and session-version changes invalidate the device token.

## Threat review

- Token theft is constrained by high entropy, digest-only server storage, idle/absolute expiry and revocation.
- Namespace confusion fails closed before capability evaluation.
- A copied token does not satisfy fresh-passkey step-up for sensitive mutations.
- Vault failure fails closed; the client does not fall back to plaintext persistence.
- Native transport accepts only the configured RustyAuth origin, refuses redirects and bounds response bytes.
- Losing the device does not preserve access after the originating passkey or account sessions are revoked.

## Consequences

Native previews and the supported browser client use equivalent authorization semantics without pretending
their storage primitives are the same. Before a native channel is supported, operators must protect the OS
account and device vault, and its release qualification must verify the platform credential-store
implementation on each supported target.

## Rejected alternatives

- Persisting the browser cookie in application storage was rejected because it defeats HttpOnly protection.
- Persisting an ordinary access token was rejected because its audience and lifecycle are not an interactive
  console session contract.
- A long-lived device secret without passkey/session binding was rejected because credential revocation would
  not contain a stolen device.

## Rollback

Disable native enrollment and revoke existing device sessions. Browser sessions, service accounts, realm
authentication and Fleet connector credentials are unchanged.
