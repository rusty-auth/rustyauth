# Application integration

RustyAuth proves identity and issues claims. Your application owns roles, permissions, entitlements and
resource authorization. Use the stable RustyAuth account UUID as the downstream identity key; do not authorize
by an email, phone number or display name.

This guide describes the intended browser and API boundary. Exact request and response fields live in
[API](API.md), [OpenAPI](openapi.yaml) and the versioned [`proto/`](../proto/) packages.

## Pick the correct protocol

| Consumer              | Surface                            | Credential                                      |
| --------------------- | ---------------------------------- | ----------------------------------------------- |
| Relying-party browser | HTTP/JSON plus `@rustyauth/client` | Secure HttpOnly session cookie                  |
| Dioxus web dashboard  | Connect/Protobuf                   | Secure HttpOnly operator session                |
| Trusted backend       | Native gRPC/Protobuf               | Short-lived scoped service credential; TLS/mTLS |
| Application API       | Local ES256 JWT verification       | In-memory short-lived access token              |

Protobuf makes service contracts typed and efficient. TLS, authentication, server-side authorization and
scoped credentials provide security.

## 1. Start a local realm

```sh
scripts/local-stack standalone up
```

Open <http://localhost:8081>. The complete relying-party and JWT verification examples are under
[`examples/`](../examples/README.md), and the browser client is under
[`packages/client`](../packages/client/README.md).

## 2. Register a passkey

Initial registration is a privileged enrolment operation:

1. a trusted controller requests registration options with an administrative bootstrap credential;
2. RustyAuth stores WebAuthn ceremony state server-side for five minutes;
3. the browser calls `navigator.credentials.create()`;
4. RustyAuth atomically consumes and verifies the ceremony, creates the account and starts a session.

For local evaluation, read the generated bootstrap value from `.env.standalone.local`. Never ship it in a
production browser bundle. Replace this development path with a reviewed invitation or provisioning boundary.

Conceptually, the browser client performs:

```ts
import { RustyAuthClient } from "@rustyauth/client";

const auth = new RustyAuthClient({
  baseUrl: "http://localhost:8081",
  credentials: "include",
});

await auth.registerPasskey({
  email: "ada@example.test",
  bootstrapToken: localDevelopmentToken,
});
```

Pin the `1.x` client package to the exact version qualified by your application.

## 3. Sign in

1. request authentication options for a canonical email or E.164 phone;
2. call `navigator.credentials.get()` with the returned options;
3. submit the assertion to RustyAuth;
4. allow the response to set the Secure, HttpOnly, SameSite session cookie.

Always use `credentials: "include"` for same-site browser calls. JavaScript should never receive or persist
the raw durable session bearer value.

## 4. Mint a short-lived token

Call `POST /v1/token` with the authenticated browser session. Hold the returned access token in memory and
send it to your application API as a bearer token. Do not place it in local storage.

## 5. Verify in the application API

Fetch and cache `/.well-known/jwks.json`, then verify at least:

- the signature uses the expected ES256 key and allowed algorithm;
- `iss` exactly matches the configured public issuer;
- `aud` contains the expected application API audience;
- `exp` and `nbf` are valid with a small, bounded clock skew;
- `tenant_id` matches the isolated realm your API expects;
- `sub` is a valid RustyAuth account UUID; and
- any authentication-method or session claim required by the operation.

Key application records by `sub`. Profile and contact identifiers are mutable presentation/contact data.

JWT verification authenticates claims; it does not answer whether the subject may read or mutate an
application resource. Apply authorization after verification.

## 6. Consume lifecycle events

Trusted services can poll ordered events, use `rustyauth.events.v1.AuthEventService` for resumable streaming,
or receive durable signed webhooks. Create a service account with `events.read`; add `identity.read` only when
the consumer needs to call `IdentityService/GetUser` for the current safe profile. Persist the last committed
cursor, process idempotently and expect reconnects. Event projections exclude contact values, cookies, JWTs,
credential material and challenge payloads.

For a profile projection, use the event `subject` as the stable application identity key, fetch the current
safe account projection, then upsert the profile, record the event ID or sequence and advance the cursor in one
application-database transaction. Webhook receivers must verify HMAC-SHA256 over
`timestamp + "." + exact_body` before parsing, reject stale timestamps, deduplicate on
`x-rustyauth-delivery`, and return `2xx` only after durable work commits.

The public [authentication events guide](https://rustyauth.dev/authentication-events/) contains complete
`grpcurl`, profile-sync, YAML webhook and Rust signature-verification examples.

Never put private identity or event RPC credentials in browser code. Use TLS and narrowly scoped credentials;
prefer mTLS or workload identity between controlled services.

## Browser security requirements

- Serve production origins over HTTPS.
- Configure one exact WebAuthn origin and matching RP ID.
- Keep the session cookie HttpOnly, Secure and SameSite.
- Permit credentials only to the expected origin; do not use wildcard CORS.
- Keep access tokens in memory and renew through the session.
- Retain the restrictive CSP, frame denial and permissions policy at the public edge.
- Treat the Dioxus or application UI as untrusted presentation; authorize again on the server.

## Production checklist

- [ ] Bootstrap enrolment is replaced by a reviewed product flow.
- [ ] The first Owner is created through deployment-shell authorization.
- [ ] Email/SMS verification and recovery policy are designed for the application.
- [ ] Abuse controls and rate limits are deployed at appropriate boundaries.
- [ ] Every required JWT claim is tested negatively as well as positively.
- [ ] Private service credentials are short-lived, scoped, rotated and absent from logs.
- [ ] Account and credential lifecycle consumers are idempotent.
- [ ] A clean-room restore has completed with a real passkey sign-in.
- [ ] The deployment-specific [security hardening](SECURITY_HARDENING.md) requirements are accepted or completed.

## Related reference

- [Public and private APIs](API.md)
- [Identity data model](IDENTITY_DATA_MODEL.md)
- [Architecture and trust boundaries](ARCHITECTURE.md)
- [Runnable examples](../examples/README.md)
- [Security policy](../SECURITY.md)
