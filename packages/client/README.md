# @rustyauth/client

Framework-agnostic browser client for the RustyAuth **public** passkey HTTP API — the `/v1/*` JSON surface
documented in `docs/API.md`. It drives the WebAuthn ceremonies with `navigator.credentials`, sends every
request with `credentials: "include"` for the HttpOnly session cookie, and has zero runtime dependencies.

The private ConnectRPC surface (identity, events, organization and service-account services) is deliberately
out of scope here; use `@rustyauth/protocol` with `@rustyauth/connect-solid` for that.

## Usage

```ts
import { createRustyAuthClient, RustyAuthError } from "@rustyauth/client";

const auth = createRustyAuthClient({ baseUrl: "http://localhost:8081" });

// Register a new account. Initial enrolment is administrative and needs the
// deployment's bootstrap token; the browser prompts for a passkey.
await auth.register({
  identifier: { type: "email", value: "person@example.com" },
  displayName: "Ada Lovelace",
  bootstrapToken: "vtr-local-enrolment-only", // dev fixture from .env.example
});

// Later: sign in with the same identifier. The session cookie is set for you.
const signedIn = await auth.signIn({ type: "email", value: "person@example.com" });
console.log(signedIn.email, signedIn.expiresIn);

// Mint a fresh short-lived JWT for calls to your own backend.
const { token } = await auth.mintToken();

// Account and passkey management on the current session.
const account = await auth.getAccount();
const passkeys = await auth.listCredentials();
await auth.renameCredential({ credentialId: passkeys[0].id, label: "Laptop" });

await auth.signOut();
```

Failures throw `RustyAuthError` with the HTTP `status`, the server's `{ error: "…" }` envelope as `body`, and
`retryAfterSeconds` when rate limited:

```ts
try {
  await auth.signIn({ type: "email", value: "person@example.com" });
} catch (error) {
  if (error instanceof RustyAuthError && error.status === 401) {
    // No such account, or the ceremony was refused.
  }
}
```

The page calling `register`/`signIn` must be served from the exact `WEBAUTHN_RP_ORIGIN` the server is
configured with; RustyAuth's CORS policy admits only that origin.

## WebAuthn JSON mapping

Options bodies are the `webauthn-rs` serializations (`{ publicKey: … }` with unpadded base64url binary fields)
and verify bodies are the spec `RegistrationResponseJSON`/`AuthenticationResponseJSON` shapes. The client
prefers the native `PublicKeyCredential.parseCreationOptionsFromJSON`, `parseRequestOptionsFromJSON` and
`credential.toJSON()` when the browser provides them and falls back to equivalent manual conversions (exported
as `creationOptionsFromJSON`, `requestOptionsFromJSON`, `registrationResponseToJSON` and
`authenticationResponseToJSON`).

## License

Apache-2.0
