# relying-party-web

A static page — `index.html` plus `main.js`, no build step, no dependencies — that walks the full browser flow
against a local RustyAuth at `http://localhost:8081`:

1. register a passkey (initial enrolment needs the administrative bootstrap token generated in the ignored
   `.env.standalone.local`);
2. sign in with the same email;
3. mint a short-lived token with `POST /v1/token` and show its decoded claims;
4. sign out.

## 1. Point RustyAuth at this page's origin

WebAuthn and RustyAuth's CORS policy are bound to one exact browser origin. This page is served from
`http://localhost:8000`, so the stack must be started with that as the relying-party origin (variables from
`docs/CONFIGURATION.md`):

From the repository root:

```sh
STANDALONE_RP_ORIGIN=http://localhost:8000 scripts/local-stack standalone up
```

- The RP origin must be the exact origin serving this page — `http://localhost:8000`, no trailing slash. The
  launcher's default is `http://localhost:8081`, which fits the same-origin dashboard.
- The RP ID must equal the host of that origin. The local value `localhost` is already right, so it needs no
  change. Ports 8000 and 8081 are also the same _site_, which is what lets the `SameSite=Strict` session
  cookie flow between them.
- The public issuer stays `http://localhost:8081`; the issuer and relying-party application may be different
  origins.

Copy `BOOTSTRAP_TOKEN` from `.env.standalone.local` into the example's input only for this local evaluation.
Changing the RP origin does not invalidate existing local passkeys as long as the RP ID remains `localhost`.

## 2. Serve this directory

Any static file server works; from this directory either of:

```sh
python3 -m http.server 8000
```

```sh
deno run --allow-net --allow-read jsr:@std/http/file-server --port 8000
```

Then open <http://localhost:8000>. Register, sign in, mint a token — then paste the token into
[`../verify-jwt-node`](../verify-jwt-node/) to see the downstream verification side.

Note: the page decodes the JWT payload for display only. A real downstream service must verify the signature
against `/.well-known/jwks.json`; that is what the verify-jwt-node example shows.

Never copy the local bootstrap value into source code, logs or a production browser bundle. Production
enrolment needs a reviewed invitation or provisioning boundary.
