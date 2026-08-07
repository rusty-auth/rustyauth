# verify-jwt-node

What a downstream service does with a RustyAuth access token: verify it against the deployment's JWKS endpoint
with [`jose`](https://github.com/panva/jose), then check the claims its own policy depends on. Requires Node
18+ and the compose stack running at `http://localhost:8081`.

## Run it

```sh
npm install
node index.mjs <access-token>
```

Get an access token from the [`relying-party-web`](../relying-party-web/) example (the "Mint token" button
prints the raw JWT in the token response), or from any signed-in session via `POST /v1/token`. Tokens expire
after `AUTH_ACCESS_TOKEN_SECONDS` (300 seconds by default), so mint one right before verifying.

The defaults match the development stack; point the script elsewhere with environment variables:

```sh
RUSTYAUTH_ISSUER=https://auth.example.com \
RUSTYAUTH_AUDIENCE=example-dashboard \
RUSTYAUTH_TENANT_ID=example \
node index.mjs <access-token>
```

## What a downstream service must check

RustyAuth's cookie session is not the authorization boundary — the JWT is. Every consumer must verify, as this
example does:

- the **signature** against `GET /.well-known/jwks.json` (`createRemoteJWKSet` fetches and caches it; the set
  already contains prepublished and recently retired keys, so rotation is seamless);
- **`iss`** equals the deployment's `AUTH_ISSUER`;
- **`aud`** equals the audience your service expects (`SPACETIME_AUDIENCE`);
- **`exp`** — tokens are short-lived by design; reject expired ones and do not add slack;
- **`tenant_id`** equals the tenant the service is scoped to;
- plus whatever claims its own policy needs (`sub` is the stable account UUID; `sid`, `token_type`, `amr` and
  `auth_time` are also present on session tokens).

Pinning `algorithms: ["ES256"]` refuses tokens signed any other way.
