# RustyAuth examples

Small, self-contained demonstrations of the two integration surfaces a relying party touches.

Every example expects the local standalone stack to be running first:

```sh
scripts/local-stack standalone up
```

That generates private development values in ignored `.env.standalone.local`, then serves the Dioxus dashboard
at `http://localhost:8081` with the backend and SableDB on private Compose networks. No working bootstrap
token is committed to the repository.

| Example                                    | Shows                                                                                                                                                         |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`relying-party-web/`](relying-party-web/) | The full browser flow against the public HTTP API: register a passkey, sign in, mint a token, inspect its claims, sign out. A static page with no build step. |
| [`verify-jwt-node/`](verify-jwt-node/)     | What a downstream Node service does with a minted token: verify it against `/.well-known/jwks.json` and check `iss`, `aud`, `exp` and `tenant_id`.            |

The intended tour: start the stack with the relying-party origin described in
[`relying-party-web/README.md`](relying-party-web/README.md), enrol and mint a token in the browser, then
paste that token into `verify-jwt-node` to see the downstream check pass. These are evaluation flows;
bootstrap is an administrative credential and must not ship in a production browser bundle.
