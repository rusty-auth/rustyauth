# RustyAuth examples

Small, self-contained demonstrations of the two integration surfaces a relying party touches.

Every example expects the local compose stack to be running first:

```sh
docker compose up --build
```

That serves RustyAuth at `http://localhost:8081` with the public development fixtures from `.env.example`
(bootstrap token `vtr-local-enrolment-only`).

| Example                                    | Shows                                                                                                                                                         |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`relying-party-web/`](relying-party-web/) | The full browser flow against the public HTTP API: register a passkey, sign in, mint a token, inspect its claims, sign out. A static page with no build step. |
| [`verify-jwt-node/`](verify-jwt-node/)     | What a downstream Node service does with a minted token: verify it against `/.well-known/jwks.json` and check `iss`, `aud`, `exp` and `tenant_id`.            |

The intended tour: start the stack, follow `relying-party-web/README.md` to enrol and mint a token in the
browser, then paste that token into `verify-jwt-node` to see the downstream check pass.
