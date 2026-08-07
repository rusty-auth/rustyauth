// Downstream JWT verification: what any service receiving a RustyAuth access
// token must do before trusting it. The token is ES256-signed; the public
// keys are published at /.well-known/jwks.json (active, prepublished and
// unexpired retired keys, so rotation needs no consumer coordination).

import { createRemoteJWKSet, jwtVerify } from "jose";

// Defaults match the .env.example / compose.yaml development stack.
const issuer = process.env.RUSTYAUTH_ISSUER ?? "http://localhost:8081";
const audience = process.env.RUSTYAUTH_AUDIENCE ?? "vtr-dashboard-v2-local";
const tenantId = process.env.RUSTYAUTH_TENANT_ID ?? "vtr";

const token = process.argv[2];
if (!token) {
  console.error("usage: node index.mjs <access-token>");
  console.error("Mint one with the relying-party-web example or POST /v1/token.");
  process.exit(1);
}

const jwks = createRemoteJWKSet(new URL("/.well-known/jwks.json", issuer));

try {
  // jwtVerify checks the signature against the JWKS and enforces iss, aud and
  // exp. Pinning the algorithm refuses any token that is not ES256.
  const { payload, protectedHeader } = await jwtVerify(token, jwks, {
    issuer,
    audience,
    algorithms: ["ES256"],
  });

  // Session tokens carry the deployment's single tenant; a service that
  // handles several deployments must check it explicitly.
  if (payload.tenant_id !== tenantId) {
    throw new Error(`unexpected tenant_id ${JSON.stringify(payload.tenant_id)}`);
  }

  console.log("token verified");
  console.log("  kid:      ", protectedHeader.kid);
  console.log("  subject:  ", payload.sub);
  console.log("  tenant_id:", payload.tenant_id);
  console.log("  expires:  ", new Date(payload.exp * 1000).toISOString());
  console.log("claims:", JSON.stringify(payload, null, 2));
} catch (error) {
  console.error("token rejected:", error.message);
  process.exit(1);
}
