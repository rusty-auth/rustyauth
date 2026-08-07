// Vanilla-JS walk through the RustyAuth public HTTP API. Teaching material:
// no dependencies, no build step. The @rustyauth/client package wraps exactly
// these calls (and prefers the browser's native WebAuthn JSON helpers).

const AUTH_ORIGIN = "http://localhost:8081";

// --- base64url: RustyAuth encodes every binary WebAuthn field as an unpadded
// base64url string; the browser API wants ArrayBuffers.

function decodeBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function encodeBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// --- HTTP: every call includes credentials, because the durable session is an
// HttpOnly cookie. Failures carry a stable { "error": "…" } envelope.

async function api(path, { method = "POST", body, headers = {} } = {}) {
  const response = await fetch(`${AUTH_ORIGIN}${path}`, {
    method,
    credentials: "include",
    headers: body === undefined ? headers : { ...headers, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const envelope = await response.json().catch(() => null);
    throw new Error(envelope?.error ?? `request failed with status ${response.status}`);
  }
  return response.status === 204 ? null : response.json();
}

// --- WebAuthn ceremonies. Options arrive as { publicKey: … } with base64url
// challenge/user.id/credential ids; responses go back with each buffer
// base64url encoded again.

async function register() {
  const email = document.querySelector("#register-email").value.trim();
  const displayName = document.querySelector("#register-name").value.trim();
  const bootstrapToken = document.querySelector("#bootstrap-token").value.trim();

  const { ceremonyId, options } = await api("/v1/passkeys/registration/options", {
    headers: { "x-bootstrap-token": bootstrapToken },
    body: {
      identifier: { type: "email", value: email },
      displayName: displayName || undefined,
    },
  });

  const publicKey = {
    ...options.publicKey,
    challenge: decodeBase64Url(options.publicKey.challenge),
    user: { ...options.publicKey.user, id: decodeBase64Url(options.publicKey.user.id) },
    excludeCredentials: options.publicKey.excludeCredentials?.map((credential) => ({
      ...credential,
      id: decodeBase64Url(credential.id),
    })),
  };
  const credential = await navigator.credentials.create({ publicKey });

  return api("/v1/passkeys/registration/verify", {
    headers: { "x-bootstrap-token": bootstrapToken },
    body: {
      ceremonyId,
      response: {
        id: credential.id,
        rawId: encodeBase64Url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
          attestationObject: encodeBase64Url(credential.response.attestationObject),
        },
        clientExtensionResults: credential.getClientExtensionResults(),
      },
    },
  });
}

async function signIn() {
  const email = document.querySelector("#signin-email").value.trim();

  const { ceremonyId, options } = await api("/v1/passkeys/authentication/options", {
    body: { identifier: { type: "email", value: email } },
  });

  const publicKey = {
    ...options.publicKey,
    challenge: decodeBase64Url(options.publicKey.challenge),
    allowCredentials: options.publicKey.allowCredentials.map((credential) => ({
      ...credential,
      id: decodeBase64Url(credential.id),
    })),
  };
  const credential = await navigator.credentials.get({ publicKey });

  return api("/v1/passkeys/authentication/verify", {
    body: {
      ceremonyId,
      response: {
        id: credential.id,
        rawId: encodeBase64Url(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: encodeBase64Url(credential.response.authenticatorData),
          clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
          signature: encodeBase64Url(credential.response.signature),
          userHandle: credential.response.userHandle ? encodeBase64Url(credential.response.userHandle) : null,
        },
        clientExtensionResults: credential.getClientExtensionResults(),
      },
    },
  });
}

// --- Display helpers.

const status = document.querySelector("#status");
const tokenOutput = document.querySelector("#token-output");
const claimsOutput = document.querySelector("#claims-output");

function showToken(tokenResponse) {
  tokenOutput.textContent = JSON.stringify(tokenResponse, null, 2);
  // The JWT payload is base64url JSON; decoding it here is display only.
  // Downstream services must verify the signature — see verify-jwt-node.
  const [, payload] = tokenResponse.token.split(".");
  const claims = JSON.parse(new TextDecoder().decode(decodeBase64Url(payload)));
  claimsOutput.textContent = JSON.stringify(claims, null, 2);
}

function run(label, action) {
  return async () => {
    status.textContent = `${label}…`;
    try {
      await action();
      status.textContent = `${label}: ok`;
    } catch (error) {
      status.textContent = `${label}: ${error.message}`;
    }
  };
}

document.querySelector("#register").onclick = run("Register", async () => {
  showToken(await register());
});
document.querySelector("#sign-in").onclick = run("Sign in", async () => {
  showToken(await signIn());
});
document.querySelector("#mint-token").onclick = run("Mint token", async () => {
  showToken(await api("/v1/token"));
});
document.querySelector("#sign-out").onclick = run("Sign out", async () => {
  await api("/v1/sign-out");
  tokenOutput.textContent = "—";
  claimsOutput.textContent = "—";
});
