import http from "k6/http";
import encoding from "k6/encoding";
import exec from "k6/execution";
import { check } from "k6";
import { SharedArray } from "k6/data";
import { Counter, Rate, Trend } from "k6/metrics";

const fixtures = new SharedArray(
  "single-realm-fixtures",
  () =>
    open(__ENV.FIXTURES_PATH || "/data/fixtures.jsonl")
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line)),
);

const mode = __ENV.MODE || "read";
const rate = Number(__ENV.ARRIVAL_RATE || (mode === "signin" ? 6 : 25));
const timeUnit = __ENV.TIME_UNIT || (mode === "signin" ? "1m" : "1s");
const duration = __ENV.DURATION || (mode === "signin" ? "5m" : "90s");
const preAllocatedVUs = Math.max(10, Number(__ENV.PRE_ALLOCATED_VUS || Math.ceil(rate * 0.5)));
const maxVUs = Math.max(preAllocatedVUs, Number(__ENV.MAX_VUS || Math.ceil(rate * 3)));

if (!__ENV.TARGET_URL || !__ENV.RP_ORIGIN) {
  throw new Error("TARGET_URL and RP_ORIGIN are required");
}
if (!Number.isInteger(rate) || rate <= 0) throw new Error("ARRIVAL_RATE must be a positive integer");
if (fixtures.length === 0) throw new Error("fixture dataset is empty");

const authenticatedReadDuration = new Trend("authenticated_read_duration", true);
const authenticatedReadFailures = new Rate("authenticated_read_failures");
const signInDuration = new Trend("signin_duration", true);
const signInFailures = new Rate("signin_failures");
const unplanned5xx = new Counter("unplanned_5xx");

const scenario = {
  executor: "constant-arrival-rate",
  rate,
  timeUnit,
  duration,
  preAllocatedVUs,
  maxVUs,
  gracefulStop: "15s",
  exec: mode === "signin" ? "signIn" : "authenticatedRead",
};

export const options = {
  scenarios: { [mode]: scenario },
  summaryTrendStats: ["avg", "min", "med", "max", "p(90)", "p(95)", "p(99)"],
  thresholds: mode === "signin"
    ? {
      signin_failures: ["rate<0.001"],
      signin_duration: ["p(95)<750", "p(99)<1500"],
      unplanned_5xx: ["count==0"],
      dropped_iterations: ["count==0"],
    }
    : {
      authenticated_read_failures: ["rate<0.001"],
      authenticated_read_duration: ["p(95)<250", "p(99)<750"],
      unplanned_5xx: ["count==0"],
      dropped_iterations: ["count==0"],
    },
};

const jsonHeaders = {
  "Content-Type": "application/json",
  Origin: __ENV.RP_ORIGIN,
};

export function authenticatedRead() {
  const fixture = fixtureForIteration();
  const response = http.get(`${__ENV.TARGET_URL}/v1/account`, {
    headers: {
      ...jsonHeaders,
      Cookie: `__Host-Http-rustyauth_session=${fixture.sessionToken}`,
    },
    tags: { operation: "authenticated_read" },
    responseType: "none",
  });
  const failed = response.status !== 200;
  authenticatedReadDuration.add(response.timings.duration);
  authenticatedReadFailures.add(failed);
  if (response.status >= 500) unplanned5xx.add(1);
  check(response, { "authenticated read returned 200": (value) => value.status === 200 });
}

export async function signIn() {
  const fixture = fixtureForIteration();
  const started = Date.now();
  const optionsResponse = http.post(
    `${__ENV.TARGET_URL}/v1/passkeys/authentication/options`,
    JSON.stringify({ email: fixture.email }),
    { headers: jsonHeaders, tags: { operation: "signin_options" } },
  );
  if (optionsResponse.status !== 200) {
    recordSignInFailure(optionsResponse, started, "options");
    return;
  }

  let ceremony;
  try {
    ceremony = optionsResponse.json();
  } catch (_) {
    signInFailures.add(true);
    signInDuration.add(Date.now() - started);
    return;
  }

  const assertion = await webauthnAssertion(fixture, ceremony.options);
  const verifyResponse = http.post(
    `${__ENV.TARGET_URL}/v1/passkeys/authentication/verify`,
    JSON.stringify({ ceremonyId: ceremony.ceremonyId, response: assertion }),
    { headers: jsonHeaders, tags: { operation: "signin_verify" } },
  );
  const failed = verifyResponse.status !== 200;
  signInDuration.add(Date.now() - started);
  signInFailures.add(failed);
  if (verifyResponse.status >= 500) unplanned5xx.add(1);
  check(verifyResponse, { "passkey sign-in returned 200": (value) => value.status === 200 });
}

function fixtureForIteration() {
  const offset = mode === "signin" ? 0 : 1_000;
  const index = (offset + exec.scenario.iterationInTest) % fixtures.length;
  return fixtures[index];
}

function recordSignInFailure(response, started, stage) {
  signInFailures.add(true);
  signInDuration.add(Date.now() - started);
  if (response.status >= 500) unplanned5xx.add(1);
  check(response, { [`passkey ${stage} returned 200`]: (value) => value.status === 200 });
}

async function webauthnAssertion(fixture, options) {
  const publicKey = options.publicKey;
  const clientData = utf8(
    JSON.stringify({
      type: "webauthn.get",
      challenge: publicKey.challenge,
      origin: __ENV.RP_ORIGIN,
      crossOrigin: false,
    }),
  );
  const rpHash = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(publicKey.rpId)));
  const authenticatorData = concat(rpHash, new Uint8Array([0x05, 0, 0, 0, 1]));
  const clientHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientData));
  const signed = concat(authenticatorData, clientHash);
  const key = await crypto.subtle.importKey(
    "jwk",
    fixture.privateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, key, signed),
  );

  return {
    id: fixture.credentialId,
    rawId: fixture.credentialId,
    type: "public-key",
    response: {
      authenticatorData: base64url(authenticatorData),
      clientDataJSON: base64url(clientData),
      signature: base64url(ecdsaDer(signature)),
      userHandle: null,
    },
    clientExtensionResults: {},
  };
}

function utf8(value) {
  return new TextEncoder().encode(value);
}

function concat(...parts) {
  const size = parts.reduce((total, part) => total + part.length, 0);
  const joined = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return joined;
}

function base64url(value) {
  return encoding.b64encode(
    value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength),
    "rawurl",
  );
}

function ecdsaDer(signature) {
  if (signature.length > 8 && signature[0] === 0x30 && signature[1] === signature.length - 2) {
    return signature;
  }
  if (signature.length !== 64) throw new Error(`unexpected P-256 signature length ${signature.length}`);
  const r = derInteger(signature.slice(0, 32));
  const s = derInteger(signature.slice(32));
  return concat(new Uint8Array([0x30, r.length + s.length]), r, s);
}

function derInteger(value) {
  let offset = 0;
  while (offset < value.length - 1 && value[offset] === 0) offset += 1;
  let integer = value.slice(offset);
  if ((integer[0] & 0x80) !== 0) integer = concat(new Uint8Array([0]), integer);
  return concat(new Uint8Array([0x02, integer.length]), integer);
}
