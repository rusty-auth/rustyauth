import { assertEquals, assertRejects } from "@std/assert";
import { encodeBase64Url } from "./base64url.ts";
import { createRustyAuthClient } from "./client.ts";
import { RustyAuthError } from "./errors.ts";
import type { TokenResponse } from "./types.ts";

interface RecordedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  credentials: string | undefined;
  body: unknown;
}

/** Queues canned responses and records every request the client makes. */
function stubFetch(responses: Response[]): { fetch: typeof globalThis.fetch; calls: RecordedRequest[] } {
  const calls: RecordedRequest[] = [];
  const fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      headers: (init?.headers ?? {}) as Record<string, string>,
      credentials: init?.credentials,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
    });
    const next = responses.shift();
    if (!next) throw new Error("stub fetch ran out of responses");
    return Promise.resolve(next);
  }) as typeof globalThis.fetch;
  return { fetch, calls };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const TOKEN_RESPONSE: TokenResponse = {
  email: "person@example.com",
  emailVerified: true,
  phoneNumber: null,
  phoneNumberVerified: false,
  profile: { givenName: "Ada", familyName: "Lovelace", displayName: "Ada Lovelace" },
  token: "eyJ.test.token",
  expiresIn: 300,
};

const CREATION_OPTIONS = {
  publicKey: {
    rp: { id: "localhost", name: "RustyAuth Local" },
    user: { id: encodeBase64Url(new Uint8Array([1])), name: "person@example.com", displayName: "Ada" },
    challenge: encodeBase64Url(new Uint8Array([2, 2])),
    pubKeyCredParams: [{ type: "public-key" as const, alg: -7 }],
  },
};

const REQUEST_OPTIONS = {
  publicKey: {
    challenge: encodeBase64Url(new Uint8Array([3, 3])),
    rpId: "localhost",
    allowCredentials: [{ type: "public-key" as const, id: encodeBase64Url(new Uint8Array([4])) }],
    userVerification: "required",
  },
};

function fakeRegistrationCredential() {
  return {
    id: "cred-id",
    rawId: new Uint8Array([4]).buffer,
    type: "public-key",
    response: {
      clientDataJSON: new Uint8Array([5]).buffer,
      attestationObject: new Uint8Array([6]).buffer,
    },
  };
}

function fakeAssertionCredential() {
  return {
    id: "cred-id",
    rawId: new Uint8Array([4]).buffer,
    type: "public-key",
    response: {
      authenticatorData: new Uint8Array([7]).buffer,
      clientDataJSON: new Uint8Array([8]).buffer,
      signature: new Uint8Array([9]).buffer,
      userHandle: null,
    },
  };
}

Deno.test("register sends bootstrap headers and the mapped attestation", async () => {
  const { fetch, calls } = stubFetch([
    jsonResponse(200, { ceremonyId: "ceremony-1", options: CREATION_OPTIONS }),
    jsonResponse(201, TOKEN_RESPONSE),
  ]);
  const seen: unknown[] = [];
  const client = createRustyAuthClient({
    baseUrl: "http://localhost:8081/",
    fetch,
    ceremonies: {
      create: (options) => {
        seen.push(options);
        return Promise.resolve(fakeRegistrationCredential());
      },
      get: () => Promise.reject(new Error("unexpected get")),
    },
  });

  const token = await client.register({
    identifier: { type: "email", value: "person@example.com" },
    bootstrapToken: "vtr-local-enrolment-only",
    givenName: "Ada",
  });

  assertEquals(token, TOKEN_RESPONSE);
  assertEquals(calls.length, 2);
  assertEquals(calls[0].url, "http://localhost:8081/v1/passkeys/registration/options");
  assertEquals(calls[0].method, "POST");
  assertEquals(calls[0].credentials, "include");
  assertEquals(calls[0].headers["x-bootstrap-token"], "vtr-local-enrolment-only");
  assertEquals(calls[0].headers["content-type"], "application/json");
  assertEquals(calls[0].body, {
    identifier: { type: "email", value: "person@example.com" },
    givenName: "Ada",
  });

  // The ceremony consumed the decoded creation options.
  const created = seen[0] as { publicKey: { challenge: Uint8Array } };
  assertEquals(created.publicKey.challenge, new Uint8Array([2, 2]));

  assertEquals(calls[1].url, "http://localhost:8081/v1/passkeys/registration/verify");
  assertEquals(calls[1].headers["x-bootstrap-token"], "vtr-local-enrolment-only");
  assertEquals(calls[1].body, {
    ceremonyId: "ceremony-1",
    response: {
      id: "cred-id",
      rawId: encodeBase64Url(new Uint8Array([4])),
      type: "public-key",
      response: {
        clientDataJSON: encodeBase64Url(new Uint8Array([5])),
        attestationObject: encodeBase64Url(new Uint8Array([6])),
      },
      clientExtensionResults: {},
    },
  });
});

Deno.test("signIn maps the assertion and never sends a bootstrap token", async () => {
  const { fetch, calls } = stubFetch([
    jsonResponse(200, { ceremonyId: "ceremony-2", options: REQUEST_OPTIONS }),
    jsonResponse(200, TOKEN_RESPONSE),
  ]);
  const client = createRustyAuthClient({
    baseUrl: "http://localhost:8081",
    fetch,
    ceremonies: {
      create: () => Promise.reject(new Error("unexpected create")),
      get: () => Promise.resolve(fakeAssertionCredential()),
    },
  });

  const token = await client.signIn({ type: "phone", value: "+447700900123" });

  assertEquals(token, TOKEN_RESPONSE);
  assertEquals(calls[0].url, "http://localhost:8081/v1/passkeys/authentication/options");
  assertEquals(calls[0].body, { identifier: { type: "phone", value: "+447700900123" } });
  assertEquals("x-bootstrap-token" in calls[0].headers, false);
  assertEquals(calls[1].url, "http://localhost:8081/v1/passkeys/authentication/verify");
  assertEquals(calls[1].body, {
    ceremonyId: "ceremony-2",
    response: {
      id: "cred-id",
      rawId: encodeBase64Url(new Uint8Array([4])),
      type: "public-key",
      response: {
        authenticatorData: encodeBase64Url(new Uint8Array([7])),
        clientDataJSON: encodeBase64Url(new Uint8Array([8])),
        signature: encodeBase64Url(new Uint8Array([9])),
        userHandle: null,
      },
      clientExtensionResults: {},
    },
  });
});

Deno.test("addPasskey posts the label and accepts the 204 verify", async () => {
  const { fetch, calls } = stubFetch([
    jsonResponse(200, { ceremonyId: "ceremony-3", options: CREATION_OPTIONS }),
    new Response(null, { status: 204 }),
  ]);
  const client = createRustyAuthClient({
    baseUrl: "http://localhost:8081",
    fetch,
    ceremonies: {
      create: () => Promise.resolve(fakeRegistrationCredential()),
      get: () => Promise.reject(new Error("unexpected get")),
    },
  });

  await client.addPasskey({ label: "YubiKey 5" });

  assertEquals(calls[0].url, "http://localhost:8081/v1/passkeys/registration/add/options");
  assertEquals(calls[0].body, { label: "YubiKey 5" });
  assertEquals("x-bootstrap-token" in calls[0].headers, false);
  assertEquals(calls[1].url, "http://localhost:8081/v1/passkeys/registration/add/verify");
  assertEquals((calls[1].body as { ceremonyId: string }).ceremonyId, "ceremony-3");
});

Deno.test("session endpoints use the right methods, paths and bodies", async () => {
  const { fetch, calls } = stubFetch([
    jsonResponse(200, TOKEN_RESPONSE),
    new Response(null, { status: 204 }),
    jsonResponse(200, { id: "user-1", profile: {}, identifiers: [], createdAt: "now" }),
    jsonResponse(200, { credentials: [{ id: "cred-1", label: "Primary", current: true }] }),
    new Response(null, { status: 204 }),
    new Response(null, { status: 204 }),
  ]);
  const client = createRustyAuthClient({ baseUrl: "http://localhost:8081", fetch });

  assertEquals((await client.mintToken()).token, TOKEN_RESPONSE.token);
  await client.signOut();
  assertEquals((await client.getAccount()).id, "user-1");
  assertEquals((await client.listCredentials())[0].id, "cred-1");
  await client.renameCredential({ credentialId: "cred-1", label: "Office key" });
  await client.revokeCredential({ credentialId: "cred-1" });

  assertEquals(
    calls.map((call) => [call.method, call.url]),
    [
      ["POST", "http://localhost:8081/v1/token"],
      ["POST", "http://localhost:8081/v1/sign-out"],
      ["GET", "http://localhost:8081/v1/account"],
      ["GET", "http://localhost:8081/v1/credentials"],
      ["POST", "http://localhost:8081/v1/credentials/rename"],
      ["POST", "http://localhost:8081/v1/credentials/revoke"],
    ],
  );
  // Bodiless POSTs must not claim a JSON content type.
  assertEquals("content-type" in calls[0].headers, false);
  assertEquals(calls[4].body, { credentialId: "cred-1", label: "Office key" });
  assertEquals(calls[5].body, { credentialId: "cred-1" });
  for (const call of calls) assertEquals(call.credentials, "include");
});

Deno.test("failures surface the server's error envelope as a typed error", async () => {
  const { fetch } = stubFetch([jsonResponse(409, { error: "identifier already has an account" })]);
  const client = createRustyAuthClient({ baseUrl: "http://localhost:8081", fetch });

  const error = await assertRejects(
    () => client.getAccount(),
    RustyAuthError,
    "identifier already has an account",
  );
  assertEquals(error.status, 409);
  assertEquals(error.body, { error: "identifier already has an account" });
  assertEquals(error.retryAfterSeconds, null);
});

Deno.test("rate limits carry the Retry-After header through", async () => {
  const { fetch } = stubFetch([
    new Response(JSON.stringify({ error: "too many requests; retry later" }), {
      status: 429,
      headers: { "content-type": "application/json", "retry-after": "17" },
    }),
  ]);
  const client = createRustyAuthClient({ baseUrl: "http://localhost:8081", fetch });

  const error = await assertRejects(() => client.mintToken(), RustyAuthError);
  assertEquals(error.status, 429);
  assertEquals(error.retryAfterSeconds, 17);
});

Deno.test("non-JSON failure bodies still produce a typed error", async () => {
  const { fetch } = stubFetch([new Response("bad gateway", { status: 502 })]);
  const client = createRustyAuthClient({ baseUrl: "http://localhost:8081", fetch });

  const error = await assertRejects(
    () => client.signOut(),
    RustyAuthError,
    "RustyAuth request failed with status 502",
  );
  assertEquals(error.body, null);
});

Deno.test("a rejected ceremony surfaces without a verify request", async () => {
  const { fetch, calls } = stubFetch([
    jsonResponse(200, { ceremonyId: "ceremony-4", options: REQUEST_OPTIONS }),
  ]);
  const client = createRustyAuthClient({
    baseUrl: "http://localhost:8081",
    fetch,
    ceremonies: {
      create: () => Promise.reject(new Error("unexpected create")),
      get: () => Promise.reject(new DOMException("user cancelled", "NotAllowedError")),
    },
  });

  await assertRejects(
    () => client.signIn({ type: "email", value: "person@example.com" }),
    DOMException,
    "user cancelled",
  );
  assertEquals(calls.length, 1);
});
