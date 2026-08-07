import { assertEquals } from "@std/assert";
import { decodeBase64Url, encodeBase64Url } from "./base64url.ts";
import type { CreationOptionsJSON, RequestOptionsJSON } from "./types.ts";
import {
  authenticationResponseToJSON,
  creationOptionsFromJSON,
  parseCreationOptions,
  registrationResponseToJSON,
  requestOptionsFromJSON,
} from "./webauthn.ts";

const CHALLENGE = encodeBase64Url(new Uint8Array([1, 2, 3, 4]));
const USER_ID = encodeBase64Url(new Uint8Array([9, 9, 9]));
const CREDENTIAL_ID = encodeBase64Url(new Uint8Array([7, 7]));

function creationJSON(): CreationOptionsJSON {
  return {
    rp: { id: "localhost", name: "RustyAuth Local" },
    user: { id: USER_ID, name: "person@example.com", displayName: "Ada" },
    challenge: CHALLENGE,
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    timeout: 60000,
    excludeCredentials: [{ type: "public-key", id: CREDENTIAL_ID, transports: ["internal"] }],
    authenticatorSelection: { userVerification: "required" },
    attestation: "none",
  };
}

Deno.test("creation options decode only the binary fields", () => {
  const decoded = creationOptionsFromJSON(creationJSON()) as unknown as {
    challenge: Uint8Array;
    user: { id: Uint8Array; name: string; displayName: string };
    excludeCredentials: { type: string; id: Uint8Array; transports: string[] }[];
    rp: { id: string };
    timeout: number;
    attestation: string;
  };
  assertEquals(decoded.challenge, new Uint8Array([1, 2, 3, 4]));
  assertEquals(decoded.user.id, new Uint8Array([9, 9, 9]));
  assertEquals(decoded.user.name, "person@example.com");
  assertEquals(decoded.excludeCredentials[0].id, new Uint8Array([7, 7]));
  assertEquals(decoded.excludeCredentials[0].transports, ["internal"]);
  assertEquals(decoded.rp.id, "localhost");
  assertEquals(decoded.timeout, 60000);
  assertEquals(decoded.attestation, "none");
});

Deno.test("creation options tolerate absent excludeCredentials", () => {
  const json = creationJSON();
  delete json.excludeCredentials;
  const decoded = creationOptionsFromJSON(json) as unknown as { excludeCredentials?: unknown[] };
  assertEquals(decoded.excludeCredentials, undefined);
});

Deno.test("request options decode challenge and allowed credential ids", () => {
  const json: RequestOptionsJSON = {
    challenge: CHALLENGE,
    timeout: 300000,
    rpId: "localhost",
    allowCredentials: [{ type: "public-key", id: CREDENTIAL_ID }],
    userVerification: "required",
  };
  const decoded = requestOptionsFromJSON(json) as unknown as {
    challenge: Uint8Array;
    rpId: string;
    allowCredentials: { id: Uint8Array }[];
    userVerification: string;
  };
  assertEquals(decoded.challenge, new Uint8Array([1, 2, 3, 4]));
  assertEquals(decoded.rpId, "localhost");
  assertEquals(decoded.allowCredentials[0].id, new Uint8Array([7, 7]));
  assertEquals(decoded.userVerification, "required");
});

Deno.test("parseCreationOptions falls back to the manual decoder off-browser", () => {
  // Deno has no PublicKeyCredential global, so this exercises the fallback.
  const parsed = parseCreationOptions({ publicKey: creationJSON() }) as unknown as {
    publicKey: { challenge: Uint8Array };
  };
  assertEquals(parsed.publicKey.challenge, new Uint8Array([1, 2, 3, 4]));
});

Deno.test("registration responses encode buffers and keep transports", () => {
  const clientData = new Uint8Array([10, 11]);
  const attestation = new Uint8Array([12, 13, 14]);
  const rawId = new Uint8Array([7, 7]);
  const json = registrationResponseToJSON({
    id: CREDENTIAL_ID,
    rawId: rawId.buffer,
    type: "public-key",
    response: {
      clientDataJSON: clientData.buffer,
      attestationObject: attestation.buffer,
      getTransports: () => ["internal", "hybrid"],
    },
    getClientExtensionResults: () => ({ credProps: { rk: true } }),
  });
  assertEquals(json, {
    id: CREDENTIAL_ID,
    rawId: encodeBase64Url(rawId),
    type: "public-key",
    response: {
      clientDataJSON: encodeBase64Url(clientData),
      attestationObject: encodeBase64Url(attestation),
      transports: ["internal", "hybrid"],
    },
    clientExtensionResults: { credProps: { rk: true } },
  });
});

Deno.test("registration responses omit transports and default extensions when unavailable", () => {
  const json = registrationResponseToJSON({
    id: "abc",
    rawId: new Uint8Array([1]).buffer,
    type: "public-key",
    response: {
      clientDataJSON: new Uint8Array([2]).buffer,
      attestationObject: new Uint8Array([3]).buffer,
    },
  });
  assertEquals("transports" in json.response, false);
  assertEquals(json.clientExtensionResults, {});
});

Deno.test("registration responses prefer the credential's own toJSON", () => {
  const canonical = { id: "native", rawId: "native", type: "public-key" };
  const json = registrationResponseToJSON({
    id: "ignored",
    rawId: new Uint8Array([1]).buffer,
    type: "public-key",
    response: {
      clientDataJSON: new Uint8Array([2]).buffer,
      attestationObject: new Uint8Array([3]).buffer,
    },
    toJSON: () => canonical,
  });
  assertEquals(json.id, "native");
});

Deno.test("authentication responses encode buffers and the user handle", () => {
  const authenticatorData = new Uint8Array([20, 21]);
  const clientData = new Uint8Array([22]);
  const signature = new Uint8Array([23, 24, 25]);
  const userHandle = new Uint8Array([9, 9, 9]);
  const json = authenticationResponseToJSON({
    id: CREDENTIAL_ID,
    rawId: decodeBase64Url(CREDENTIAL_ID).buffer as ArrayBuffer,
    type: "public-key",
    response: {
      authenticatorData: authenticatorData.buffer,
      clientDataJSON: clientData.buffer,
      signature: signature.buffer,
      userHandle: userHandle.buffer,
    },
  });
  assertEquals(json.response.authenticatorData, encodeBase64Url(authenticatorData));
  assertEquals(json.response.signature, encodeBase64Url(signature));
  assertEquals(json.response.userHandle, USER_ID);
  assertEquals(json.clientExtensionResults, {});
});

Deno.test("authentication responses map an absent user handle to null", () => {
  const json = authenticationResponseToJSON({
    id: "abc",
    rawId: new Uint8Array([1]).buffer,
    type: "public-key",
    response: {
      authenticatorData: new Uint8Array([2]).buffer,
      clientDataJSON: new Uint8Array([3]).buffer,
      signature: new Uint8Array([4]).buffer,
      userHandle: null,
    },
  });
  assertEquals(json.response.userHandle, null);
});
