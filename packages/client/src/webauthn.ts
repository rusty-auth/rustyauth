/**
 * JSON ↔ browser-structure conversions for WebAuthn ceremonies.
 *
 * The server side of every ceremony is `webauthn-rs`: options arrive as
 * `{ publicKey: … }` with base64url binary fields, and verify requests carry
 * the spec `RegistrationResponseJSON`/`AuthenticationResponseJSON` shapes
 * (the server aliases `clientExtensionResults`, defaults absent extensions
 * and ignores unknown fields and transports). The native
 * `PublicKeyCredential.parseCreationOptionsFromJSON` /
 * `parseRequestOptionsFromJSON` / `credential.toJSON()` APIs are used when
 * the browser provides them; the manual fallbacks produce the same shapes.
 */

import { decodeBase64Url, encodeBase64Url } from "./base64url.ts";
import type {
  AuthenticationResponseJSON,
  CreationOptionsJSON,
  RegistrationResponseJSON,
  RequestOptionsJSON,
} from "./types.ts";

/** The registration credential fields the mapping reads; satisfied by a browser `PublicKeyCredential`. */
export interface RegistrationCredentialLike {
  id: string;
  rawId: ArrayBuffer;
  type: string;
  response: {
    clientDataJSON: ArrayBuffer;
    attestationObject: ArrayBuffer;
    getTransports?: () => string[];
  };
  getClientExtensionResults?: () => unknown;
  toJSON?: () => unknown;
}

/** The assertion credential fields the mapping reads; satisfied by a browser `PublicKeyCredential`. */
export interface AuthenticationCredentialLike {
  id: string;
  rawId: ArrayBuffer;
  type: string;
  response: {
    authenticatorData: ArrayBuffer;
    clientDataJSON: ArrayBuffer;
    signature: ArrayBuffer;
    userHandle?: ArrayBuffer | null;
  };
  getClientExtensionResults?: () => unknown;
  toJSON?: () => unknown;
}

interface NativeParsers {
  parseCreationOptionsFromJSON?: (json: CreationOptionsJSON) => PublicKeyCredentialCreationOptions;
  parseRequestOptionsFromJSON?: (json: RequestOptionsJSON) => PublicKeyCredentialRequestOptions;
}

function nativeParsers(): NativeParsers {
  const statics = (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential;
  return typeof statics === "function" ? (statics as unknown as NativeParsers) : {};
}

/** Manual decode of registration options; exported for testing and advanced use. */
export function creationOptionsFromJSON(json: CreationOptionsJSON): PublicKeyCredentialCreationOptions {
  const { challenge, user, excludeCredentials, ...rest } = json;
  return {
    ...rest,
    challenge: decodeBase64Url(challenge),
    user: { ...user, id: decodeBase64Url(user.id) },
    excludeCredentials: excludeCredentials?.map((descriptor) => ({
      ...descriptor,
      id: decodeBase64Url(descriptor.id),
    })),
  } as unknown as PublicKeyCredentialCreationOptions;
}

/** Manual decode of authentication options; exported for testing and advanced use. */
export function requestOptionsFromJSON(json: RequestOptionsJSON): PublicKeyCredentialRequestOptions {
  const { challenge, allowCredentials, ...rest } = json;
  return {
    ...rest,
    challenge: decodeBase64Url(challenge),
    allowCredentials: allowCredentials.map((descriptor) => ({
      ...descriptor,
      id: decodeBase64Url(descriptor.id),
    })),
  } as unknown as PublicKeyCredentialRequestOptions;
}

/**
 * Converts a registration `options` body into `navigator.credentials.create()`
 * input, preferring the browser's own JSON parser when present.
 */
export function parseCreationOptions(
  options: { publicKey: CreationOptionsJSON },
): CredentialCreationOptions {
  const native = nativeParsers().parseCreationOptionsFromJSON;
  return { publicKey: native ? native(options.publicKey) : creationOptionsFromJSON(options.publicKey) };
}

/**
 * Converts an authentication `options` body into `navigator.credentials.get()`
 * input, preferring the browser's own JSON parser when present.
 */
export function parseRequestOptions(
  options: { publicKey: RequestOptionsJSON; mediation?: string },
): CredentialRequestOptions {
  const native = nativeParsers().parseRequestOptionsFromJSON;
  const request: CredentialRequestOptions = {
    publicKey: native ? native(options.publicKey) : requestOptionsFromJSON(options.publicKey),
  };
  if (options.mediation !== undefined) {
    request.mediation = options.mediation as CredentialMediationRequirement;
  }
  return request;
}

function extensionResults(
  credential: RegistrationCredentialLike | AuthenticationCredentialLike,
): Record<string, unknown> {
  return (credential.getClientExtensionResults?.() ?? {}) as Record<string, unknown>;
}

/**
 * Serializes a created credential into the registration verify `response`
 * field, preferring the browser's own `toJSON()` when present.
 */
export function registrationResponseToJSON(
  credential: RegistrationCredentialLike,
): RegistrationResponseJSON {
  if (typeof credential.toJSON === "function") {
    return credential.toJSON() as RegistrationResponseJSON;
  }
  const response: RegistrationResponseJSON["response"] = {
    clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
    attestationObject: encodeBase64Url(credential.response.attestationObject),
  };
  const transports = credential.response.getTransports?.();
  if (transports) response.transports = transports;
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response,
    clientExtensionResults: extensionResults(credential),
  };
}

/**
 * Serializes an assertion into the authentication verify `response` field,
 * preferring the browser's own `toJSON()` when present.
 */
export function authenticationResponseToJSON(
  credential: AuthenticationCredentialLike,
): AuthenticationResponseJSON {
  if (typeof credential.toJSON === "function") {
    return credential.toJSON() as AuthenticationResponseJSON;
  }
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: encodeBase64Url(credential.response.authenticatorData),
      clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
      signature: encodeBase64Url(credential.response.signature),
      userHandle: credential.response.userHandle ? encodeBase64Url(credential.response.userHandle) : null,
    },
    clientExtensionResults: extensionResults(credential),
  };
}
