/**
 * The RustyAuth browser client: a thin, dependency-free wrapper over the
 * public `/v1/*` HTTP surface that also drives the WebAuthn ceremonies.
 *
 * Every request is sent with `credentials: "include"` because the durable
 * session is an HttpOnly cookie, and the browser supplies the exact `Origin`
 * header RustyAuth's access checks require. Registration endpoints
 * additionally carry the administrative `x-bootstrap-token` header.
 */

import { type ErrorBody, RustyAuthError } from "./errors.ts";
import type {
  Account,
  AuthenticationCeremony,
  CredentialSummary,
  Identifier,
  RegistrationCeremony,
  TokenResponse,
} from "./types.ts";
import {
  type AuthenticationCredentialLike,
  authenticationResponseToJSON,
  parseCreationOptions,
  parseRequestOptions,
  type RegistrationCredentialLike,
  registrationResponseToJSON,
} from "./webauthn.ts";

/** The `navigator.credentials` surface the client drives; injectable for tests. */
export interface CeremonyContainer {
  create(options: CredentialCreationOptions): Promise<unknown>;
  get(options: CredentialRequestOptions): Promise<unknown>;
}

export interface RustyAuthClientOptions {
  /** RustyAuth origin, e.g. `"http://localhost:8081"`. Use `""` when served same-origin. */
  baseUrl: string;
  /** Fetch implementation; defaults to `globalThis.fetch`. Injectable for tests. */
  fetch?: typeof globalThis.fetch;
  /** WebAuthn ceremony container; defaults to `navigator.credentials`. Injectable for tests. */
  ceremonies?: CeremonyContainer;
}

/** Initial account enrolment. Requires the deployment's bootstrap token. */
export interface RegisterInput {
  identifier: Identifier;
  /** Sent as `x-bootstrap-token` on both registration requests. */
  bootstrapToken: string;
  givenName?: string;
  familyName?: string;
  displayName?: string;
}

export interface RustyAuthClient {
  /**
   * Registers a new account: requests creation options, runs
   * `navigator.credentials.create()` and verifies the attestation. On success
   * the session cookie is set and the token response returned.
   */
  register(input: RegisterInput): Promise<TokenResponse>;
  /**
   * Signs in an existing account by identifier: requests assertion options,
   * runs `navigator.credentials.get()` and verifies the assertion. On success
   * the session cookie is set and the token response returned.
   */
  signIn(identifier: Identifier): Promise<TokenResponse>;
  /**
   * Adds another passkey to the signed-in account. Requires a passkey session
   * created within the last five minutes.
   */
  addPasskey(input: { label: string }): Promise<void>;
  /** Mints a fresh short-lived access token for the existing session. */
  mintToken(): Promise<TokenResponse>;
  /** Ends the current session and expires the cookie. Idempotent. */
  signOut(): Promise<void>;
  /** Reads the signed-in account: profile and linked identifiers. */
  getAccount(): Promise<Account>;
  /** Lists the account's passkeys. */
  listCredentials(): Promise<CredentialSummary[]>;
  /** Renames one passkey. Labels are 1–80 characters. */
  renameCredential(input: { credentialId: string; label: string }): Promise<void>;
  /**
   * Removes one passkey and ends the sessions it created. Requires a recent
   * passkey session; removing the final passkey fails with `409`.
   */
  revokeCredential(input: { credentialId: string }): Promise<void>;
}

interface RequestInit2 {
  method: "GET" | "POST";
  body?: unknown;
  headers?: Record<string, string>;
}

async function errorFrom(response: Response): Promise<RustyAuthError> {
  let body: ErrorBody | null = null;
  try {
    const parsed: unknown = await response.json();
    if (
      typeof parsed === "object" && parsed !== null &&
      typeof (parsed as { error?: unknown }).error === "string"
    ) {
      body = parsed as ErrorBody;
    }
  } catch {
    // A non-JSON body (e.g. a proxy error page) still yields a typed error.
  }
  const retryAfter = response.headers.get("retry-after");
  const retryAfterSeconds = retryAfter === null ? null : Number(retryAfter);
  return new RustyAuthError(
    body?.error ?? `RustyAuth request failed with status ${response.status}`,
    {
      status: response.status,
      body,
      retryAfterSeconds: retryAfterSeconds !== null && Number.isFinite(retryAfterSeconds)
        ? retryAfterSeconds
        : null,
    },
  );
}

function asRegistrationCredential(value: unknown): RegistrationCredentialLike {
  const credential = value as RegistrationCredentialLike | null;
  if (
    !credential || typeof credential.id !== "string" || !credential.response ||
    !credential.response.attestationObject
  ) {
    throw new Error("the authenticator did not return a registration credential");
  }
  return credential;
}

function asAuthenticationCredential(value: unknown): AuthenticationCredentialLike {
  const credential = value as AuthenticationCredentialLike | null;
  if (
    !credential || typeof credential.id !== "string" || !credential.response ||
    !credential.response.signature
  ) {
    throw new Error("the authenticator did not return an assertion");
  }
  return credential;
}

/** Builds a client bound to one RustyAuth deployment. */
export function createRustyAuthClient(options: RustyAuthClientOptions): RustyAuthClient {
  const baseUrl = options.baseUrl.replace(/\/+$/, "");
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);

  function ceremonies(): CeremonyContainer {
    const container = options.ceremonies ?? globalThis.navigator?.credentials;
    if (!container) {
      throw new Error("WebAuthn ceremonies need navigator.credentials or an injected container");
    }
    return container;
  }

  async function request(path: string, init: RequestInit2): Promise<Response> {
    const headers: Record<string, string> = { ...init.headers };
    let body: string | undefined;
    if (init.body !== undefined) {
      headers["content-type"] = "application/json";
      body = JSON.stringify(init.body);
    }
    const response = await fetchImpl(`${baseUrl}${path}`, {
      method: init.method,
      credentials: "include",
      headers,
      body,
    });
    if (!response.ok) throw await errorFrom(response);
    return response;
  }

  async function requestJSON<T>(path: string, init: RequestInit2): Promise<T> {
    const response = await request(path, init);
    return await response.json() as T;
  }

  return {
    async register(input: RegisterInput): Promise<TokenResponse> {
      const bootstrap = { "x-bootstrap-token": input.bootstrapToken };
      const ceremony = await requestJSON<RegistrationCeremony>(
        "/v1/passkeys/registration/options",
        {
          method: "POST",
          headers: bootstrap,
          body: {
            identifier: input.identifier,
            givenName: input.givenName,
            familyName: input.familyName,
            displayName: input.displayName,
          },
        },
      );
      const created = asRegistrationCredential(
        await ceremonies().create(parseCreationOptions(ceremony.options)),
      );
      return await requestJSON<TokenResponse>("/v1/passkeys/registration/verify", {
        method: "POST",
        headers: bootstrap,
        body: { ceremonyId: ceremony.ceremonyId, response: registrationResponseToJSON(created) },
      });
    },

    async signIn(identifier: Identifier): Promise<TokenResponse> {
      const ceremony = await requestJSON<AuthenticationCeremony>(
        "/v1/passkeys/authentication/options",
        { method: "POST", body: { identifier } },
      );
      const asserted = asAuthenticationCredential(
        await ceremonies().get(parseRequestOptions(ceremony.options)),
      );
      return await requestJSON<TokenResponse>("/v1/passkeys/authentication/verify", {
        method: "POST",
        body: { ceremonyId: ceremony.ceremonyId, response: authenticationResponseToJSON(asserted) },
      });
    },

    async addPasskey(input: { label: string }): Promise<void> {
      const ceremony = await requestJSON<RegistrationCeremony>(
        "/v1/passkeys/registration/add/options",
        { method: "POST", body: { label: input.label } },
      );
      const created = asRegistrationCredential(
        await ceremonies().create(parseCreationOptions(ceremony.options)),
      );
      await request("/v1/passkeys/registration/add/verify", {
        method: "POST",
        body: { ceremonyId: ceremony.ceremonyId, response: registrationResponseToJSON(created) },
      });
    },

    async mintToken(): Promise<TokenResponse> {
      return await requestJSON<TokenResponse>("/v1/token", { method: "POST" });
    },

    async signOut(): Promise<void> {
      await request("/v1/sign-out", { method: "POST" });
    },

    async getAccount(): Promise<Account> {
      return await requestJSON<Account>("/v1/account", { method: "GET" });
    },

    async listCredentials(): Promise<CredentialSummary[]> {
      const body = await requestJSON<{ credentials: CredentialSummary[] }>("/v1/credentials", {
        method: "GET",
      });
      return body.credentials;
    },

    async renameCredential(input: { credentialId: string; label: string }): Promise<void> {
      await request("/v1/credentials/rename", { method: "POST", body: input });
    },

    async revokeCredential(input: { credentialId: string }): Promise<void> {
      await request("/v1/credentials/revoke", { method: "POST", body: input });
    },
  };
}
