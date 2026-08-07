/**
 * Wire types for the RustyAuth public HTTP API (`/v1/*`), transcribed from
 * `docs/API.md`. The WebAuthn `options`/`response` shapes are the
 * `webauthn-rs` serializations: spec-standard camelCase JSON in which every
 * binary field is an unpadded base64url string.
 */

/** The two identifier kinds an account can hold. */
export type IdentifierType = "email" | "phone";

/**
 * An account discovery key. Emails are trimmed and lowercased server-side;
 * phone numbers are normalized to E.164.
 */
export interface Identifier {
  type: IdentifierType;
  value: string;
}

/** The small mutable profile attached to an account. Absent names are `null`. */
export interface AccountProfile {
  givenName: string | null;
  familyName: string | null;
  displayName: string | null;
}

/**
 * Body of `201`/`200` sign-in responses and `POST /v1/token`. The session
 * itself lives in the HttpOnly cookie; `token` is the short-lived ES256 JWT
 * for downstream services.
 */
export interface TokenResponse {
  email: string | null;
  emailVerified: boolean;
  phoneNumber: string | null;
  phoneNumberVerified: boolean;
  profile: AccountProfile;
  token: string;
  expiresIn: number;
}

/** One linked identifier in the `GET /v1/account` response. */
export interface AccountIdentifier {
  type: IdentifierType;
  value: string;
  verified: boolean;
  /** May be `null` for verified identifiers migrated from the original single-email record. */
  verifiedAt: string | null;
  primary: boolean;
  createdAt: string;
}

/** Body of `GET /v1/account`. */
export interface Account {
  id: string;
  profile: AccountProfile;
  identifiers: AccountIdentifier[];
  createdAt: string;
}

/** One passkey in the `GET /v1/credentials` response. */
export interface CredentialSummary {
  /** Base64url credential ID, the handle for rename/revoke. */
  id: string;
  label: string;
  createdAt: string;
  /** Empty string before first use. */
  lastUsedAt: string;
  authenticator: string;
  /** True for the credential that created the current passkey session. */
  current: boolean;
}

/** A credential reference inside WebAuthn options; `id` is base64url. */
export interface CredentialDescriptorJSON {
  type: "public-key";
  id: string;
  transports?: string[];
}

/**
 * The `options.publicKey` object of registration ceremonies: the W3C
 * `PublicKeyCredentialCreationOptions` in JSON form. `challenge`,
 * `user.id` and `excludeCredentials[].id` are base64url strings.
 */
export interface CreationOptionsJSON {
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  timeout?: number;
  excludeCredentials?: CredentialDescriptorJSON[];
  authenticatorSelection?: Record<string, unknown>;
  hints?: string[];
  attestation?: string;
  attestationFormats?: string[];
  extensions?: Record<string, unknown>;
}

/**
 * The `options.publicKey` object of authentication ceremonies: the W3C
 * `PublicKeyCredentialRequestOptions` in JSON form. `challenge` and
 * `allowCredentials[].id` are base64url strings.
 */
export interface RequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId: string;
  allowCredentials: CredentialDescriptorJSON[];
  userVerification: string;
  hints?: string[];
  extensions?: Record<string, unknown>;
}

/** Body of `POST /v1/passkeys/registration/options` and `…/registration/add/options`. */
export interface RegistrationCeremony {
  ceremonyId: string;
  options: { publicKey: CreationOptionsJSON };
}

/** Body of `POST /v1/passkeys/authentication/options`. */
export interface AuthenticationCeremony {
  ceremonyId: string;
  options: { publicKey: RequestOptionsJSON; mediation?: string };
}

/**
 * The `response` field of registration verify requests — the browser
 * attestation with binary fields base64url encoded. This is the shape
 * `PublicKeyCredential.prototype.toJSON()` produces; the server also accepts
 * its extra fields and tolerates unknown transports.
 */
export interface RegistrationResponseJSON {
  id: string;
  rawId: string;
  type: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: string[];
  };
  clientExtensionResults: Record<string, unknown>;
}

/**
 * The `response` field of authentication verify requests — the browser
 * assertion with binary fields base64url encoded. `userHandle` may be `null`
 * or omitted when the authenticator returned none.
 */
export interface AuthenticationResponseJSON {
  id: string;
  rawId: string;
  type: string;
  response: {
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
    userHandle?: string | null;
  };
  clientExtensionResults: Record<string, unknown>;
}
