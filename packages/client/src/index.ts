/**
 * Framework-agnostic browser client for the RustyAuth public passkey HTTP
 * API — the `/v1/*` JSON surface. The private ConnectRPC services are covered
 * by `@rustyauth/protocol` and `@rustyauth/connect-solid`.
 */

export { decodeBase64Url, encodeBase64Url } from "./base64url.ts";
export { type ErrorBody, RustyAuthError } from "./errors.ts";
export type {
  Account,
  AccountIdentifier,
  AccountProfile,
  AuthenticationCeremony,
  AuthenticationResponseJSON,
  CreationOptionsJSON,
  CredentialDescriptorJSON,
  CredentialSummary,
  Identifier,
  IdentifierType,
  RegistrationCeremony,
  RegistrationResponseJSON,
  RequestOptionsJSON,
  TokenResponse,
} from "./types.ts";
export {
  type AuthenticationCredentialLike,
  authenticationResponseToJSON,
  creationOptionsFromJSON,
  parseCreationOptions,
  parseRequestOptions,
  type RegistrationCredentialLike,
  registrationResponseToJSON,
  requestOptionsFromJSON,
} from "./webauthn.ts";
export {
  type CeremonyContainer,
  createRustyAuthClient,
  type RegisterInput,
  type RustyAuthClient,
  type RustyAuthClientOptions,
} from "./client.ts";
