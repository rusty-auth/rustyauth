import { createClient } from "@connectrpc/connect";
import { createConnectSolidTransport } from "@rustyauth/connect-solid";
import {
  IdentifierType,
  IdentityService,
  type Operator,
  OperatorRole,
  type Organization,
  OrganizationService,
  type ServiceAccount,
  ServiceAccountService,
  ServiceAccountStatus,
  type User,
} from "@rustyauth/protocol";
import type { OperatorView, OrganizationView, ServiceAccountView, UserView } from "./models.ts";

// Round trips a single search may spend, and the most rows it returns. Both bound
// what one operator keystroke can cost when the term matches nothing.
const MAX_SEARCH_PAGES = 10;
const MAX_SEARCH_RESULTS = 50;

const transport = createConnectSolidTransport({ baseUrl: "/" });
const identity = createClient(IdentityService, transport);
const organizations = createClient(OrganizationService, transport);
const serviceAccounts = createClient(ServiceAccountService, transport);

export async function getCurrentOperator(
  signal?: AbortSignal,
): Promise<OperatorView> {
  return operatorView(await organizations.getCurrentOperator({}, { signal }));
}

export async function getOrganization(
  signal?: AbortSignal,
): Promise<OrganizationView> {
  return organizationView(await organizations.getOrganization({}, { signal }));
}

export async function updateOrganization(
  name: string,
): Promise<OrganizationView> {
  return organizationView(await organizations.updateOrganization({ name }));
}

export async function searchUsers(
  term: string,
  signal?: AbortSignal,
): Promise<UserView[]> {
  const value = term.trim();
  if (!value) return [];
  const input: Parameters<typeof identity.searchUsers>[0] = { pageSize: 50 };
  if (/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(value)) {
    input.userId = value;
  } else if (value.startsWith("+")) {
    input.identifier = { type: IdentifierType.PHONE, value };
  } else if (value.includes("@")) {
    input.identifier = {
      type: IdentifierType.EMAIL,
      value: value.toLowerCase(),
    };
  } else {
    input.displayName = value;
  }
  // A name search has no index behind it, so the server walks accounts under a
  // per-request budget and hands back a cursor when it stops early. A single call
  // therefore sees only the first slice of a large tenant — following the cursor
  // is what makes the search find anything beyond it. The round-trip cap keeps a
  // no-match term from walking the whole namespace.
  const users: UserView[] = [];
  let pageToken = "";
  for (let page = 0; page < MAX_SEARCH_PAGES; page += 1) {
    const response = await identity.searchUsers(
      pageToken ? { ...input, pageToken } : input,
      { signal },
    );
    users.push(...response.users.map(userView));
    pageToken = response.nextPageToken;
    if (!pageToken || users.length >= MAX_SEARCH_RESULTS) break;
  }
  return users.slice(0, MAX_SEARCH_RESULTS);
}

export async function listServiceAccounts(
  signal?: AbortSignal,
): Promise<ServiceAccountView[]> {
  const response = await serviceAccounts.listServiceAccounts(
    { pageSize: 100 },
    { signal },
  );
  return response.serviceAccounts.map(serviceAccountView);
}

export async function createServiceAccount(input: {
  name: string;
  description: string;
  scopes: string[];
}): Promise<ServiceAccountView> {
  return serviceAccountView(await serviceAccounts.createServiceAccount(input));
}

export async function createServiceCredential(input: {
  serviceAccountId: string;
  name: string;
  expiresAt?: string;
}): Promise<
  { accountId: string; credentialId: string; secret: string; hint: string }
> {
  const response = await serviceAccounts.createCredential({
    serviceAccountId: input.serviceAccountId,
    name: input.name,
    expiresAt: input.expiresAt ?? "",
  });
  return {
    accountId: input.serviceAccountId,
    credentialId: response.credential?.id ?? "",
    secret: response.secret,
    hint: response.credential?.secretHint ?? "",
  };
}

export async function revokeServiceCredential(input: {
  serviceAccountId: string;
  credentialId: string;
  reason: string;
}): Promise<void> {
  await serviceAccounts.revokeCredential(input);
}

export async function signInWithPasskey(email: string): Promise<void> {
  const optionsResponse = await fetch("/v1/passkeys/authentication/options", {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: email.trim().toLowerCase() }),
  });
  if (!optionsResponse.ok) {
    throw new Error("Passkey authentication is unavailable for that account.");
  }
  const challenge = await optionsResponse.json();
  const publicKey = normalizeRequestOptions(
    challenge.options.publicKey ?? challenge.options,
  );
  const credential = await navigator.credentials.get({ publicKey });
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error("No passkey assertion was returned.");
  }
  const response = credential.response;
  if (!(response instanceof AuthenticatorAssertionResponse)) {
    throw new Error("Invalid passkey assertion.");
  }
  const verifyResponse = await fetch("/v1/passkeys/authentication/verify", {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      ceremonyId: challenge.ceremonyId,
      response: {
        id: credential.id,
        rawId: encodeBase64Url(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: encodeBase64Url(response.authenticatorData),
          clientDataJSON: encodeBase64Url(response.clientDataJSON),
          signature: encodeBase64Url(response.signature),
          userHandle: response.userHandle ? encodeBase64Url(response.userHandle) : null,
        },
        clientExtensionResults: credential.getClientExtensionResults(),
      },
    }),
  });
  if (!verifyResponse.ok) throw new Error("Passkey verification failed.");
}

function normalizeRequestOptions(
  options: PublicKeyCredentialRequestOptionsJSON,
): PublicKeyCredentialRequestOptions {
  return {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    allowCredentials: options.allowCredentials?.map((credential) => ({
      ...credential,
      id: decodeBase64Url(credential.id),
    })),
  } as PublicKeyCredentialRequestOptions;
}

function decodeBase64Url(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "=",
  );
  const bytes = Uint8Array.from(
    atob(padded),
    (character) => character.charCodeAt(0),
  );
  return bytes.buffer;
}

function encodeBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(
    /=+$/,
    "",
  );
}

function operatorView(operator: Operator): OperatorView {
  const roles: Record<number, string> = {
    [OperatorRole.OWNER]: "Owner",
    [OperatorRole.ADMINISTRATOR]: "Administrator",
    [OperatorRole.SUPPORT]: "Support",
    [OperatorRole.AUDITOR]: "Auditor",
  };
  return {
    id: operator.id,
    email: operator.email,
    displayName: operator.displayName || operator.email,
    role: roles[operator.role] ?? "Operator",
  };
}

function organizationView(organization: Organization): OrganizationView {
  return {
    id: organization.id,
    slug: organization.slug,
    name: organization.name,
    createdAt: organization.createdAt,
  };
}

function userView(user: User): UserView {
  const name = user.profile?.displayName ||
    [user.profile?.givenName, user.profile?.familyName].filter(Boolean).join(
      " ",
    ) ||
    user.identifiers.find((identifier) => identifier.primary)?.value || user.id;
  const primary = user.identifiers.find((identifier) => identifier.primary) ??
    user.identifiers[0];
  return {
    id: user.id,
    name,
    primaryIdentifier: primary?.value ?? "No identifier",
    identifiers: user.identifiers.length,
    passkeys: user.passkeys.length,
    lastActive: mostRecent(
      user.passkeys.map((passkey) => passkey.lastUsedAt).filter(Boolean),
    ),
    createdAt: user.createdAt,
    status: user.identifiers.some((identifier) => identifier.verified) ? "Active" : "Needs verification",
  };
}

function serviceAccountView(account: ServiceAccount): ServiceAccountView {
  return {
    id: account.id,
    name: account.name,
    description: account.description,
    status: account.status === ServiceAccountStatus.DISABLED ? "Disabled" : "Active",
    scopes: [...account.scopes],
    credentials: account.credentials.map((credential) => ({
      id: credential.id,
      name: credential.name,
      hint: credential.secretHint,
      createdAt: credential.createdAt,
      lastUsedAt: credential.lastUsedAt,
      revokedAt: credential.revokedAt,
    })),
    createdAt: account.createdAt,
    lastUsedAt: account.lastUsedAt,
  };
}

function mostRecent(values: string[]): string {
  if (!values.length) return "Never";
  const timestamp = values.sort().at(-1)!;
  return new Intl.RelativeTimeFormat("en", { numeric: "auto" }).format(
    -Math.max(
      1,
      Math.round((Date.now() - new Date(timestamp).getTime()) / 86_400_000),
    ),
    "day",
  );
}

interface PublicKeyCredentialDescriptorJSON {
  type: PublicKeyCredentialType;
  id: string;
  transports?: AuthenticatorTransport[];
}

interface PublicKeyCredentialRequestOptionsJSON
  extends Omit<PublicKeyCredentialRequestOptions, "challenge" | "allowCredentials"> {
  challenge: string;
  allowCredentials?: PublicKeyCredentialDescriptorJSON[];
}
