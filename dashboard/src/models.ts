export type NavKey =
  | "overview"
  | "users"
  | "organization"
  | "service-accounts"
  | "webhooks"
  | "metrics";

export interface OperatorView {
  id: string;
  email: string;
  displayName: string;
  role: string;
}

export interface OrganizationView {
  id: string;
  slug: string;
  name: string;
  createdAt: string;
}

export interface UserView {
  id: string;
  name: string;
  primaryIdentifier: string;
  identifiers: number;
  passkeys: number;
  lastActive: string;
  createdAt: string;
  status: "Active" | "Needs verification";
}

export interface CredentialView {
  id: string;
  name: string;
  hint: string;
  createdAt: string;
  lastUsedAt: string;
  revokedAt: string;
}

export interface ServiceAccountView {
  id: string;
  name: string;
  description: string;
  status: "Active" | "Disabled";
  scopes: string[];
  credentials: CredentialView[];
  createdAt: string;
  lastUsedAt: string;
}

export interface WebhookView {
  id: string;
  name: string;
  url: string;
  status: "Healthy" | "Retrying" | "Paused";
  events: string[];
  successRate: string;
  lastDelivery: string;
}

export interface MetricView {
  label: string;
  value: string;
  change: string;
  direction: "up" | "down" | "flat";
  note: string;
}
