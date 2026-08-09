export * from "./gen/rustyauth/events/v1/events_pb.ts";
export * from "./gen/rustyauth/identity/v1/identity_pb.ts";
export * from "./gen/rustyauth/metrics/v1/metrics_pb.ts";
export * from "./gen/rustyauth/organization/v1/organization_pb.ts";
export * from "./gen/rustyauth/service_accounts/v1/service_accounts_pb.ts";
export * from "./gen/rustyauth/webhooks/v1/webhooks_pb.ts";

// Fleet and realm-management packages intentionally reuse domain names such
// as Organization. Namespace exports keep the root entry point complete
// without creating ambiguous named exports for existing consumers.
export * as fleetV1 from "./gen/rustyauth/fleet/v1/fleet_pb.ts";
export * as analyticsV1 from "./gen/rustyauth/analytics/v1/analytics_pb.ts";
export * as connectorV1 from "./gen/rustyauth/management/v1/connector_pb.ts";
export * as managementV1 from "./gen/rustyauth/management/v1/management_pb.ts";
