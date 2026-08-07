/**
 * ConnectRPC v2 option factories for Solid Query.
 *
 * Connect owns transport and protobuf. Solid Query owns caching,
 * cancellation, retries, and query lifecycle. This package is only the seam.
 */

export { createConnectSolidTransport, type TransportOptions } from "./transport.ts";
export {
  connectMutationOptions,
  connectQueryOptions,
  connectStreamOptions,
  type MutationOptions,
  openSubscription,
  type QueryOptions,
  type StreamOptions,
  type Subscription,
} from "./options.ts";
export { QUERY_KEY_ROOT, queryKeyFor } from "./keys.ts";
