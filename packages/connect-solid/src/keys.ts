/** Namespace for every RustyAuth Connect-derived cache key. */
export const QUERY_KEY_ROOT = "rustyauth-rpc" as const;

/**
 * Builds a cache key from the RPC identity plus its input. Keeping service and
 * method as separate segments allows service-wide invalidation after a
 * control-plane mutation.
 */
export function queryKeyFor(
  service: string,
  method: string,
  input?: unknown,
): readonly unknown[] {
  return input === undefined
    ? [QUERY_KEY_ROOT, service, method] as const
    : [QUERY_KEY_ROOT, service, method, input] as const;
}
