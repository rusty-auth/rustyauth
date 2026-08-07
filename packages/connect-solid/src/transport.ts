import type { Interceptor, Transport } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";

export interface TransportOptions {
  /** Defaults to the current origin; RustyAuth serves both API and dashboard. */
  baseUrl?: string;
  interceptors?: readonly Interceptor[];
  fetch?: typeof globalThis.fetch;
  /** Use Protobuf binary payloads for high-volume consumers. */
  useBinaryFormat?: boolean;
}

/** Tags each request so browser failures can be correlated with server logs. */
function requestIDInterceptor(): Interceptor {
  return (next) => (req) => {
    req.header.set("x-request-id", globalThis.crypto.randomUUID());
    return next(req);
  };
}

/**
 * Builds a credentialed Connect transport. The dashboard authenticates with
 * an HttpOnly operator cookie, so every request must include credentials.
 */
export function createConnectSolidTransport(options: TransportOptions = {}): Transport {
  const baseFetch = options.fetch ?? globalThis.fetch;
  const credentialedFetch = ((input: RequestInfo | URL, init?: RequestInit) =>
    baseFetch(input, {
      ...init,
      credentials: "include",
    })) as typeof globalThis.fetch;

  return createConnectTransport({
    baseUrl: (options.baseUrl ?? "/").replace(/\/$/, "") || "/",
    interceptors: [requestIDInterceptor(), ...(options.interceptors ?? [])],
    fetch: credentialedFetch,
    useBinaryFormat: options.useBinaryFormat ?? false,
  });
}
