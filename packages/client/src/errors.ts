/** The stable error envelope every RustyAuth failure response carries. */
export interface ErrorBody {
  error: string;
}

/**
 * A non-2xx response from RustyAuth.
 *
 * Carries the HTTP status and the parsed `{ "error": "…" }` body so consumers
 * can branch on failures: `401` for missing origin/bootstrap/session or a
 * failed ceremony, `409` for existing identifiers/credentials or a prohibited
 * final removal, `429` with `retryAfterSeconds` when rate limited.
 */
export class RustyAuthError extends Error {
  /** HTTP status code of the failed response. */
  readonly status: number;
  /** Parsed error body, or `null` when the response body was not the JSON envelope. */
  readonly body: ErrorBody | null;
  /** Seconds from the `Retry-After` header, or `null` when absent. */
  readonly retryAfterSeconds: number | null;

  constructor(
    message: string,
    options: { status: number; body?: ErrorBody | null; retryAfterSeconds?: number | null },
  ) {
    super(message);
    this.name = "RustyAuthError";
    this.status = options.status;
    this.body = options.body ?? null;
    this.retryAfterSeconds = options.retryAfterSeconds ?? null;
  }
}
