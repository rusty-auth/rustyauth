import { queryKeyFor } from "./keys.ts";

/** A unary RPC read. */
export interface QueryOptions<Input, Output> {
  service: string;
  method: string;
  /** Part of the cache key, so it must be serializable. */
  input: Input;
  call: (input: Input, signal: AbortSignal) => Promise<Output>;
  staleTime?: number;
  enabled?: boolean;
}

/** The query shape accepted by `createQuery`. */
export interface QueryOptionsResult<Output> {
  queryKey: readonly unknown[];
  queryFn: (context: { signal: AbortSignal }) => Promise<Output>;
  staleTime?: number;
  enabled?: boolean;
}

/** Builds Solid Query options and forwards cancellation to Connect. */
export function connectQueryOptions<Input, Output>(
  options: QueryOptions<Input, Output>,
): QueryOptionsResult<Output> {
  return {
    queryKey: queryKeyFor(options.service, options.method, options.input),
    queryFn: ({ signal }) => options.call(options.input, signal),
    staleTime: options.staleTime,
    enabled: options.enabled,
  };
}

/** A unary RPC write. */
export interface MutationOptions<Input, Output> {
  service: string;
  method: string;
  call: (input: Input, signal?: AbortSignal) => Promise<Output>;
  signal?: () => AbortSignal | undefined;
}

export interface MutationOptionsResult<Input, Output> {
  mutationKey: readonly unknown[];
  mutationFn: (input: Input) => Promise<Output>;
}

/** Builds mutation options; the key identifies the action, not its payload. */
export function connectMutationOptions<Input, Output>(
  options: MutationOptions<Input, Output>,
): MutationOptionsResult<Input, Output> {
  return {
    mutationKey: queryKeyFor(options.service, options.method),
    mutationFn: (input) => options.call(input, options.signal?.()),
  };
}

/** A finite server stream collected to completion. */
export interface StreamOptions<Input, Output> {
  service: string;
  method: string;
  input: Input;
  call: (input: Input, signal: AbortSignal) => AsyncIterable<Output>;
  /** Hard cap on buffered messages. Defaults to 1000. */
  maxMessages?: number;
  staleTime?: number;
}

/**
 * Builds options for a finite stream. Live feeds belong in
 * {@linkcode openSubscription}, outside the query cache.
 */
export function connectStreamOptions<Input, Output>(
  options: StreamOptions<Input, Output>,
): QueryOptionsResult<Output[]> {
  const maxMessages = options.maxMessages ?? 1_000;
  if (!Number.isSafeInteger(maxMessages) || maxMessages <= 0) {
    throw new Error("maxMessages must be a positive safe integer");
  }

  return {
    queryKey: queryKeyFor(options.service, `${options.method}:stream`, options.input),
    queryFn: async ({ signal }) => {
      const messages: Output[] = [];
      for await (const message of options.call(options.input, signal)) {
        if (messages.length >= maxMessages) {
          throw new Error(
            `stream ${options.service}/${options.method} exceeded ${maxMessages} messages`,
          );
        }
        messages.push(message);
      }
      return messages;
    },
    staleTime: options.staleTime,
  };
}

export interface SubscriptionOptions<Input, Output> {
  service: string;
  method: string;
  input: Input;
  call: (input: Input, signal: AbortSignal) => AsyncIterable<Output>;
  onMessage: (message: Output) => void;
  onError?: (error: unknown) => void;
  onComplete?: () => void;
  signal?: AbortSignal;
}

export interface Subscription {
  key: readonly unknown[];
  signal: AbortSignal;
  abort: (reason?: unknown) => void;
  completed: Promise<void>;
}

/** Opens a cancellable live stream without buffering it in the query cache. */
export function openSubscription<Input, Output>(
  options: SubscriptionOptions<Input, Output>,
): Subscription {
  const controller = new AbortController();
  const abortFromParent = (): void => controller.abort(options.signal?.reason);
  if (options.signal?.aborted) {
    abortFromParent();
  } else {
    options.signal?.addEventListener("abort", abortFromParent, { once: true });
  }

  const completed = (async (): Promise<void> => {
    try {
      for await (const message of options.call(options.input, controller.signal)) {
        options.onMessage(message);
      }
      if (!controller.signal.aborted) options.onComplete?.();
    } catch (error) {
      if (!controller.signal.aborted) {
        options.onError?.(error);
        throw error;
      }
    } finally {
      options.signal?.removeEventListener("abort", abortFromParent);
    }
  })();

  return {
    key: queryKeyFor(options.service, `${options.method}:subscription`, options.input),
    signal: controller.signal,
    abort: (reason?: unknown) => controller.abort(reason),
    completed,
  };
}
