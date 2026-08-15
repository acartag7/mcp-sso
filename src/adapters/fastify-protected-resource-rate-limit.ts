// Fastify protected-resource admission (contracts §8.4 / §15).
//
// This is deliberately separate from Bridge's optional, fail-open RateLimitPort:
// `/mcp` is an attacker-reachable resource boundary, so every shipped Fastify
// composition installs a finite limiter and store errors fail closed before the
// bearer verifier or protected handler runs.

import fastifyRateLimit, {
  type FastifyRateLimitOptions,
  type FastifyRateLimitStore,
  type FastifyRateLimitStoreCtor,
} from "@fastify/rate-limit";
import type { FastifyInstance } from "fastify";
import { AuthConfigError } from "../config.ts";

const DEFAULT_MAX = 60;
const DEFAULT_WINDOW_MS = 60_000;
const MAX_REQUESTS = 10_000;
const MAX_WINDOW_MS = 3_600_000;

export interface ProtectedResourceRateLimitOptions {
  max?: number;
  timeWindowMs?: number;
  /** Optional shared/custom store. Errors are sanitized and fail closed. */
  store?: FastifyRateLimitStoreCtor;
}

export interface ProtectedResourceRateLimitPolicy {
  readonly max: number;
  readonly timeWindowMs: number;
  readonly groupId: "mcp-protected-resource";
}

/** Register the real Fastify limiter and return the snapshotted per-route policy. */
export async function registerProtectedResourceRateLimit(
  app: FastifyInstance,
  options: ProtectedResourceRateLimitOptions = {},
): Promise<ProtectedResourceRateLimitPolicy> {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw new AuthConfigError("protectedResourceRateLimit must be an object");
  }
  let ownKeys: (string | symbol)[];
  let max: number;
  let timeWindowMs: number;
  let store: FastifyRateLimitStoreCtor | undefined;
  try {
    ownKeys = Reflect.ownKeys(options);
    // Snapshot accessor-backed config once before validation or registration.
    max = options.max ?? DEFAULT_MAX;
    timeWindowMs = options.timeWindowMs ?? DEFAULT_WINDOW_MS;
    store = options.store;
  } catch {
    throw new AuthConfigError("protectedResourceRateLimit could not be read");
  }
  if (ownKeys.some((key) => typeof key !== "string" || !["max", "timeWindowMs", "store"].includes(key))) {
    throw new AuthConfigError("protectedResourceRateLimit contains an unknown option");
  }
  if (!Number.isInteger(max) || max < 1 || max > MAX_REQUESTS) {
    throw new AuthConfigError(`protectedResourceRateLimit.max must be an integer in 1..${MAX_REQUESTS}`);
  }
  if (!Number.isInteger(timeWindowMs) || timeWindowMs < 1_000 || timeWindowMs > MAX_WINDOW_MS) {
    throw new AuthConfigError(`protectedResourceRateLimit.timeWindowMs must be an integer in 1000..${MAX_WINDOW_MS}`);
  }
  if (store !== undefined && typeof store !== "function") {
    throw new AuthConfigError("protectedResourceRateLimit.store must be a store constructor");
  }

  const pluginOptions = {
    global: false,
    hook: "onRequest",
    skipOnError: false,
    max,
    timeWindow: timeWindowMs,
    ...(store === undefined ? {} : { store: failClosedStore(store) }),
  } as const;
  await app.register(fastifyRateLimit, pluginOptions);
  return Object.freeze({ max, timeWindowMs, groupId: "mcp-protected-resource" as const });
}

function unavailable(): Error & { statusCode: number } {
  return Object.assign(new Error("Protected resource rate limiter unavailable"), { statusCode: 503 });
}

function checkedCounter(result: { current: number; ttl: number } | undefined): { current: number; ttl: number } | undefined {
  if (!result) return undefined;
  try {
    const current = result.current;
    const ttl = result.ttl;
    if (!Number.isSafeInteger(current) || !Number.isSafeInteger(ttl)
      || current < 1 || ttl < 0) return undefined;
    return { current, ttl };
  } catch {
    return undefined;
  }
}

/** Wrap custom stores so their failure channel is fixed, single-shot, and closed. */
function failClosedStore(Store: FastifyRateLimitStoreCtor): FastifyRateLimitStoreCtor {
  return class implements FastifyRateLimitStore {
    private readonly inner: FastifyRateLimitStore;

    constructor(options: FastifyRateLimitOptions) {
      try { this.inner = new Store(options); }
      catch { throw unavailable(); }
    }

    incr(
      key: string,
      callback: (error: Error | null, result?: { current: number; ttl: number }) => void,
      timeWindow: number,
      max: number,
    ): void {
      let settled = false;
      const finish = (error: Error | null, result?: { current: number; ttl: number }): void => {
        if (settled) return;
        settled = true;
        const checked = checkedCounter(result);
        if (error || !checked) {
          callback(unavailable());
          return;
        }
        callback(null, checked);
      };
      invokeIncr(this.inner, key, finish, timeWindow, max);
    }

    child(routeOptions: Parameters<FastifyRateLimitStore["child"]>[0]): FastifyRateLimitStore {
      try { return wrapStore(this.inner.child(routeOptions)); }
      catch { throw unavailable(); }
    }
  };
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return typeof value === "object" && value !== null && typeof (value as PromiseLike<unknown>).then === "function";
}

function invokeIncr(
  store: FastifyRateLimitStore,
  key: string,
  finish: (error: Error | null, result?: { current: number; ttl: number }) => void,
  timeWindow: number,
  max: number,
): void {
  try {
    const returned = store.incr(key, finish, timeWindow, max) as unknown;
    if (isThenable(returned)) returned.then(undefined, () => finish(unavailable()));
  } catch {
    finish(unavailable());
  }
}

function wrapStore(inner: FastifyRateLimitStore): FastifyRateLimitStore {
  return {
    incr(key, callback, timeWindow, max) {
      let settled = false;
      const finish = (error: Error | null, result?: { current: number; ttl: number }): void => {
        if (settled) return;
        settled = true;
        const checked = checkedCounter(result);
        if (error || !checked) callback(unavailable());
        else callback(null, checked);
      };
      invokeIncr(inner, key, finish, timeWindow, max);
    },
    child(routeOptions) {
      try { return wrapStore(inner.child(routeOptions)); }
      catch { throw unavailable(); }
    },
  };
}
