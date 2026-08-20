import type { FastifyInstance } from "fastify";
import type { RateLimitPort } from "../../src/ports/rate-limit.ts";

/** Example-owned, finite admission budget for the anonymous DCR write route. */
export const FASTIFY_DCR_REGISTER_RATE_LIMIT = Object.freeze({
  max: 30,
  timeWindow: 60_000,
  groupId: "oauth-client-registration",
});
export const EXAMPLE_UPSTREAM_BUCKET_CAP = 1_024;

interface FixedWindow {
  startedAt?: number;
  remaining: number;
}

/** Bound aggregate registration work and upstream redirect work in one process.
 * Registration stays aggregate so rotating source IPs cannot expand durable
 * stored-DCR writes. Upstream uses the exact per-IP key supplied by the flow. */
export function createDcrRegistrationRateLimitPort(): RateLimitPort {
  const registration: FixedWindow = { remaining: FASTIFY_DCR_REGISTER_RATE_LIMIT.max };
  const upstream = new Map<string, FixedWindow>();
  return Object.freeze({
    async check(key: string): Promise<boolean> {
      const registrationKey = key.startsWith("register:");
      if (!registrationKey && !key.startsWith("upstream:")) return true;
      const now = Date.now();
      if (!Number.isFinite(now)) return false;
      if (registrationKey) return charge(registration, now);
      let bucket = upstream.get(key);
      if (!bucket) {
        if (upstream.size >= EXAMPLE_UPSTREAM_BUCKET_CAP) {
          for (const [storedKey, window] of upstream) {
            if (window.startedAt !== undefined
              && now - window.startedAt >= FASTIFY_DCR_REGISTER_RATE_LIMIT.timeWindow) {
              upstream.delete(storedKey);
            }
          }
          if (upstream.size >= EXAMPLE_UPSTREAM_BUCKET_CAP) return false;
        }
        bucket = { remaining: FASTIFY_DCR_REGISTER_RATE_LIMIT.max };
      }
      upstream.set(key, bucket);
      return charge(bucket, now);
    },
  });
}

function charge(window: FixedWindow, now: number): boolean {
  if (window.startedAt === undefined
    || now - window.startedAt >= FASTIFY_DCR_REGISTER_RATE_LIMIT.timeWindow) {
    window.startedAt = now;
    window.remaining = FASTIFY_DCR_REGISTER_RATE_LIMIT.max - 1;
    return true;
  }
  if (now < window.startedAt || window.remaining === 0) return false;
  window.remaining -= 1;
  return true;
}

/** Attach exact-path admission before registerOAuthRoutes creates its child scope. */
export function installDcrRegistrationRateLimit(app: FastifyInstance): void {
  const limit = app.rateLimit(FASTIFY_DCR_REGISTER_RATE_LIMIT);
  app.addHook("onRequest", async (request, reply) => {
    if (request.method !== "POST" || !isRegistrationPath(request.url)) return;
    await limit.call(app, request, reply);
  });
}

function isRegistrationPath(requestUrl: string): boolean {
  try { return new URL(requestUrl, "http://localhost").pathname === "/oauth/register"; }
  catch { return false; }
}
