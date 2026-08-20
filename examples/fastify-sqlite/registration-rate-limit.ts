import type { FastifyInstance } from "fastify";
import type { RateLimitPort } from "../../src/ports/rate-limit.ts";

/** Example-owned, finite admission budget for the anonymous DCR write route. */
export const FASTIFY_DCR_REGISTER_RATE_LIMIT = Object.freeze({
  max: 30,
  timeWindow: 60_000,
  groupId: "oauth-client-registration",
});
export const EXAMPLE_PER_IP_BUCKET_CAP = 1_024;

interface FixedWindow {
  startedAt?: number;
  remaining: number;
}

/** Bound aggregate registration work and anonymous identity work in one process.
 * Registration stays aggregate so rotating source IPs cannot expand durable
 * stored-DCR writes. Direct and upstream identity paths use their exact per-IP
 * keys, with distinct budgets in one bounded map. */
export function createDcrRegistrationRateLimitPort(): RateLimitPort {
  const registration: FixedWindow = { remaining: FASTIFY_DCR_REGISTER_RATE_LIMIT.max };
  const perIp = new Map<string, FixedWindow>();
  return Object.freeze({
    async check(key: string): Promise<boolean> {
      const registrationKey = key.startsWith("register:");
      const perIpKey = key.startsWith("authorize:") || key.startsWith("upstream:");
      if (!registrationKey && !perIpKey) return true;
      const now = Date.now();
      if (!Number.isFinite(now)) return false;
      if (registrationKey) return charge(registration, now);
      let bucket = perIp.get(key);
      if (!bucket) {
        if (perIp.size >= EXAMPLE_PER_IP_BUCKET_CAP) {
          for (const [storedKey, window] of perIp) {
            if (window.startedAt !== undefined
              && now - window.startedAt >= FASTIFY_DCR_REGISTER_RATE_LIMIT.timeWindow) {
              perIp.delete(storedKey);
            }
          }
          if (perIp.size >= EXAMPLE_PER_IP_BUCKET_CAP) return false;
        }
        bucket = { remaining: FASTIFY_DCR_REGISTER_RATE_LIMIT.max };
      }
      perIp.set(key, bucket);
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
