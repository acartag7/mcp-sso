import type { FastifyInstance } from "fastify";
import type { RateLimitPort } from "../../src/ports/rate-limit.ts";

/** Example-owned, finite admission budget for the anonymous DCR write route. */
export const FASTIFY_DCR_REGISTER_RATE_LIMIT = Object.freeze({
  max: 30,
  timeWindow: 60_000,
  groupId: "oauth-client-registration",
});

/** Bound aggregate stored-DCR writes in one process; other Bridge keys remain
 * available so this example-owned port does not redefine their policy. */
export function createDcrRegistrationRateLimitPort(): RateLimitPort {
  let startedAt: number | undefined;
  let remaining: number = FASTIFY_DCR_REGISTER_RATE_LIMIT.max;
  return Object.freeze({
    async check(key: string): Promise<boolean> {
      if (!key.startsWith("register:")) return true;
      const now = Date.now();
      if (!Number.isFinite(now)) return false;
      if (startedAt === undefined || now - startedAt >= FASTIFY_DCR_REGISTER_RATE_LIMIT.timeWindow) {
        startedAt = now;
        remaining = FASTIFY_DCR_REGISTER_RATE_LIMIT.max - 1;
        return true;
      }
      if (now < startedAt || remaining === 0) return false;
      remaining -= 1;
      return true;
    },
  });
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
