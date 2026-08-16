import type { FastifyInstance } from "fastify";

/** Example-owned, finite admission budget for the anonymous DCR write route. */
export const FASTIFY_DCR_REGISTER_RATE_LIMIT = Object.freeze({
  max: 30,
  timeWindow: 60_000,
  groupId: "oauth-client-registration",
});

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
