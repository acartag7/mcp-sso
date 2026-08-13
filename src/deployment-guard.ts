import { AuthConfigError, type BridgeConfig } from "./config.ts";
import { noopRateLimit, type RateLimitPort } from "./ports/rate-limit.ts";
import { DEFAULT_ALLOWED_REDIRECT_ORIGINS } from "./redirect.ts";

const STARTER_REDIRECT_ORIGINS = new Set([
  ...DEFAULT_ALLOWED_REDIRECT_ORIGINS,
  "http://localhost", "http://127.0.0.1", "http://[::1]",
]);

export function assertSafeDeploymentCombination(deps: {
  config: BridgeConfig;
  rateLimit?: RateLimitPort;
  acknowledgeUnsafeStatelessDefaults?: true;
}): void {
  const bounded = deps.rateLimit !== undefined && deps.rateLimit !== noopRateLimit;
  if (deps.config.dcr.mode !== "stateless" || bounded) return;
  const starterOnly = deps.config.redirectAllowlist.every((entry) => {
    try { return STARTER_REDIRECT_ORIGINS.has(new URL(entry).origin); }
    catch { return false; } // createBridgeConfig already rejects malformed entries.
  });
  if (starterOnly) {
    if (deps.acknowledgeUnsafeStatelessDefaults === true) {
      console.warn(
        "[mcp-sso] acknowledgeUnsafeStatelessDefaults is ON — stateless DCR, starter-only redirect trust, and no limiter are unsafe for internet-facing use.",
      );
      return;
    }
    throw new AuthConfigError(
      "stateless DCR with no application-specific HTTPS redirect and no RateLimitPort is unsafe; use stored DCR, configure an application callback, supply a limiter, or explicitly acknowledge the temporary starter risk",
    );
  }
}
