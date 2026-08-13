import { AuthConfigError, type BridgeConfig } from "./config.ts";
import { noopRateLimit, type RateLimitPort } from "./ports/rate-limit.ts";
import { DEFAULT_ALLOWED_REDIRECT_ORIGINS } from "./redirect.ts";

const STARTER_REDIRECT_ORIGINS = new Set(DEFAULT_ALLOWED_REDIRECT_ORIGINS);
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

function isLoopbackUrl(value: string): boolean {
  try { return LOOPBACK_HOSTS.has(new URL(value).hostname); }
  catch { return false; }
}

function isGenericLoopbackRedirect(value: string): boolean {
  try {
    const url = new URL(value);
    return LOOPBACK_HOSTS.has(url.hostname) && url.pathname === "/" && !url.search && !url.hash;
  } catch { return false; }
}

function isApplicationSpecificHttpsRedirect(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:"
      && !STARTER_REDIRECT_ORIGINS.has(url.origin)
      && !isGenericLoopbackRedirect(value);
  } catch { return false; }
}

export function assertSafeDeploymentCombination(deps: {
  config: BridgeConfig;
  rateLimit?: RateLimitPort;
  acknowledgeUnsafeStatelessDefaults?: true;
}, options: { emitAcknowledgementWarning?: boolean } = {}): void {
  if (deps.rateLimit !== undefined && typeof deps.rateLimit?.check !== "function") {
    throw new AuthConfigError("rateLimit must implement an async check(key) method");
  }
  const bounded = deps.rateLimit !== undefined && deps.rateLimit !== noopRateLimit;
  if (deps.config.dcr.mode !== "stateless" || bounded) return;
  const localOnly = deps.config.dev?.allowInsecureLocalhost === true
    && isLoopbackUrl(deps.config.issuer) && isLoopbackUrl(deps.config.resource);
  if (localOnly) {
    if (deps.acknowledgeUnsafeStatelessDefaults === true
      && options.emitAcknowledgementWarning !== false) warnAcknowledgement();
    return;
  }
  const hasApplicationSpecificHttps = deps.config.redirectAllowlist.some(
    isApplicationSpecificHttpsRedirect,
  );
  if (!hasApplicationSpecificHttps) {
    if (deps.acknowledgeUnsafeStatelessDefaults === true) {
      if (!isLoopbackUrl(deps.config.issuer) || !isLoopbackUrl(deps.config.resource)) {
        throw new AuthConfigError("acknowledgeUnsafeStatelessDefaults is restricted to loopback issuer and resource URLs");
      }
      if (options.emitAcknowledgementWarning !== false) {
        warnAcknowledgement();
      }
      return;
    }
    throw new AuthConfigError(
      "stateless DCR with no application-specific HTTPS redirect and no RateLimitPort is unsafe; use stored DCR, configure an application callback, supply a limiter, or explicitly acknowledge the temporary starter risk",
    );
  }
}

function warnAcknowledgement(): void {
  console.warn(
    "[mcp-sso] acknowledgeUnsafeStatelessDefaults is ON — stateless DCR, starter-only redirect trust, and no limiter are unsafe for internet-facing use.",
  );
}
