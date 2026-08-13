import { AuthConfigError, type BridgeConfig } from "./config.ts";
import { noopRateLimit, type RateLimitPort } from "./ports/rate-limit.ts";
import { DEFAULT_ALLOWED_REDIRECT_ORIGINS } from "./redirect.ts";

const STARTER_REDIRECT_ORIGINS = new Set(DEFAULT_ALLOWED_REDIRECT_ORIGINS);
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

function isLoopbackUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === "http:" || url.protocol === "https:")
      && LOOPBACK_HOSTS.has(url.hostname);
  }
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
  if (deps.rateLimit !== undefined) snapshotRateLimit(deps.rateLimit);
  if (deps.acknowledgeUnsafeStatelessDefaults === true) {
    if (!isLoopbackUrl(deps.config.issuer) || !isLoopbackUrl(deps.config.resource)) {
      throw new AuthConfigError("acknowledgeUnsafeStatelessDefaults is restricted to loopback issuer and resource URLs");
    }
    if (options.emitAcknowledgementWarning !== false) warnAcknowledgement();
  }
  const bounded = deps.rateLimit !== undefined && deps.rateLimit !== noopRateLimit;
  if (deps.config.dcr.mode !== "stateless" || bounded) return;
  const localOnly = deps.config.dev?.allowInsecureLocalhost === true
    && isLoopbackUrl(deps.config.issuer) && isLoopbackUrl(deps.config.resource);
  if (localOnly) return;
  const retainsGenericLoopback = deps.config.redirectAllowlist.some(isGenericLoopbackRedirect);
  const hasApplicationSpecificHttps = !retainsGenericLoopback
    && deps.config.redirectAllowlist.some(isApplicationSpecificHttpsRedirect);
  if (!hasApplicationSpecificHttps) {
    if (deps.acknowledgeUnsafeStatelessDefaults === true) {
      return;
    }
    throw new AuthConfigError(
      "stateless DCR with no application-specific HTTPS redirect and no RateLimitPort is unsafe; use stored DCR, configure an application callback, supply a limiter, or explicitly acknowledge the temporary starter risk",
    );
  }
}

/** Read and bind a RateLimitPort once so an accessor-backed `check` cannot pass
 * boot validation and disappear when a request reaches the guard. */
export function snapshotRateLimit(rateLimit: RateLimitPort | undefined): RateLimitPort | undefined {
  if (rateLimit === undefined || rateLimit === noopRateLimit) return rateLimit;
  let check: unknown;
  try { check = rateLimit.check; }
  catch { throw new AuthConfigError("rateLimit must implement an async check(key) method"); }
  if (typeof check !== "function") {
    throw new AuthConfigError("rateLimit must implement an async check(key) method");
  }
  return Object.freeze({
    async check(key: string): Promise<boolean> {
      return await Reflect.apply(check, rateLimit, [key]) as boolean;
    },
  });
}

/** Reject the acknowledged console-pairing composition before its signing-key
 * and SQLite helpers create state. Bridge repeats the complete guard at boot. */
export function assertLoopbackStarterBeforeState(issuer: string, resource: string): void {
  if (!isLoopbackUrl(issuer) || !isLoopbackUrl(resource)) {
    throw new AuthConfigError("the console-pairing starter requires loopback issuer and resource URLs");
  }
}

function warnAcknowledgement(): void {
  console.warn(
    "[mcp-sso] acknowledgeUnsafeStatelessDefaults is ON — stateless DCR, starter-only redirect trust, and no limiter are unsafe for internet-facing use.",
  );
}
