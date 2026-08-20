import { AuthConfigError, type BridgeConfig } from "./config.ts";
import {
  noopRateLimit, rateLimitIdentity, recordRateLimitSnapshot, type RateLimitPort,
} from "./ports/rate-limit.ts";
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

/** Any redirect entry on a loopback host is starter trust regardless of path,
 * port, or scheme (§5): native CLI clients choose their callback path at
 * runtime, and an entry with a path re-widens starter trust exactly like the
 * root spelling. Query/fragment spellings stay excluded — §10.0 already
 * rejects them, and this predicate must not widen past origin-form trust. */
function isGenericLoopbackRedirect(value: string): boolean {
  try {
    const url = new URL(value);
    return LOOPBACK_HOSTS.has(url.hostname) && !url.search && !url.hash;
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
}, options: { emitAcknowledgementWarning?: boolean } = {}): RateLimitPort | undefined {
  const config = deps.config;
  const rateLimit = snapshotRateLimit(deps.rateLimit);
  const acknowledged = deps.acknowledgeUnsafeStatelessDefaults === true;
  const emitAcknowledgementWarning = options.emitAcknowledgementWarning !== false;
  if (acknowledged) {
    if (!isLoopbackUrl(config.issuer) || !isLoopbackUrl(config.resource)) {
      throw new AuthConfigError("acknowledgeUnsafeStatelessDefaults is restricted to loopback issuer and resource URLs");
    }
  }
  const bounded = rateLimit !== undefined && rateLimit !== noopRateLimit;
  if (config.dcr.mode === "stored" && !bounded) {
    throw new AuthConfigError(
      "stored DCR requires a bounded RateLimitPort because anonymous registrations create durable state; supply a limiter (mcp-sso/rate-limit/redis ships one)",
    );
  }
  if (acknowledged && emitAcknowledgementWarning) warnAcknowledgement();
  if (bounded) return rateLimit;
  const localOnly = config.dev?.allowInsecureLocalhost === true
    && isLoopbackUrl(config.issuer) && isLoopbackUrl(config.resource);
  if (localOnly) return rateLimit;
  const retainsGenericLoopback = config.redirectAllowlist.some(isGenericLoopbackRedirect);
  const hasApplicationSpecificHttps = !retainsGenericLoopback
    && config.redirectAllowlist.some(isApplicationSpecificHttpsRedirect);
  if (!hasApplicationSpecificHttps) {
    if (acknowledged) return rateLimit;
    throw new AuthConfigError(
      "stateless DCR with no application-specific HTTPS redirect and no RateLimitPort is unsafe; configure an application callback, supply a limiter, or explicitly acknowledge the temporary starter risk",
    );
  }
  return rateLimit;
}

/** Read and bind a RateLimitPort once so an accessor-backed `check` cannot pass
 * boot validation and disappear when a request reaches the guard. */
export function snapshotRateLimit(rateLimit: RateLimitPort | undefined): RateLimitPort | undefined {
  if (rateLimit === undefined || rateLimit === noopRateLimit) return rateLimit;
  if (rateLimitIdentity(rateLimit) !== rateLimit) return rateLimit;
  let check: unknown;
  try { check = rateLimit.check; }
  catch { throw new AuthConfigError("rateLimit must implement an async check(key) method"); }
  if (typeof check !== "function") {
    throw new AuthConfigError("rateLimit must implement an async check(key) method");
  }
  const snapshot: RateLimitPort = {
    async check(key: string): Promise<boolean> {
      return await Reflect.apply(check, rateLimit, [key]) as boolean;
    },
  };
  recordRateLimitSnapshot(snapshot, rateLimit);
  return Object.freeze(snapshot);
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
