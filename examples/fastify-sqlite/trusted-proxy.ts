import { isIP } from "node:net";
import { AuthConfigError } from "../../src/config.ts";

export const TRUSTED_PROXIES_ENV = "MCP_SSO_TRUSTED_PROXIES";
const MAX_TRUSTED_PROXIES = 32;
const MAX_TRUSTED_PROXY_LENGTH = 64;

function invalidTrustedProxies(): never {
  throw new AuthConfigError(
    "trusted proxies must be 1..32 unique IP or CIDR entries (MCP_SSO_TRUSTED_PROXIES is comma-separated)",
  );
}

/** Snapshot the narrow Fastify trustProxy shape exposed by the examples.
 *  Fastify/proxy-addr remains authoritative for request-chain resolution; this
 *  boundary deliberately excludes trust-all, hop-count, callback, and named-range
 *  forms so forwarded headers never become trusted through ambiguous config. */
export function validatedTrustedProxies(value: unknown): string[] | undefined {
  if (value === undefined) return undefined;
  try {
    if (!Array.isArray(value) || value.length < 1 || value.length > MAX_TRUSTED_PROXIES) {
      return invalidTrustedProxies();
    }
    const snapshot: string[] = [];
    const seen = new Set<string>();
    for (let i = 0; i < value.length; i += 1) {
      if (!Object.hasOwn(value, i)) return invalidTrustedProxies();
      const raw: unknown = value[i];
      if (typeof raw !== "string") return invalidTrustedProxies();
      const entry = raw.trim();
      if (entry.length < 1 || entry.length > MAX_TRUSTED_PROXY_LENGTH || seen.has(entry)) {
        return invalidTrustedProxies();
      }
      const slash = entry.indexOf("/");
      if (slash !== entry.lastIndexOf("/")) return invalidTrustedProxies();
      const address = slash === -1 ? entry : entry.slice(0, slash);
      const family = isIP(address);
      if (family === 0) return invalidTrustedProxies();
      if (slash !== -1) {
        const prefixText = entry.slice(slash + 1);
        if (prefixText.length < 1) return invalidTrustedProxies();
        for (const c of prefixText) if (c < "0" || c > "9") return invalidTrustedProxies();
        const prefix = Number(prefixText);
        if (!Number.isSafeInteger(prefix) || prefix < 1 || prefix > (family === 4 ? 32 : 128)) {
          return invalidTrustedProxies();
        }
      }
      seen.add(entry);
      snapshot.push(entry);
    }
    return snapshot;
  } catch (error) {
    if (error instanceof AuthConfigError) throw error;
    return invalidTrustedProxies();
  }
}

/** Read the option through the same fixed-error boundary (a getter is external too). */
export function trustedProxiesFromOptions(options: object): string[] | undefined {
  let value: unknown;
  try { value = (options as { trustedProxies?: unknown }).trustedProxies; }
  catch { return invalidTrustedProxies(); }
  return validatedTrustedProxies(value);
}

/** Parse the examples' production env before state directories or listeners. */
export function trustedProxiesFromEnv(
  env: Record<string, string | undefined> = process.env,
): string[] | undefined {
  let raw: unknown;
  try { raw = env[TRUSTED_PROXIES_ENV]; } catch { return invalidTrustedProxies(); }
  if (raw === undefined) return undefined;
  if (typeof raw !== "string") return invalidTrustedProxies();
  return validatedTrustedProxies(raw.split(","));
}
