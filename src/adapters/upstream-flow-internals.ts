// Pure helpers for the §17.11 upstream redirect-leg orchestrator
// (`upstream-flow.ts`). Factored out of the orchestrator so the factory + the
// two handlers stay well under the 250-line file limit (contracts §6). No I/O
// here except jose (HS256 sign/verify) and node:crypto (timing-safe compare);
// the clock is passed in (no ambient time). Everything is framework-free.

import { randomBytes, timingSafeEqual } from "node:crypto";
import { AuthConfigError, type BridgeConfig } from "../config.ts";
import { OAuthError, oauthErrorBody } from "../errors.ts";
import { buildAuthorizationErrorRedirect } from "../challenge.ts";
import { headerString, queryString, resourceParam, type NormRequest, type NormResponse } from "./http.ts";
import { OAUTH_PARAM_KEYS } from "./authorize-params.ts";

// Re-export the shared authorize occurrence boundary so existing internal
// importers keep the same surface while direct and pairing use the same source.
export { OAUTH_PARAM_KEYS };
export { OAUTH_SINGLETON_PARAM_KEYS, findDuplicatedKeys, findRepeatedKeys } from "./authorize-params.ts";

// The flow JWT moved to its own module (250-line limit); re-exported here so
// every existing importer of these names keeps working unchanged.
export {
  FLOW_AUDIENCE, flowAudience, signFlowToken, verifyFlowToken, type FlowClaims,
} from "./upstream-flow-jwt.ts";

/** Callback query params checked for RFC 6749 §3.1 duplicates (failure row 1). */
const CALLBACK_DUP_KEYS = ["state", "code", "error", "error_description"] as const;

/** A browser rejects a cookie whose value exceeds ~4096 bytes; the flow cookie
 *  value is the signed JWT (it carries the round-tripped client params, so an
 *  oversized request fails fast at authorize rather than setting an unusable
 *  cookie). §17.11 caps the serialized Set-Cookie value at 4096 bytes. */
const MAX_FLOW_COOKIE_BYTES = 4096;

// --- cookie profile (the library's first cookie — threat-model row 4) ---

export interface CookieProfile {
  readonly name: string;
  readonly secure: boolean;
}

/** Decide the cookie profile at boot from the issuer scheme. https ⇒ `__Host-`
 *  prefix (Path=/, Secure, no Domain per RFC 6265bis); http loopback (legal only
 *  under §5 dev.allowInsecureLocalhost) ⇒ the non-prefixed name without Secure. */
export function resolveCookieProfile(issuer: string): CookieProfile {
  let protocol = "https:";
  try { protocol = new URL(issuer).protocol; } catch { /* config already validated */ }
  return protocol === "https:" ? { name: "__Host-mcp-sso-upstream", secure: true } : { name: "mcp-sso-upstream", secure: false };
}

/** Serialize a Set-Cookie value. Same attributes for set and clear (the clear
 *  uses Max-Age=0 + empty value); `__Host-` requires identical Path=/, Secure,
 *  and no Domain on BOTH or browsers treat it as a different cookie (§17.11). */
export function setCookieValue(profile: CookieProfile, value: string, maxAge: number): string {
  const segs = [`${profile.name}=${value}`, "Path=/"];
  if (profile.secure) segs.push("Secure");
  segs.push("HttpOnly", "SameSite=Lax", `Max-Age=${maxAge}`);
  return segs.join("; ");
}

export function clearCookieValue(profile: CookieProfile): string {
  return setCookieValue(profile, "", 0);
}

/** Read the flow cookie value from a request. Returns undefined if no cookie of
 *  the profile's name is present (failure row 2); returns the value (possibly
 *  empty/garbage) if the name is present — so "readable cookie" = !== undefined
 *  drives the clear-on-response decision (rows 3+). */
export function readFlowCookie(headers: NormRequest["headers"], profile: CookieProfile): string | undefined {
  const raw = headerString(headers, "cookie");
  if (!raw) return undefined;
  const prefix = `${profile.name}=`;
  for (const part of raw.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) return trimmed.slice(prefix.length);
  }
  return undefined;
}

/** True if the serialized Set-Cookie value (name + value + attributes — RFC 6265
 *  §6.1 caps name+value+attributes) would exceed 4096 bytes. §17.11 measures the
 *  *serialized* header, not the bare cookie value, so a too-large cookie is
 *  rejected fast at authorize rather than silently dropped by the browser at the
 *  callback (which would surface as a confusing flow_cookie_missing post-login). */
export function flowCookieOversized(profile: CookieProfile, value: string, maxAge: number): boolean {
  return Buffer.byteLength(setCookieValue(profile, value, maxAge), "utf8") > MAX_FLOW_COOKIE_BYTES;
}

// --- callbackPath boot validation (§17.11) ---

const RESERVED_CALLBACK_ROUTES = [
  "/oauth/authorize", "/oauth/authorize/approve", "/oauth/token",
  "/oauth/register", "/oauth/revoke", "/oauth/jwks",
];

/** Validate `callbackPath` as a plain pathname that registers the route the real
 *  callback request hits. RAW char checks run BEFORE URL parsing (the §17.1
 *  dot-segment lesson: WHATWG normalizes `/%2e%2e/` away pre-parse); the
 *  normalized-equality check catches whatever survives. */
export function assertCallbackPath(path: string, issuerOrigin: string, resourcePath: string): void {
  if (typeof path !== "string" || !path.startsWith("/")) {
    throw new AuthConfigError("callbackPath must start with '/'");
  }
  if (/[?#%\\\s]/.test(path) || /[\x00-\x1F\x7F]/.test(path)) {
    throw new AuthConfigError("callbackPath must be a plain pathname (no '?', '#', '%', '\\', whitespace, or control chars)");
  }
  const segments = path.split("/");
  for (let i = 1; i < segments.length; i++) { // index 0 is the leading "" from "/"
    const s = segments[i];
    if (s === undefined) continue;
    if (s === "") throw new AuthConfigError("callbackPath must not contain empty (//) segments");
    if (s === "." || s === "..") throw new AuthConfigError("callbackPath must not contain dot (./..) segments");
  }
  let normalized: string;
  try { normalized = new URL(issuerOrigin + path).pathname; } catch { throw new AuthConfigError("callbackPath is not a valid path under the issuer origin"); }
  if (normalized !== path) throw new AuthConfigError(`callbackPath must equal its normalized form (got '${normalized}')`);
  if (RESERVED_CALLBACK_ROUTES.includes(path) || path === resourcePath || path.startsWith("/.well-known/")) {
    throw new AuthConfigError(`callbackPath must not be a reserved route: ${path}`);
  }
}

/** Timing-safe string compare; length mismatch fails (returns false). */
export function timingSafeStringEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length > 0 && left.length === right.length && timingSafeEqual(left, right);
}

export const CALLBACK_DUP_KEYS_EXPORT = CALLBACK_DUP_KEYS;

export function randomFlowToken(): string {
  return randomBytes(32).toString("base64url");
}

export function gatherOAuthParams(req: NormRequest): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of OAUTH_PARAM_KEYS) {
    const value = key === "resource" ? resourceParam(req.query[key]) : queryString(req.query, key);
    if (typeof value === "string") out[key] = value;
  }
  return out;
}

export function pickOAuthParams(params: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of OAUTH_PARAM_KEYS) {
    const value = params[key];
    if (typeof value === "string") out[key] = value;
  }
  return out;
}

// --- response builders (failure-table rows) ---

/** A redirect-channel error (rows 7/8/10/11): 302 to the §10-validated
 *  `redirect_uri` (from the verified flow params) with a FIXED description; the
 *  IdP's own error/error_description are never echoed. */
export function redirectErrorResponse(config: BridgeConfig, redirectUri: string, code: string, state: string | undefined, description: string): NormResponse {
  const location = buildAuthorizationErrorRedirect(config, redirectUri, code, state, description);
  return { status: 302, headers: { location }, redirect: location };
}

/** A direct 4xx error (rows 1-6, 9): RFC 6749 §5.2 body, no Location. */
export function directErrorResponse(code: string, message: string, status = 400): NormResponse {
  return { status, headers: {}, body: oauthErrorBody(new OAuthError(code, message, status)) };
}
