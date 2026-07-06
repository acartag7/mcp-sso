// Pure helpers for the §17.11 upstream redirect-leg orchestrator
// (`upstream-flow.ts`). Factored out of the orchestrator so the factory + the
// two handlers stay well under the 250-line file limit (contracts §6). No I/O
// here except jose (HS256 sign/verify) and node:crypto (timing-safe compare);
// the clock is passed in (no ambient time). Everything is framework-free.

import { timingSafeEqual } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import { AuthConfigError } from "../config.ts";
import { OAuthError, oauthErrorBody } from "../errors.ts";
import { buildErrorRedirect } from "../challenge.ts";
import { headerString, type NormRequest, type NormResponse } from "./http.ts";

/** The client OAuth params that round-trip through the signed flow cookie —
 *  exactly the §9.3 authorize inputs (same set pairing-flow.ts hidden-fields). */
export const OAUTH_PARAM_KEYS = [
  "response_type", "client_id", "redirect_uri", "code_challenge",
  "code_challenge_method", "resource", "scope", "state",
] as const;

/** Callback query params checked for RFC 6749 §3.1 duplicates (failure row 1). */
const CALLBACK_DUP_KEYS = ["state", "code", "error", "error_description"] as const;

/** Pinned audience for the flow JWT — distinct from `mcp-sso/consent` so a flow
 *  token can never be replayed as a consent token (and vice-versa), even though
 *  both are HS256-signed with the same consent secret (§17.11). */
export const FLOW_AUDIENCE = "mcp-sso/upstream-flow";

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

// --- flow JWT (HS256, consent secret, pinned aud) ---

export interface FlowClaims {
  jti: string;
  state: string;
  nonce: string;
  codeVerifier: string;
  params: Record<string, string>;
  exp: number;
}

function flowSecret(consentSigningSecret: string): Uint8Array {
  return new TextEncoder().encode(consentSigningSecret);
}

export async function signFlowToken(args: {
  secret: string; issuer: string; clock: { nowMs(): number };
  jti: string; state: string; nonce: string; codeVerifier: string;
  params: Record<string, string>; ttlSeconds: number;
}): Promise<string> {
  const now = Math.floor(args.clock.nowMs() / 1000);
  return await new SignJWT({
    jti: args.jti, state: args.state, nonce: args.nonce,
    code_verifier: args.codeVerifier, params: args.params,
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(args.issuer)
    .setAudience(FLOW_AUDIENCE)
    .setIssuedAt(now)
    .setExpirationTime(now + args.ttlSeconds)
    .sign(flowSecret(args.secret));
}

/** Verify signature + iss + aud. Expiry is NOT checked here (currentDate=epoch
 *  disables jose's exp rejection) so the caller can distinguish row 3 (this
 *  throw ⇒ flow_cookie_invalid) from row 4 (manual exp ⇒ flow_expired). A
 *  structurally-malformed payload on a validly-signed token also throws ⇒ row 3. */
export async function verifyFlowToken(token: string, secret: string, issuer: string): Promise<FlowClaims> {
  const { payload } = await jwtVerify(token, flowSecret(secret), {
    algorithms: ["HS256"], issuer, audience: FLOW_AUDIENCE, currentDate: new Date(0),
  });
  const rawParams = payload.params;
  if (typeof rawParams !== "object" || rawParams === null || Array.isArray(rawParams)) {
    throw new Error("flow params missing");
  }
  const params: Record<string, string> = {};
  for (const [k, v] of Object.entries(rawParams)) if (typeof v === "string") params[k] = v;
  return {
    jti: requiredString(payload.jti, "jti"),
    state: requiredString(payload.state, "state"),
    nonce: requiredString(payload.nonce, "nonce"),
    codeVerifier: requiredString(payload.code_verifier, "code_verifier"),
    params,
    // exp is always set by signFlowToken; a signed token missing it (or non-numeric)
    // is structurally malformed ⇒ throw ⇒ row 3 flow_cookie_invalid. Never coerce
    // to 0 (that would silently skip the row-4 expiry check).
    exp: requiredPositiveNumber(payload.exp, "exp"),
  };
}

function requiredPositiveNumber(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) throw new Error(`flow token missing ${label}`);
  return value;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value) throw new Error(`flow token missing ${label}`);
  return value;
}

/** Timing-safe string compare; length mismatch fails (returns false). */
export function timingSafeStringEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length > 0 && left.length === right.length && timingSafeEqual(left, right);
}

/** RFC 6749 §3.1 duplicate-param check: any key present more than once (array
 *  length > 1 in the normalized query) ⇒ reject, never pick first/last. */
export function findDuplicatedKeys(query: NormRequest["query"], keys: readonly string[]): string[] {
  const dup: string[] = [];
  for (const k of keys) {
    const v = query[k];
    if (Array.isArray(v) && v.length > 1) dup.push(k);
  }
  return dup;
}

export const CALLBACK_DUP_KEYS_EXPORT = CALLBACK_DUP_KEYS;

// --- response builders (failure-table rows) ---

/** A redirect-channel error (rows 7/8/10/11): 302 to the §10-validated
 *  `redirect_uri` (from the verified flow params) with a FIXED description; the
 *  IdP's own error/error_description are never echoed. */
export function redirectErrorResponse(redirectUri: string, code: string, state: string | undefined, description: string): NormResponse {
  const location = buildErrorRedirect(redirectUri, code, state, description);
  return { status: 302, headers: { location }, redirect: location };
}

/** A direct 4xx error (rows 1-6, 9): RFC 6749 §5.2 body, no Location. */
export function directErrorResponse(code: string, message: string, status = 400): NormResponse {
  return { status, headers: {}, body: oauthErrorBody(new OAuthError(code, message, status)) };
}
