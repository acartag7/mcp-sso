// Framework-free HTTP helpers shared by the fastify/express/hono adapters
// (contracts §9.6). Normalized request/response shapes so the Bridge logic is
// framework-agnostic, plus OAuthError → response mapping and subject resolution.

import type { BridgeConfig } from "../config.ts";
import { originOf } from "../config.ts";
import { OAuthError, oauthErrorBody } from "../errors.ts";
import { buildAuthorizationErrorRedirect, buildUnauthorizedChallenge } from "../challenge.ts";

/** Raw request-body budget shared by every built-in OAuth POST route (§9.6). */
export const OAUTH_POST_BODY_MAX_BYTES = 256 * 1024;

export interface NormRequest {
  query: Record<string, string | string[] | undefined>;
  body: unknown;
  /** Exact parsed URL-encoded occurrence snapshot; JSON arrays are not forms. */
  formBody?: unknown;
  headers: Record<string, string | string[] | undefined>;
  /** Best-effort client identifier for rate-limiting (IP). */
  ip?: string;
}

export interface NormResponse {
  status: number;
  headers: Record<string, string>;
  /** JSON body (when not a redirect). */
  body?: unknown;
  /** When set, the adapter issues a 302 to this URL (with `status`). */
  redirect?: string;
}

export interface HeaderRead {
  value?: string;
  ambiguous: boolean;
}

/** Add the cache directive shared by credential-bearing normalized responses. */
export function noStoreHeaders(headers: Record<string, string>): Record<string, string> {
  return { ...headers, "cache-control": "no-store" };
}

/** Preserve Node's occurrence metadata; repeated Cookie fields form one string.
 *  `normalized` supports framework injectors whose mock IncomingMessage omits
 *  `headersDistinct`; its arrays/case-variant keys remain ambiguous. */
export function headersFromDistinct(
  distinct: Record<string, string[] | undefined> | undefined,
  normalized?: NormRequest["headers"],
): NormRequest["headers"] {
  if (distinct === undefined) {
    if (normalized === undefined) throw new TypeError("header occurrence metadata is unavailable");
    const fallback: NormRequest["headers"] = Object.create(null) as NormRequest["headers"];
    for (const [key, raw] of Object.entries(normalized)) {
      fallback[key] = key.toLowerCase() === "cookie" && Array.isArray(raw)
        ? raw.join("; ") : Array.isArray(raw) ? [...raw] : raw;
    }
    return fallback;
  }
  const headers: NormRequest["headers"] = Object.create(null) as NormRequest["headers"];
  for (const [key, values] of Object.entries(distinct)) {
    if (!values?.length) continue;
    const lower = key.toLowerCase();
    headers[lower] = lower === "cookie"
      ? values.join("; ")
      : values.length === 1 ? values[0] : [...values];
  }
  return headers;
}

/** Snapshot one case-insensitive normalized header without selecting a duplicate. */
export function readHeader(headers: NormRequest["headers"], name: string): HeaderRead {
  const lower = name.toLowerCase();
  let value: string | undefined;
  let found = false;
  for (const [key, raw] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) {
      if (found || Array.isArray(raw)) return { ambiguous: true };
      found = true;
      if (typeof raw === "string") {
        if (lower !== "cookie" && raw.includes(",")) return { ambiguous: true };
        value = raw;
      }
    }
  }
  return { value, ambiguous: false };
}

export function headerString(headers: NormRequest["headers"], name: string): string | undefined {
  return readHeader(headers, name).value;
}

const AMBIGUOUS_FORM_CONTENT_TYPE = Symbol("ambiguous-form-content-type");
const FORM_MEDIA_TYPE = "application/x-www-form-urlencoded";
const JSON_MEDIA_TYPE = "application/json";

/** Lower-cased media-type essence of a single unambiguous `Content-Type`. */
function contentTypeEssence(headers: NormRequest["headers"]): { essence?: string; ambiguous: boolean } {
  const { value, ambiguous } = readHeader(headers, "content-type");
  if (ambiguous) return { ambiguous: true };
  return { essence: value?.split(";", 1)[0]?.trim().toLowerCase(), ambiguous: false };
}

/** Retain form provenance so Bridge can distinguish repeats from JSON arrays. */
export function formBodySnapshot(body: unknown, headers: NormRequest["headers"]): unknown {
  const { essence, ambiguous } = contentTypeEssence(headers);
  if (ambiguous) return AMBIGUOUS_FORM_CONTENT_TYPE;
  return essence === FORM_MEDIA_TYPE ? body : undefined;
}

/** Adapter-owned media gate (§9.6). An adapter hands the core a parsed body ONLY
 *  for the two media types it interprets semantically, keyed on the request's own
 *  `Content-Type` rather than on which parser happened to fill the framework's
 *  body slot. So a value produced by a parser the application mounted earlier on
 *  the same path — `express.json({ type: "text/plain" })`, a Fastify `text/plain`
 *  parser returning an object — is dropped here, before any OAuth field selection.
 *  Absent, ambiguous, and unsupported `Content-Type` all fail closed to absent. */
export function semanticOAuthBody(body: unknown, headers: NormRequest["headers"]): unknown {
  const { essence, ambiguous } = contentTypeEssence(headers);
  if (ambiguous || essence === undefined) return undefined;
  return essence === JSON_MEDIA_TYPE || essence === FORM_MEDIA_TYPE ? body : undefined;
}

export function isAmbiguousFormContentType(value: unknown): boolean {
  return value === AMBIGUOUS_FORM_CONTENT_TYPE;
}

export function queryString(query: NormRequest["query"], name: string): string | undefined {
  const value = query[name];
  if (Array.isArray(value)) return value.find((entry) => entry.length > 0);
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/** Preserve RFC 8707 multiplicity as unsupported target input for this
 * singleton AS instead of selecting the first occurrence. RFC 6749 treats
 * valueless parameters as omitted, so empty occurrences are discarded before
 * deciding whether more than one requested resource remains. */
export const INVALID_RESOURCE = " invalid-resource";
export function resourceParam(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "string") return value.length > 0 ? value : undefined;
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) return INVALID_RESOURCE;
  const resources = value.filter((entry) => entry.length > 0);
  if (resources.length === 0) return undefined;
  const unique = [...new Set(resources)];
  return unique.length === 1 ? unique[0] : INVALID_RESOURCE;
}

export function formField(body: unknown, name: string): string | undefined {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return undefined;
  const value = (body as Record<string, unknown>)[name];
  return typeof value === "string" && value ? value : undefined;
}

export function formObject(body: unknown): Record<string, unknown> {
  return typeof body === "object" && body !== null && !Array.isArray(body) ? body as Record<string, unknown> : {};
}

/** True when an inbound request targets `/mcp`. PARSES the pathname rather than a
 *  raw string check on `request.url`, so it holds for an absolute-form
 *  request-target (`POST http://host/mcp HTTP/1.1`), which a framework still
 *  routes to `/mcp` while `request.url` is the full URL — a raw `=== "/mcp"` (or
 *  `.split("?")[0]`) misses that form and skips the gate. Centralized here so the
 *  examples' Origin gate + JSON body parser treat `/mcp` consistently regardless
 *  of request-target form (the absolute-form string check is a recurring footgun). */
export function isMcpPath(requestUrl: string): boolean {
  try {
    return new URL(requestUrl, "http://localhost").pathname === "/mcp";
  } catch {
    return false;
  }
}

/** Map an OAuthError to a normalized response: a redirect-tagged error ⇒ 302 to
 *  redirect_uri?error=…&iss=…; otherwise a direct status with the RFC 6749 §5.2
 *  body. `challenge` adds the §8.2 WWW-Authenticate challenge on 401 (the /mcp
 *  surface passes it; the OAuth authorize/token endpoints do not). */
export function oauthErrorResponse(config: BridgeConfig, error: OAuthError, challenge?: { scope?: string[] }): NormResponse {
  if (error.redirect) {
    const location = buildAuthorizationErrorRedirect(config, error.redirect.redirectUri, error.code, error.redirect.state, error.message);
    return { status: 302, headers: { location }, redirect: location };
  }
  const headers: Record<string, string> = {};
  if (error.status === 401 && challenge) {
    headers["www-authenticate"] = buildUnauthorizedChallenge(config, { scope: challenge.scope, error: error.code, errorDescription: error.message });
  }
  return { status: error.status, headers, body: oauthErrorBody(error) };
}

/** Same-origin issuer origin, for the consent-page CSRF/Origin check. */
export function issuerOrigin(config: BridgeConfig): string {
  return originOf(config.issuer);
}
