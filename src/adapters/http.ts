// Framework-free HTTP helpers shared by the fastify/express/hono adapters
// (contracts §9.6). Normalized request/response shapes so the Bridge logic is
// framework-agnostic, plus OAuthError → response mapping and subject resolution.

import type { AnyBridgeConfig as BridgeConfig } from "../config.ts";
import { originOf } from "../config.ts";
import { OAuthError, oauthErrorBody } from "../errors.ts";
import { buildErrorRedirect, buildUnauthorizedChallenge } from "../challenge.ts";

export interface NormRequest {
  query: Record<string, string | string[] | undefined>;
  body: unknown;
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

export function queryString(query: NormRequest["query"], name: string): string | undefined {
  const value = query[name];
  if (Array.isArray(value)) return value[0];
  return typeof value === "string" ? value : undefined;
}

export function formField(body: unknown, name: string): string | undefined {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return undefined;
  const value = (body as Record<string, unknown>)[name];
  return typeof value === "string" && value ? value : undefined;
}

/** The RFC 8707 `resource` parameter, read WITHOUT collapsing an invalid value
 *  into omission (contracts §9.7).
 *
 *  `queryString`/`formField` deliberately normalize junk to `undefined` for the
 *  parameters whose absence is benign. `resource` is not one of those: omission
 *  is MEANINGFUL — it selects the sole configured resource — so mapping an empty
 *  string, a repeated parameter, or a non-string onto `undefined` would silently
 *  select a resource the caller never asked for. Each of those is returned as
 *  the sentinel `INVALID_RESOURCE` instead, which the core rejects as
 *  `invalid_target`. It is a non-canonical string, so it can never match a
 *  configured resource even if a caller reached the resolver another way. */
// A leading SPACE makes this never-canonical: canonicalResource rejects ASCII
// whitespace, so no configured or request resource can ever equal it. Plain
// ASCII deliberately — an earlier version embedded a literal NUL, which made
// this file diff as BINARY, so twelve review rounds never saw the gate below.
export const INVALID_RESOURCE = " invalid-resource";

export function resourceParam(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  // Repeated occurrence (array) or any non-string: invalid, never first-wins.
  if (typeof value !== "string") return INVALID_RESOURCE;
  return value === "" ? INVALID_RESOURCE : value;
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
 *  of request-target form (the absolute-form string check is a recurring footgun).
 *
 *  SINGLE-RESOURCE ONLY. It matches the literal pathname `/mcp`, so it returns
 *  false for a resource mounted anywhere else (`/grafana/mcp`, `/team-a/mcp`).
 *  A multi-resource deployment must scope its Origin gate to its OWN configured
 *  resource paths: using this helper there installs a hook that never fires,
 *  silently disabling DNS-rebinding protection. See
 *  `examples/fastify-multi-resource` for that pattern. */
export function isMcpPath(requestUrl: string): boolean {
  try {
    return new URL(requestUrl, "http://localhost").pathname === "/mcp";
  } catch {
    return false;
  }
}

/** Map an OAuthError to a normalized response: a redirect-tagged error ⇒ 302 to
 *  redirect_uri?error=…; otherwise a direct status with the RFC 6749 §5.2 body.
 *  `challengeConfig` adds the §8.2 WWW-Authenticate challenge on 401 (the /mcp
 *  surface passes it; the OAuth authorize/token endpoints do not). */
export function oauthErrorResponse(error: OAuthError, challengeConfig?: { config: BridgeConfig; scope?: string[]; }): NormResponse {
  if (error.redirect) {
    return { status: 302, headers: { location: buildErrorRedirect(error.redirect.redirectUri, error.code, error.redirect.state, error.message) }, redirect: buildErrorRedirect(error.redirect.redirectUri, error.code, error.redirect.state, error.message) };
  }
  const headers: Record<string, string> = {};
  if (error.status === 401 && challengeConfig) {
    headers["www-authenticate"] = buildUnauthorizedChallenge(challengeConfig.config, { scope: challengeConfig.scope, error: error.code, errorDescription: error.message });
  }
  return { status: error.status, headers, body: oauthErrorBody(error) };
}

/** Same-origin issuer origin, for the consent-page CSRF/Origin check. */
export function issuerOrigin(config: BridgeConfig): string {
  return originOf(config.issuer);
}
