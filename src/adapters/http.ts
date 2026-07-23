// Framework-free HTTP helpers shared by the fastify/express/hono adapters
// (contracts §9.6). Normalized request/response shapes so the Bridge logic is
// framework-agnostic, plus OAuthError → response mapping and subject resolution.

import type { BridgeConfig } from "../config.ts";
import { assertBridgeConfig, originOf } from "../config.ts";
import { OAuthError, oauthErrorBody } from "../errors.ts";
import { buildErrorRedirect, buildUnauthorizedChallenge } from "../challenge.ts";
import { snapshotOwnDataArray, snapshotOwnDataRecord } from "../own-property.ts";

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

/** OAuth authorization parameters that RFC 6749 permits at most once. */
export const OAUTH_AUTHORIZE_PARAM_KEYS = [
  "response_type", "client_id", "redirect_uri", "code_challenge",
  "code_challenge_method", "resource", "scope", "state",
] as const;

/** Parse form-urlencoded bytes without collapsing repeated fields. Framework
 * parsers commonly choose the first or last value, which erases the evidence
 * needed by OAuth's duplicate-parameter rejection. */
export function parseUrlEncodedForm(body: string): Record<string, string | string[]> {
  const out = Object.create(null) as Record<string, string | string[]>;
  for (const [key, value] of new URLSearchParams(body)) {
    const previous = out[key];
    if (previous === undefined) out[key] = value;
    else if (Array.isArray(previous)) previous.push(value);
    else out[key] = [previous, value];
  }
  return out;
}

/** Snapshot the normalized request envelope before any route decision. */
export function parseNormRequest(value: unknown): Readonly<NormRequest> | null {
  const fields = snapshotOwnDataRecord(value);
  const query = fields && snapshotHttpStringRecord(fields.query);
  const headers = fields && snapshotHttpStringRecord(fields.headers);
  if (fields === null || query === null || headers === null
    || (fields.ip !== undefined && typeof fields.ip !== "string")) return null;
  const bodyRecord = fields.body !== null && typeof fields.body === "object"
    ? snapshotHttpBody(fields.body) : fields.body;
  if (bodyRecord === null && fields.body !== null) return null;
  return Object.freeze({
    query,
    body: bodyRecord,
    headers,
    ip: fields.ip as string | undefined,
  });
}

function snapshotHttpStringRecord(value: unknown): NormRequest["query"] | null {
  const fields = snapshotOwnDataRecord(value);
  if (fields === null) return null;
  const out = Object.create(null) as NormRequest["query"];
  for (const [key, item] of Object.entries(fields)) {
    if (item === undefined || typeof item === "string") out[key] = item;
    else {
      const values = snapshotOwnDataArray(item);
      if (values === null || !values.every((entry) => typeof entry === "string")) return null;
      out[key] = Object.freeze([...values]) as string[];
    }
  }
  return Object.freeze(out);
}

function snapshotHttpBody(value: unknown): Readonly<Record<string, unknown>> | null {
  const fields = snapshotOwnDataRecord(value);
  if (fields === null) return null;
  const out = Object.create(null) as Record<string, unknown>;
  for (const [key, item] of Object.entries(fields)) {
    if (Array.isArray(item)) {
      const values = snapshotOwnDataArray(item);
      if (values === null) return null;
      out[key] = Object.freeze([...values]);
    } else out[key] = item;
  }
  return Object.freeze(out);
}

export function headerString(headers: NormRequest["headers"], name: string): string | undefined {
  const lower = name.toLowerCase();
  let descriptors: Record<PropertyKey, PropertyDescriptor>;
  try {
    descriptors = Object.getOwnPropertyDescriptors(headers) as Record<PropertyKey, PropertyDescriptor>;
  } catch {
    return undefined;
  }
  for (const key of Reflect.ownKeys(descriptors)) {
    const descriptor = descriptors[key]!;
    if (typeof key === "string" && key.toLowerCase() === lower
      && descriptor.enumerable && "value" in descriptor) {
      const value = descriptor.value as unknown;
      if (Array.isArray(value)) {
        const values = snapshotOwnDataArray(value);
        return values && typeof values[0] === "string" ? values[0] : undefined;
      }
      return typeof value === "string" ? value : undefined;
    }
  }
  return undefined;
}

export function queryString(query: NormRequest["query"], name: string): string | undefined {
  const value = ownEnumerableDataValue(query, name);
  if (Array.isArray(value)) {
    const values = snapshotOwnDataArray(value);
    return values && typeof values[0] === "string" ? values[0] : undefined;
  }
  return typeof value === "string" ? value : undefined;
}

/** Reject ambiguous repeated OAuth parameters instead of choosing first/last. */
export function findDuplicatedKeys(
  query: NormRequest["query"],
  keys: readonly string[],
): string[] {
  const duplicates: string[] = [];
  for (const key of keys) {
    const value = ownEnumerableDataValue(query, key);
    if (Array.isArray(value)) {
      const values = snapshotOwnDataArray(value);
      if (values !== null && values.length > 1) duplicates.push(key);
    }
  }
  return duplicates;
}

export function formField(body: unknown, name: string): string | undefined {
  const value = ownEnumerableDataValue(body, name);
  return typeof value === "string" && value ? value : undefined;
}

export function formObject(body: unknown): Record<string, unknown> {
  return snapshotOwnDataRecord(body) ?? Object.create(null) as Record<string, unknown>;
}

function ownEnumerableDataValue(value: unknown, key: PropertyKey): unknown {
  if (typeof value !== "object" || value === null) return undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && "value" in descriptor ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
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
  assertBridgeConfig(config);
  return originOf(config.issuer);
}
