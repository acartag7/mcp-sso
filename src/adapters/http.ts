// Framework-free HTTP helpers shared by the fastify/express/hono adapters
// (contracts §9.6). Normalized request/response shapes so the Bridge logic is
// framework-agnostic, plus OAuthError → response mapping and subject resolution.

import type { BridgeConfig } from "../config.ts";
import { originOf } from "../config.ts";
import { OAuthError, oauthErrorBody } from "../errors.ts";
import { buildErrorRedirect, buildUnauthorizedChallenge } from "../challenge.ts";
import type { IdentityPort, IdentityResult } from "../ports/identity.ts";

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

export function headerString(headers: NormRequest["headers"], name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) {
      if (Array.isArray(value)) return value[0];
      return typeof value === "string" ? value : undefined;
    }
  }
  return undefined;
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

export function formObject(body: unknown): Record<string, unknown> {
  return typeof body === "object" && body !== null && !Array.isArray(body) ? body as Record<string, unknown> : {};
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

/** Resolve a verified subject via the IdentityPort, or throw access_denied (401,
 *  direct — pre-validation). Used by the adapter before calling Bridge.authorize. */
export async function resolveSubject(identity: IdentityPort, input: unknown): Promise<string> {
  const result: IdentityResult = await identity.verify(input);
  if (!result.ok) {
    throw new OAuthError("access_denied", `Identity rejected: ${result.reason}`, 401);
  }
  return result.identity.subject;
}

/** Same-origin issuer origin, for the consent-page CSRF/Origin check. */
export function issuerOrigin(config: BridgeConfig): string {
  return originOf(config.issuer);
}
