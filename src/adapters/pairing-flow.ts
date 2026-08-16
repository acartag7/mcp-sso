// handlePairingAuthorize (contracts §17.5) — framework-free orchestration of the
// console-pairing authorize surface. Used by an adapter/example that has opted
// out of the default header-based authorize (e.g. via `skipAuthorize`) so it can
// render a code-entry page BEFORE identity is resolved (the standard
// resolveSubject → 401 path cannot host a paste-code UI).
//
// Flow:
//   GET                 → beginSession() (prints code to stderr) → render pairing page.
//   POST + pairing_code → verify(); success → bridge.handleAuthorize (consent page);
//                         failure → beginSession() (reprints if invalidated) → re-render.
//
// On success the round-tripped OAuth params (hidden in the form) are placed into
// the synthetic request's `query` — bridge.handleAuthorize reads query, not body.

import type { Bridge } from "./bridge.ts";
import { asOAuth, checkedFormObject } from "./bridge-internals.ts";
import { assertApproveOrigin } from "../authorize-internals.ts";
import type { ConsolePairingIdentity } from "../identity/console-pairing.ts";
import { OAuthError } from "../errors.ts";
import { OAUTH_PARAM_KEYS, OAUTH_SINGLETON_PARAM_KEYS, PAIRING_BODY_SINGLETON_PARAM_KEYS, findDuplicatedKeys } from "./authorize-params.ts";
import { formField, headerString, INVALID_RESOURCE, oauthErrorResponse, queryString, resourceParam, type NormRequest, type NormResponse } from "./http.ts";
import { renderPairingPage } from "./pairing-page.ts";
import { beginPairingSession, verifyPairingIdentity } from "./pairing-flow-port.ts";

// Pairing keeps its page-specific `form-action`: Continue terminates on this
// origin. It shares consent's frame protections; its referrer policy differs.
//
// The threat here is NOT the consent-page one. This page's only control is
// `Continue`, and the pairing code is TYPED IN by the operator (it is printed to
// stderr, never rendered), so there is no Approve button to overlay and no
// code in the markup to leak: a typed form value cannot reach a Referer header
// either. Framing it buys an attacker a UI-redress surface on a form whose
// submission still requires the operator to possess a code they can only read
// from the server console — the value is defense-in-depth, not a specific
// bypass. Keep framing, form-action, nosniff, and legacy XFO on pairing;
// consent intentionally omits form-action to permit its client redirect.
const PAIRING_HEADERS: Record<string, string> = {
  "content-type": "text/html; charset=utf-8",
  "x-content-type-options": "nosniff",
  "content-security-policy":
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
};

export const PAIRING_AUTHORIZE_WINDOW_MS = 60_000;
export const PAIRING_AUTHORIZE_MAX_REQUESTS = 60;
const pairingAuthorizeWindows = new WeakMap<ConsolePairingIdentity, { startedAtMs: number; requests: number }>();

function pairingAuthorizeRateLimitAllows(pairing: ConsolePairingIdentity): boolean {
  const now = Date.now();
  const window = pairingAuthorizeWindows.get(pairing);
  if (!window || now - window.startedAtMs >= PAIRING_AUTHORIZE_WINDOW_MS) {
    pairingAuthorizeWindows.set(pairing, { startedAtMs: now, requests: 1 });
    return true;
  }
  if (now < window.startedAtMs || window.requests >= PAIRING_AUTHORIZE_MAX_REQUESTS) return false;
  window.requests += 1;
  return true;
}

export interface PairingAuthorizeDeps {
  bridge: Bridge;
  pairing: ConsolePairingIdentity;
}

export async function handlePairingAuthorize(
  deps: PairingAuthorizeDeps,
  method: "GET" | "POST",
  req: NormRequest,
): Promise<NormResponse> {
  const { bridge, pairing } = deps;
  if (!pairingAuthorizeRateLimitAllows(pairing)) {
    return oauthErrorResponse(bridge.config, new OAuthError("temporarily_unavailable", "Too many requests", 429));
  }
  if (findDuplicatedKeys(req.query, OAUTH_SINGLETON_PARAM_KEYS).length > 0) {
    return oauthErrorResponse(bridge.config, new OAuthError("invalid_request", "duplicate request parameters"));
  }
  let body = req.body;
  if (method === "POST") {
    try {
      body = checkedFormObject(req, PAIRING_BODY_SINGLETON_PARAM_KEYS);
      assertApproveOrigin(bridge.config, headerString(req.headers, "origin"));
    }
    catch (error) { return oauthErrorResponse(bridge.config, asOAuth(error)); }
  }
  try {
    await bridge.guardPairingAuthorize(req.ip);
  } catch (error) {
    return oauthErrorResponse(bridge.config, asOAuth(error));
  }
  const gathered = gatherOAuthParams(req, body);
  const oauthParams = gathered.page;
  const submittedCode = method === "POST" ? formField(body, "pairing_code") : undefined;
  const lostInvalidResource = gathered.query.resource === INVALID_RESOURCE && oauthParams.resource === undefined;

  if (submittedCode) {
    const nonce = formField(body, "pairing_nonce") ?? "";
    let result;
    try {
      result = await verifyPairingIdentity(pairing, { code: submittedCode, nonce, ip: req.ip });
    } catch (error) {
      return oauthErrorResponse(bridge.config, asOAuth(error));
    }
    if (result.ok) {
      // bridge.handleAuthorize validates the params and renders the consent page
      // (or returns an OAuth error response if they are invalid — its own try/catch).
      // Pass the resolved identity object so any allowedScopes ceiling travels
      // through (console-pairing sets none today — old no-ceiling behavior).
      const synthetic: NormRequest = {
        query: gathered.query, body: undefined, headers: req.headers, ip: req.ip,
      };
      return bridge.handleAuthorize(synthetic, { subject: result.identity.subject, allowedScopes: result.identity.allowedScopes });
    }
    if (lostInvalidResource) return lostResourceResponse(bridge);
    // Failure: the code may be invalidated (expiry / attempts exhausted), so
    // beginSession() reprints a fresh one when needed; the form round-trips so
    // the operator can retry without losing the OAuth context.
    try {
      const session = await beginPairingSession(pairing);
      return pairingPage(session, oauthParams, "Invalid or expired pairing code — check the server console and try again.");
    } catch (error) {
      return oauthErrorResponse(bridge.config, asOAuth(error));
    }
  }

  if (lostInvalidResource) return lostResourceResponse(bridge);
  // Initial render. beginSession() generates + prints the code on first need and
  // reuses the live one on repeat visits (one active code per process).
  try {
    const session = await beginPairingSession(pairing);
    return pairingPage(session, oauthParams);
  } catch (error) {
    return oauthErrorResponse(bridge.config, asOAuth(error));
  }
}

function formMember(body: unknown, name: string): unknown {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return undefined;
  return Object.hasOwn(body, name) ? (body as Record<string, unknown>)[name] : undefined;
}

function resourceOccurrences(value: unknown): string[] {
  if (typeof value === "string") return value.length > 0 ? [value] : [];
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === "string" && entry.length > 0);
}

function combinedResource(queryValue: unknown, bodyValue: unknown): string | undefined {
  const query = resourceParam(queryValue);
  const body = resourceParam(bodyValue);
  if (query === undefined) return body;
  if (body === undefined) return query;
  if (query === INVALID_RESOURCE || body === INVALID_RESOURCE || query !== body) return INVALID_RESOURCE;
  return query;
}

function gatherOAuthParams(req: NormRequest, body: unknown): {
  page: Record<string, string | string[]>;
  query: Record<string, string>;
} {
  const page: Record<string, string | string[]> = {};
  for (const key of OAUTH_PARAM_KEYS) {
    if (key === "resource") continue;
    const v = queryString(req.query, key) ?? formField(body, key);
    if (typeof v === "string") page[key] = v;
  }
  const queryValue = req.query.resource;
  const bodyValue = formMember(body, "resource");
  const resource = combinedResource(queryValue, bodyValue);
  const raw = [...resourceOccurrences(queryValue), ...resourceOccurrences(bodyValue)];
  if (raw.length === 1) page.resource = raw[0]!;
  else if (raw.length > 1) page.resource = raw;
  const query: Record<string, string> = {};
  for (const [key, value] of Object.entries(page)) {
    if (key !== "resource" && typeof value === "string") query[key] = value;
  }
  if (resource !== undefined) query.resource = resource;
  return { page, query };
}

function lostResourceResponse(bridge: Bridge): NormResponse {
  return oauthErrorResponse(bridge.config, new OAuthError("invalid_target", "Unknown OAuth resource"));
}

function pairingPage(
  session: { nonce: string; expiresAt: string },
  oauthParams: Record<string, string | string[]>,
  error?: string,
): NormResponse {
  return {
    status: 200,
    headers: { ...PAIRING_HEADERS },
    body: renderPairingPage({
      nonce: session.nonce,
      expiresAt: session.expiresAt,
      oauthParams,
      error,
    }),
  };
}
