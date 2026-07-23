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
import type { ConsolePairingIdentity } from "../identity/console-pairing.ts";
import { captureIdentityPort, parseIdentityResult } from "../ports/identity.ts";
import {
  findDuplicatedKeys, formField, formObject, oauthErrorResponse,
  OAUTH_AUTHORIZE_PARAM_KEYS, parseNormRequest, queryString,
  type NormRequest, type NormResponse,
} from "./http.ts";
import { renderPairingPage } from "./pairing-page.ts";
import { bindClassDataMethod, snapshotOwnDataRecord } from "../own-property.ts";
import { OAuthError } from "../errors.ts";

// Mirrors bridge.ts CONSENT_HEADERS (text/html + CSP + nosniff) for the pairing page.
const PAIRING_HEADERS: Record<string, string> = {
  "content-type": "text/html; charset=utf-8",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'",
};

export interface PairingAuthorizeDeps {
  bridge: Bridge;
  pairing: ConsolePairingIdentity;
}

export async function handlePairingAuthorize(
  deps: PairingAuthorizeDeps,
  method: "GET" | "POST",
  req: NormRequest,
): Promise<NormResponse> {
  const fields = snapshotOwnDataRecord(deps);
  const request = parseNormRequest(req);
  if (fields === null || !fields.bridge || !fields.pairing || request === null
    || (method !== "GET" && method !== "POST")) {
    throw new OAuthError("invalid_request", "Pairing request is malformed");
  }
  const bridge = fields.bridge as Bridge;
  const identity = captureIdentityPort(fields.pairing);
  const beginSession =
    bindClassDataMethod<ConsolePairingIdentity["beginSession"]>(
      fields.pairing, "beginSession",
    );
  if (identity === null || beginSession === undefined) {
    throw new OAuthError("invalid_request", "Pairing identity is malformed");
  }
  const pairing = Object.freeze({ verify: identity.verify, beginSession });
  if (hasAmbiguousOAuthParams(request)) {
    return oauthErrorResponse(new OAuthError(
      "invalid_request", "Duplicate authorization request parameters",
    ));
  }
  const oauthParams = gatherOAuthParams(request);
  const submittedCode = method === "POST" ? formField(request.body, "pairing_code") : undefined;

  if (submittedCode) {
    const nonce = formField(request.body, "pairing_nonce") ?? "";
    const result = parseIdentityResult(await pairing.verify({ code: submittedCode, nonce, ip: request.ip }));
    if (result?.ok) {
      // bridge.handleAuthorize validates the params and renders the consent page
      // (or returns an OAuth error response if they are invalid — its own try/catch).
      // Pass the resolved identity object so any allowedScopes ceiling travels
      // through (console-pairing sets none today — old no-ceiling behavior).
      const synthetic: NormRequest = {
        query: { ...oauthParams }, body: undefined, headers: request.headers, ip: request.ip,
      };
      return bridge.handleAuthorize(synthetic, { subject: result.identity.subject, allowedScopes: result.identity.allowedScopes });
    }
    // Failure: the code may be invalidated (expiry / attempts exhausted), so
    // beginSession() reprints a fresh one when needed; the form round-trips so
    // the operator can retry without losing the OAuth context.
    const session = await pairing.beginSession();
    return pairingPage(session, oauthParams, "Invalid or expired pairing code — check the server console and try again.");
  }

  // Initial render. beginSession() generates + prints the code on first need and
  // reuses the live one on repeat visits (one active code per process).
  const session = await pairing.beginSession();
  return pairingPage(session, oauthParams);
}

function gatherOAuthParams(req: NormRequest): Record<string, string> {
  const out = Object.create(null) as Record<string, string>;
  for (const key of OAUTH_AUTHORIZE_PARAM_KEYS) {
    const v = queryString(req.query, key) ?? formField(req.body, key);
    if (typeof v === "string") out[key] = v;
  }
  return out;
}

function hasAmbiguousOAuthParams(req: NormRequest): boolean {
  const body = formObject(req.body);
  if (findDuplicatedKeys(req.query, OAUTH_AUTHORIZE_PARAM_KEYS).length > 0
    || findDuplicatedKeys(body as NormRequest["query"], OAUTH_AUTHORIZE_PARAM_KEYS).length > 0) {
    return true;
  }
  return OAUTH_AUTHORIZE_PARAM_KEYS.some((key) =>
    Object.hasOwn(req.query, key) && Object.hasOwn(body, key));
}

function pairingPage(
  session: { nonce: string; expiresAt: string },
  oauthParams: Record<string, string>,
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
