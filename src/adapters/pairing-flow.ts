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
import { formField, queryString, type NormRequest, type NormResponse } from "./http.ts";
import { renderPairingPage } from "./pairing-page.ts";

// Mirrors bridge.ts CONSENT_HEADERS (text/html + CSP + nosniff) for the pairing page.
const PAIRING_HEADERS: Record<string, string> = {
  "content-type": "text/html; charset=utf-8",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'",
};

// OAuth authorize params that round-trip through the pairing form's hidden fields.
const OAUTH_PARAM_KEYS = [
  "response_type", "client_id", "redirect_uri", "code_challenge",
  "code_challenge_method", "resource", "scope", "state",
] as const;

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
  const oauthParams = gatherOAuthParams(req);
  const submittedCode = method === "POST" ? formField(req.body, "pairing_code") : undefined;

  if (submittedCode) {
    const nonce = formField(req.body, "pairing_nonce") ?? "";
    const result = await pairing.verify({ code: submittedCode, nonce, ip: req.ip });
    if (result.ok) {
      // bridge.handleAuthorize validates the params and renders the consent page
      // (or returns an OAuth error response if they are invalid — its own try/catch).
      // Pass the resolved identity object so any allowedScopes ceiling travels
      // through (console-pairing sets none today — old no-ceiling behavior).
      const synthetic: NormRequest = {
        query: { ...oauthParams }, body: undefined, headers: req.headers, ip: req.ip,
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
  const out: Record<string, string> = {};
  for (const key of OAUTH_PARAM_KEYS) {
    const v = queryString(req.query, key) ?? formField(req.body, key);
    if (typeof v === "string") out[key] = v;
  }
  return out;
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
