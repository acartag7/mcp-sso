// createEntraRedirectIdentity (contracts §17.11) — wraps the shipped Entra
// *primitives* (getAuthorizationUrl / exchangeCodeForToken / verify — §6.5) into
// a `RedirectIdentityPort` so the framework-free `createUpstreamRedirectFlow`
// orchestrator can drive the browser↔Entra leg. The current `EntraIdentity` API
// (the host-driven primitives) is unchanged; this is the turnkey companion.
//
// Transport: the default token-endpoint transport is the global `fetch` against
// the hardcoded `https://login.microsoftonline.com` endpoint with a 10 s
// `AbortSignal.timeout` deadline (a deployer-trusted endpoint — deliberately
// NOT the §17.1 SSRF guard, same rationale as §17.6 discovery). The transport
// stays injectable for tests. Scope: `openid profile email` exactly — NO
// `offline_access`, because the bridge discards the upstream token response, so
// requesting a long-lived upstream refresh token it will never use violates
// least-grant. Outcome mapping: an exchange throw/non-200/missing-id_token ⇒
// `exchange_failed`; a verify `{ ok:false }` ⇒ `identity_rejected` EXCEPT the
// `entra_verify_failed` reason (Entra's non-JOSEError catch-all — a JWKS-fetch
// network/transport failure), which is `exchange_failed` per §17.11's deterministic
// throw-rule (an infrastructure failure makes no identity decision). A throw from
// `exchangeAndVerify` is always classified `exchange_failed` by the orchestrator.
//
// --- Manual checklist: live-tenant verification for the REDIRECT flow (cannot be
//   automated without a real tenant; run before claiming the Entra redirect flow
//   works end-to-end. Sibling to the entra.ts primitives checklist; lives here
//   because entra.ts is at the 250-line limit.) ---
//   R1. Register ONE Entra app: redirect URI = originOf(OAUTH_ISSUER)+callbackPath
//       (https in production — Entra refuses plain-http redirect URIs off-loopback);
//       allow public-client PKCE OR create a client secret; expose
//       openid/profile/email (this port requests NO offline_access).
//   R2. GET /oauth/authorize 302s to Entra AND sets the __Host-mcp-sso-upstream
//       cookie (Secure; HttpOnly; SameSite=Lax; Path=/; no Domain) on the https
//       issuer (the loopback dev variant drops Secure/__Host-).
//   R3. After Entra login the callback validates (state/nonce/single-use jti),
//       exchanges the code, verifies the id_token (iss/aud/tid/nonce), and
//       renders the consent page as the DIRECT callback response — never a second
//       redirect or a retrievable URL (§17.11 same-browser binding).
//   R4. Approve → the bridge mints its OWN audience-bound token; the Entra
//       access/refresh tokens are discarded immediately (never stored, logged,
//       audited, forwarded, or placed in the flow cookie).
//   R5. A replayed callback URL is rejected (flow_replayed, direct 400) with NO
//       second outbound exchange; the cookie is cleared on every callback outcome.

import type {
  IdentityClaims, RedirectExchangeResult, RedirectIdentityPort,
} from "../ports/identity.ts";
import {
  type EntraConfig, type EntraTokenTransport, type EntraVerifyKey,
  createEntraIdentity, exchangeCodeForToken, getAuthorizationUrl,
  verifyEntraIdToken,
} from "./entra.ts";

/** The exact upstream scope this port requests — `offline_access` is omitted on
 *  purpose (the bridge never uses an upstream refresh token). */
const UPSTREAM_SCOPE = "openid profile email";

/** Injectable transport override + an explicit verify key (so the full path is
 *  testable with a known key and NO JWKS fetch). `scopeCatalog` is the boot-time
 *  junction where the Entra group mapping meets the bridge catalog (§17.4). */
export interface EntraRedirectOptions {
  transport?: EntraTokenTransport;
  /** When set, id_token signature is verified against this key instead of the
   *  Entra JWKS (test-only; production leaves it unset for the JWKS path). */
  verifyKey?: EntraVerifyKey;
  /** Override the verify clock (test-only; the JWKS path uses wall-clock). */
  currentDate?: Date;
  scopeCatalog?: readonly string[];
}

/** Default token-endpoint transport: global fetch, 10 s hard deadline, against
 *  the URL `exchangeCodeForToken` supplies (always the hardcoded Entra endpoint). */
const defaultTransport: EntraTokenTransport = {
  async postForm(url, body) {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      signal: AbortSignal.timeout(10_000),
    });
    return { status: resp.status, text: () => resp.text() };
  },
};

/** Build an Entra `RedirectIdentityPort`. The orchestrator generates
 *  `state`/`nonce`/PKCE; this port contributes its fixed scope + response_mode
 *  and the exchange+verify against the shipped primitives. */
export function createEntraRedirectIdentity(
  config: EntraConfig,
  opts?: EntraRedirectOptions,
): RedirectIdentityPort {
  // Reuse the shipped identity for the JWKS verify path (caching + group-ceiling
  // resolution + boot validation of the group mapping subset).
  const base = createEntraIdentity(config, { scopeCatalog: opts?.scopeCatalog });
  const transport = opts?.transport ?? defaultTransport;

  return {
    redirectUri: config.redirectUri,
    buildAuthorizationUrl(req) {
      return getAuthorizationUrl(config, {
        state: req.state,
        nonce: req.nonce,
        codeChallenge: req.codeChallenge,
        codeChallengeMethod: "S256",
        scope: UPSTREAM_SCOPE,
      });
    },
    async exchangeAndVerify({ code, codeVerifier, nonce }): Promise<RedirectExchangeResult> {
      let idToken: string;
      try {
        idToken = await exchangeCodeForToken(config, { code, codeVerifier }, transport);
      } catch {
        // Transport/protocol failure (non-200, timeout, malformed body, missing
        // id_token) — no identity decision was made.
        return { ok: false, kind: "exchange_failed", reason: "entra_exchange_failed" };
      }
      const result = opts?.verifyKey
        ? await verifyEntraIdToken(idToken, opts.verifyKey, config, { expectedNonce: nonce, currentDate: opts.currentDate })
        : await base.verify(idToken, { expectedNonce: nonce });
      if (!result.ok) {
        // §17.11 deterministic throw-rule: an *infrastructure* failure during
        // exchangeAndVerify (no identity decision made) is exchange_failed, never
        // identity_rejected. Entra's `jwtErrorReason` funnels every non-JOSEError
        // throw — i.e. a JWKS-fetch network/transport failure — into the
        // `entra_verify_failed` bucket; that is the one reason classified here as
        // exchange_failed (so the callback redirects server_error and emits NO
        // identity.verify). Every other reason is a verified-context denial (bad
        // iss/aud/tid/nonce/signature/allowlist/group) ⇒ identity_rejected.
        if (result.reason === "entra_verify_failed") {
          return { ok: false, kind: "exchange_failed", reason: result.reason };
        }
        return { ok: false, kind: "identity_rejected", reason: result.reason };
      }
      const identity: IdentityClaims = result.identity;
      return { ok: true, identity };
    },
  };
}
