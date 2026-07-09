// createGenericOidcRedirectIdentity (contracts §17.6 / §17.11) — wraps the
// generic OIDC *primitives* into a `RedirectIdentityPort` so the framework-free
// `createUpstreamRedirectFlow` orchestrator can drive the browser↔IdP leg. The
// shared `wrapRedirectIdentity` is reused by the Google preset (`google.ts`) —
// the outcome mapping (exchange_failed vs identity_rejected) is written once.
//
// Outcome mapping mirrors Entra's `entra-redirect.ts` (the §17.11 throw-rule):
// an exchange throw/non-200/missing-id_token ⇒ `exchange_failed` (no identity
// decision); a verify `{ok:false}` whose reason is `generic_oidc_verify_failed`
// (the non-JOSEError catch-all = a JWKS-fetch network/transport failure) is ALSO
// `exchange_failed` (an infrastructure failure makes no identity decision);
// every other verify reason ⇒ `identity_rejected` (a verified-context denial).
// Transport: injectable (default = global fetch + 10s `AbortSignal.timeout`).

import type { IdentityClaims, RedirectExchangeResult, RedirectIdentityPort } from "../ports/identity.ts";
import { createGenericOidcIdentity, type GenericOidcConfig, type GenericOidcIdentity, type GenericOidcVerifyOpts } from "./generic-oidc.ts";
import type { DiscoveryTransport, GenericOidcTokenTransport } from "./generic-oidc-discovery.ts";

export interface GenericOidcRedirectOpts {
  discoveryFetch?: DiscoveryTransport;
  /** Token-endpoint transport override (default: global fetch + 10s timeout). */
  transport?: GenericOidcTokenTransport;
  /** Verify against this key instead of the JWKS (test-only). */
  verifyKey?: GenericOidcVerifyOpts["verifyKey"];
  /** Override the verify clock (test-only). */
  currentDate?: Date;
}

/** Wrap a built `GenericOidcIdentity` (generic OR Google) as a
 *  `RedirectIdentityPort`. The orchestrator generates state/nonce/PKCE; this
 *  port contributes the exchange + verify. Exported so the Google preset reuses
 *  it — DO NOT duplicate the outcome mapping (sibling of entra-redirect.ts). */
export function wrapRedirectIdentity(
  base: GenericOidcIdentity,
  opts: { transport?: GenericOidcTokenTransport; verifyKey?: GenericOidcVerifyOpts["verifyKey"]; currentDate?: Date } = {},
): RedirectIdentityPort {
  return {
    redirectUri: base.redirectUri,
    buildAuthorizationUrl(req) {
      return base.getAuthorizationUrl({
        state: req.state, nonce: req.nonce,
        codeChallenge: req.codeChallenge, codeChallengeMethod: "S256",
      });
    },
    async exchangeAndVerify({ code, codeVerifier, nonce }): Promise<RedirectExchangeResult> {
      let tokens: { id_token: string; access_token?: string };
      try {
        tokens = await base.exchangeCodeForToken({ code, codeVerifier }, opts.transport);
      } catch {
        // Transport/protocol failure (non-200, timeout, malformed body, missing
        // id_token) — no identity decision was made.
        return { ok: false, kind: "exchange_failed", reason: "generic_oidc_exchange_failed" };
      }
      const result = await base.verify(tokens.id_token, {
        expectedNonce: nonce, accessToken: tokens.access_token,
        verifyKey: opts.verifyKey, currentDate: opts.currentDate,
      });
      if (!result.ok) {
        // §17.11 throw-rule: an infrastructure failure during verify (no identity
        // decision) is exchange_failed. `generic_oidc_verify_failed` is the non-
        // JOSEError catch-all (a JWKS-fetch network failure); every other reason
        // is a verified-context denial ⇒ identity_rejected.
        if (result.reason === "generic_oidc_verify_failed") {
          return { ok: false, kind: "exchange_failed", reason: result.reason };
        }
        return { ok: false, kind: "identity_rejected", reason: result.reason };
      }
      const identity: IdentityClaims = result.identity;
      return { ok: true, identity };
    },
  };
}

/** Build a generic OIDC `RedirectIdentityPort` (async: discovery is a boot fetch). */
export async function createGenericOidcRedirectIdentity(config: GenericOidcConfig, opts?: GenericOidcRedirectOpts): Promise<RedirectIdentityPort> {
  const base = await createGenericOidcIdentity(config, { discoveryFetch: opts?.discoveryFetch });
  return wrapRedirectIdentity(base, { transport: opts?.transport, verifyKey: opts?.verifyKey, currentDate: opts?.currentDate });
}
