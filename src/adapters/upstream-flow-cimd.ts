// CIMD helpers for the §17.11 upstream-redirect orchestrator (§17.1.6 decision
// 1). Factored out of `upstream-flow.ts` so the factory + the two handlers stay
// under the 250-line file limit (contracts §6). Two seams live here:
//
//   • `resolveUpstreamAuthorizeClient` — the authorize-time resolve boundary
//     (decision 2 boundary 1): shape-first dispatch, the shared success cache,
//     the redirect matcher, and the anti-oracle error map, ALL completing
//     BEFORE Set-Cookie / the IdP 302 (decision 1b).
//   • `assertCallbackCimdPolicy` — callback row 5a: the claim/mode/redirect
//     matrix, run after the state match and BEFORE jti consumption, the
//     exchange, and every redirect-channel branch.

import type { BridgeConfig } from "../config.ts";
import { OAuthError } from "../errors.ts";
import type { CimdResolver } from "../cimd/resolve.ts";
import { cimdGenericError, mapCimdError } from "../cimd/resolve.ts";
import type { CimdTransport, DnsResolver } from "../cimd/guarded-fetcher.ts";
import type { RateLimitPort } from "../ports/rate-limit.ts";
import { cimdRedirectMatches, isCimdClientId, isSchemeShaped, type CimdRegistration } from "../cimd/registration.ts";
import { resolveOpaqueRedirect } from "../authorize-internals.ts";
import type { FlowClaims } from "./upstream-flow-internals.ts";

export interface UpstreamCimdOutcome {
  readonly registration?: CimdRegistration;
  /** Emitted only AFTER the 4096-byte cookie-oversize guard passes (1b). */
  emitSuccess(): Promise<void>;
}

/** Authorize-time resolution for the upstream-redirect leg. Every CIMD failure
 *  — admission, DNS, blocklist, fetch, status, content-type, encoding, size,
 *  timeout, document, redirect-match, overload — is mapped HERE to the
 *  decision-2 generic `invalid_client` 401 so it can never escape to
 *  `handleAuthorize`'s own catch as `internal_error` 500 (a distinguishable
 *  channel would reopen the SSRF oracle). The `cimd:<ip>` rate-limit denial is
 *  OUTSIDE the map and propagates as its own direct 429. */
export async function resolveUpstreamAuthorizeClient(args: {
  config: BridgeConfig;
  cimd: CimdResolver;
  seams: { readonly transport?: CimdTransport; readonly resolver?: DnsResolver } | undefined;
  rateLimit?: RateLimitPort;
  clientId: string;
  redirectUri: string;
  ip?: string;
}): Promise<UpstreamCimdOutcome> {
  const noop = async (): Promise<void> => { /* nothing resolved */ };
  if (isCimdClientId(args.clientId)) {
    if (args.config.cimd?.enabled !== true) throw cimdGenericError(); // 1a branch 2
    try {
      const resolution = await args.cimd.resolve({
        clientId: args.clientId, redirectUri: args.redirectUri, ip: args.ip,
        ...(args.seams === undefined ? {} : { seams: args.seams }),
        ...(args.rateLimit === undefined ? {} : { rateLimit: args.rateLimit }),
      });
      return { registration: resolution.registration, emitSuccess: () => resolution.emitSuccess() };
    } catch (error) {
      throw error instanceof OAuthError ? error : mapCimdError(error);
    }
  }
  if (isSchemeShaped(args.clientId)) throw cimdGenericError(); // 1a branch 2
  // 1a branch 3: the unchanged §10 path for an opaque id.
  await resolveOpaqueRedirect(args.config, args.clientId, args.redirectUri);
  return { emitSuccess: noop };
}

/** Callback row 5a (decision 1d(ii)) — the claim/mode/redirect matrix. Returns
 *  true when the flow may proceed; false ⇒ the caller answers a DIRECT 400
 *  `invalid_request` audited `flow_cookie_invalid`, WITHOUT consuming the jti,
 *  exchanging, or emitting any redirect-channel response. */
export function assertCallbackCimdPolicy(config: BridgeConfig, claims: FlowClaims): boolean {
  const clientId = claims.params.client_id;
  const carried = claims.cimd;
  if (typeof clientId !== "string" || clientId === "") return false;
  if (isCimdClientId(clientId)) {
    if (config.cimd?.enabled !== true) return false;
    if (carried === undefined) return false;
  } else if (carried !== undefined) {
    return false; // a non-CIMD client_id MUST carry NO cimd claim
  }
  if (carried === undefined) return true;
  return cimdRedirectMatches(claims.params.redirect_uri, carried.redirect_uris);
}
