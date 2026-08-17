// createUpstreamRedirectFlow (contracts §17.11) — the framework-free orchestrator
// for redirect-based upstream IdPs, sibling to handlePairingAuthorize. GET
// /oauth/authorize → persist flow state in a signed cookie → 302 to the IdP;
// callback → validate (13-row failure table) → exchange → verify → hand the
// identity (with its allowedScopes ceiling) to bridge.handleAuthorize → consent
// page. Root-exported (§15). All deps mirror BridgeDeps (store/clock/audit
// REQUIRED, rateLimit? default noop) — the Bridge keeps its deps private, and
// this contract adds NO new Bridge surface; the composition root passes the
// SAME instances to both.

import type { Bridge } from "./bridge.ts";
import type { RedirectIdentityPort } from "../ports/identity.ts";
import type { StorePort } from "../ports/store.ts";
import { finiteClockSnapshot, type ClockPort } from "../ports/clock.ts";
import type { AuditPort, AuthAuditStatus } from "../ports/audit.ts";
import type { RateLimitPort } from "../ports/rate-limit.ts";
import { noopRateLimit } from "../ports/rate-limit.ts";
import { AuthConfigError, originOf, pathAfterOrigin } from "../config.ts";
import { OAuthError } from "../errors.ts";
import { assertOAuthRedirectEntry } from "../redirect.ts";
import { pkceChallenge } from "../crypto.ts";
import { noStoreHeaders, queryString, type NormRequest, type NormResponse } from "./http.ts";
import { redactForStderr } from "../audit/util.ts";
import { writeAuditBestEffort } from "../audit/best-effort.ts";
import type { CimdTransport, DnsResolver } from "../cimd/transport.ts";
import { resolveUpstreamAuthorizeClient, assertCallbackCimdPolicy } from "./upstream-flow-cimd.ts";
import { isSchemeShaped } from "../cimd/registration.ts";
import { resolveOpaqueRedirect } from "../authorize-internals.ts";
import { identityRejectionDescription, normalizedIdentityFailureReason } from "./bridge-internals.ts";
import { buildUpstreamAuthorizationUrl, exchangeUpstreamIdentity } from "./upstream-flow-port.ts";
import { consumeConsentJtiSnapshot } from "../port-result.ts";
import {
  OAUTH_SINGLETON_PARAM_KEYS, CALLBACK_DUP_KEYS_EXPORT, assertCallbackPath, resolveCookieProfile,
  setCookieValue, clearCookieValue, readFlowCookie, flowCookieOversized, signFlowToken,
  verifyFlowToken, timingSafeStringEqual, findDuplicatedKeys, findRepeatedKeys, redirectErrorResponse,
  directErrorResponse, gatherOAuthParams, pickOAuthParams, randomFlowToken, type FlowClaims,
} from "./upstream-flow-internals.ts";

export interface UpstreamFlowDeps {
  bridge: Bridge;
  identity: RedirectIdentityPort;
  /** REQUIRED — the SAME StorePort the Bridge uses (flow JTIs share the consent-JTI registry). */
  store: StorePort;
  /** REQUIRED — the same ClockPort the Bridge uses. */
  clock: ClockPort;
  /** REQUIRED — the Bridge's audit sink (pass noopAudit only deliberately). */
  audit: AuditPort;
  /** Optional rate limiter (default noopRateLimit — mirrors BridgeDeps). */
  rateLimit?: RateLimitPort;
  /** Default "/oauth/callback". */
  callbackPath?: string;
  /** Flow-cookie TTL in seconds; default 600, max 3600. */
  flowTtlSeconds?: number;
  /** BELOW-GUARD CIMD test seams (§17.1.5 rule 14 / §17.1.6 decision 1e),
   *  mirroring `BridgeDeps`. The guard pipeline always runs around them and
   *  they can never widen `allowLoopback` or the caps. */
  cimdTransport?: CimdTransport;
  cimdResolver?: DnsResolver;
}

export interface UpstreamRedirectFlow {
  handleAuthorize(req: NormRequest): Promise<NormResponse>;
  handleCallback(req: NormRequest): Promise<NormResponse>;
  readonly callbackPath: string;
}

export function createUpstreamRedirectFlow(deps: UpstreamFlowDeps): UpstreamRedirectFlow {
  const { bridge, identity, store, clock, audit } = deps;
  const rateLimit = deps.rateLimit ?? noopRateLimit;
  const callbackPath = deps.callbackPath ?? "/oauth/callback";
  const flowTtlSeconds = deps.flowTtlSeconds ?? 600;
  const issuer = bridge.config.issuer;
  const secret = bridge.config.consentSigningSecret;
  const issuerOrigin = originOf(issuer);
  const resourcePath = pathAfterOrigin(bridge.config.resource);

  // Boot validation (all AuthConfigError, fail-closed — §17.11).
  if (!Number.isInteger(flowTtlSeconds) || flowTtlSeconds <= 0 || flowTtlSeconds > 3600) {
    throw new AuthConfigError("flowTtlSeconds must be a positive integer <= 3600");
  }
  assertCallbackPath(callbackPath, issuerOrigin, resourcePath);
  if (identity.redirectUri.includes("?") || identity.redirectUri.includes("#")) {
    throw new AuthConfigError("identity.redirectUri must not contain a query or fragment");
  }
  if (identity.redirectUri !== issuerOrigin + callbackPath) {
    throw new AuthConfigError(`identity.redirectUri must equal issuerOrigin + callbackPath ('${issuerOrigin + callbackPath}')`);
  }
  const cookieProfile = resolveCookieProfile(issuer);
  // §17.1.6 decision 4: the SAME CimdResolver instance the Bridge owns, so its
  // success cache / single-flight / in-flight cap are shared across BOTH modes.
  // Only the below-guard fetcher differs when this factory carries its own
  // seams — the caps and allowLoopback still come from the validated config.
  const cimd = bridge.cimd;
  // Pass the below-guard SEAMS, never a constructed fetcher: the resolver
  // builds the guard itself from the validated profile (decision 1e).
  const cimdSeams = deps.cimdTransport !== undefined || deps.cimdResolver !== undefined
    ? { transport: deps.cimdTransport, resolver: deps.cimdResolver }
    : undefined;

  const guard = async (req: NormRequest, prefix: string): Promise<void> => {
    let allowed = true;
    try { allowed = await rateLimit.check(`${prefix}:${req.ip ?? "unknown"}`); } catch { allowed = true; } // fail-open
    if (!allowed) throw new OAuthError("temporarily_unavailable", "Rate limit exceeded; retry later", 429);
  };
  const handleAuthorize = async (req: NormRequest): Promise<NormResponse> => {
    try {
      await guard(req, "upstream"); // step 1: upstream:<ip> rate-limit (advisory, fail-open)
      if (findDuplicatedKeys(req.query, OAUTH_SINGLETON_PARAM_KEYS).length > 0) { // step 2: RFC 6749 §3.1
        return directErrorResponse("invalid_request", "duplicate request parameters");
      }
      const clientId = queryString(req.query, "client_id");
      if (!clientId) return directErrorResponse("invalid_request", "client_id is required"); // step 3
      // Step 3a — §17.1.6 decision 1a/1b: shape-first dispatch + (for a CIMD id)
      // resolve-once through the SHARED success cache and match the presented
      // redirect_uri against the validated document, ALL before any Set-Cookie
      // or IdP 302. For an opaque id this is the unchanged mode-appropriate §10
      // pre-validation, so the callback's redirect-channel errors (rows
      // 7/8/10/11) only ever target a validated URI. Every CIMD failure is
      // mapped to the decision-2 generic INSIDE this boundary.
      const presentedRedirect = queryString(req.query, "redirect_uri") ?? "";
      const resolved = await resolveUpstreamAuthorizeClient({
        config: bridge.config, cimd, seams: cimdSeams, rateLimit, clientId,
        redirectUri: presentedRedirect, ip: req.ip,
      });
      const params = gatherOAuthParams(req); // step 4
      const state = randomFlowToken(), nonce = randomFlowToken(), codeVerifier = randomFlowToken();
      const jti = `upf_${randomFlowToken()}`;
      const flowJwt = await signFlowToken({
        secret, issuer, clock, callbackPath, jti, state, nonce, codeVerifier, params, ttlSeconds: flowTtlSeconds,
        ...(resolved.registration === undefined ? {} : { cimd: resolved.registration }),
      });
      if (flowCookieOversized(cookieProfile, flowJwt, flowTtlSeconds)) {
        // 1b: for a CIMD id the oversize residual maps to the SAME generic
        // invalid_client (never invalid_request — that would be a content
        // oracle) and audits a FAILURE reason `oversize`, never a success.
        if (resolved.registration !== undefined) throw await cimd.rejectAfterResolve("oversize", clientId, req.ip);
        return directErrorResponse("invalid_request", "request parameters too large");
      }
      await resolved.emitSuccess(); // decision 1b: success only AFTER the oversize guard
      const location = await buildUpstreamAuthorizationUrl(identity, {
        state, nonce, codeChallenge: pkceChallenge(codeVerifier), codeChallengeMethod: "S256",
      });
      return { status: 302, headers: noStoreHeaders({ location, "set-cookie": setCookieValue(cookieProfile, flowJwt, flowTtlSeconds) }), redirect: location };
    } catch (error) {
      const mapped = error instanceof OAuthError ? error : new OAuthError("internal_error", "OAuth request failed", 500);
      return directErrorResponse(mapped.code, mapped.message, mapped.status);
    }
  };

  const handleCallback = async (req: NormRequest): Promise<NormResponse> => {
    const ip = req.ip;
    const cookieValue = readFlowCookie(req.headers, cookieProfile);
    const cookiePresent = cookieValue !== undefined;
    const clear = (res: NormResponse): NormResponse => cookiePresent ? { ...res, headers: noStoreHeaders({ ...res.headers, "set-cookie": clearCookieValue(cookieProfile) }) } : res;
    let nowIso: string;
    try { nowIso = new Date(finiteClockSnapshot(clock)).toISOString(); }
    catch { return clear(directErrorResponse("internal_error", "OAuth request failed", 500)); }
    const finish = async (res: NormResponse, status: AuthAuditStatus, reason: string | undefined, clientId?: string): Promise<NormResponse> => {
      const response = clear(res);
      await writeAuditBestEffort(audit, { occurredAt: nowIso, event: "oauth.upstream.callback", status, reason, clientId, ip });
      return response;
    };
    const emitIdentityVerify = (status: AuthAuditStatus, reason: string | undefined, subject: string | undefined): Promise<void> =>
      writeAuditBestEffort(audit, { occurredAt: nowIso, event: "identity.verify", status, subject, reason, ip });
    try {
      let clientId: string | undefined;
      if (findRepeatedKeys(req.query, CALLBACK_DUP_KEYS_EXPORT).length > 0) return finish(directErrorResponse("invalid_request", "duplicate request parameters"), "failure", "duplicate_params"); // row 1
      if (!cookiePresent) return finish(directErrorResponse("invalid_request", "flow cookie missing"), "failure", "flow_cookie_missing"); // row 2 (nothing to clear)
      let claims: FlowClaims;
      try { claims = await verifyFlowToken(cookieValue as string, secret, issuer, callbackPath); } catch { return finish(directErrorResponse("invalid_request", "flow cookie invalid"), "failure", "flow_cookie_invalid"); } // row 3
      clientId = claims.params.client_id;
      if (claims.exp > 0 && claims.exp * 1000 <= finiteClockSnapshot(clock)) return finish(directErrorResponse("invalid_request", "flow expired"), "failure", "flow_expired", clientId); // row 4
      const clientRedirectUri = claims.params.redirect_uri; const clientState = claims.params.state;
      if (!clientRedirectUri) return finish(directErrorResponse("invalid_request", "flow cookie invalid"), "failure", "flow_cookie_invalid");
      try { assertOAuthRedirectEntry(clientRedirectUri); } catch {
        return finish(directErrorResponse("invalid_request", "flow cookie invalid"), "failure", "flow_cookie_invalid", clientId);
      }
      const queryState = queryString(req.query, "state");
      if (!queryState || !timingSafeStringEqual(queryState, claims.state)) return finish(directErrorResponse("invalid_request", "state mismatch"), "failure", "state_mismatch", clientId); // row 5
      // Row 5a (§17.1.6 decision 1d(ii)): the CIMD claim/mode/redirect matrix,
      // AFTER the state match and BEFORE jti consumption, the exchange, and
      // every redirect-channel branch (rows 7/8/10/11) — otherwise an
      // internally-inconsistent signed cookie would 302 an OAuth error to an
      // unmatched params.redirect_uri.
      if (!assertCallbackCimdPolicy(bridge.config, claims)) return finish(directErrorResponse("invalid_request", "flow cookie invalid"), "failure", "flow_cookie_invalid", clientId);
      // Re-read opaque stored-DCR state at callback. The flow cookie proves the
      // registration was valid at initiation, not that its persisted row is
      // still well-formed now. Keep this before every remaining early return,
      // JTI mutation, IdP exchange, consent signing, and callback success audit.
      if (clientId !== undefined && !isSchemeShaped(clientId)) {
        try { await resolveOpaqueRedirect(bridge.config, clientId, clientRedirectUri); }
        catch (error) {
          if (error instanceof OAuthError && (error.code === "invalid_client" || error.code === "invalid_redirect_uri")) {
            return finish(directErrorResponse("invalid_request", "flow cookie invalid"), "failure", "flow_cookie_invalid", clientId);
          }
          return finish(directErrorResponse("internal_error", "OAuth request failed", 500), "failure", "internal_error", clientId);
        }
      }
      let firstUse: boolean; // row 6: single-use jti — consumed BEFORE the IdP-error branch and the exchange
      try { firstUse = await consumeConsentJtiSnapshot(store, claims.jti, new Date(claims.exp * 1000).toISOString()); } catch { return finish(directErrorResponse("internal_error", "OAuth request failed", 500), "failure", "internal_error", clientId); }
      if (!firstUse) return finish(directErrorResponse("invalid_request", "flow already used"), "failure", "flow_replayed", clientId);
      const idpError = queryString(req.query, "error"); // rows 7/8: IdP error params are NEVER echoed
      if (idpError) {
        if (["access_denied", "consent_required", "interaction_required", "login_required"].includes(idpError)) return finish(redirectErrorResponse(bridge.config, clientRedirectUri, "access_denied", clientState, "upstream identity provider denied the request"), "failure", "upstream_denied", clientId);
        return finish(redirectErrorResponse(bridge.config, clientRedirectUri, "server_error", clientState, "upstream identity provider error"), "failure", "upstream_error", clientId);
      }
      const code = queryString(req.query, "code");
      if (!code) return finish(directErrorResponse("invalid_request", "missing authorization code"), "failure", "missing_code", clientId); // row 9
      let exchange; // rows 10/11: exchange + verify (a throw is always exchange_failed)
      try {
        exchange = await exchangeUpstreamIdentity(identity, {
          code, codeVerifier: claims.codeVerifier, nonce: claims.nonce,
        });
      } catch { console.error("[mcp-sso] upstream exchange failed (exchange_failed)", redactForStderr(clientId)); return finish(redirectErrorResponse(bridge.config, clientRedirectUri, "server_error", clientState, "upstream identity provider error"), "failure", "exchange_failed", clientId); }
      if (!exchange.ok) {
        if (exchange.kind === "exchange_failed") { console.error("[mcp-sso] upstream exchange failed (exchange_failed)", redactForStderr(clientId)); return finish(redirectErrorResponse(bridge.config, clientRedirectUri, "server_error", clientState, "upstream identity provider error"), "failure", "exchange_failed", clientId); }
        const reason = normalizedIdentityFailureReason(exchange.reason);
        await emitIdentityVerify("failure", reason, undefined);
        return finish(redirectErrorResponse(bridge.config, clientRedirectUri, "access_denied", clientState, identityRejectionDescription(reason)), "failure", "identity_rejected", clientId); // row 11 (§9.3 extension)
      }
      await emitIdentityVerify("success", undefined, exchange.identity.subject); // identity decision reached
      const synthetic: NormRequest = { query: pickOAuthParams(claims.params), body: undefined, headers: req.headers, ip }; // rows 12/13 — ceiling travels
      let bridgeResp: NormResponse;
      try {
        bridgeResp = await bridge.handleAuthorize(synthetic, {
          subject: exchange.identity.subject, allowedScopes: exchange.identity.allowedScopes,
          // §17.1.6 decision 1c/1d: the carried registration — validated once at
          // authorize, integrity-covered by the flow-cookie signature, gated by
          // row 5a above. `prepare` uses it and does NOT re-fetch.
          ...(claims.cimd === undefined ? {} : { registration: claims.cimd }),
        });
      }
      catch { return finish(directErrorResponse("internal_error", "OAuth request failed", 500), "failure", "internal_error", clientId); }
      if (bridgeResp.status === 200) return finish(bridgeResp, "success", undefined, clientId); // row 13: consent page (the direct callback response)
      return finish(bridgeResp, "failure", "bridge_error", clientId); // row 12: the bridge's own §9.3 channel
    } catch {
      return finish(directErrorResponse("internal_error", "OAuth request failed", 500), "failure", "internal_error");
    }
  };

  return { handleAuthorize, handleCallback, callbackPath };
}
