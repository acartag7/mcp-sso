// createUpstreamRedirectFlow (contracts §17.11) — the framework-free orchestrator
// for redirect-based upstream IdPs, sibling to handlePairingAuthorize. GET
// /oauth/authorize → persist flow state in a signed cookie → 302 to the IdP;
// callback → validate (13-row failure table) → exchange → verify → hand the
// identity (with its allowedScopes ceiling) to bridge.handleAuthorize → consent
// page. Root-exported (§15). All deps mirror BridgeDeps (store/clock/audit
// REQUIRED, rateLimit? default noop) — the Bridge keeps its deps private, and
// this contract adds NO new Bridge surface; the composition root passes the
// SAME instances to both.

import { randomBytes } from "node:crypto";
import type { Bridge } from "./bridge.ts";
import type { RedirectIdentityPort } from "../ports/identity.ts";
import { parseRedirectExchangeResult } from "../ports/identity.ts";
import type { StorePort } from "../ports/store.ts";
import type { ClockPort } from "../ports/clock.ts";
import type { AuditPort, AuthAuditStatus } from "../ports/audit.ts";
import type { RateLimitPort } from "../ports/rate-limit.ts";
import { noopRateLimit } from "../ports/rate-limit.ts";
import { AuthConfigError, originOf, pathAfterOrigin, type BridgeConfig } from "../config.ts";
import { OAuthError } from "../errors.ts";
import { assertAllowedRedirectUri, assertRedirectAllowedForClient } from "../redirect.ts";
import { parseFoundClientRegistration } from "../stored-records.ts";
import { pkceChallenge } from "../crypto.ts";
import { findDuplicatedKeys, parseNormRequest, queryString, type NormRequest, type NormResponse } from "./http.ts";
import { redactForStderr } from "../audit/util.ts";
import {
  OAUTH_PARAM_KEYS, CALLBACK_DUP_KEYS_EXPORT, assertCallbackPath, resolveCookieProfile,
  setCookieValue, clearCookieValue, readFlowCookie, flowCookieOversized, signFlowToken,
  verifyFlowToken, timingSafeStringEqual, redirectErrorResponse,
  directErrorResponse, type FlowClaims,
} from "./upstream-flow-internals.ts";
import { snapshotOwnDataRecord } from "../own-property.ts";

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
}

export interface UpstreamRedirectFlow {
  handleAuthorize(req: NormRequest): Promise<NormResponse>;
  handleCallback(req: NormRequest): Promise<NormResponse>;
  readonly callbackPath: string;
}

export function createUpstreamRedirectFlow(deps: UpstreamFlowDeps): UpstreamRedirectFlow {
  const fields = snapshotOwnDataRecord(deps);
  if (fields === null || !fields.bridge || !fields.identity || !fields.store
    || !fields.clock || !fields.audit) throw new AuthConfigError("upstream-flow dependencies must be own data properties");
  const bridge = fields.bridge as Bridge;
  const identity = fields.identity as RedirectIdentityPort;
  const store = fields.store as StorePort;
  const clock = fields.clock as ClockPort;
  const audit = fields.audit as AuditPort;
  const rateLimit = (fields.rateLimit as RateLimitPort | undefined) ?? noopRateLimit;
  const callbackPath = (fields.callbackPath as string | undefined) ?? "/oauth/callback";
  const flowTtlSeconds = (fields.flowTtlSeconds as number | undefined) ?? 600;
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

  const guard = async (req: NormRequest, prefix: string): Promise<void> => {
    let allowed = true;
    try { allowed = await rateLimit.check(`${prefix}:${req.ip ?? "unknown"}`); } catch { allowed = true; } // fail-open
    if (!allowed) throw new OAuthError("temporarily_unavailable", "Rate limit exceeded; retry later", 429);
  };
  const emitIdentityVerify = (status: AuthAuditStatus, reason: string | undefined, subject: string | undefined, ip: string | undefined): Promise<void> =>
    audit.writeAuthEvent({ occurredAt: new Date(clock.nowMs()).toISOString(), event: "identity.verify", status, subject, reason, ip });

  const handleAuthorize = async (req: NormRequest): Promise<NormResponse> => {
    try {
      const request = parseNormRequest(req);
      if (request === null) return directErrorResponse("invalid_request", "request is malformed");
      await guard(request, "upstream"); // step 1: upstream:<ip> rate-limit (advisory, fail-open)
      if (findDuplicatedKeys(request.query, OAUTH_PARAM_KEYS).length > 0) { // step 2: RFC 6749 §3.1
        return directErrorResponse("invalid_request", "duplicate request parameters");
      }
      const clientId = queryString(request.query, "client_id");
      if (!clientId) return directErrorResponse("invalid_request", "client_id is required"); // step 3
      // §10 pre-validation — the redirect_uri signed into the flow cookie must be
      // validated to the MODE-APPROPRIATE policy so the callback's redirect-channel
      // errors (rows 7/8/10/11, which fire before bridge.handleAuthorize→prepare)
      // only ever target a §10-validated URI. Mirrors authorize.ts resolveRedirect:
      // stored mode ⇒ §10.2 per-client (resolve the client first); stateless ⇒ §10.1.
      await resolveAuthorizeRedirect(bridge.config, clientId, queryString(request.query, "redirect_uri") ?? "");
      const params = gatherOAuthParams(request); // step 4
      const state = randomToken(), nonce = randomToken(), codeVerifier = randomToken();
      const jti = `upf_${randomToken()}`;
      const flowJwt = await signFlowToken({ secret, issuer, clock, jti, state, nonce, codeVerifier, params, ttlSeconds: flowTtlSeconds });
      if (flowCookieOversized(cookieProfile, flowJwt, flowTtlSeconds)) return directErrorResponse("invalid_request", "request parameters too large");
      const location = identity.buildAuthorizationUrl({ state, nonce, codeChallenge: pkceChallenge(codeVerifier), codeChallengeMethod: "S256" });
      return { status: 302, headers: { location, "set-cookie": setCookieValue(cookieProfile, flowJwt, flowTtlSeconds) }, redirect: location };
    } catch (error) {
      const mapped = error instanceof OAuthError ? error : new OAuthError("internal_error", "OAuth request failed", 500);
      return directErrorResponse(mapped.code, mapped.message, mapped.status);
    }
  };

  const handleCallback = async (req: NormRequest): Promise<NormResponse> => {
    const request = parseNormRequest(req);
    if (request === null) return directErrorResponse("invalid_request", "request is malformed");
    const nowIso = new Date(clock.nowMs()).toISOString();
    const ip = request.ip;
    const cookieValue = readFlowCookie(request.headers, cookieProfile);
    const cookiePresent = cookieValue !== undefined;
    const clear = (res: NormResponse): NormResponse => cookiePresent ? { ...res, headers: { ...res.headers, "set-cookie": clearCookieValue(cookieProfile) } } : res;
    const emit = (status: AuthAuditStatus, reason: string | undefined, clientId?: string): Promise<void> =>
      audit.writeAuthEvent({ occurredAt: nowIso, event: "oauth.upstream.callback", status, reason, clientId, ip });
    try {
      let clientId: string | undefined;
      if (findDuplicatedKeys(request.query, CALLBACK_DUP_KEYS_EXPORT).length > 0) { await emit("failure", "duplicate_params"); return clear(directErrorResponse("invalid_request", "duplicate request parameters")); } // row 1
      if (!cookiePresent) { await emit("failure", "flow_cookie_missing"); return directErrorResponse("invalid_request", "flow cookie missing"); } // row 2 (nothing to clear)
      let claims: FlowClaims;
      try { claims = await verifyFlowToken(cookieValue as string, secret, issuer); } catch { await emit("failure", "flow_cookie_invalid"); return clear(directErrorResponse("invalid_request", "flow cookie invalid")); } // row 3
      clientId = claims.params.client_id;
      if (claims.exp > 0 && claims.exp * 1000 <= clock.nowMs()) { await emit("failure", "flow_expired", clientId); return clear(directErrorResponse("invalid_request", "flow expired")); } // row 4
      const clientRedirectUri = claims.params.redirect_uri; const clientState = claims.params.state; // verified context (authorize §10-validated + signed)
      if (!clientRedirectUri) { await emit("failure", "flow_cookie_invalid"); return clear(directErrorResponse("invalid_request", "flow cookie invalid")); }
      const queryState = queryString(request.query, "state");
      if (!queryState || !timingSafeStringEqual(queryState, claims.state)) { await emit("failure", "state_mismatch", clientId); return clear(directErrorResponse("invalid_request", "state mismatch")); } // row 5
      let firstUse: boolean; // row 6: single-use jti — consumed BEFORE the IdP-error branch and the exchange
      try { firstUse = await store.consumeConsentJti(claims.jti, new Date(claims.exp * 1000).toISOString()); } catch { await emit("failure", "internal_error", clientId); return clear(directErrorResponse("internal_error", "OAuth request failed", 500)); }
      if (firstUse !== true) { await emit("failure", "flow_replayed", clientId); return clear(directErrorResponse("invalid_request", "flow already used")); }
      const idpError = queryString(request.query, "error"); // rows 7/8: IdP error params are NEVER echoed
      if (idpError) {
        if (["access_denied", "consent_required", "interaction_required", "login_required"].includes(idpError)) { await emit("failure", "upstream_denied", clientId); return clear(redirectErrorResponse(clientRedirectUri, "access_denied", clientState, "upstream identity provider denied the request")); }
        await emit("failure", "upstream_error", clientId); return clear(redirectErrorResponse(clientRedirectUri, "server_error", clientState, "upstream identity provider error"));
      }
      const code = queryString(request.query, "code");
      if (!code) { await emit("failure", "missing_code", clientId); return clear(directErrorResponse("invalid_request", "missing authorization code")); } // row 9
      let exchange; // rows 10/11: exchange + verify (a throw is always exchange_failed)
      try {
        exchange = parseRedirectExchangeResult(
          await identity.exchangeAndVerify({ code, codeVerifier: claims.codeVerifier, nonce: claims.nonce }),
        );
      } catch (e) { console.error("[mcp-sso] upstream exchange failed (exchange_failed)", redactForStderr(clientId), redactForStderr(e)); await emit("failure", "exchange_failed", clientId); return clear(redirectErrorResponse(clientRedirectUri, "server_error", clientState, "upstream identity provider error")); }
      if (exchange === null) { await emit("failure", "exchange_failed", clientId); return clear(redirectErrorResponse(clientRedirectUri, "server_error", clientState, "upstream identity provider error")); }
      if (!exchange.ok) {
        if (exchange.kind === "exchange_failed") { console.error("[mcp-sso] upstream exchange failed (exchange_failed)", redactForStderr(clientId), redactForStderr(exchange.reason)); await emit("failure", "exchange_failed", clientId); return clear(redirectErrorResponse(clientRedirectUri, "server_error", clientState, "upstream identity provider error")); }
        await emitIdentityVerify("failure", exchange.reason, undefined, ip); await emit("failure", "identity_rejected", clientId); return clear(redirectErrorResponse(clientRedirectUri, "access_denied", clientState, "upstream identity verification failed")); // row 11 (§9.3 extension)
      }
      await emitIdentityVerify("success", undefined, exchange.identity.subject, ip); // identity decision reached
      const synthetic: NormRequest = { query: pickOAuthParams(claims.params), body: undefined, headers: request.headers, ip }; // rows 12/13 — ceiling travels
      let bridgeResp: NormResponse;
      try { bridgeResp = await bridge.handleAuthorize(synthetic, { subject: exchange.identity.subject, allowedScopes: exchange.identity.allowedScopes }); }
      catch { await emit("failure", "internal_error", clientId); return clear(directErrorResponse("internal_error", "OAuth request failed", 500)); }
      if (bridgeResp.status === 200) { await emit("success", undefined, clientId); return clear(bridgeResp); } // row 13: consent page (the direct callback response)
      await emit("failure", "bridge_error", clientId); return clear(bridgeResp); // row 12: the bridge's own §9.3 channel
    } catch {
      await emit("failure", "internal_error");
      return clear(directErrorResponse("internal_error", "OAuth request failed", 500));
    }
  };

  return { handleAuthorize, handleCallback, callbackPath };
}

function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

/** Mode-appropriate §10 redirect validation at authorize — mirrors authorize.ts
 *  resolveRedirect. Stored mode resolves the client and applies the per-client
 *  policy (§10.2); stateless applies the global allowlist (§10.1). Throws a
 *  direct OAuthError (invalid_client / invalid_redirect_uri). */
async function resolveAuthorizeRedirect(config: BridgeConfig, clientId: string, redirectUri: string): Promise<void> {
  if (config.dcr.mode === "stored") {
    const client = await config.dcr.store.find(clientId);
    const parsed = parseFoundClientRegistration(client, clientId);
    if (parsed === null) throw new OAuthError("invalid_client", "Unknown or malformed client_id", 401);
    assertRedirectAllowedForClient(redirectUri, parsed);
    return;
  }
  assertAllowedRedirectUri(redirectUri, config.redirectAllowlist);
}

function gatherOAuthParams(req: NormRequest): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of OAUTH_PARAM_KEYS) { const v = queryString(req.query, k); if (typeof v === "string") out[k] = v; }
  return out;
}

function pickOAuthParams(params: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of OAUTH_PARAM_KEYS) { const v = params[k]; if (typeof v === "string") out[k] = v; }
  return out;
}
