// Bridge — framework-free wiring of the core use-cases to normalized HTTP
// requests/responses (contracts §9.6). Each fastify/express/hono adapter is a thin
// mapper; the adapter resolves the subject before calling handleAuthorize.
import type { BridgeConfig } from "../config.ts";
import { finiteClockSnapshot, type ClockPort } from "../ports/clock.ts";
import type { AuditPort, AuthAuditStatus } from "../ports/audit.ts";
import type { RateLimitPort } from "../ports/rate-limit.ts";
import { noopRateLimit } from "../ports/rate-limit.ts";
import type { IdentityPort, IdentityResult } from "../ports/identity.ts";
import { OAuthAuthorizationUseCase, type PreparedConsent } from "../authorize.ts";
import { OAuthTokenUseCase, type UserTokenResponse, type MachineTokenResponse } from "../token.ts";
import { registerClient } from "../register.ts";
import { authorizationServerMetadata, jwks, protectedResourceMetadata } from "../metadata.ts";
import { OAuthError } from "../errors.ts";
import { buildBasicClientChallenge } from "../challenge.ts";
import { renderConsentPage } from "./consent-page.ts";
import { APPROVE_SINGLETON_PARAM_KEYS, OAUTH_SINGLETON_PARAM_KEYS, REGISTER_JSON_ARRAY_PARAM_KEYS, REGISTER_SINGLETON_PARAM_KEYS, REVOKE_SINGLETON_PARAM_KEYS, TOKEN_SINGLETON_PARAM_KEYS, findDuplicatedKeys } from "./authorize-params.ts";
import { asOAuth, assertStoredRegistrationIp, assertUnambiguousAuthorization, checkedFormObject, consentCookie, hasBasicAuthorization, parseApproved, resolveIdentityWithAudit } from "./bridge-internals.ts";
export { asOAuth, asDirectOAuth } from "./bridge-internals.ts";
import { CimdResolver } from "../cimd/resolve.ts";
import type { CimdRegistration } from "../cimd/registration.ts";
import { writeAuditBestEffort } from "../audit/best-effort.ts";
import { assertSafeDeploymentCombination, snapshotRateLimit } from "../deployment-guard.ts";
import { formField, headerString, noStoreHeaders, oauthErrorResponse, queryString, readHeader, resourceParam,
  type NormRequest, type NormResponse,
} from "./http.ts";
import type { BridgeDeps } from "./bridge-deps.ts";
export type { BridgeDeps } from "./bridge-deps.ts";

// `referrer-policy: same-origin` preserves the scheme/host/port `Origin` on the
// same-origin Approve POST, which the strict `assertApproveOrigin` gate needs.
// `no-referrer` serialized that Origin as `null` in Chromium and broke browser
// consent. Cross-origin Referer still omits the authorize URL's sensitive query.
//
// `frame-ancestors 'none'` is load-bearing, not hygiene: threat-model row 17
// makes the user's judgment at this page the LAST line of defence against CIMD
// client impersonation (lookalike domain / loopback-only redirect). A framed,
// overlaid Approve button removes that judgment entirely — one click issues a
// code — and CIMD means the attacker needs no registration to get here.
// `frame-ancestors` does NOT fall back to `default-src` under CSP3, so
// `default-src 'none'` alone does not frame-block; `x-frame-options` covers
// pre-CSP3 agents. Consent omits `form-action`: Chromium applies it across the
// POST redirect chain, so `'self'` blocks loopback callbacks; the literal action and exact Origin gate remain.
const CONSENT_HEADERS = noStoreHeaders({
  "content-type": "text/html; charset=utf-8",
  "x-content-type-options": "nosniff",
  "content-security-policy":
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
  "x-frame-options": "DENY",
  "referrer-policy": "same-origin",
});

export class Bridge {
  readonly config: BridgeConfig;
  private readonly clock: ClockPort;
  private readonly audit: AuditPort;
  private readonly auth: OAuthAuthorizationUseCase;
  private readonly token: OAuthTokenUseCase;
  private readonly rateLimit: RateLimitPort;
  /** The ONE shared CIMD resolution service for this Bridge instance — its
   *  success cache, single-flight registry, and in-flight cap serve BOTH
   *  direct-mode prepare AND the upstream-redirect authorize (§17.1.6
   *  decision 4). Constructed eagerly so a bad `cimd` cap surfaces as an
   *  `AuthConfigError` at BOOT, never at the first request. */
  readonly cimd: CimdResolver;

  constructor(deps: BridgeDeps) {
    // BridgeDeps is a runtime boundary: accessor-backed objects must not show the
    // guard one composition and initialize the use-cases with another.
    const snapshot: BridgeDeps = {
      config: deps.config,
      store: deps.store,
      clock: deps.clock,
      audit: deps.audit,
      rateLimit: snapshotRateLimit(deps.rateLimit),
      acknowledgeUnsafeStatelessDefaults: deps.acknowledgeUnsafeStatelessDefaults,
      cimdTransport: deps.cimdTransport,
      cimdResolver: deps.cimdResolver,
    };
    assertSafeDeploymentCombination(snapshot);
    this.config = snapshot.config;
    this.clock = snapshot.clock;
    this.audit = snapshot.audit;
    this.rateLimit = snapshot.rateLimit ?? noopRateLimit;
    this.cimd = new CimdResolver(snapshot);
    if (this.cimd.enabled) this.cimd.assertCapProfile(snapshot.cimdTransport, snapshot.cimdResolver); // boot-validate the cap profile
    this.auth = new OAuthAuthorizationUseCase({ ...snapshot, cimd: this.cimd });
    this.token = new OAuthTokenUseCase(snapshot);
    snapshot.store.startExpiryCollection?.(snapshot.clock);
  }

  async handleAuthorizationServerMetadata(): Promise<NormResponse> {
    return { status: 200, headers: { "cache-control": "public, max-age=300" }, body: authorizationServerMetadata(this.config) };
  }
  async handleProtectedResourceMetadata(): Promise<NormResponse> {
    return { status: 200, headers: { "cache-control": "public, max-age=300" }, body: protectedResourceMetadata(this.config) };
  }
  async handleJwks(): Promise<NormResponse> {
    return { status: 200, headers: { "cache-control": "public, max-age=60" }, body: jwks(this.config) };
  }

  async handleRegister(req: NormRequest): Promise<NormResponse> {
    try {
      // §6.7 D2 runtime half: never register:unknown for the anonymous durable write.
      assertStoredRegistrationIp(this.config.dcr.mode, req.ip);
      await this.guard("register", req.ip, this.config.dcr.mode === "stored");
      const body = checkedFormObject(req, REGISTER_SINGLETON_PARAM_KEYS, REGISTER_JSON_ARRAY_PARAM_KEYS);
      // All DCR metadata crosses as raw unknown values. registerClient owns the
      // container → member → grammar checks and snapshots arrays before use.
      const redirectUris = Object.hasOwn(body, "redirect_uris") ? body.redirect_uris : undefined;
      const applicationType = Object.hasOwn(body, "application_type") ? body.application_type : undefined;
      const tokenEndpointAuthMethod = Object.hasOwn(body, "token_endpoint_auth_method")
        ? body.token_endpoint_auth_method : undefined;
      const grantTypes = Object.hasOwn(body, "grant_types") ? body.grant_types : undefined;
      const registered = await registerClient(
        { config: this.config, clock: this.clock, audit: this.audit },
        { redirectUris, applicationType, tokenEndpointAuthMethod, grantTypes },
      );
      return { status: 201, headers: { "cache-control": "no-store" }, body: registered };
    } catch (error) {
      return oauthErrorResponse(this.config, asOAuth(error));
    }
  }

  /** GET /oauth/authorize. `identity` ({ subject, allowedScopes? }) is resolved
   *  by the adapter via its IdentityPort — or by Bridge.resolveIdentity, which
   *  also emits the identity.verify audit event (§17.4 item 4). The bare-string
   *  form is removed (§17.4 item 3): the ceiling must travel the whole path. */
  async handleAuthorize(
    req: NormRequest,
    identity: { subject: string; allowedScopes?: string[]; registration?: CimdRegistration },
  ): Promise<NormResponse> {
    try {
      if (findDuplicatedKeys(req.query, OAUTH_SINGLETON_PARAM_KEYS).length > 0) throw new OAuthError("invalid_request", "duplicate request parameters");
      const prepared: PreparedConsent = await this.auth.prepare({
        clientId: queryString(req.query, "client_id"),
        redirectUri: queryString(req.query, "redirect_uri"),
        responseType: queryString(req.query, "response_type"),
        codeChallenge: queryString(req.query, "code_challenge"),
        codeChallengeMethod: queryString(req.query, "code_challenge_method"),
        resource: resourceParam(req.query["resource"]),
        scope: queryString(req.query, "scope"),
        state: queryString(req.query, "state"),
        subject: identity.subject,
        allowedScopes: identity.allowedScopes,
        // §17.1.6 decision 1c: orchestrator-resolved trusted state. Adapters
        // NEVER bind this to a request field — it comes from the verified,
        // row-5a-gated flow cookie only.
        registration: identity.registration,
        ip: req.ip,
      });
      return { status: 200, headers: { ...CONSENT_HEADERS }, body: renderConsentPage(this.config, prepared) };
    } catch (error) {
      return oauthErrorResponse(this.config, asOAuth(error));
    }
  }
  /** Resolve a verified identity via the IdentityPort and emit the identity.verify
   *  audit event (§17.4 item 4 / §17.7). Fail-closed: { ok:false } ⇒ 401
   *  access_denied DIRECT (redirect_uri is untrusted pre-validation). A thrown
   *  OAuthError can select only an allowlisted 401/403 rejection status; its
   *  code, description, and redirect are replaced. Every other throw becomes
   *  a generic 500 through the direct-error mapping. The port's returned `reason` is
   *  carried as the audit reason (Entra-specific reasons land in S2b). The
   *  console-pairing path does NOT use this — it emits oauth.pairing.attempt.
   *  A present-but-malformed or over-bound allowedScopes ceiling (non-array /
   *  non-string elements / more than 128 entries / an overlong token — a port
   *  bug) fails CLOSED: it must never widen to full access
   *  (fail-closed house rule; threat-model row 22 ceiling-bypass class). An
   *  empty array is a valid "entitled to nothing" ceiling (prepare's empty
   *  intersection denies). undefined ⇒ no ceiling (v0.1 behavior). */
  async resolveIdentity(identity: IdentityPort, input: unknown, ip?: string): Promise<{ subject: string; allowedScopes?: string[] }> {
    await this.guard("authorize", ip);
    return resolveIdentityWithAudit(identity, input, ip, (status, reason, subject, at) => this.emitIdentityVerify(status, reason, subject, at));
  }
  /** Charge console-pairing authorize once at its flow-level entry point. */
  async guardPairingAuthorize(ip?: string): Promise<void> {
    await this.guard("authorize", ip);
  }
  private async emitIdentityVerify(status: AuthAuditStatus, reason: string | undefined, subject: string | undefined, ip: string | undefined): Promise<void> {
    await writeAuditBestEffort(this.audit, { occurredAt: new Date(finiteClockSnapshot(this.clock)).toISOString(), event: "identity.verify", status, subject, reason, ip });
  }

  async handleApprove(req: NormRequest): Promise<NormResponse> {
    try {
      await this.guard("approve", req.ip);
      const body = checkedFormObject(req, APPROVE_SINGLETON_PARAM_KEYS);
      const consentToken = formField(body, "consent_token") ?? consentCookie(req);
      const result = await this.auth.approve({
        consentToken,
        approved: parseApproved(body.approved),
        origin: headerString(req.headers, "origin"),
      });
      return { status: 302, headers: result.code === undefined ? { location: result.redirectTo } : noStoreHeaders({ location: result.redirectTo }), redirect: result.redirectTo };
    } catch (error) {
      return oauthErrorResponse(this.config, asOAuth(error));
    }
  }

  async handleToken(req: NormRequest): Promise<NormResponse> {
    let basicAttempted = false;
    try {
      await this.guard("token", req.ip);
      const body = checkedFormObject(req, TOKEN_SINGLETON_PARAM_KEYS);
      const { value: authorization, ambiguous } = readHeader(req.headers, "authorization");
      basicAttempted = hasBasicAuthorization(req.headers);
      const grantType = formField(body, "grant_type");
      await assertUnambiguousAuthorization(ambiguous, grantType, formField(body, "client_id"), this.audit, this.clock);
      let response: UserTokenResponse | MachineTokenResponse;
      if (grantType === "refresh_token") {
        response = await this.token.refresh({ grantType, refreshToken: formField(body, "refresh_token"), clientId: formField(body, "client_id") });
      } else if (grantType === "client_credentials") {
        response = await this.token.exchangeClientCredentials({
          grantType, authorization, clientId: formField(body, "client_id"), clientSecret: formField(body, "client_secret"),
          scope: formField(body, "scope"), resource: formField(body, "resource"),
        });
      } else {
        response = await this.token.exchangeAuthorizationCode({
          grantType, code: formField(body, "code"), redirectUri: formField(body, "redirect_uri"),
          clientId: formField(body, "client_id"), codeVerifier: formField(body, "code_verifier"),
        });
      }
      return { status: 200, headers: { "cache-control": "no-store", "pragma": "no-cache" }, body: response };
    } catch (error) {
      // §17.2: failed Basic auth earns the Basic challenge; post-only does not.
      const oauth = asOAuth(error);
      const res = oauthErrorResponse(this.config, oauth);
      if (oauth.code === "invalid_client" && oauth.status === 401 && basicAttempted) {
        res.headers["www-authenticate"] = buildBasicClientChallenge(this.config);
      }
      return res;
    }
  }

  async handleRevoke(req: NormRequest): Promise<NormResponse> {
    // RFC 7009 unrecognized-token is still 200 (handled inside revoke()); this
    // catch is for unexpected throws (e.g. store outage), which must map to the
    // §9.5 body like every other route — never a framework-shaped error.
    try {
      await this.guard("revoke", req.ip);
      await this.token.revoke(formField(checkedFormObject(req, REVOKE_SINGLETON_PARAM_KEYS), "token"));
      return { status: 200, headers: { "cache-control": "no-store" }, body: {} };
    } catch (error) {
      return oauthErrorResponse(this.config, asOAuth(error));
    }
  }

  private async guard(prefix: string, ip: string | undefined, failClosedOnThrow = false): Promise<void> {
    let allowed = true;
    try {
      allowed = await this.rateLimit.check(`${prefix}:${ip ?? "unknown"}`);
    } catch {
      if (failClosedOnThrow) throw new OAuthError("temporarily_unavailable", "Rate limiter unavailable; retry later", 503);
    }
    if (!allowed) throw new OAuthError("temporarily_unavailable", "Rate limit exceeded; retry later", 429);
  }
}
