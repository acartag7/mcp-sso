// Bridge — framework-free wiring of the core use-cases to normalized HTTP
// requests/responses (contracts §9.6). Each fastify/express/hono adapter is a
// thin mapper around this; all OAuth logic stays in the core. The adapter resolves
// the subject (via its IdentityPort) before calling handleAuthorize.

import type { AnyBridgeConfig, BridgeConfig } from "../config.ts";
import type { ClockPort } from "../ports/clock.ts";
import type { AuditPort, AuthAuditStatus } from "../ports/audit.ts";
import type { StorePort } from "../ports/store.ts";
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
import { asOAuth, assertUnambiguousAuthorization, consentCookie, hasBasicAuthorization, parseApproved, resolveIdentityWithAudit } from "./bridge-internals.ts";
export { asOAuth, asDirectOAuth } from "./bridge-internals.ts";
import { CimdResolver } from "../cimd/resolve.ts";
import type { CimdRegistration } from "../cimd/registration.ts";
import type { CimdTransport, DnsResolver } from "../cimd/transport.ts";
import {
  formField, formObject, headerString, oauthErrorResponse, queryString, readHeader, resourceParam,
  type NormRequest, type NormResponse,
} from "./http.ts";

export interface BridgeDeps<Config extends AnyBridgeConfig = BridgeConfig> {
  config: Config;
  store: StorePort;
  clock: ClockPort;
  audit: AuditPort;
  /** Optional register/token/direct-identity rate limiter (fix #7); defaults to no-op. */
  rateLimit?: RateLimitPort;
  /** BELOW-GUARD CIMD test seams (§17.1.5 rule 14 / §17.1.6 decision 1e). They
   *  inject the low-level connect-to-validated-IP transport / DNS resolver; the
   *  guard pipeline — URL admission, blocklists, DNS validation, redirect
   *  refusal, caps — always runs AROUND them and cannot be skipped, and they
   *  can never widen `allowLoopback` or the caps. Never a whole `GuardedFetcher`,
   *  never a `BridgeConfig` field. */
  cimdTransport?: CimdTransport;
  cimdResolver?: DnsResolver;
}

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
const CONSENT_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "x-content-type-options": "nosniff",
  "content-security-policy":
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
  "x-frame-options": "DENY",
  "referrer-policy": "same-origin",
};

export class Bridge<Config extends AnyBridgeConfig = BridgeConfig> {
  readonly config: Config;
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

  constructor(deps: BridgeDeps<Config>) {
    this.config = deps.config;
    this.clock = deps.clock;
    this.audit = deps.audit;
    this.rateLimit = deps.rateLimit ?? noopRateLimit;
    this.cimd = new CimdResolver(deps);
    if (this.cimd.enabled) this.cimd.assertCapProfile(deps.cimdTransport, deps.cimdResolver); // boot-validate the cap profile
    this.auth = new OAuthAuthorizationUseCase({ ...deps, cimd: this.cimd });
    this.token = new OAuthTokenUseCase(deps);
  }

  async handleAuthorizationServerMetadata(): Promise<NormResponse> {
    return { status: 200, headers: { "cache-control": "public, max-age=300" }, body: authorizationServerMetadata(this.config) };
  }
  async handleProtectedResourceMetadata(resource?: string): Promise<NormResponse> {
    return { status: 200, headers: { "cache-control": "public, max-age=300" }, body: protectedResourceMetadata(this.config, resource) };
  }
  async handleJwks(): Promise<NormResponse> {
    return { status: 200, headers: { "cache-control": "public, max-age=60" }, body: jwks(this.config) };
  }

  async handleRegister(req: NormRequest): Promise<NormResponse> {
    try {
      await this.guard("register", req.ip);
      const body = formObject(req.body);
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
      return oauthErrorResponse(asOAuth(error));
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
      return oauthErrorResponse(asOAuth(error));
    }
  }

  /** Resolve a verified identity via the IdentityPort and emit the identity.verify
   *  audit event (§17.4 item 4 / §17.7). Fail-closed: { ok:false } ⇒ 401
   *  access_denied DIRECT (redirect_uri is untrusted pre-validation). A thrown
   *  error propagates RAW so the adapter's direct-error mapping (HF.1–HF.3,
   *  redirect stripped, no internal leak) is unchanged. The port's `reason` is
   *  carried as the audit reason (Entra-specific reasons land in S2b). The
   *  console-pairing path does NOT use this — it emits oauth.pairing.attempt.
   *  A present-but-malformed allowedScopes ceiling (non-array / non-string
   *  elements — a port bug) fails CLOSED: it must never widen to full access
   *  (fail-closed house rule; threat-model row 22 ceiling-bypass class). An
   *  empty array is a valid "entitled to nothing" ceiling (prepare's empty
   *  intersection denies). undefined ⇒ no ceiling (v0.1 behavior). */
  async resolveIdentity(identity: IdentityPort, input: unknown, ip?: string): Promise<{ subject: string; allowedScopes?: string[] }> {
    await this.guard("authorize", ip);
    return resolveIdentityWithAudit(identity, input, ip, (status, reason, subject, at) => this.emitIdentityVerify(status, reason, subject, at));
  }
  private async emitIdentityVerify(status: AuthAuditStatus, reason: string | undefined, subject: string | undefined, ip: string | undefined): Promise<void> {
    await this.audit.writeAuthEvent({ occurredAt: new Date(this.clock.nowMs()).toISOString(), event: "identity.verify", status, subject, reason, ip });
  }

  async handleApprove(req: NormRequest): Promise<NormResponse> {
    try {
      const body = formObject(req.body);
      const consentToken = formField(body, "consent_token") ?? consentCookie(req);
      const result = await this.auth.approve({
        consentToken,
        approved: parseApproved(body.approved),
        origin: headerString(req.headers, "origin"),
      });
      return { status: 302, headers: { location: result.redirectTo }, redirect: result.redirectTo };
    } catch (error) {
      return oauthErrorResponse(asOAuth(error));
    }
  }

  async handleToken(req: NormRequest): Promise<NormResponse> {
    let basicAttempted = false;
    try {
      const { value: authorization, ambiguous } = readHeader(req.headers, "authorization");
      basicAttempted = hasBasicAuthorization(req.headers);
      const body = formObject(req.body);
      const grantType = formField(body, "grant_type");
      await this.guard("token", req.ip);
      await assertUnambiguousAuthorization(ambiguous, grantType, formField(body, "client_id"), this.audit, this.clock);
      let response: UserTokenResponse | MachineTokenResponse;
      if (grantType === "refresh_token") {
        response = await this.token.refresh({ grantType, refreshToken: formField(body, "refresh_token"), clientId: formField(body, "client_id"), resource: resourceParam(formObject(body)["resource"]) });
      } else if (grantType === "client_credentials") {
        response = await this.token.exchangeClientCredentials({
          grantType, authorization, clientId: formField(body, "client_id"), clientSecret: formField(body, "client_secret"),
          scope: formField(body, "scope"), resource: resourceParam(formObject(body)["resource"]),
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
      const res = oauthErrorResponse(oauth);
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
      await this.token.revoke(formField(formObject(req.body), "token"));
      return { status: 200, headers: { "cache-control": "no-store" }, body: {} };
    } catch (error) {
      return oauthErrorResponse(asOAuth(error));
    }
  }

  private async guard(prefix: string, ip: string | undefined): Promise<void> {
    let allowed = true;
    try {
      allowed = await this.rateLimit.check(`${prefix}:${ip ?? "unknown"}`);
    } catch {
      allowed = true; // fail-open: a rate-limiter outage must not lock out auth
    }
    if (!allowed) throw new OAuthError("temporarily_unavailable", "Rate limit exceeded; retry later", 429);
  }
}
