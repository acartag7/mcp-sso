// Bridge — framework-free wiring of the core use-cases to normalized HTTP
// requests/responses (contracts §9.6). Each fastify/express/hono adapter is a
// thin mapper around this; all OAuth logic stays in the core. The adapter resolves
// the subject (via its IdentityPort) before calling handleAuthorize.

import { assertBridgeConfig, type BridgeConfig } from "../config.ts";
import type { ClockPort } from "../ports/clock.ts";
import type { AuditPort, AuthAuditStatus } from "../ports/audit.ts";
import type { StorePort } from "../ports/store.ts";
import type { RateLimitPort } from "../ports/rate-limit.ts";
import { noopRateLimit } from "../ports/rate-limit.ts";
import type { ApplicationType } from "../ports/client-store.ts";
import { captureIdentityPort, parseIdentityResult, type IdentityPort, type IdentityResult } from "../ports/identity.ts";
import { OAuthAuthorizationUseCase, type PreparedConsent } from "../authorize.ts";
import { OAuthTokenUseCase, type UserTokenResponse, type MachineTokenResponse } from "../token.ts";
import { registerClient } from "../register.ts";
import { authorizationServerMetadata, jwks, protectedResourceMetadata } from "../metadata.ts";
import { OAuthError } from "../errors.ts";
import { assertAllowedScopesCeiling } from "../scopes.ts";
import { isBasicAttempt } from "../client-auth.ts";
import { buildBasicClientChallenge } from "../challenge.ts";
import { ownDataValue, snapshotOwnDataRecord } from "../own-property.ts";
import { renderConsentPage } from "./consent-page.ts";
import {
  findDuplicatedKeys, formField, formObject, headerString, OAUTH_AUTHORIZE_PARAM_KEYS,
  oauthErrorResponse, queryString,
  type NormRequest, type NormResponse,
} from "./http.ts";
import {
  asOAuth, CONSENT_HEADERS, consentCookie, parseApproved, requiredRequest,
} from "./bridge-internals.ts";
import type { BridgeDeps } from "./bridge-types.ts";

export { asOAuth, asDirectOAuth } from "./bridge-internals.ts";
export type { BridgeDeps } from "./bridge-types.ts";

export class Bridge {
  readonly config: BridgeConfig;
  private readonly clock: ClockPort;
  private readonly audit: AuditPort;
  private readonly auth: OAuthAuthorizationUseCase;
  private readonly token: OAuthTokenUseCase;
  private readonly rateLimit: RateLimitPort;

  constructor(deps: BridgeDeps) {
    const fields = snapshotOwnDataRecord(deps);
    if (fields === null || !fields.config || !fields.store || !fields.clock || !fields.audit) {
      throw new TypeError("Bridge dependencies must be own data properties");
    }
    const safeDeps = Object.freeze({
      config: assertBridgeConfig(fields.config),
      store: fields.store as StorePort,
      clock: fields.clock as ClockPort,
      audit: fields.audit as AuditPort,
    });
    this.config = safeDeps.config;
    this.clock = safeDeps.clock;
    this.audit = safeDeps.audit;
    this.auth = new OAuthAuthorizationUseCase(safeDeps);
    this.token = new OAuthTokenUseCase(safeDeps);
    this.rateLimit = (fields.rateLimit as RateLimitPort | undefined) ?? noopRateLimit;
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
      const request = requiredRequest(req);
      await this.guard(request.ip, "register");
      const body = formObject(request.body);
      // Preserve the original value types for the core validator. Best-effort
      // filtering here would turn malformed metadata into a valid registration.
      const redirectUris = body.redirect_uris as string[] | undefined;
      const applicationType = body.application_type as ApplicationType | undefined;
      const tokenEndpointAuthMethod = body.token_endpoint_auth_method as string | undefined;
      const grantTypes = body.grant_types as string[] | undefined;
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
  async handleAuthorize(req: NormRequest, identity: { subject: string; allowedScopes?: string[] }): Promise<NormResponse> {
    try {
      const request = requiredRequest(req);
      if (findDuplicatedKeys(request.query, OAUTH_AUTHORIZE_PARAM_KEYS).length > 0) {
        throw new OAuthError("invalid_request", "Duplicate authorization request parameters");
      }
      const identityFields = snapshotOwnDataRecord(identity);
      if (identityFields === null || typeof identityFields.subject !== "string" || !identityFields.subject) {
        throw new OAuthError("access_denied", "Resolved identity is malformed", 401);
      }
      const prepared: PreparedConsent = await this.auth.prepare({
        clientId: queryString(request.query, "client_id"),
        redirectUri: queryString(request.query, "redirect_uri"),
        responseType: queryString(request.query, "response_type"),
        codeChallenge: queryString(request.query, "code_challenge"),
        codeChallengeMethod: queryString(request.query, "code_challenge_method"),
        resource: queryString(request.query, "resource"),
        scope: queryString(request.query, "scope"),
        state: queryString(request.query, "state"),
        subject: identityFields.subject,
        allowedScopes: assertAllowedScopesCeiling(identityFields.allowedScopes),
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
    await this.guard(ip, "authorize");
    let result: IdentityResult;
    try {
      const captured = captureIdentityPort(identity);
      if (captured === null) throw new OAuthError("access_denied", "Identity port is malformed", 401);
      const rawResult = await captured.verify(input);
      const parsedResult = parseIdentityResult(rawResult);
      if (parsedResult === null) throw new OAuthError("access_denied", "Identity port returned a malformed result", 401);
      result = parsedResult;
    } catch (error) {
      await this.emitIdentityVerify("failure", error instanceof OAuthError ? error.code : "internal_error", undefined, ip);
      throw error;
    }
    if (!result.ok) {
      await this.emitIdentityVerify("failure", result.reason, undefined, ip);
      throw new OAuthError("access_denied", `Identity rejected: ${result.reason}`, 401);
    }
    const subject = result.identity.subject;
    // Fail CLOSED on a present-but-malformed ceiling (§17.4) via the shared
    // validator (also used at the prepare core boundary). Emits a specific
    // identity.verify reason before re-throwing.
    let allowedScopes: string[] | undefined;
    try {
      allowedScopes = assertAllowedScopesCeiling(result.identity.allowedScopes);
    } catch (error) {
      await this.emitIdentityVerify("failure", "malformed_allowed_scopes", undefined, ip);
      throw error;
    }
    await this.emitIdentityVerify("success", undefined, subject, ip);
    return { subject, allowedScopes };
  }

  private async emitIdentityVerify(status: AuthAuditStatus, reason: string | undefined, subject: string | undefined, ip: string | undefined): Promise<void> {
    await this.audit.writeAuthEvent({ occurredAt: new Date(this.clock.nowMs()).toISOString(), event: "identity.verify", status, subject, reason, ip });
  }

  async handleApprove(req: NormRequest): Promise<NormResponse> {
    try {
      const request = requiredRequest(req);
      const body = formObject(request.body);
      const consentToken = formField(body, "consent_token") ?? consentCookie(request);
      const result = await this.auth.approve({
        consentToken,
        approved: parseApproved(ownDataValue(body, "approved")),
        origin: headerString(request.headers, "origin"),
      });
      return { status: 302, headers: { location: result.redirectTo }, redirect: result.redirectTo };
    } catch (error) {
      return oauthErrorResponse(asOAuth(error));
    }
  }

  async handleToken(req: NormRequest): Promise<NormResponse> {
    let authorization: string | undefined;
    try {
      const request = requiredRequest(req);
      authorization = headerString(request.headers, "authorization");
      await this.guard(request.ip, "token");
      const body = formObject(request.body);
      const grantType = formField(body, "grant_type");
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
      // §17.2: failed Basic client auth ⇒ WWW-Authenticate: Basic (a
      // client_secret_post failure does not earn the Basic challenge).
      const oauth = asOAuth(error);
      const res = oauthErrorResponse(oauth);
      if (oauth.code === "invalid_client" && oauth.status === 401 && isBasicAttempt(authorization)) {
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
      const request = requiredRequest(req);
      await this.token.revoke(formField(formObject(request.body), "token"));
      return { status: 200, headers: { "cache-control": "no-store" }, body: {} };
    } catch (error) {
      return oauthErrorResponse(asOAuth(error));
    }
  }

  private async guard(ip: string | undefined, prefix: string): Promise<void> {
    let allowed = true;
    try {
      allowed = await this.rateLimit.check(`${prefix}:${ip ?? "unknown"}`);
    } catch {
      allowed = true; // fail-open: a rate-limiter outage must not lock out auth
    }
    if (!allowed) throw new OAuthError("temporarily_unavailable", "Rate limit exceeded; retry later", 429);
  }
}
