// Bridge — framework-free wiring of the core use-cases to normalized HTTP
// requests/responses (contracts §9.6). Each fastify/express/hono adapter is a
// thin mapper around this; all OAuth logic stays in the core. The adapter resolves
// the subject (via its IdentityPort) before calling handleAuthorize.

import type { BridgeConfig } from "../config.ts";
import type { ClockPort } from "../ports/clock.ts";
import type { AuditPort, AuthAuditStatus } from "../ports/audit.ts";
import type { StorePort } from "../ports/store.ts";
import type { RateLimitPort } from "../ports/rate-limit.ts";
import { noopRateLimit } from "../ports/rate-limit.ts";
import type { ApplicationType } from "../ports/client-store.ts";
import type { IdentityPort, IdentityResult } from "../ports/identity.ts";
import { OAuthAuthorizationUseCase, type PreparedConsent } from "../authorize.ts";
import { OAuthTokenUseCase } from "../token.ts";
import { registerClient } from "../register.ts";
import { authorizationServerMetadata, jwks, protectedResourceMetadata } from "../metadata.ts";
import { OAuthError } from "../errors.ts";
import { assertAllowedScopesCeiling } from "../scopes.ts";
import { renderConsentPage } from "./consent-page.ts";
import {
  formField, formObject, headerString, oauthErrorResponse, queryString,
  type NormRequest, type NormResponse,
} from "./http.ts";

export interface BridgeDeps {
  config: BridgeConfig;
  store: StorePort;
  clock: ClockPort;
  audit: AuditPort;
  /** Optional register/token rate limiter (fix #7); defaults to no-op. */
  rateLimit?: RateLimitPort;
}

const CONSENT_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'",
};

export class Bridge {
  readonly config: BridgeConfig;
  private readonly clock: ClockPort;
  private readonly audit: AuditPort;
  private readonly auth: OAuthAuthorizationUseCase;
  private readonly token: OAuthTokenUseCase;
  private readonly rateLimit: RateLimitPort;

  constructor(deps: BridgeDeps) {
    this.config = deps.config;
    this.clock = deps.clock;
    this.audit = deps.audit;
    this.auth = new OAuthAuthorizationUseCase(deps);
    this.token = new OAuthTokenUseCase(deps);
    this.rateLimit = deps.rateLimit ?? noopRateLimit;
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
      await this.guard(req, "register");
      const body = formObject(req.body);
      const redirectUris = stringArray(body.redirect_uris);
      const applicationType = formField(body, "application_type") as ApplicationType | undefined;
      // §17.2 machine-shape signals — parsed only so registerClient can REJECT them.
      const tokenEndpointAuthMethod = formField(body, "token_endpoint_auth_method");
      const grantTypes = stringArray(body.grant_types);
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
      const prepared: PreparedConsent = await this.auth.prepare({
        clientId: queryString(req.query, "client_id"),
        redirectUri: queryString(req.query, "redirect_uri"),
        responseType: queryString(req.query, "response_type"),
        codeChallenge: queryString(req.query, "code_challenge"),
        codeChallengeMethod: queryString(req.query, "code_challenge_method"),
        resource: queryString(req.query, "resource"),
        scope: queryString(req.query, "scope"),
        state: queryString(req.query, "state"),
        subject: identity.subject,
        allowedScopes: identity.allowedScopes,
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
    let result: IdentityResult;
    try {
      result = await identity.verify(input);
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
    try {
      await this.guard(req, "token");
      const body = formObject(req.body);
      const grantType = formField(body, "grant_type");
      const response = grantType === "refresh_token"
        ? await this.token.refresh({ grantType, refreshToken: formField(body, "refresh_token"), clientId: formField(body, "client_id") })
        : await this.token.exchangeAuthorizationCode({
          grantType, code: formField(body, "code"), redirectUri: formField(body, "redirect_uri"),
          clientId: formField(body, "client_id"), codeVerifier: formField(body, "code_verifier"),
        });
      return { status: 200, headers: { "cache-control": "no-store", "pragma": "no-cache" }, body: response };
    } catch (error) {
      return oauthErrorResponse(asOAuth(error));
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

  private async guard(req: NormRequest, prefix: string): Promise<void> {
    let allowed = true;
    try {
      allowed = await this.rateLimit.check(`${prefix}:${req.ip ?? "unknown"}`);
    } catch {
      allowed = true; // fail-open: a rate-limiter outage must not lock out auth
    }
    if (!allowed) throw new OAuthError("temporarily_unavailable", "Rate limit exceeded; retry later", 429);
  }
}

export function asOAuth(error: unknown): OAuthError {
  return error instanceof OAuthError ? error : new OAuthError("internal_error", "OAuth request failed", 500);
}

export function asDirectOAuth(error: unknown): OAuthError {
  const mapped = asOAuth(error);
  return new OAuthError(mapped.code, mapped.message, mapped.status);
}

function parseApproved(raw: unknown): boolean | undefined {
  return raw === false || raw === "false" ? false : true;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string" && v.length > 0) : [];
}

function consentCookie(req: NormRequest): string | undefined {
  const raw = headerString(req.headers, "cookie");
  if (!raw) return undefined;
  const found = raw.split(";").map((p) => p.trim()).find((p) => p.startsWith("mcp_idp_consent="));
  return found ? decodeURIComponent(found.slice("mcp_idp_consent=".length)) : undefined;
}
