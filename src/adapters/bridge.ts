// Bridge — framework-free wiring of the core use-cases to normalized HTTP
// requests/responses (contracts §9.6). Each fastify/express/hono adapter is a
// thin mapper around this; all OAuth logic stays in the core. The adapter resolves
// the subject (via its IdentityPort) before calling handleAuthorize.

import type { BridgeConfig } from "../config.ts";
import type { ClockPort } from "../ports/clock.ts";
import type { AuditPort } from "../ports/audit.ts";
import type { StorePort } from "../ports/store.ts";
import type { RateLimitPort } from "../ports/rate-limit.ts";
import { noopRateLimit } from "../ports/rate-limit.ts";
import type { ApplicationType } from "../ports/client-store.ts";
import { OAuthAuthorizationUseCase, type PreparedConsent } from "../authorize.ts";
import { OAuthTokenUseCase } from "../token.ts";
import { registerClient } from "../register.ts";
import { authorizationServerMetadata, jwks, protectedResourceMetadata } from "../metadata.ts";
import { OAuthError } from "../errors.ts";
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
      const registered = await registerClient({ config: this.config, clock: this.clock, audit: this.audit }, { redirectUris, applicationType });
      return { status: 201, headers: { "cache-control": "no-store" }, body: registered };
    } catch (error) {
      return oauthErrorResponse(asOAuth(error));
    }
  }

  /** GET /oauth/authorize. `subject` is resolved by the adapter via its IdentityPort. */
  async handleAuthorize(req: NormRequest, subject: string): Promise<NormResponse> {
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
        subject,
      });
      return { status: 200, headers: { ...CONSENT_HEADERS }, body: renderConsentPage(this.config, prepared) };
    } catch (error) {
      return oauthErrorResponse(asOAuth(error));
    }
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
