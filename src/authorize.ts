// OAuthAuthorizationUseCase — the authorize + consent flow (contracts §9.3).
// Error channels follow RFC 6749 §4.1.2.1: pre-validation errors are direct 4xx
// (untrusted redirect destination); post-validation errors are tagged with a
// redirect target so the adapter can 302 them. Scope accumulation (RC item c)
// runs in stored-DCR mode only, deriving prior grants from active refresh tokens.

import type { ClockPort } from "./ports/clock.ts";
import type { AuditPort } from "./ports/audit.ts";
import type { StorePort } from "./ports/store.ts";
import type { BridgeConfig } from "./config.ts";
import { originOf } from "./config.ts";
import type { ConsentRequestClaims } from "./crypto.ts";
import { OAuthError, withRedirect } from "./errors.ts";
import {
  expiresAtIso, generateAuthorizationCode, sha256Hex,
  signConsentToken, verifyConsentToken,
} from "./crypto.ts";
import { normalizeScopes } from "./scopes.ts";
import {
  assertAllowedRedirectUri, assertRedirectAllowedForClient,
} from "./redirect.ts";
import { buildErrorRedirect } from "./challenge.ts";

export interface OAuthAuthorizationDeps {
  config: BridgeConfig;
  store: StorePort;
  clock: ClockPort;
  audit: AuditPort;
}

export interface AuthorizeRequestInput {
  clientId?: string;
  redirectUri?: string;
  responseType?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  resource?: string;
  scope?: string;
  state?: string;
  /** Verified subject (resolved by the IdentityPort before prepare). REQUIRED. */
  subject?: string;
}

export interface PreparedConsent extends ConsentRequestClaims {
  consentToken: string;
  /** Already-granted scopes for (subject, clientId); [] in stateless mode.
   *  The consent UI renders scopes not in this set as "new". */
  priorScopes: string[];
}

export interface ApproveInput {
  consentToken?: string;
  approved?: boolean;
  /** Required Origin for the CSRF check. */
  origin?: string;
}

export interface ApproveResult {
  redirectTo: string;
  code?: string;
  state?: string;
}

const AUDIT_PREPARE = "oauth.authorize.prepare";
const AUDIT_APPROVE = "oauth.authorize.approve";

export class OAuthAuthorizationUseCase {
  private readonly config: BridgeConfig;
  private readonly store: StorePort;
  private readonly clock: ClockPort;
  private readonly audit: AuditPort;

  constructor(deps: OAuthAuthorizationDeps) {
    this.config = deps.config;
    this.store = deps.store;
    this.clock = deps.clock;
    this.audit = deps.audit;
  }

  async prepare(input: AuthorizeRequestInput): Promise<PreparedConsent> {
    let clientId: string | undefined;
    let redirectUri: string | undefined;
    try {
      // --- PRE-VALIDATION: direct errors, never redirect ---
      if (!input.subject) throw new OAuthError("access_denied", "Authenticated subject is required", 401);
      clientId = requiredStr(input.clientId, "client_id");
      redirectUri = await this.resolveRedirect(input.redirectUri, clientId);
      const state = input.state;

      // --- POST-VALIDATION: redirect-tagged errors ---
      let claims: ConsentRequestClaims;
      try {
        if (input.responseType !== "code") {
          throw new OAuthError("unsupported_response_type", "Only response_type=code is supported");
        }
        const resource = input.resource || this.config.resource;
        if (resource !== this.config.resource) throw new OAuthError("invalid_target", "Unknown OAuth resource");
        if (input.codeChallengeMethod !== "S256") {
          throw new OAuthError("invalid_request", "PKCE code_challenge_method must be S256");
        }
        const codeChallenge = requiredStr(input.codeChallenge, "code_challenge");
        const scopes = normalizeScopes(input.scope, this.config.scopeCatalog, this.config.defaultScopes);
        claims = { clientId, redirectUri, resource, scopes, codeChallenge, codeChallengeMethod: "S256", state, subject: input.subject };
      } catch (error) {
        if (error instanceof OAuthError && !error.redirect) throw withRedirect(error, redirectUri, state);
        throw error;
      }

      const priorScopes = this.config.dcr.mode === "stored"
        ? await this.store.findGrantedScopes(input.subject, clientId, new Date(this.clock.nowMs()).toISOString())
        : [];
      const consentToken = await signConsentToken(claims, this.config, this.clock);
      await this.auditSuccess(AUDIT_PREPARE, { clientId, redirectUri, resource: claims.resource, scopes: claims.scopes, subject: input.subject });
      return { consentToken, ...claims, priorScopes };
    } catch (error) {
      await this.auditFailure(AUDIT_PREPARE, error, clientId, input.redirectUri);
      throw error;
    }
  }

  async approve(input: ApproveInput): Promise<ApproveResult> {
    try {
      this.assertOrigin(input.origin);
      const token = requiredStr(input.consentToken, "consent_token");
      const consent = await verifyConsentToken(token, this.config, this.clock);

      // Deny: redirect access_denied WITHOUT consuming the JTI (fix #5).
      if (input.approved === false) {
        const redirectTo = buildErrorRedirect(consent.redirectUri, "access_denied", consent.state);
        await this.auditFailure(AUDIT_APPROVE, new OAuthError("access_denied", "Consent was denied"), consent.clientId, undefined, consent.subject);
        return { redirectTo, state: consent.state };
      }

      // Single-use consent JTI; replay is an integrity failure (direct).
      const consentExpiresAt = expiresAtIso(this.clock, this.config.consentTokenTtlSeconds);
      if (!(await this.store.consumeConsentJti(consent.jti, consentExpiresAt))) {
        throw new OAuthError("invalid_grant", "Consent token has already been used");
      }

      // Scope accumulation: stored mode unions requested + active grants (RC c).
      const priorScopes = this.config.dcr.mode === "stored"
        ? await this.store.findGrantedScopes(consent.subject, consent.clientId, new Date(this.clock.nowMs()).toISOString())
        : [];
      const scopes = dedupe([...consent.scopes, ...priorScopes]);

      const code = generateAuthorizationCode();
      await this.store.saveAuthCode({
        codeHash: sha256Hex(code),
        clientId: consent.clientId,
        subject: consent.subject,
        redirectUri: consent.redirectUri,
        resource: consent.resource,
        scopes,
        codeChallenge: consent.codeChallenge,
        codeChallengeMethod: "S256",
        expiresAt: expiresAtIso(this.clock, this.config.authorizationCodeTtlSeconds),
      });
      await this.auditSuccess(AUDIT_APPROVE, { clientId: consent.clientId, redirectUri: consent.redirectUri, resource: consent.resource, scopes, subject: consent.subject });
      return { code, redirectTo: redirectWithCode(consent.redirectUri, code, this.config.issuer, consent.state), state: consent.state };
    } catch (error) {
      await this.auditFailure(AUDIT_APPROVE, error);
      throw error;
    }
  }

  /** Pre-validation redirect resolution. Stored mode: per-client policy (RC b);
   *  stateless: the global allowlist. Both throw direct (untrusted destination). */
  private async resolveRedirect(value: string | undefined, clientId: string): Promise<string> {
    const raw = requiredStr(value, "redirect_uri");
    if (this.config.dcr.mode === "stored") {
      const client = await this.config.dcr.store.find(clientId);
      if (!client) throw new OAuthError("invalid_client", "Unknown client_id", 401);
      return assertRedirectAllowedForClient(raw, client);
    }
    return assertAllowedRedirectUri(raw, this.config.redirectAllowlist);
  }

  private assertOrigin(origin: string | undefined): void {
    const issuerOrigin = originOf(this.config.issuer);
    if (!origin || (!this.config.allowedOrigins.includes(origin) && origin !== issuerOrigin)) {
      throw new OAuthError("invalid_origin", "Origin not allowed", 403);
    }
  }

  private async auditSuccess(event: typeof AUDIT_PREPARE | typeof AUDIT_APPROVE, r: { clientId: string; redirectUri: string; resource: string; scopes: string[]; subject: string; }): Promise<void> {
    await this.audit.writeAuthEvent({
      occurredAt: new Date(this.clock.nowMs()).toISOString(), event, status: "success",
      clientId: r.clientId, subject: r.subject, resource: r.resource, scopes: r.scopes, redirectHost: hostOf(r.redirectUri),
    });
  }

  private async auditFailure(event: typeof AUDIT_PREPARE | typeof AUDIT_APPROVE, error: unknown, clientId?: string, redirectUri?: string, subject?: string): Promise<void> {
    await this.audit.writeAuthEvent({
      occurredAt: new Date(this.clock.nowMs()).toISOString(), event, status: "failure",
      clientId, subject, redirectHost: redirectUri ? hostOf(redirectUri) : undefined,
      reason: error instanceof OAuthError ? error.code : "internal_error",
    });
  }
}

function redirectWithCode(redirectUri: string, code: string, issuer: string, state?: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set("code", code);
  url.searchParams.set("iss", issuer); // RFC 9207 (RC item a)
  if (state) url.searchParams.set("state", state);
  url.hash = "";
  return url.href;
}

function hostOf(value: string): string | undefined {
  try {
    const u = new URL(value);
    return `${u.protocol}//${u.host}`;
  } catch {
    return undefined;
  }
}

function dedupe(values: string[]): string[] {
  const out: string[] = [];
  for (const v of values) if (!out.includes(v)) out.push(v);
  return out;
}

function requiredStr(value: string | undefined, label: string): string {
  if (typeof value === "string" && value) return value;
  throw new OAuthError("invalid_request", `${label} is required`);
}
