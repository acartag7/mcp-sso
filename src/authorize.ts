// OAuthAuthorizationUseCase — the authorize + consent flow (contracts §9.3).
// Error channels follow RFC 6749 §4.1.2.1: pre-validation errors are direct 4xx
// (untrusted redirect destination); post-validation errors are tagged with a
// redirect target so the adapter can 302 them. Scope accumulation (RC item c)
// runs in stored-DCR mode only, deriving prior grants from active refresh tokens.

import type { ClockPort } from "./ports/clock.ts";
import type { AuditPort } from "./ports/audit.ts";
import type { StorePort } from "./ports/store.ts";
import type { BridgeConfig } from "./config.ts";
import { assertBridgeConfig, originOf } from "./config.ts";
import type { ConsentRequestClaims } from "./crypto.ts";
import { OAuthError, withRedirect } from "./errors.ts";
import {
  expiresAtIso, generateAuthorizationCode, sha256Hex,
  signConsentToken, verifyConsentToken,
} from "./crypto.ts";
import { assertAllowedScopesCeiling, normalizeScopes } from "./scopes.ts";
import { assertAllowedRedirectUri, assertRedirectAllowedForClient } from "./redirect.ts";
import { buildErrorRedirect } from "./challenge.ts";
import { ownBooleanTrue, snapshotOwnDataRecord } from "./own-property.ts";
import { parseFoundClientRegistration } from "./stored-records.ts";
import {
  dedupe, grantedScopes, hostOf, optionalStr, redirectWithCode, requiredStr,
} from "./authorize-internals.ts";

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
  /** Authorization ceiling from the resolved identity (contracts §17.4). When
   *  present, requested/default scopes are narrowed by intersection and the
   *  ceiling is embedded in the consent token for `approve` to re-intersect. */
  allowedScopes?: string[];
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
    const fields = snapshotOwnDataRecord(deps);
    if (fields === null || !fields.config || !fields.store || !fields.clock || !fields.audit) {
      throw new TypeError("Authorization dependencies must be own data properties");
    }
    this.config = assertBridgeConfig(fields.config);
    this.store = fields.store as StorePort;
    this.clock = fields.clock as ClockPort;
    this.audit = fields.audit as AuditPort;
  }

  async prepare(input: AuthorizeRequestInput): Promise<PreparedConsent> {
    let clientId: string | undefined;
    let redirectUri: string | undefined;
    let subject: string | undefined;
    try {
      const fields = snapshotOwnDataRecord(input);
      if (fields === null) throw new OAuthError("invalid_request", "Authorization request is malformed");
      // --- PRE-VALIDATION: direct errors, never redirect ---
      if (typeof fields.subject !== "string" || !fields.subject) throw new OAuthError("access_denied", "Authenticated subject is required", 401);
      subject = fields.subject;
      if (subject.startsWith("mcc_")) throw new OAuthError("access_denied", "Subject uses the reserved machine-client namespace", 401); // RFC 9700 §4.15.1: sub-prefix classification stays sound
      // §17.4: fail closed on a malformed ceiling here too — prepare is exported,
      // so a direct caller bypassing Bridge.resolveIdentity is still guarded.
      const ceiling = assertAllowedScopesCeiling(fields.allowedScopes as string[] | undefined);
      clientId = requiredStr(fields.clientId as string | undefined, "client_id");
      redirectUri = await this.resolveRedirect(fields.redirectUri as string | undefined, clientId);
      const state = optionalStr(fields.state, "state");

      // --- POST-VALIDATION: redirect-tagged errors ---
      let claims: ConsentRequestClaims;
      try {
        if (fields.responseType !== "code") {
          throw new OAuthError("unsupported_response_type", "Only response_type=code is supported");
        }
        const resource = fields.resource === undefined
          ? this.config.resource : requiredStr(fields.resource as string | undefined, "resource");
        if (resource !== this.config.resource) throw new OAuthError("invalid_target", "Unknown OAuth resource");
        if (fields.codeChallengeMethod !== "S256") {
          throw new OAuthError("invalid_request", "PKCE code_challenge_method must be S256");
        }
        const codeChallenge = requiredStr(fields.codeChallenge as string | undefined, "code_challenge");
        const requested = normalizeScopes(optionalStr(fields.scope, "scope"), this.config.scopeCatalog, this.config.defaultScopes);
        // §17.4: a present ceiling (any array, incl. []) narrows requested/default
        // scopes by intersection (defaultScopes already folded into `requested`).
        const scopes = ceiling ? requested.filter((s) => ceiling.includes(s)) : requested;
        // Empty intersection ⇒ access_denied on the redirect channel — ONLY when a
        // ceiling is present (without one, an empty requested set is unchanged v0.1
        // behavior, e.g. scopeless authorize with empty defaultScopes).
        if (ceiling && scopes.length === 0) {
          throw new OAuthError("access_denied", "No requested scopes are within the authorized ceiling");
        }
        claims = { clientId, redirectUri, resource, scopes, codeChallenge, codeChallengeMethod: "S256", state, subject, allowedScopes: ceiling };
      } catch (error) {
        if (error instanceof OAuthError && !error.redirect) throw withRedirect(error, redirectUri, state);
        throw error;
      }

      const rawPrior = this.config.dcr.mode === "stored"
        ? await this.store.findGrantedScopes(subject, clientId, new Date(this.clock.nowMs()).toISOString())
        : [];
      const safePrior = grantedScopes(rawPrior, this.config.scopeCatalog);
      // Display-only: ceiling-strip prior grants so they aren't tagged "already granted".
      const priorScopes = claims.allowedScopes ? safePrior.filter((s) => claims.allowedScopes!.includes(s)) : safePrior;
      const consentToken = await signConsentToken(claims, this.config, this.clock);
      await this.auditSuccess(AUDIT_PREPARE, { clientId, redirectUri, resource: claims.resource, scopes: claims.scopes, subject });
      return { consentToken, ...claims, priorScopes };
    } catch (error) {
      await this.auditFailure(AUDIT_PREPARE, error, clientId, redirectUri, subject);
      throw error;
    }
  }

  async approve(input: ApproveInput): Promise<ApproveResult> {
    try {
      const fields = snapshotOwnDataRecord(input);
      if (fields === null) throw new OAuthError("invalid_request", "Consent input is malformed");
      this.assertOrigin(optionalStr(fields.origin, "origin"));
      const token = requiredStr(fields.consentToken as string | undefined, "consent_token");
      const consent = await verifyConsentToken(token, this.config, this.clock);

      // Fail-closed (§9.3): only approved===true proceeds; else Deny WITHOUT consuming the JTI (fix #5).
      if (!ownBooleanTrue(fields, "approved")) {
        const redirectTo = buildErrorRedirect(consent.redirectUri, "access_denied", consent.state);
        await this.auditFailure(AUDIT_APPROVE, new OAuthError("access_denied", "Consent was denied"), consent.clientId, undefined, consent.subject);
        return { redirectTo, state: consent.state };
      }

      // Single-use consent JTI; replay is an integrity failure (direct).
      const consentExpiresAt = expiresAtIso(this.clock, this.config.consentTokenTtlSeconds);
      if ((await this.store.consumeConsentJti(consent.jti, consentExpiresAt)) !== true) {
        throw new OAuthError("invalid_grant", "Consent token has already been used");
      }

      // Scope accumulation: stored mode unions requested + active grants (RC c).
      const priorScopes = this.config.dcr.mode === "stored"
        ? await this.store.findGrantedScopes(consent.subject, consent.clientId, new Date(this.clock.nowMs()).toISOString())
        : [];
      const union = dedupe([...consent.scopes, ...grantedScopes(priorScopes, this.config.scopeCatalog)]);
      // §17.4: re-intersect the union against the ceiling from the VERIFIED
      // consent token — prior grants can't resurrect a removed-group scope.
      const scopes = consent.allowedScopes ? union.filter((s) => consent.allowedScopes!.includes(s)) : union;

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
      const parsed = parseFoundClientRegistration(client, clientId);
      if (parsed === null) throw new OAuthError("invalid_client", "Stored client record is malformed", 401);
      return assertRedirectAllowedForClient(raw, parsed);
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
