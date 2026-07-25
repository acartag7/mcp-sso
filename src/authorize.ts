// OAuthAuthorizationUseCase — the authorize + consent flow (contracts §9.3).
// Error channels follow RFC 6749 §4.1.2.1: pre-validation errors are direct 4xx
// (untrusted redirect destination); post-validation errors are tagged with a
// redirect target so the adapter can 302 them. Scope accumulation (RC item c)
// runs for stored-DCR OPAQUE clients only — every scheme-shaped (CIMD) client
// stands alone (§17.1.6 decision 3). CIMD resolution is one of the two named
// resolution boundaries (decision 2): it happens inside `prepare`'s
// pre-validation, and every failure maps to the anti-oracle generic there.

import type { ClockPort } from "./ports/clock.ts";
import type { AuditPort } from "./ports/audit.ts";
import type { StorePort } from "./ports/store.ts";
import type { BridgeConfig } from "./config.ts";
import type { ConsentRequestClaims } from "./crypto.ts";
import { OAuthError, withRedirect } from "./errors.ts";
import { writeAuthorizeFailure, writeAuthorizeSuccess, type AuthorizeAuditEvent, type AuthorizeAuditSuccess } from "./authorize-audit.ts";
import {
  expiresAtIso, generateAuthorizationCode, sha256Hex,
  signConsentToken, verifyConsentToken,
} from "./crypto.ts";
import { assertAllowedScopesCeiling, normalizeScopes } from "./scopes.ts";
import { buildErrorRedirect } from "./challenge.ts";
import type { CimdResolver } from "./cimd/resolve.ts";
import type { CimdRegistration } from "./cimd/registration.ts";
import {
  accumulationAllowed, assertApproveCimdGate, assertApproveOrigin, cimdDisplay, dedupe, hostOf,
  redirectWithCode, requiredStr, resolveAuthorizeClient,
  type CimdConsentDisplay,
} from "./authorize-internals.ts";

export interface OAuthAuthorizationDeps {
  config: BridgeConfig;
  store: StorePort;
  clock: ClockPort;
  audit: AuditPort;
  /** The shared CIMD resolution service (§17.1.6 decision 1a/4) — the Bridge
   *  constructs one per instance so direct and upstream share ONE cache. */
  cimd?: CimdResolver;
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
  /** A CIMD registration already validated THIS flow and carried forward under
   *  the flow cookie's signature (§17.1.6 decision 1c). Orchestrator-resolved
   *  TRUSTED state, the same category as `subject`/`allowedScopes`: ONLY
   *  `createUpstreamRedirectFlow` (after its row-5a gate) may set it, and
   *  adapters MUST NEVER bind it to any client-controlled request field. When
   *  present `prepare` uses it and does NOT re-fetch. */
  registration?: CimdRegistration;
  /** Client IP for the `cimd:<ip>` pre-resolution rate-limit key. */
  ip?: string;
}

export interface PreparedConsent extends ConsentRequestClaims {
  consentToken: string;
  /** Already-granted scopes for (subject, clientId); [] in stateless mode AND
   *  for every scheme-shaped client_id (§17.1.6 decision 3).
   *  The consent UI renders scopes not in this set as "new". */
  priorScopes: string[];
  /** Display-only CIMD fields (§17.1.4); absent for non-CIMD flows. */
  cimd?: CimdConsentDisplay;
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
  private readonly cimd?: CimdResolver;

  constructor(deps: OAuthAuthorizationDeps) {
    this.config = deps.config;
    this.store = deps.store;
    this.clock = deps.clock;
    this.audit = deps.audit;
    this.cimd = deps.cimd;
  }

  async prepare(input: AuthorizeRequestInput): Promise<PreparedConsent> {
    let clientId: string | undefined;
    let redirectUri: string | undefined;
    try {
      // --- PRE-VALIDATION: direct errors, never redirect ---
      if (!input.subject) throw new OAuthError("access_denied", "Authenticated subject is required", 401);
      if (input.subject.startsWith("mcc_")) throw new OAuthError("access_denied", "Subject uses the reserved machine-client namespace", 401); // RFC 9700 §4.15.1: sub-prefix classification stays sound
      // §17.4: fail closed on a malformed ceiling here too — prepare is exported,
      // so a direct caller bypassing Bridge.resolveIdentity is still guarded.
      const ceiling = assertAllowedScopesCeiling(input.allowedScopes);
      clientId = requiredStr(input.clientId, "client_id");
      // §17.1.6 decision 1a: shape-first dispatch. For a CIMD id this REPLACES
      // the §10 check entirely (no store.find miss); every other scheme-shaped
      // value is a direct invalid_client.
      const resolved = await resolveAuthorizeClient({
        config: this.config, cimd: this.cimd, clientId,
        redirectUri: requiredStr(input.redirectUri, "redirect_uri"),
        registration: input.registration, ip: input.ip,
      });
      redirectUri = resolved.redirectUri;
      // Audit the RESOLUTION as soon as it succeeds: deferring past the checks
      // below hid a fetched+cached document whenever an unrelated OAuth check
      // (response_type/resource/scope/PKCE) then threw. The upstream leg keeps
      // its own deferral (upstream-flow.ts:136) — decision 1b ties ITS success
      // to the cookie-oversize guard, which does not exist on this path.
      await resolved.emitCimdSuccess();
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
        const requested = normalizeScopes(input.scope, this.config.scopeCatalog, this.config.defaultScopes);
        // §17.4: a present ceiling (any array, incl. []) narrows requested/default
        // scopes by intersection (defaultScopes already folded into `requested`).
        const scopes = ceiling ? requested.filter((s) => ceiling.includes(s)) : requested;
        // Empty intersection ⇒ access_denied on the redirect channel — ONLY when a
        // ceiling is present (without one, an empty requested set is unchanged v0.1
        // behavior, e.g. scopeless authorize with empty defaultScopes).
        if (ceiling && scopes.length === 0) {
          throw new OAuthError("access_denied", "No requested scopes are within the authorized ceiling");
        }
        claims = {
          clientId, redirectUri, resource, scopes, codeChallenge, codeChallengeMethod: "S256",
          state, subject: input.subject, allowedScopes: ceiling,
          // Provenance for THIS flow only (decision 3): a genuinely-validated
          // CIMD registration — its own fetch/cache hit, or the carried one.
          ...(resolved.registration ? { cimdVerified: true as const } : {}),
        };
      } catch (error) {
        if (error instanceof OAuthError && !error.redirect) throw withRedirect(error, redirectUri, state);
        throw error;
      }

      // §17.1.6 decision 3 (NEGATIVE class): accumulate iff stored-DCR AND NOT
      // scheme-shaped. Never keyed on cimd_verified.
      const rawPrior = accumulationAllowed(this.config, clientId)
        ? await this.store.findGrantedScopes(input.subject, clientId, new Date(this.clock.nowMs()).toISOString())
        : [];
      // Display-only: ceiling-strip prior grants so they aren't tagged "already granted".
      const priorScopes = claims.allowedScopes ? rawPrior.filter((s) => claims.allowedScopes!.includes(s)) : rawPrior;
      const consentToken = await signConsentToken(claims, this.config, this.clock);
      await this.auditSuccess(AUDIT_PREPARE, { clientId, redirectUri, resource: claims.resource, scopes: claims.scopes, subject: input.subject });
      return {
        consentToken, ...claims, priorScopes,
        ...(resolved.registration ? { cimd: cimdDisplay(resolved.registration, redirectUri) } : {}),
      };
    } catch (error) {
      await this.auditFailure(AUDIT_PREPARE, error, clientId, input.redirectUri);
      throw error;
    }
  }

  async approve(input: ApproveInput): Promise<ApproveResult> {
    try {
      assertApproveOrigin(this.config, input.origin);
      const token = requiredStr(input.consentToken, "consent_token");
      const consent = await verifyConsentToken(token, this.config, this.clock);
      // §17.1.6 decision 3: the scheme/claim gate runs FIRST — before the Deny
      // branch (which would 302 to the token's redirectUri), before any jti
      // consume or code storage. A legacy URL-shaped token cannot be redeemed.
      assertApproveCimdGate(this.config, consent.clientId, consent.cimdVerified);

      // Fail-closed (§9.3): only approved===true proceeds; else Deny WITHOUT consuming the JTI (fix #5).
      if (input.approved !== true) {
        const redirectTo = buildErrorRedirect(consent.redirectUri, "access_denied", consent.state);
        await this.auditFailure(AUDIT_APPROVE, new OAuthError("access_denied", "Consent was denied"), consent.clientId, undefined, consent.subject);
        return { redirectTo, state: consent.state };
      }

      // Single-use consent JTI; replay is an integrity failure (direct).
      const consentExpiresAt = expiresAtIso(this.clock, this.config.consentTokenTtlSeconds);
      if (!(await this.store.consumeConsentJti(consent.jti, consentExpiresAt))) {
        throw new OAuthError("invalid_grant", "Consent token has already been used");
      }

      // Scope accumulation: stored-DCR OPAQUE clients only (§17.1.6 decision 3).
      const priorScopes = accumulationAllowed(this.config, consent.clientId)
        ? await this.store.findGrantedScopes(consent.subject, consent.clientId, new Date(this.clock.nowMs()).toISOString())
        : [];
      const union = dedupe([...consent.scopes, ...priorScopes]);
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

  private auditSuccess(event: AuthorizeAuditEvent, r: AuthorizeAuditSuccess): Promise<void> {
    return writeAuthorizeSuccess(this.audit, this.clock, event, r);
  }

  private auditFailure(event: AuthorizeAuditEvent, error: unknown, clientId?: string, redirectUri?: string, subject?: string): Promise<void> {
    return writeAuthorizeFailure(this.audit, this.clock, event, error, clientId, redirectUri, subject);
  }
}
