// OAuthAuthorizationUseCase — the authorize + consent flow (contracts §9.3).
// Error channels follow RFC 6749 §4.1.2.1: pre-validation errors are direct 4xx
// (untrusted redirect destination); post-validation errors are tagged with a
// redirect target so the adapter can 302 them. Scope accumulation (RC item c)
// runs for stored-DCR OPAQUE clients only — every scheme-shaped (CIMD) client
// stands alone (§17.1.6 decision 3). CIMD resolution is one of the two named
// resolution boundaries (decision 2): it happens inside `prepare`'s
// pre-validation, and every failure maps to the anti-oracle generic there.
import { finiteClockSnapshot, fixedClockSnapshot, type ClockPort } from "./ports/clock.ts";
import type { AuditPort } from "./ports/audit.ts";
import type { StorePort } from "./ports/store.ts";
import type { AnyBridgeConfig as BridgeConfig } from "./config.ts";
import type { ConsentRequestClaims } from "./crypto.ts";
import { OAuthError, withRedirect } from "./errors.ts";
import { writeAuthorizeFailure, writeAuthorizeSuccess } from "./authorize-audit.ts";
import {
  expiresAtIso, generateAuthorizationCode, sha256Hex,
  signConsentToken, verifyConsentToken,
} from "./crypto.ts";
import { assertAllowedScopesCeiling, normalizeScopes } from "./scopes.ts";
import { buildErrorRedirect } from "./challenge.ts";
import type { CimdResolver } from "./cimd/resolve.ts";
import type { CimdRegistration } from "./cimd/registration.ts";
import { assertOAuthRedirectEntry } from "./redirect.ts";
import { expectedStoredDcrGrantGeneration, newGrantGeneration } from "./stored-dcr-generation.ts";
import {
  accumulationAllowed, assertApproveCimdGate, assertApproveOrigin, assertConsentResourceCurrent,
  authorizeBinding, cimdDisplay, dedupe, hostOf, initAuthorizeCatalog, redirectWithCode, requiredStr,
  accumulableScopes, resolveAuthorizeClient, resolveResource, type CimdConsentDisplay, type ResourceCatalog,
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
  private readonly catalog: ResourceCatalog;
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
    this.catalog = initAuthorizeCatalog(this.config, this.store);
  }

  async prepare(input: AuthorizeRequestInput): Promise<PreparedConsent> {
    let clientId: string | undefined; let resolvedResource: string | undefined; // §13: set on resolve
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
        const selected = resolveResource(this.catalog, input.resource);
        resolvedResource = selected.resource;
        if (input.codeChallengeMethod !== "S256") {
          throw new OAuthError("invalid_request", "PKCE code_challenge_method must be S256");
        }
        const codeChallenge = requiredStr(input.codeChallenge, "code_challenge");
        const requested = normalizeScopes(input.scope, selected.scopeCatalog, selected.defaultScopes);
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
          clientId, redirectUri, resource: selected.resource, scopes, codeChallenge, codeChallengeMethod: "S256",
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
        ? await this.store.findGrantedScopes(input.subject, clientId, new Date(this.clock.nowMs()).toISOString(), expectedStoredDcrGrantGeneration(this.config), authorizeBinding(this.catalog, claims.resource))
        : [];
      // Display-only, and must match what approve() accumulates.
      const priorScopes = accumulableScopes(this.catalog, claims.resource, rawPrior, claims.allowedScopes);
      const consentToken = await signConsentToken(claims, this.config, this.clock);
      await writeAuthorizeSuccess(this.audit, this.clock, AUDIT_PREPARE, { clientId, redirectUri, resource: claims.resource, scopes: claims.scopes, subject: input.subject });
      return {
        consentToken, ...claims, priorScopes,
        ...(resolved.registration ? { cimd: cimdDisplay(resolved.registration, redirectUri) } : {}),
      };
    } catch (error) {
      await writeAuthorizeFailure(this.audit, this.clock, AUDIT_PREPARE, error, clientId, input.redirectUri, undefined, resolvedResource);
      throw error;
    }
  }
  async approve(input: ApproveInput): Promise<ApproveResult> {
    let operationClock: ClockPort; let approvedResource: string | undefined; // §13: set on verify
    const maxFutureMs = Math.max(this.config.consentTokenTtlSeconds, this.config.authorizationCodeTtlSeconds) * 1000;
    try { operationClock = fixedClockSnapshot(finiteClockSnapshot(this.clock, maxFutureMs)); }
    catch { throw new OAuthError("invalid_consent", "Consent token is invalid or expired"); }
    try {
      assertApproveOrigin(this.config, input.origin);
      const token = requiredStr(input.consentToken, "consent_token");
      const consent = await verifyConsentToken(token, this.config, operationClock);
      approvedResource = consent.resource; // VERIFIED signed lineage: safe to audit (§13)
      // Scheme/claim gate runs before Deny, jti consume, or storage (§17.1.6 decision 3).
      assertApproveCimdGate(this.config, consent.clientId, consent.cimdVerified);
      assertOAuthRedirectEntry(consent.redirectUri); // §10.0 pre-upgrade token guard
      // Fail-closed (§9.3): only approved===true proceeds; else Deny WITHOUT consuming the JTI (fix #5).
      if (input.approved !== true) {
        const redirectTo = buildErrorRedirect(consent.redirectUri, "access_denied", consent.state);
        await writeAuthorizeFailure(this.audit, operationClock, AUDIT_APPROVE, new OAuthError("access_denied", "Consent was denied"), consent.clientId, undefined, consent.subject, consent.resource);
        return { redirectTo, state: consent.state };
      }

      // §9.7: re-resolve the signed resource against the CURRENT catalog before any
      // side effect. A removed resource is invalid_target; a scope no longer in that
      // resource's catalog is invalid_scope. Neither consumes the JTI nor saves a code.
      assertConsentResourceCurrent(this.catalog, consent.resource, consent.scopes);

      // Single-use consent JTI; replay is an integrity failure (direct).
      const consentExpiresAt = expiresAtIso(operationClock, this.config.consentTokenTtlSeconds);
      if (!(await this.store.consumeConsentJti(consent.jti, consentExpiresAt))) {
        throw new OAuthError("invalid_grant", "Consent token has already been used");
      }

      // Scope accumulation: stored-DCR OPAQUE clients only (§17.1.6 decision 3).
      const priorScopes = accumulationAllowed(this.config, consent.clientId)
        ? await this.store.findGrantedScopes(consent.subject, consent.clientId, new Date(operationClock.nowMs()).toISOString(), expectedStoredDcrGrantGeneration(this.config), authorizeBinding(this.catalog, consent.resource))
        : [];
      // Catalog-filter accumulated scopes, then re-intersect the VERIFIED
      // ceiling; prior grants cannot resurrect removed scopes (§17.4).
      const union = accumulableScopes(this.catalog, consent.resource, dedupe([...consent.scopes, ...priorScopes]));
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
        expiresAt: expiresAtIso(operationClock, this.config.authorizationCodeTtlSeconds),
        grantGeneration: newGrantGeneration(this.config),
      });
      await writeAuthorizeSuccess(this.audit, operationClock, AUDIT_APPROVE, { clientId: consent.clientId, redirectUri: consent.redirectUri, resource: consent.resource, scopes, subject: consent.subject });
      return { code, redirectTo: redirectWithCode(consent.redirectUri, code, this.config.issuer, consent.state), state: consent.state };
    } catch (error) {
      await writeAuthorizeFailure(this.audit, operationClock, AUDIT_APPROVE, error, undefined, undefined, undefined, approvedResource);
      throw error;
    }
  }
}
