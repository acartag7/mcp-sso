// createGoogleIdentity (contracts §17.6 Google preset) — the generic OIDC port
// pinned to https://accounts.google.com + discovery, with Google-specific claim
// shaping: strict iss (only the https scheme — the generic exact-match already
// rejects the schemeless legacy `accounts.google.com` variant); optional
// hostedDomain validated against the **`hd` claim** (NEVER the email domain);
// email surfaced only when `email_verified === true`. Subject = `sub` (Google's
// stable id — don't key on email). clientSecret is REQUIRED (Google's token auth
// methods are secret-based; its docs' newer "Optional" marking is unverified —
// treated as required).
//
// Reuses the generic port wholesale (`createGenericOidcIdentity` + the shared
// `verifyIdTokenWithKey` seam + `wrapRedirectIdentity`); only the claim validator
// differs — `validateGoogleIdToken` layers `hd`/`email_verified` on top of the
// generic iss/aud/iat/exp/nonce/at_hash/sub/allowlist checks. No claim-logic
// duplication. The shared `jwtErrorReason` returns `generic_oidc_*` for Google
// too, so the redirect outcome mapping (`generic_oidc_verify_failed` ⇒
// exchange_failed) is uniform; Google-only reasons come from the hd/email checks
// and are correctly `identity_rejected`.
//
// --- Manual checklist: live Google sign-in (run before claiming Google works
//   end-to-end; sibling of generic-oidc.ts) ---
//   1. Google Cloud Console → APIs & Services → Credentials → Create Credentials
//      → OAuth client ID (Web application): Authorized redirect URIs = the
//      bridge's OIDC callback URL; note the Client ID + Client secret. Configure
//      the OAuth consent screen (scopes openid/profile/email; restrict to your
//      Workspace org if applicable).
//   2. GET /oauth/authorize 302s to https://accounts.google.com/o/oauth2/v2/auth.
//   3. After Google sign-in the callback validates + exchanges + verifies the
//      id_token (iss = https://accounts.google.com, aud = clientId, NO multi-
//      audience, iat+exp, nonce, at_hash when present); subject = the stable
//      numeric `sub` (NOT the email).
//   4. (hostedDomain) A user outside the configured Workspace (hd mismatch) is
//      rejected (google_bad_hosted_domain); a personal Google account (no hd)
//      when hostedDomain is set → google_missing_hosted_domain.
//   5. Approve → the bridge mints its OWN token; the Google access/refresh
//      tokens are discarded (never stored/logged/audited/forwarded).

import type { IdentityResult, RedirectIdentityPort } from "../ports/identity.ts";
import { assertHttpsRaw } from "./util.ts";
import {
  validateGenericOidcIdToken,
  type GenericOidcIdTokenPayload, type GenericOidcValidateOpts, type GenericOidcClaimConfig,
} from "./generic-oidc-claims.ts";
import {
  createGenericOidcIdentity, verifyIdTokenWithKey, resolveAllowedAlgs,
  type GenericOidcConfig, type GenericOidcIdentity, type GenericOidcVerifyOpts, type GenericOidcVerifyKey,
} from "./generic-oidc.ts";
import type { DiscoveryTransport, GenericOidcTokenTransport } from "./generic-oidc-discovery.ts";
import { wrapRedirectIdentity } from "./generic-oidc-redirect.ts";

export const GOOGLE_ISSUER = "https://accounts.google.com";

export interface GoogleConfig {
  clientId: string;
  /** REQUIRED — Google's token auth methods are secret-based. */
  clientSecret: string;
  redirectUri: string;
  /** Optional Google Workspace restriction — validated against the `hd` claim
   *  (never the email domain). */
  hostedDomain?: string;
  /** Optional defense-in-depth allowlist (matches `sub`; case-insensitive). */
  subjectAllowlist?: string[];
  /** Opt-in: also match a VERIFIED email against `subjectAllowlist`. */
  allowEmailAllowlist?: boolean;
  /** Upstream scopes; default "openid profile email". */
  scopes?: string;
}

/** Google id_token payload (adds the Workspace `hd` claim). */
export type GoogleIdTokenPayload = GenericOidcIdTokenPayload & { hd?: string };

/** Google claim validation: the generic checks PLUS the `hd` hosted-domain check
 *  and `email_verified` display gating. Pure — unit-testable without the JWKS. */
export function validateGoogleIdToken(
  payload: GoogleIdTokenPayload,
  config: GoogleConfig,
  opts?: GenericOidcValidateOpts,
): IdentityResult {
  const genericConfig: GenericOidcClaimConfig = {
    issuer: GOOGLE_ISSUER,
    clientId: config.clientId,
    subjectAllowlist: config.subjectAllowlist,
    allowEmailAllowlist: config.allowEmailAllowlist,
  };
  const result = validateGenericOidcIdToken(payload, genericConfig, opts);
  if (!result.ok) return result;
  // Google's `sub` is a stable, globally-unique numeric id — return it raw (the Google contract
  // says subject = sub). The generic validator namespaces opaque subs as `${issuer}|${sub}` to
  // defend cross-issuer collisions; Google's sub needs no namespace, so unwrap it (the generic
  // validator already confirmed payload.sub is a non-empty string).
  if (typeof payload.sub !== "string") return { ok: false, reason: "generic_oidc_no_subject" };
  let identity = { ...result.identity, subject: payload.sub };
  // hostedDomain configured ⇒ the Workspace gate is ON. A defined-but-blank value
  // is a misconfig (e.g. an empty env var) that must NOT silently disable the gate.
  if (config.hostedDomain !== undefined) {
    const expected = config.hostedDomain.trim().toLowerCase();
    if (!expected) return { ok: false, reason: "google_bad_hosted_domain" };
    const actual = typeof payload.hd === "string" ? payload.hd.trim().toLowerCase() : null;
    if (actual !== expected) {
      return { ok: false, reason: typeof payload.hd === "string" ? "google_bad_hosted_domain" : "google_missing_hosted_domain" };
    }
  }
  // email surfaced only when email_verified === true (strict).
  if (payload.email_verified !== true && identity.claims && "email" in identity.claims) {
    const claims = { ...identity.claims };
    delete claims.email;
    identity = { ...identity, claims };
  }
  return { ok: true, identity };
}

/** Verify a Google id_token against an explicit key (testable with a known key, no JWKS). */
export async function verifyGoogleIdToken(
  token: string,
  key: GenericOidcVerifyKey,
  config: GoogleConfig,
  opts?: Omit<GenericOidcVerifyOpts, "verifyKey">,
): Promise<IdentityResult> {
  return verifyIdTokenWithKey(token, key, {
    allowedAlgs: opts?.allowedAlgs ?? resolveAllowedAlgs(undefined),
    validate: (p, o) => validateGoogleIdToken(p as GoogleIdTokenPayload, config, o),
    expectedNonce: opts?.expectedNonce,
    accessToken: opts?.accessToken,
    currentDate: opts?.currentDate,
  });
}

/** Build the Google identity (the generic port pinned to accounts.google.com).
 *  clientSecret is required; discovery is fetched at boot against GOOGLE_ISSUER. */
export async function createGoogleIdentity(config: GoogleConfig, opts?: { discoveryFetch?: DiscoveryTransport }): Promise<GenericOidcIdentity> {
  if (typeof config.clientSecret !== "string" || !config.clientSecret) {
    throw new Error("google_client_secret_required: Google requires a client secret (its token auth methods are secret-based; the docs' newer 'Optional' marking is unverified — treated as required)");
  }
  if (config.hostedDomain !== undefined && !config.hostedDomain.trim()) {
    throw new Error("google_bad_config: hostedDomain must be a non-empty string (a blank value would silently disable the Workspace gate)");
  }
  assertHttpsRaw(GOOGLE_ISSUER, "google issuer");
  const genericConfig: GenericOidcConfig = {
    issuer: GOOGLE_ISSUER,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    redirectUri: config.redirectUri,
    endpoints: "discover",
    scopes: config.scopes,
    subjectAllowlist: config.subjectAllowlist,
    allowEmailAllowlist: config.allowEmailAllowlist,
  };
  return createGenericOidcIdentity(genericConfig, {
    discoveryFetch: opts?.discoveryFetch,
    validate: (p, o) => validateGoogleIdToken(p as GoogleIdTokenPayload, config, o),
  });
}

export interface GoogleRedirectOpts {
  discoveryFetch?: DiscoveryTransport;
  transport?: GenericOidcTokenTransport;
  verifyKey?: GenericOidcVerifyOpts["verifyKey"];
  currentDate?: Date;
}

/** Build a Google `RedirectIdentityPort` (async: discovery at boot). */
export async function createGoogleRedirectIdentity(config: GoogleConfig, opts?: GoogleRedirectOpts): Promise<RedirectIdentityPort> {
  const base = await createGoogleIdentity(config, { discoveryFetch: opts?.discoveryFetch });
  return wrapRedirectIdentity(base, { transport: opts?.transport, verifyKey: opts?.verifyKey, currentDate: opts?.currentDate });
}
