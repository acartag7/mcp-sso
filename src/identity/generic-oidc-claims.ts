// Pure claim-validation core for the §17.6 generic OIDC + Google ports. NO jose
// runtime here (types only) and NO network — every function is unit-testable in
// isolation (addendum 12). The signature check is jose's job, done by the
// verifying wrapper `verifyIdTokenWithKey` in generic-oidc.ts; this module
// operates on an ALREADY-signature-verified payload.
//
// ⚠️ Addendum 12 / threat-model row 12: `validateGenericOidcIdToken` is
// claim-validation ONLY — it never checks the signature and only requires
// `exp`/`iat` presence (their VALUES are checked by jose). A custom IdentityPort
// MUST route raw id_tokens through `verifyGenericOidcIdToken` /
// `createGenericOidcIdentity().verify`, NEVER this pure validator alone.
//
// Security posture (contracts §17.6): `iss` exact-match; `aud` must contain
// `clientId` with multi-audience tokens rejected (the check lives HERE, not in
// jose's `audience` option, which accepts multi-audience tokens); `exp` AND
// `iat` presence required (OIDC Core §2); nonce mandatory when an expected value
// is set; `at_hash` validated when present in the code flow; subject = `sub`
// (never email). Email is a display attribute; `allowEmailAllowlist` matches a
// verified email only when `email_verified === true` (strict).

import { createHash } from "node:crypto";
import type { JWTPayload } from "jose";
import type { IdentityClaims } from "../ports/identity.ts";

/** An id_token's decoded payload. `nonce`/`at_hash`/`exp`/`iat`/`iss`/`aud`/`sub`
 *  come from `JWTPayload`; `email`/`email_verified` are the standard OIDC claims. */
export type GenericOidcIdTokenPayload = JWTPayload & {
  email?: string;
  /** OIDC: a boolean. Validated with strict `=== true` (string `"true"` is NOT
   *  accepted) wherever it gates a decision. */
  email_verified?: unknown;
};

/** The subset of config the pure validator consumes (the full `GenericOidcConfig`
 *  in generic-oidc.ts satisfies this). Kept here to avoid a runtime cycle. */
export interface GenericOidcClaimConfig {
  issuer: string;
  clientId: string;
  subjectAllowlist?: string[];
  allowEmailAllowlist?: boolean;
}

export interface GenericOidcValidateOpts {
  /** When set, `payload.nonce` MUST equal this (the redirect flow always sets it). */
  expectedNonce?: string;
  /** The access_token just exchanged — present in the code flow so `at_hash` can
   *  be validated. Absent in header mode (the at_hash residual). Never enters
   *  `IdentityClaims`/audit. */
  accessToken?: string;
  /** The id_token's signing alg (from the jose protectedHeader) — needed to pick
   *  the `at_hash` hash function. */
  alg?: string;
}

/** The algs this library will accept for an OIDC id_token, intersected with the
 *  provider's advertised set. Missing advertised metadata ⇒ the pin set (don't
 *  over-reject providers that omit it); present-but-empty intersection ⇒ throw
 *  (boot-fail: no usable alg). */
export function resolveAllowedAlgs(advertised: string[] | undefined): string[] {
  const PIN: ReadonlyArray<string> = ["RS256", "ES256"];
  if (!Array.isArray(advertised)) return [...PIN];
  const set = advertised.filter((a) => a === "RS256" || a === "ES256");
  if (set.length === 0) {
    throw new Error("generic_oidc_no_supported_alg: issuer advertises no RS256/ES256 id_token signing alg");
  }
  return set;
}

/** OIDC Core §3.1.3.6 at_hash = base64url(leftmost half of SHA-256(access_token)).
 *  RS256 and ES256 both use SHA-256 (the only two pinned algs); any other alg ⇒
 *  null so the caller fails closed rather than hashing with the wrong function. */
export function computeAtHash(accessToken: string, alg: string): string | null {
  if (alg !== "RS256" && alg !== "ES256") return null;
  const hash = createHash("sha256").update(accessToken).digest();
  return hash.subarray(0, hash.length / 2).toString("base64url");
}

/** `aud` as a string array, or null if absent/malformed (non-string entry, or a
 *  non-array/non-string value). A single-element array is the legitimate
 *  single-audience array form; the caller rejects length > 1. */
function normalizeAud(aud: JWTPayload["aud"]): string[] | null {
  if (aud === undefined || aud === null) return null;
  if (Array.isArray(aud)) {
    if (aud.length === 0) return null;
    if (!aud.every((a) => typeof a === "string")) return null;
    return aud;
  }
  if (typeof aud === "string") return [aud];
  return null;
}

/** Case-insensitive, trimmed membership. Matches `sub` always; matches a
 *  verified email only when `allowEmail && emailVerified` (strict `=== true`). */
export function subjectAllowedGeneric(
  sub: string,
  email: string | undefined,
  emailVerified: boolean,
  allowlist: string[],
  allowEmail: boolean,
): boolean {
  const norm = (s: string): string => s.trim().toLowerCase();
  if (allowlist.some((entry) => norm(entry) === norm(sub))) return true;
  if (allowEmail && emailVerified && email !== undefined && allowlist.some((entry) => norm(entry) === norm(email))) return true;
  return false;
}

/** Validate a signature-verified id_token's claims and extract the identity.
 *  Exported pure so the gate is unit-testable WITHOUT the JWKS fetch. */
export function validateGenericOidcIdToken(
  payload: GenericOidcIdTokenPayload,
  config: GenericOidcClaimConfig,
  opts?: GenericOidcValidateOpts,
): { ok: true; identity: IdentityClaims } | { ok: false; reason: string } {
  if (payload.iss !== config.issuer) return { ok: false, reason: "generic_oidc_bad_iss" };
  const aud = normalizeAud(payload.aud);
  if (aud === null || aud.length === 0) return { ok: false, reason: "generic_oidc_bad_aud" };
  if (aud.length > 1) return { ok: false, reason: "generic_oidc_multi_audience" };
  if (aud[0] !== config.clientId) return { ok: false, reason: "generic_oidc_bad_aud" };
  if (!payload.exp) return { ok: false, reason: "generic_oidc_missing_exp" };
  if (!payload.iat) return { ok: false, reason: "generic_oidc_missing_iat" };
  if (opts?.expectedNonce !== undefined) {
    if (typeof payload.nonce !== "string" || payload.nonce !== opts.expectedNonce) {
      return { ok: false, reason: "generic_oidc_bad_nonce" };
    }
  }
  // at_hash: validate ONLY in the code flow (access_token available). Header mode
  // (no access_token) skips it — the documented residual. Never hash undefined.
  if (payload.at_hash !== undefined && opts?.accessToken !== undefined) {
    if (typeof opts.alg !== "string") return { ok: false, reason: "generic_oidc_bad_at_hash" };
    const computed = computeAtHash(opts.accessToken, opts.alg);
    if (computed === null || computed !== payload.at_hash) return { ok: false, reason: "generic_oidc_bad_at_hash" };
  }
  if (typeof payload.sub !== "string" || !payload.sub) return { ok: false, reason: "generic_oidc_no_subject" };
  // `email` is an untrusted claim — a non-string value (e.g. 123, {}) would otherwise
  // reach subjectAllowedGeneric's .trim() and throw ⇒ exchange_failed; coerce to
  // string|undefined before matching or surfacing it.
  const email = typeof payload.email === "string" ? payload.email : undefined;
  if (config.subjectAllowlist && config.subjectAllowlist.length > 0) {
    if (!subjectAllowedGeneric(payload.sub, email, payload.email_verified === true, config.subjectAllowlist, config.allowEmailAllowlist === true)) {
      return { ok: false, reason: "generic_oidc_subject_not_allowed" };
    }
  }
  return {
    ok: true,
    identity: {
      subject: payload.sub,
      claims: {
        email,
        emailVerified: payload.email_verified === true,
        issuer: config.issuer,
        expiresAt: payload.exp,
        issuedAt: payload.iat,
      },
    },
  };
}
