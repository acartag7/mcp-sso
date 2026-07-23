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
import {
  ownBooleanTrue, ownDataValue, snapshotOwnDataRecord, snapshotOwnStringArray,
} from "../own-property.ts";

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
  if (advertised === undefined) return [...PIN];
  const values = snapshotOwnStringArray(advertised);
  if (values === null) throw new Error("generic_oidc_no_supported_alg: malformed signing algorithm list");
  const set = values.filter((a) => a === "RS256" || a === "ES256");
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
    const values = snapshotOwnStringArray(aud);
    if (values === null || values.length === 0) return null;
    return [...values];
  }
  if (typeof aud === "string") return [aud];
  return null;
}

/** Allowlist membership. `sub` is an opaque, case-sensitive identifier — matched
 *  EXACTLY (no trim/lower; normalizing would let `alice` match an entry for `Alice`).
 *  A verified email is matched case-insensitively (RFC 5321) only when allowed. */
export function subjectAllowedGeneric(
  sub: string,
  email: string | undefined,
  emailVerified: boolean,
  allowlist: string[],
  allowEmail: boolean,
): boolean {
  const entries = snapshotOwnStringArray(allowlist);
  if (entries === null) return false;
  if (entries.includes(sub)) return true;
  if (allowEmail === true && emailVerified === true && email !== undefined) {
    const e = email.trim().toLowerCase();
    if (entries.some((entry) => entry.trim().toLowerCase() === e)) return true;
  }
  return false;
}

/** Validate a signature-verified id_token's claims and extract the identity.
 *  Exported pure so the gate is unit-testable WITHOUT the JWKS fetch. */
export function validateGenericOidcIdToken(
  payload: GenericOidcIdTokenPayload,
  config: GenericOidcClaimConfig,
  opts?: GenericOidcValidateOpts,
): { ok: true; identity: IdentityClaims } | { ok: false; reason: string } {
  const snapshot = snapshotOwnDataRecord(payload);
  const configSnapshot = snapshotGenericClaimConfig(config);
  const optionSnapshot = opts === undefined ? undefined : snapshotOwnDataRecord(opts);
  if (snapshot === null || configSnapshot === null || optionSnapshot === null) return { ok: false, reason: "generic_oidc_bad_claim" };
  const claims = snapshot as GenericOidcIdTokenPayload;
  if (claims.iss !== configSnapshot.issuer) return { ok: false, reason: "generic_oidc_bad_iss" };
  const aud = normalizeAud(claims.aud);
  if (aud === null || aud.length === 0) return { ok: false, reason: "generic_oidc_bad_aud" };
  if (aud.length > 1) return { ok: false, reason: "generic_oidc_multi_audience" };
  if (aud[0] !== configSnapshot.clientId) return { ok: false, reason: "generic_oidc_bad_aud" };
  if (!claims.exp) return { ok: false, reason: "generic_oidc_missing_exp" };
  if (!claims.iat) return { ok: false, reason: "generic_oidc_missing_iat" };
  const expectedNonce = ownDataValue(optionSnapshot, "expectedNonce");
  const accessToken = ownDataValue(optionSnapshot, "accessToken");
  const alg = ownDataValue(optionSnapshot, "alg");
  if (expectedNonce !== undefined) {
    if (typeof expectedNonce !== "string" || typeof claims.nonce !== "string" || claims.nonce !== expectedNonce) {
      return { ok: false, reason: "generic_oidc_bad_nonce" };
    }
  }
  // at_hash: validate ONLY in the code flow (access_token available). Header mode
  // (no access_token) skips it — the documented residual. Never hash undefined.
  if (claims.at_hash !== undefined && accessToken !== undefined) {
    if (typeof accessToken !== "string" || typeof alg !== "string") return { ok: false, reason: "generic_oidc_bad_at_hash" };
    const computed = computeAtHash(accessToken, alg);
    if (computed === null || computed !== claims.at_hash) return { ok: false, reason: "generic_oidc_bad_at_hash" };
  }
  if (typeof claims.sub !== "string" || !claims.sub) return { ok: false, reason: "generic_oidc_no_subject" };
  // `email` is an untrusted claim — a non-string value (e.g. 123, {}) would otherwise
  // reach subjectAllowedGeneric's .trim() and throw ⇒ exchange_failed; coerce to
  // string|undefined before matching or surfacing it.
  const email = typeof claims.email === "string" ? claims.email : undefined;
  const emailVerified = ownBooleanTrue(claims, "email_verified");
  if (configSnapshot.subjectAllowlist && configSnapshot.subjectAllowlist.length > 0) {
    if (!subjectAllowedGeneric(claims.sub, email, emailVerified,
      configSnapshot.subjectAllowlist, configSnapshot.allowEmailAllowlist === true)) {
      return { ok: false, reason: "generic_oidc_subject_not_allowed" };
    }
  }
  return {
    ok: true,
    identity: {
      // Canonicalize as (issuer, sub): the bridge keys granted scopes by the
      // subject string, so an opaque `sub` that collides across issuers (e.g. a
      // stored-DCR store reused after changing issuers) must not inherit another
      // issuer's grants. Entra oid / CF sub are globally-unique (GUID/UUID); a
      // generic `sub` is not, so it is namespaced with the configured issuer.
      subject: `${configSnapshot.issuer}|${claims.sub}`,
      claims: {
        email,
        emailVerified,
        issuer: configSnapshot.issuer,
        expiresAt: claims.exp,
        issuedAt: claims.iat,
      },
    },
  };
}

function snapshotGenericClaimConfig(config: unknown): Readonly<GenericOidcClaimConfig> | null {
  const fields = snapshotOwnDataRecord(config);
  if (fields === null || typeof fields.issuer !== "string" || !fields.issuer
    || typeof fields.clientId !== "string" || !fields.clientId
    || (fields.allowEmailAllowlist !== undefined && typeof fields.allowEmailAllowlist !== "boolean")) return null;
  const subjectAllowlist = fields.subjectAllowlist === undefined
    ? undefined : snapshotOwnStringArray(fields.subjectAllowlist);
  if (subjectAllowlist === null) return null;
  return Object.freeze({
    issuer: fields.issuer,
    clientId: fields.clientId,
    subjectAllowlist: subjectAllowlist && Object.freeze([...subjectAllowlist]) as string[],
    allowEmailAllowlist: fields.allowEmailAllowlist === true,
  });
}
