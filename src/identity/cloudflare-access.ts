// CloudflareAccessIdentity — verifies a Cloudflare Access JWT
// (`Cf-Access-Jwt-Assertion`) so the OAuth subject is the real authenticated email,
// not a placeholder. RS256 against Cloudflare's public JWKS, aud/iss/exp checked.
// The email ALLOWLIST (who may mint a token) is enforced by the CF Zero Trust app
// policy by default; an optional emailAllowlist adds a defense-in-depth second gate.
//
// Addenda 11–12: certsUrl + issuer MUST be https (raw `^https://` check before
// new URL() — Node's parser normalizes `https:/host`); claim validation is exported
// and unit-testable without the JWKS network fetch.

import { createRemoteJWKSet, errors, importJWK, jwtVerify, type JWTPayload } from "jose";
import type { IdentityClaims, IdentityPort, IdentityResult } from "../ports/identity.ts";

export interface CloudflareAccessConfig {
  audience: string;
  /** CF JWKS URL. MUST be https (addendum 11). */
  certsUrl: string;
  /** CF issuer (team URL). MUST be https (addendum 11). */
  issuer: string;
  /** Optional defense-in-depth subject/email allowlist (case-insensitive, trimmed).
   *  Empty/undefined delegates WHO is allowed entirely to CF Zero Trust. */
  emailAllowlist?: string[];
}

type AccessJwtPayload = JWTPayload & { email?: string };

// A concrete verification key (CryptoKey | Uint8Array). The JWKS path uses jose's
// getKey overload directly in the factory. We infer the concrete-key type from
// importJWK rather than naming CryptoKey (a global whose type-availability depends
// on the DOM lib / @types/node variant).
export type CloudflareAccessKey = Awaited<ReturnType<typeof importJWK>>;

export interface CloudflareAccessVerifyOptions {
  currentDate?: Date;
}

/** Apply the expiry + email + allowlist gates to an already-signature-verified
 *  payload. Exported so the gate is unit-testable WITHOUT the JWKS fetch. */
export function validateCloudflareAccessClaims(
  payload: AccessJwtPayload,
  config: CloudflareAccessConfig,
): { ok: true; identity: IdentityClaims } | { ok: false; reason: string } {
  if (!payload.exp) return { ok: false, reason: "access_jwt_missing_expiry" };
  if (!payload.email) return { ok: false, reason: "access_jwt_email_not_allowed" };
  if (config.emailAllowlist && config.emailAllowlist.length > 0 && !emailAllowed(payload.email, config.emailAllowlist)) {
    return { ok: false, reason: "access_jwt_email_not_allowed" };
  }
  const subject = payload.sub ?? payload.email;
  return {
    ok: true,
    identity: { subject, claims: { email: payload.email, audience: config.audience, expiresAt: payload.exp, issuedAt: payload.iat } },
  };
}

/** Case-insensitive, whitespace-trimmed email membership. Exported for unit testing. */
export function emailAllowed(email: string, allowlist: string[]): boolean {
  const normalized = email.trim().toLowerCase();
  if (!normalized) return false;
  return allowlist.some((entry) => entry.trim().toLowerCase() === normalized);
}

/** Verify a Cf-Access-Jwt-Assertion against an explicit key (CryptoKey/Uint8Array).
 *  Exported so tests verify the full path with a known key — no JWKS network fetch. */
export async function verifyCloudflareAccessToken(
  token: string,
  key: CloudflareAccessKey,
  config: CloudflareAccessConfig,
  options?: CloudflareAccessVerifyOptions,
): Promise<IdentityResult> {
  try {
    const { payload } = await jwtVerify<AccessJwtPayload>(token, key, {
      algorithms: ["RS256"],
      audience: config.audience,
      clockTolerance: 60,
      issuer: config.issuer,
      currentDate: options?.currentDate,
    });
    return validateCloudflareAccessClaims(payload, config);
  } catch (error) {
    return { ok: false, reason: jwtErrorReason(error) };
  }
}

/** Build a CloudflareAccess IdentityPort. `input` is the raw JWT string; the JWKS
 *  is fetched (and cached) from the https certsUrl. */
export function createCloudflareAccessIdentity(config: CloudflareAccessConfig): IdentityPort {
  assertHttpsTrustRoot(config.certsUrl, "certsUrl");
  assertHttpsTrustRoot(config.issuer, "issuer");
  const jwks = createRemoteJWKSet(new URL(config.certsUrl), { cacheMaxAge: 5 * 60 * 1000 });
  const verifyOptions = { algorithms: ["RS256"], audience: config.audience, clockTolerance: 60, issuer: config.issuer };
  return {
    async verify(input: unknown): Promise<IdentityResult> {
      if (typeof input !== "string" || !input) return { ok: false, reason: "access_jwt_missing" };
      try {
        const { payload } = await jwtVerify<AccessJwtPayload>(input, jwks, verifyOptions);
        return validateCloudflareAccessClaims(payload, config);
      } catch (error) {
        return { ok: false, reason: jwtErrorReason(error) };
      }
    },
  };
}

/** Raw `^https://` prefix check BEFORE `new URL()` (addendum 11): Node's lenient
 *  URL parser normalizes `https:/host` into a valid-looking URL, so an http JWKS
 *  would otherwise slip through → MITM substitutes signing keys → total auth bypass. */
export function assertHttpsTrustRoot(value: string, label: string): void {
  if (!value.startsWith("https://")) {
    throw new Error(`${label} must be an https:// URL (http trust roots allow key substitution)`);
  }
}

function jwtErrorReason(error: unknown): string {
  if (error instanceof errors.JWTExpired) return "access_jwt_expired";
  if (error instanceof errors.JWTClaimValidationFailed) return "access_jwt_bad_claim";
  if (error instanceof errors.JOSEAlgNotAllowed) return "access_jwt_unsupported_alg";
  if (error instanceof errors.JWKSNoMatchingKey) return "access_jwt_unknown_key";
  if (error instanceof errors.JOSEError) return "access_jwt_invalid";
  return "access_jwt_verify_failed";
}
