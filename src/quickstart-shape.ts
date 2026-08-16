// Quickstart secrets SHAPE parsing (contracts §17.8). Pure: no filesystem, no
// side effects — it turns already-read JSON into a typed QuickstartSecrets or
// throws. Split from quickstart.ts, which owns the filesystem lifecycle
// (exclusive create, symlink refusal, permission admission).

import type { JWK } from "jose";
import { AuthConfigError } from "./config-error.ts";

export interface QuickstartSecrets {
  /** EC P-256 private JWK (kty/crv/d/x/y) — passes `createBridgeConfig`'s §5 check. */
  signingPrivateJwk: JWK;
  /** >=32-char HS256 consent secret (base64url of 48 random bytes). */
  consentSigningSecret: string;
}

export function validateSecrets(parsed: unknown, secretsPath: string): QuickstartSecrets {
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new AuthConfigError(`quickstart: ${secretsPath} must be a JSON object`);
  }
  const obj = parsed as Record<string, unknown>;
  const signingPrivateJwk = obj.signingPrivateJwk;
  const consentSigningSecret = obj.consentSigningSecret;
  if (typeof consentSigningSecret !== "string" || consentSigningSecret.trim().length < 32) {
    throw new AuthConfigError(`quickstart: ${secretsPath} consentSigningSecret missing or < 32 chars`);
  }
  // Mirror config.ts §5 shape validation so loaded material always passes createBridgeConfig.
  if (!isValidSigningJwk(signingPrivateJwk)) {
    throw new AuthConfigError(`quickstart: ${secretsPath} signingPrivateJwk must be an EC P-256 key with d, x, y`);
  }
  return { signingPrivateJwk: signingPrivateJwk as JWK, consentSigningSecret };
}

export function isValidSigningJwk(value: unknown): value is JWK {
  if (typeof value !== "object" || value === null) return false;
  const jwk = value as Record<string, unknown>;
  return (
    jwk.kty === "EC" && jwk.crv === "P-256" &&
    typeof jwk.d === "string" && jwk.d.length > 0 &&
    typeof jwk.x === "string" && jwk.x.length > 0 &&
    typeof jwk.y === "string" && jwk.y.length > 0
  );
}
