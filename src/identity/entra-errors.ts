// jose verification-error mapping for the Entra primitives. Kept separate from
// the factory so entra.ts stays below the repository's cohesion line limit.

import { errors } from "jose";

export function entraJwtErrorReason(error: unknown): string {
  if (error instanceof errors.JWTExpired) return "entra_token_expired";
  if (error instanceof errors.JWTClaimValidationFailed) return "entra_bad_claim";
  if (error instanceof errors.JOSEAlgNotAllowed) return "entra_unsupported_alg";
  if (error instanceof errors.JWKSNoMatchingKey) return "entra_unknown_key";
  // Remote JWKS failures map to `entra_verify_failed` ⇒ `exchange_failed`
  // (§17.11). Other jose verification errors remain identity rejections.
  if (error instanceof errors.JWKSTimeout || error instanceof errors.JWKSInvalid) return "entra_verify_failed";
  if (error instanceof errors.JOSEError && error.code === "ERR_JOSE_GENERIC") return "entra_verify_failed";
  if (error instanceof errors.JOSEError) return "entra_token_invalid";
  return "entra_verify_failed";
}
