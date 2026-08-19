// Small pure helpers for `Bridge` (bridge.ts), factored out to keep that file
// under the 250-line limit (contracts §6). No I/O, no framework types beyond
// the normalized request shape.

import { OAuthError } from "../errors.ts";
import { assertAllowedScopesCeiling } from "../scopes.ts";
import { isBasicAttempt } from "../client-auth.ts";
import type { AuditPort, AuthAuditStatus } from "../ports/audit.ts";
import { finiteClockSnapshot, type ClockPort } from "../ports/clock.ts";
import type { IdentityPort, IdentityResult } from "../ports/identity.ts";
import { formBodySnapshot, formObject, headerString, isAmbiguousFormContentType, type NormRequest } from "./http.ts";
import { findRepeatedKeys } from "./authorize-params.ts";
import { writeAuditBestEffort } from "../audit/best-effort.ts";
import { PortFailureError, callPort } from "../port-failure.ts";
import { snapshotIdentityResult } from "../port-result.ts";

// Audit is a public security surface. Only fixed reason codes emitted by the
// shipped identity implementations may cross this boundary; a custom port's
// arbitrary string collapses to one library-owned code.
const IDENTITY_FAILURE_REASONS = new Set([
  "access_jwt_missing", "access_jwt_missing_expiry", "access_jwt_email_not_allowed",
  "access_jwt_expired", "access_jwt_bad_claim", "access_jwt_unsupported_alg",
  "access_jwt_unknown_key", "access_jwt_invalid", "access_jwt_verify_failed",
  "entra_bad_tid", "entra_bad_iss", "entra_bad_aud", "entra_bad_nonce",
  "entra_missing_iat", "entra_missing_exp", "entra_no_subject", "entra_subject_not_allowed",
  "entra_groups_overage", "entra_no_groups", "entra_no_mapped_groups", "entra_token_expired",
  "entra_bad_claim", "entra_unsupported_alg", "entra_unknown_key", "entra_verify_failed",
  "entra_token_invalid", "entra_id_token_missing",
  "generic_oidc_bad_iss", "generic_oidc_bad_aud", "generic_oidc_multi_audience",
  "generic_oidc_missing_exp", "generic_oidc_missing_iat", "generic_oidc_bad_nonce",
  "generic_oidc_bad_at_hash", "generic_oidc_no_subject", "generic_oidc_subject_not_allowed",
  "generic_oidc_token_expired", "generic_oidc_bad_claim", "generic_oidc_unsupported_alg",
  "generic_oidc_unknown_key", "generic_oidc_verify_failed", "generic_oidc_token_invalid",
  "generic_oidc_id_token_missing", "google_bad_hosted_domain", "google_missing_hosted_domain",
  "pairing_invalid_input", "pairing_rate_limited", "pairing_no_active_code",
  "pairing_expired", "pairing_wrong_code",
]);

export function normalizedIdentityFailureReason(value: unknown): string {
  return typeof value === "string" && IDENTITY_FAILURE_REASONS.has(value)
    ? value : "identity_rejected";
}

/** Public redirect text for a normalized identity failure. The input selects
 *  only from this library-authored switch; it is never copied into the output. */
export function identityRejectionDescription(normalizedReason: string): string {
  switch (normalizedReason) {
    case "entra_no_groups": return "Entra returned no groups for this account";
    case "entra_no_mapped_groups": return "Entra groups do not authorize this account for this resource";
    case "entra_groups_overage": return "Entra group claims exceed the supported limit; operator configuration is required";
    default: return "upstream identity verification failed";
  }
}

export function hasBasicAuthorization(headers: NormRequest["headers"]): boolean {
  return Object.entries(headers).some(([key, raw]) =>
    key.toLowerCase() === "authorization" &&
    (Array.isArray(raw) ? raw : [raw]).some((value) =>
      typeof value === "string" && value.split(",").some((part) => isBasicAttempt(part.trim()))));
}

export async function assertUnambiguousAuthorization(
  ambiguous: boolean, grantType: string | undefined, clientId: string | undefined,
  audit: AuditPort, clock: ClockPort,
): Promise<void> {
  if (!ambiguous) return;
  if (grantType === "client_credentials") {
    await writeAuditBestEffort(audit, {
      occurredAt: new Date(finiteClockSnapshot(clock)).toISOString(), event: "oauth.token.client_credentials",
      status: "failure", clientId, reason: "invalid_client",
    });
  }
  throw new OAuthError("invalid_client", "Authorization header must occur exactly once", 401);
}

/** Body of `Bridge.resolveIdentity` (§17.4 item 4 / §17.7). Fail-closed:
 *  `{ ok:false }` ⇒ 401 access_denied DIRECT (redirect_uri is untrusted
 *  pre-validation). A thrown OAuthError can select only the fixed rejection
 *  code and an allowlisted 401/403 status; every other throw is a generic port
 *  failure. A present-but-malformed
 *  `allowedScopes` ceiling fails CLOSED — it must never widen to full access
 *  (threat-model row 22). An empty array is a valid "entitled to nothing"
 *  ceiling; undefined ⇒ no ceiling (v0.1 behavior). */
export async function resolveIdentityWithAudit(
  identity: IdentityPort, input: unknown, ip: string | undefined,
  emit: (status: AuthAuditStatus, reason: string | undefined, subject: string | undefined, ip: string | undefined) => Promise<void>,
): Promise<{ subject: string; allowedScopes?: string[] }> {
  let result: IdentityResult;
  try {
    const returned = await callPort("IdentityPort", "verify", () => identity.verify(input));
    result = await callPort("IdentityPort", "verifyResult", async () => snapshotIdentityResult(returned));
  } catch (error) {
    const portRejected = error instanceof PortFailureError
      && error.operation === "verify"
      && (error.oauthStatusSnapshot === 401 || error.oauthStatusSnapshot === 403);
    await emit("failure", error instanceof PortFailureError && error.causeIsOAuthError
      ? "port_error" : "internal_error", undefined, ip);
    // A deployment port may distinguish authentication-required from a verified
    // denial with 401/403. Code, description, redirect, and every other status
    // remain library-owned; a malformed rejection takes the generic 500 path.
    if (portRejected) {
      throw new OAuthError("access_denied", "Identity rejected: port_error", error.oauthStatusSnapshot);
    }
    throw error;
  }
  if (!result.ok) {
    const reason = normalizedIdentityFailureReason(result.reason);
    await emit("failure", reason, undefined, ip);
    throw new OAuthError("access_denied", "Identity rejected", 401);
  }
  const subject = result.identity.subject;
  let allowedScopes: string[] | undefined;
  try {
    allowedScopes = assertAllowedScopesCeiling(result.identity.allowedScopes);
  } catch (error) {
    await emit("failure", "malformed_allowed_scopes", undefined, ip);
    throw error;
  }
  await emit("success", undefined, subject, ip);
  return { subject, allowedScopes };
}

export function asOAuth(error: unknown): OAuthError {
  return error instanceof OAuthError ? error : new OAuthError("internal_error", "OAuth request failed", 500);
}

export function asDirectOAuth(error: unknown): OAuthError {
  const mapped = asOAuth(error);
  return new OAuthError(mapped.code, mapped.message, mapped.status);
}

export function parseApproved(raw: unknown): boolean {
  return raw === true || raw === "true"; // fail-closed (§9.3): absent/malformed never auto-approves
}

/** Reject ambiguous form provenance or repeated keys, then return the parsed body. */
export function checkedFormObject(
  req: NormRequest,
  keys: readonly string[],
  jsonArrayKeys: readonly string[] = [],
): Record<string, unknown> {
  const headerFormBody = formBodySnapshot(req.body, req.headers);
  const formBody = req.formBody === undefined
    ? headerFormBody
    : req.formBody;
  const legacyKeys = keys.filter((key) => !jsonArrayKeys.includes(key));
  const legacyBodyIsAmbiguous = req.formBody === undefined
    && formBody === undefined
    && headerString(req.headers, "content-type") === undefined
    && findRepeatedKeys(req.body, legacyKeys).length > 0;
  if (isAmbiguousFormContentType(headerFormBody)
    || isAmbiguousFormContentType(formBody)
    || findRepeatedKeys(formBody, keys).length > 0
    || legacyBodyIsAmbiguous) {
    throw new OAuthError("invalid_request", "duplicate request parameters");
  }
  return formObject(req.body);
}

export function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string" && v.length > 0) : [];
}

export function consentCookie(req: NormRequest): string | undefined {
  const raw = headerString(req.headers, "cookie");
  if (!raw) return undefined;
  const found = raw.split(";").map((p) => p.trim()).find((p) => p.startsWith("mcp_idp_consent="));
  if (!found) return undefined;
  try {
    return decodeURIComponent(found.slice("mcp_idp_consent=".length));
  } catch {
    // Fail closed (§9.3): the malformed cookie IS the consent credential this
    // request presented, so it takes the same direct 400 invalid_consent as an
    // unparseable form token — never a 500, and never silently absent.
    throw new OAuthError("invalid_consent", "Consent token is invalid or expired");
  }
}
