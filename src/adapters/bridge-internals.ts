// Small pure helpers for `Bridge` (bridge.ts), factored out to keep that file
// under the 250-line limit (contracts §6). No I/O, no framework types beyond
// the normalized request shape.

import { OAuthError } from "../errors.ts";
import { assertAllowedScopesCeiling } from "../scopes.ts";
import { isBasicAttempt } from "../client-auth.ts";
import type { AuditPort, AuthAuditStatus } from "../ports/audit.ts";
import type { ClockPort } from "../ports/clock.ts";
import type { IdentityPort, IdentityResult } from "../ports/identity.ts";
import { headerString, type NormRequest } from "./http.ts";

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
    try {
      await audit.writeAuthEvent({
        occurredAt: new Date(clock.nowMs()).toISOString(), event: "oauth.token.client_credentials",
        status: "failure", clientId, reason: "invalid_client",
      });
    } catch { /* the rejection remains authoritative when this evidence write fails */ }
  }
  throw new OAuthError("invalid_client", "Authorization header must occur exactly once", 401);
}

/** Body of `Bridge.resolveIdentity` (§17.4 item 4 / §17.7). Fail-closed:
 *  `{ ok:false }` ⇒ 401 access_denied DIRECT (redirect_uri is untrusted
 *  pre-validation). A thrown port error propagates RAW so the adapter's
 *  direct-error mapping (HF.1–HF.3) is unchanged. A present-but-malformed
 *  `allowedScopes` ceiling fails CLOSED — it must never widen to full access
 *  (threat-model row 22). An empty array is a valid "entitled to nothing"
 *  ceiling; undefined ⇒ no ceiling (v0.1 behavior). */
export async function resolveIdentityWithAudit(
  identity: IdentityPort, input: unknown, ip: string | undefined,
  emit: (status: AuthAuditStatus, reason: string | undefined, subject: string | undefined, ip: string | undefined) => Promise<void>,
): Promise<{ subject: string; allowedScopes?: string[] }> {
  let result: IdentityResult;
  try {
    result = await identity.verify(input);
  } catch (error) {
    await emit("failure", error instanceof OAuthError ? error.code : "internal_error", undefined, ip);
    throw error;
  }
  if (!result.ok) {
    await emit("failure", result.reason, undefined, ip);
    throw new OAuthError("access_denied", `Identity rejected: ${result.reason}`, 401);
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

export function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string" && v.length > 0) : [];
}

export function consentCookie(req: NormRequest): string | undefined {
  const raw = headerString(req.headers, "cookie");
  if (!raw) return undefined;
  const found = raw.split(";").map((p) => p.trim()).find((p) => p.startsWith("mcp_idp_consent="));
  return found ? decodeURIComponent(found.slice("mcp_idp_consent=".length)) : undefined;
}
