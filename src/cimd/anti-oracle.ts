// The CIMD anti-oracle boundary (§17.1.6 decision 2): every resolution failure
// collapses to ONE client-facing error, and every audited reason comes from a
// fixed allowlist. Kept beside `resolve.ts` rather than inside it so the
// mapping — the part a reviewer checks for information leaks — reads as one
// self-contained unit, and so `resolve.ts` stays under the 250-line cap.

import { OAuthError } from "../errors.ts";
import { CimdError, type CimdReason } from "./errors.ts";

/** The ONE client-facing description every CIMD resolution failure collapses to
 *  (the SSRF content/reachability oracle stays closed). */
const GENERIC_DESCRIPTION = "client_id could not be resolved";

/** Allowlisted audit reasons. An unrecognized (future) `CimdError.reason`, and
 *  any non-`CimdError` throw, audit the fixed `fetch_failed` — never free-form
 *  exception text (log injection / leak). */
const AUDIT_REASONS: ReadonlySet<string> = new Set<CimdReason>([
  "url_admission_denied", "dns_failed", "ip_blocked", "redirect_refused",
  "status_not_200", "content_type", "encoding", "size_exceeded", "timeout",
  "fetch_failed", "document_invalid", "overloaded",
]);

export const CIMD_AUDIT_EVENT = "oauth.cimd.fetch";

export function cimdGenericError(): OAuthError {
  return new OAuthError("invalid_client", GENERIC_DESCRIPTION, 401);
}

/** Exhaustive switch over `CimdReason` + a fail-closed default (decision 2/6). */
export function mapCimdError(error: unknown): OAuthError {
  if (error instanceof CimdError) {
    switch (error.reason) {
      case "url_admission_denied": case "dns_failed": case "ip_blocked":
      case "redirect_refused": case "status_not_200": case "content_type":
      case "encoding": case "size_exceeded": case "timeout":
      case "fetch_failed": case "document_invalid": case "overloaded":
        return cimdGenericError();
      default:
        return cimdGenericError(); // unknown/future reason ⇒ same fail-closed generic
    }
  }
  return cimdGenericError();
}

/** Reason for the `oauth.cimd.fetch` failure event — allowlisted, never raw. */
export function auditReason(error: unknown): string {
  if (error instanceof CimdError && AUDIT_REASONS.has(error.reason)) return error.reason;
  return "fetch_failed";
}
