// CIMD typed primitive error (§17.1 / §17.1.5). The `reason` is a STABLE machine
// code for the S6b `oauth.cimd.fetch` audit event ONLY — it must never be needed
// to build client-facing text (S6b maps ALL reasons to one generic
// "client_id could not be resolved", preserving the anti-SSRF-oracle property).
// The message is a short developer/audit string; it MUST NOT surface to clients.

export type CimdReason =
  | "url_admission_denied" // §17.1.1 URL admission rejected
  | "dns_failed" // DNS-layer failure: zero A/AAAA records, resolver error, or —
                 // under allowLoopback — a non-loopback record (fail-closed)
  | "ip_blocked" // §17.1.2 a resolved address hit the blocklist
  | "redirect_refused" // §17.1.2 a redirect was followed / not proven absent
  | "status_not_200" // §17.1.2 response status !== 200
  | "content_type" // §17.1.2 Content-Type not application/json|+json, or duplicated
  | "encoding" // §17.1.5 r16 any present Content-Encoding (identity-only; absent-only)
  | "size_exceeded" // §17.1.2 wire bytes > maxDocumentBytes
  | "timeout" // §17.1.2 fetchTimeoutMs deadline hit
  | "fetch_failed" // otherwise-unclassified transport/body failure (fail-closed)
  | "document_invalid"; // §17.1.3 document validation failed

export class CimdError extends Error {
  readonly reason: CimdReason;

  constructor(reason: CimdReason, message = reason) {
    super(message);
    this.name = "CimdError";
    this.reason = reason;
  }
}
