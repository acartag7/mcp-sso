// WebhookAudit — per-event POST auth-audit sink (contracts §13, §17.7). At-most-
// once (no retry), https-only, redirects NOT followed.
//
// Why this is NOT behind the §17.1 CIMD SSRF guard (deliberate, §17.7 + §17.6
// rationale): the webhook URL is static, trusted deployer config — not
// attacker-controlled client input — and SIEM/log collectors legitimately live
// on private networks (RFC 1918 / loopback). CIMD guards user-supplied URLs;
// reusing that gate here would wrongly reject private collectors. The remaining
// SSRF surface (a compromised collector returning a 3xx to an internal target)
// is closed by `redirect: "manual"`.
//
// Safety invariants (threat-model row 24):
//   - https-only via a RAW `https://` prefix check BEFORE `new URL()`. The raw
//     check is fail-closed against `http://` downgrade and survives URL-parser
//     quirks; `new URL()` then validates structure. Case-sensitive on the scheme
//     (deployer config; write it lowercase).
//   - `redirect: "manual"`: a 3xx is returned unfollowed, so a collector cannot
//     pivot a POST to an internal address.
//   - At-most-once: a single POST per event, no retry on any outcome (timeout,
//     non-2xx, network error). Guaranteed delivery is out of scope (§17.7);
//     hard-evidence deployments use the file sink + a log shipper.
//   - Fail-open: writeAuthEvent NEVER rejects (audit is evidence, not a gate).
//   - No secret leakage on failure: the deployer's `headers` may carry a SIEM
//     bearer token, and the payload — though metadata-only — is never echoed.
//     The error message is NOT trusted (a fetch implementation may echo request
//     headers/body into it); it is redacted via safeErrorMessage and the known
//     header values are scrubbed before reaching stderr (threat-model #14). The
//     stderr line carries the host and a redacted diagnostic, never the raw
//     headers, body, or query.
//
// Testability: an optional `fetchImpl` (defaults to the global) lets tests
// assert on init options without a real https server. It is a normal DI seam
// (the codebase injects Redis/Pool clients the same way), not test-only surface.

import type { AuthAuditEvent, AuditPort } from "../ports/audit.ts";
import { safeErrorMessage } from "./util.ts";
import { snapshotOwnDataRecord } from "../own-property.ts";
import { guardedGlobalFetch } from "../outbound-tls.ts";

export interface WebhookAuditOptions {
  /** Per-request deadline. Default 5000 ms (§17.7). */
  timeoutMs?: number;
  /** Extra request headers (e.g. a SIEM collector auth token). Merged over the
   *  sink's `Content-Type: application/json`. Never logged on failure. */
  headers?: Record<string, string>;
  /** Injection seam for the POST transport; defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

export class WebhookAudit implements AuditPort {
  private readonly url: string;
  private readonly host: string;
  private readonly timeoutMs: number;
  private readonly headers: Record<string, string>;
  private readonly fetchImpl: typeof fetch;
  /** Secret-shaped tokens derived from the configured URL's query string, scrubbed
   *  from any transport error before it reaches stderr. A deployer may legitimately
   *  route via query params, but those params can also carry credentials
   *  (`?access_token=…`); the regex redactor does not catch `access_token=` (the
   *  `_` before `token` defeats the `\b` boundary), so the configured values are
   *  removed precisely here. (Userinfo is rejected outright at construction.) */
  private readonly querySecrets: string[];

  constructor(url: string, options: WebhookAuditOptions = {}) {
    const optionFields = snapshotOwnDataRecord(options);
    if (optionFields === null) throw new TypeError("WebhookAudit options must be own data properties");
    // RAW prefix check FIRST — fail-closed before any URL parsing. Rejects
    // `http://`, `HTTPS://`, and anything that is not an exact `https://` start.
    if (typeof url !== "string" || !url.startsWith("https://")) {
      throw new Error("WebhookAudit: url must start with 'https://' (raw prefix check, §17.7)");
    }
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error("WebhookAudit: url must be a valid absolute https URL");
    }
    if (parsed.protocol !== "https:") {
      // Defense-in-depth: the raw check already enforced this, but a future
      // exotic scheme slipping past `startsWith` is rejected here too.
      throw new Error("WebhookAudit: url must be https://");
    }
    if (parsed.username || parsed.password) {
      // Credentials embedded in the URL are a leak hazard: a fetch transport
      // error (or any future log of the URL) would write them to stderr, and
      // regex redaction cannot reliably catch arbitrary short `user:pass@`
      // values. Fail closed — pass credentials via `headers` instead.
      throw new Error("WebhookAudit: url must not contain userinfo (user:pass@); pass credentials via `headers`");
    }
    this.url = url;
    this.host = parsed.host;
    this.querySecrets = collectQuerySecrets(parsed);
    const timeoutMs = optionFields.timeoutMs ?? 5000;
    if (typeof timeoutMs !== "number" || !Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError("WebhookAudit timeoutMs must be a positive integer");
    }
    const extraHeaders = optionFields.headers === undefined
      ? Object.freeze(Object.create(null) as Record<string, string>)
      : snapshotOwnDataRecord(optionFields.headers);
    if (extraHeaders === null || !Object.values(extraHeaders).every((value) => typeof value === "string")) {
      throw new TypeError("WebhookAudit headers must be own string properties");
    }
    if (optionFields.fetchImpl !== undefined && typeof optionFields.fetchImpl !== "function") {
      throw new TypeError("WebhookAudit fetchImpl must be a function");
    }
    this.timeoutMs = timeoutMs;
    this.headers = Object.freeze({ "Content-Type": "application/json", ...extraHeaders });
    this.fetchImpl = (optionFields.fetchImpl as typeof fetch | undefined) ?? guardedGlobalFetch;
  }

  async writeAuthEvent(event: AuthAuditEvent): Promise<void> {
    try {
      const response = await this.fetchImpl(this.url, {
        method: "POST",
        headers: this.headers,
        body: JSON.stringify(event),
        redirect: "manual", // §17.7: never follow a redirect (SSRF-by-redirect)
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (!response.ok) {
        // Non-2xx is a failed delivery — at-most-once means we do NOT retry.
        // Surface only the status + host; never the body or headers.
        console.error(
          `[mcp-sso] audit webhook non-2xx (${response.status}) from ${this.host}`,
        );
      }
    } catch (error) {
      // Timeout, DNS, connection refused, TLS — all fail-open. The error message
      // is redacted (and known header values scrubbed) before reaching stderr.
      console.error(
        `[mcp-sso] audit webhook write failed to ${this.host}: ${this.safeError(error)}`,
      );
    }
  }

  /** Redact secret-shaped substrings from `error`, then precisely remove the
   *  deployer's own header values (e.g. a SIEM bearer token) and configured
   *  query-string params in case the regex redactor missed a non-standard
   *  format. Never throws. */
  private safeError(error: unknown): string {
    let msg = safeErrorMessage(error);
    for (const value of Object.values(this.headers)) {
      if (typeof value === "string" && value.length >= 8) {
        msg = msg.split(value).join("[redacted]");
      }
    }
    for (const token of this.querySecrets) {
      msg = msg.split(token).join("[redacted]");
    }
    return msg;
  }
}

/** Tokens scrubbed from transport diagnostics: the full query string, each
 *  `key=value` pair (handles a pair echoed without the leading `?`), and any
 *  non-trivial value (handles a value echoed alone). Short tokens (<4 chars)
 *  are skipped to avoid mangling diagnostics. */
function collectQuerySecrets(url: URL): string[] {
  if (!url.search) return [];
  const tokens: string[] = [url.search];
  for (const [k, v] of url.searchParams.entries()) {
    tokens.push(`${k}=${v}`);
    if (v.length >= 8) tokens.push(v);
  }
  return tokens.filter((t) => t.length >= 4);
}

export function createWebhookAudit(url: string, options?: WebhookAuditOptions): WebhookAudit {
  return new WebhookAudit(url, options);
}
