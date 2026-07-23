// stderr redaction for audit-sink diagnostics (contracts §17.7, threat-model #14).
//
// Audit sinks catch arbitrary errors — fs IO from JsonlFileAudit, the fetch
// transport from WebhookAudit, or a throwing toJSON from JSON.stringify — and
// surface a diagnostic line on stderr. An Error.message is NOT trusted to be
// free of secrets: a fetch implementation (including a deployer-supplied
// fetchImpl) may echo request headers or the body into the message, and an
// fs error includes the configured file path. stderr is a log, so anything
// secret-shaped is redacted BEFORE it is written. Redaction is best-effort and
// over-broad by design (this is a security product — losing some diagnostics is
// always preferable to leaking a token); it preserves the error's structure so
// operators can still diagnose "ENOTDIR" vs "TimeoutError" vs "network down".

import { classDataValue, snapshotOwnDataRecord } from "../own-property.ts";

const EVENT_NAMES = new Set([
  "oauth.register", "oauth.authorize.prepare", "oauth.authorize.approve",
  "oauth.token.authorization_code", "oauth.token.refresh", "oauth.revoke",
  "auth.request", "identity.verify", "oauth.pairing.attempt",
  "oauth.device.authorization", "oauth.device.approve", "oauth.token.device_code",
  "oauth.token.client_credentials", "oauth.client.provision",
  "oauth.client.rotate_secret", "oauth.cimd.fetch", "oauth.upstream.callback",
]);

// Ordered most-specific first. Each replaces its match with "[redacted]".
const SECRET_PATTERNS = [
  /Bearer\s+[A-Za-z0-9._~+/=-]+/gi, // RFC 6750 bearer credentials
  // Authorization scheme + credentials (Basic/Digest/…), in ANY form a transport's
  // stringifier emits: `:` header, `=` assignment, or JSON-quoted key. The assignment
  // pattern below stops at whitespace, so without this the (short, <32) encoded
  // client_secret_basic creds leak. Runs BEFORE the assignment pattern so it consumes
  // scheme + creds together.
  /(?<![A-Za-z0-9])authorization["'\s]*[=:]["'\s]*[A-Za-z][A-Za-z0-9._-]*\s+[^\s"'&,;]+/gi,
  // key=value assignments. The lookbehind — NOT \b — treats `_` and `-` as
  // separators, so underscored OAuth compound keys also match: access_token=,
  // refresh_token=, id_token=, client_secret=. (\b would not match after `_`.)
  /(?<![A-Za-z0-9])(token|secret|secrets|password|passwd|api[_-]?key|apikey|authorization)["'\s]*[=:]\s*["']?[^\s"'&,;]+/gi,
  // OAuth authorization-code request fields (§17.11: codes + PKCE verifiers are never
  // logged). A transport that echoes the failed token-request body would otherwise leak
  // them — they are short / dotted, so the opaque-run rule below does not catch them.
  /(?<![A-Za-z0-9_])(code_verifier|code)["'\s]*[=:]\s*["']?[^\s"'&,;]+/gi,
  // Long opaque runs — refresh/access tokens, hashes, generated secrets. ISO
  // timestamps (contains ':' '.') and short hostnames do not match.
  /[A-Za-z0-9_-]{32,}/g,
];

/** Replace secret-shaped substrings with "[redacted]". Best-effort, over-broad. */
export function redactSecrets(input: string): string {
  let out = input;
  for (const p of SECRET_PATTERNS) out = out.replace(p, "[redacted]");
  return out;
}

/** A diagnostic string for `error` with secret-shaped substrings redacted.
 *  Includes the error name when it is more specific than "Error". NEVER throws —
 *  both sinks call this inside their catch blocks, so a throw here would reject
 *  writeAuthEvent and turn an audit write into an auth 500 (fail-open violation).
 *  A hostile thrown value (a .message getter or .toString that itself throws) is
 *  caught and falls back to a fixed string. */
export function safeErrorMessage(error: unknown): string {
  try {
    const safeMessage = classDataValue(error, "message");
    const raw = typeof safeMessage === "string" ? safeMessage
      : typeof error === "string" ? error
        : typeof error === "number" || typeof error === "boolean" || typeof error === "bigint"
          ? String(error) : "unknown error";
    const safeName = classDataValue(error, "name");
    const name = typeof safeName === "string" ? safeName : "";
    const combined = name && name !== "Error" && !raw.startsWith(name) ? `${name}: ${raw}` : raw;
    return stderrDiagnostic(combined) || "unknown error";
  } catch {
    return "unknown error";
  }
}

/** Fixed-vocabulary event label for failure diagnostics. Never invokes event
 * accessors and never emits an attacker-controlled string. */
export function safeAuditEventLabel(event: unknown): string {
  const fields = snapshotOwnDataRecord(event);
  const name = fields && typeof fields.event === "string" && EVENT_NAMES.has(fields.event)
    ? fields.event : "unknown";
  const status = fields?.status === "success" || fields?.status === "failure"
    ? fields.status : "unknown";
  return `${name}/${status}`;
}

// Line-breaking + terminal-control chars stripped from stderr diagnostics so an
// attacker-chosen client_id / provider text can't forge log lines or inject ANSI
// escapes: C0 (\x00-\x1f), DEL+C1 (\x7f-\x9f), and the Unicode line/paragraph
// separators. Built from code points so this source file holds NO literal line
// terminators (a literal U+2028/U+2029 would itself break parsing).
const STDERR_LINE_BREAKS = new RegExp("[\\x00-\\x1f\\x7f-\\x9f" + String.fromCodePoint(0x2028) + String.fromCodePoint(0x2029) + "]+", "g");

function stderrDiagnostic(input: string): string {
  return redactSecrets(input).slice(0, 200).replace(STDERR_LINE_BREAKS, " ").trim();
}

/** Single-line, secret-redacted form for arbitrary stderr diagnostics that may be
 *  attacker- or provider-controlled (a stateless `client_id`, an IdP
 *  `error_description`). Strips control chars so a value can't forge extra log
 *  lines (log injection), bounds length, then redacts secret-shaped substrings via
 *  `redactSecrets` (§17.7, threat-model #14). Best-effort, over-broad by design. */
export function redactForStderr(input: unknown): string {
  // Never throws — callers log inside their own catch (upstream-flow's exchange
  // catch), so a throw here (a hostile .message getter / toString on a thrown
  // value) would regress the §17.11 contract that any exchangeAndVerify throw is
  // classified exchange_failed. Mirrors safeErrorMessage's never-throw contract.
  // Redact BEFORE bounding: a secret starting near the cap must be fully matched
  // (≥32 chars) before slice() can fragment it below the opaque-token threshold.
  try {
    return stderrDiagnostic(String(input ?? ""));
  } catch {
    return "[redacted]";
  }
}
