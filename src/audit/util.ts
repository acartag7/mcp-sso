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

// Ordered most-specific first. Each replaces its match with "[redacted]".
const SECRET_PATTERNS = [
  /Bearer\s+[A-Za-z0-9._~+/=-]+/gi, // RFC 6750 bearer credentials
  // Authorization header with scheme + credentials (Basic/Digest/…). The assignment
  // pattern below stops at whitespace, so "Authorization: Basic <base64(id:secret)>"
  // would leave the (short, <32) encoded client_secret_basic creds on stderr. Run
  // BEFORE the assignment pattern so it consumes scheme + creds together.
  /(?<![A-Za-z0-9])authorization\s*[:]\s*[A-Za-z][A-Za-z0-9._-]*\s+[^\s"'&,;]+/gi,
  // key=value assignments. The lookbehind — NOT \b — treats `_` and `-` as
  // separators, so underscored OAuth compound keys also match: access_token=,
  // refresh_token=, id_token=, client_secret=. (\b would not match after `_`.)
  /(?<![A-Za-z0-9])(token|secret|secrets|password|passwd|api[_-]?key|apikey|authorization)\s*[=:]\s*["']?[^\s"'&,;]+/gi,
  // OAuth authorization-code request fields (§17.11: codes + PKCE verifiers are never
  // logged). A transport that echoes the failed token-request body would otherwise leak
  // them — they are short / dotted, so the opaque-run rule below does not catch them.
  /(?<![A-Za-z0-9_])(code_verifier|code)\s*[=:]\s*["']?[^\s"'&,;]+/gi,
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
    const e = error as { message?: unknown; name?: unknown } | null;
    const msg = redactSecrets(String(e?.message ?? error ?? "unknown error"));
    const name = typeof e?.name === "string" ? e.name : "";
    if (name && name !== "Error" && !msg.startsWith(name)) return `${name}: ${msg}`;
    return msg || "unknown error";
  } catch {
    return "unknown error";
  }
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
    return redactSecrets(String(input ?? "").replace(/[\x00-\x1f\x7f]+/g, " ")).slice(0, 200).trim();
  } catch {
    return "[redacted]";
  }
}
