// redactSecrets / safeErrorMessage — the stderr redaction primitive shared by
// both audit sinks (threat-model #14). Pins the patterns that MUST be redacted
// before an error message reaches stderr, and the diagnostic passthrough for
// benign messages (so redaction is not a blank wall).

import assert from "node:assert/strict";
import { test } from "node:test";
import { redactSecrets, safeErrorMessage, redactForStderr } from "../src/audit/util.ts";

test("redactSecrets: strips Bearer credentials", () => {
  const out = redactSecrets("auth failed: Bearer eyJhbGci.payload.sig more text");
  assert.equal(out.includes("eyJhbGci.payload.sig"), false, "bearer token leaked");
  assert.equal(out.includes("Bearer"), false, "'Bearer ' prefix leaked");
  assert.ok(out.includes("[redacted]"), "redaction marker present");
});

test("redactSecrets: strips token=/secret=/password= assignments", () => {
  for (const raw of [
    "token=abc123XYZ",
    "secret=hidden_value",
    "password=hunter2",
    "api_key=AKIA-something",
    "authorization: BearerXYZ",
  ]) {
    const out = redactSecrets(raw);
    assert.equal(out.includes("hidden_value"), false, `${raw}: value leaked`);
    assert.equal(out.includes("hunter2"), false, `${raw}: value leaked`);
  }
});

test("redactSecrets: strips underscored OAuth compound keys (access_token, refresh_token, id_token, client_secret)", () => {
  // \b before token/secret does not match after `_`, so these previously leaked.
  // The lookbehind treats `_`/`-` as separators. Short values must also go.
  const cases: Array<[string, string]> = [
    ["access_token=abc123SECRET", "abc123SECRET"],
    ["refresh_token=rt_xyzVALUE", "rt_xyzVALUE"],
    ["id_token=eyJpayloadVALUE", "eyJpayloadVALUE"],
    ["client_secret=shh", "shh"],
    ["access-token=dash-val-HERE", "dash-val-HERE"],
  ];
  for (const [raw, secret] of cases) {
    const out = redactSecrets(raw);
    assert.equal(out.includes(secret), false, `${raw}: value '${secret}' leaked (got: ${out})`);
  }
});

test("redactSecrets: strips long opaque runs (tokens/hashes) but not short identifiers", () => {
  const token = "rt." + "a".repeat(48) + "." + "b".repeat(48);
  const out = redactSecrets(`refresh ${token} rejected`);
  assert.equal(out.includes("a".repeat(48)), false, "long run leaked");
  assert.equal(out.includes("b".repeat(48)), false, "long run leaked");
  // Short identifiers / hostnames survive (diagnostic value preserved).
  const benign = redactSecrets("ECONNREFUSED siem.test ENOTDIR 127.0.0.1");
  assert.equal(benign, "ECONNREFUSED siem.test ENOTDIR 127.0.0.1");
});

test("redactSecrets: benign diagnostic messages pass through unchanged", () => {
  for (const raw of ["network down", "timeout", "ENOTDIR: not a directory", "The operation was aborted due to timeout"]) {
    assert.equal(redactSecrets(raw), raw);
  }
});

test("safeErrorMessage: includes the error name when more specific than 'Error'", () => {
  const e = Object.assign(new Error("aborted due to timeout"), { name: "TimeoutError" });
  assert.equal(safeErrorMessage(e), "TimeoutError: aborted due to timeout");
});

test("safeErrorMessage: omits a plain 'Error' name, redacts the message", () => {
  const out = safeErrorMessage(new Error("network down token=supersecretvalue"));
  assert.equal(out.includes("supersecretvalue"), false);
  assert.ok(out.includes("network down"));
});

test("safeErrorMessage: handles non-Error throws and never throws itself", () => {
  // null/undefined fall through to the "unknown error" fallback rather than
  // logging the literal string "null"/"undefined".
  assert.equal(safeErrorMessage(undefined), "unknown error");
  assert.equal(safeErrorMessage(null), "unknown error");
  assert.equal(safeErrorMessage("plain string"), "plain string");
  assert.ok(safeErrorMessage({}).length > 0);
});

test("safeErrorMessage: never throws on a hostile error (throwing message/name getter or toString)", () => {
  // A deployer-supplied fetchImpl (or a throwing toJSON) could yield a value
  // whose .message getter or .toString throws. safeErrorMessage must NOT
  // propagate that — both sinks call it inside their catch, so a throw would
  // reject writeAuthEvent and turn an audit write into an auth 500.
  const hostileGetter = {
    get message() { throw new Error("boom in message getter"); },
    get name() { throw new Error("boom in name getter"); },
  };
  assert.equal(safeErrorMessage(hostileGetter), "unknown error");
  const hostileToString = { toString() { throw new Error("toString boom"); } };
  assert.equal(safeErrorMessage(hostileToString), "unknown error");
});

test("safeErrorMessage: a long opaque password embedded in a userinfo URL is redacted", () => {
  // Defense-in-depth: a long secret in a URL-shaped message is caught by the
  // opaque-run rule. (Short `user:pass@` values are NOT caught by the regex —
  // which is exactly why WebhookAudit rejects userinfo at construction.)
  const msg = `TypeError: fetch failed for https://user:${"p".repeat(48)}@siem.test/ingest`;
  const out = safeErrorMessage(msg);
  assert.equal(out.includes("p".repeat(48)), false, "long password leaked");
});

test("redactForStderr: strips control chars (log-injection safe) and redacts secrets", () => {
  // an attacker-controlled client_id / a provider error_description with newlines
  // cannot forge extra log lines (CRLF injection into the stderr log).
  const injected = redactForStderr("ok\n[FAKE] log line\rhere");
  assert.equal(injected.includes("\n"), false, "newline survived — log injection");
  assert.equal(injected.includes("\r"), false, "CR survived — log injection");
  assert.equal(injected, "ok [FAKE] log line here", "control chars collapsed to spaces — one line, no forged entry");
  // a secret-shaped IdP error_description is redacted before it reaches stderr.
  const secret = redactForStderr("invalid_client — token=supersecretvalueXYZ");
  assert.equal(secret.includes("supersecretvalueXYZ"), false, "secret leaked to stderr");
  assert.ok(secret.includes("[redacted]"), "redaction marker present");
});

test("redactForStderr: never throws on a hostile value (throwing message getter / toString)", () => {
  // upstream-flow logs inside its exchange catch, so a throw here would regress the
  // §17.11 contract that any exchangeAndVerify throw is classified exchange_failed.
  const hostileGetter = { get message() { throw new Error("boom in message getter"); }, toString() { throw new Error("toString boom"); } };
  const out = redactForStderr(hostileGetter);
  assert.equal(typeof out, "string");
  assert.ok(out.length > 0, "fell back to a fixed string instead of throwing");
  assert.equal(redactForStderr(undefined), "", "undefined passes through (String('') )");
});

test("redactForStderr: redacts BEFORE bounding — a long opaque token near the cap is not fragmented past the threshold", () => {
  // slice-before-redact would cut a ≥32-char opaque token below the threshold and
  // leak the fragment; redact-then-bound redacts the full token first.
  const token = "SECRET" + "t".repeat(60); // 66-char opaque run starting at char 180 (past the 200 cap)
  const out = redactForStderr("x".repeat(180) + token);
  assert.equal(out.includes("SECRET"), false, "opaque token leaked — bounded before redaction fragmented it below the threshold");
  assert.equal(out.includes(token), false, "full token leaked");
});

test("redactSecrets: strips OAuth authorization-code request fields (code=, code_verifier=)", () => {
  // §17.11: authorization codes + PKCE verifiers are never logged. A transport that
  // echoes the failed token-request body would otherwise leak them — they are short /
  // dotted, so the opaque-run rule does not catch them.
  const body = "grant_type=authorization_code&code=ac_ABC.def-123&code_verifier=dBjfrN3";
  const out = redactSecrets(body);
  assert.equal(out.includes("ac_ABC.def-123"), false, "authorization code leaked");
  assert.equal(out.includes("dBjfrN3"), false, "code_verifier leaked");
  assert.ok(out.includes("[redacted]"), "redaction marker present");
});

test("redactSecrets: strips Authorization: Basic credentials (short base64 id:secret)", () => {
  // The assignment pattern stops at whitespace, so "Authorization: Basic <b64>" would
  // leave the (short, <32) encoded client_secret_basic creds on stderr.
  const creds = Buffer.from("mcpdc_id:shh").toString("base64"); // short (<32) so the opaque-run rule doesn't catch it
  const out = redactSecrets(`exchange failed: Authorization: Basic ${creds}`);
  assert.equal(out.includes(creds), false, "Basic credentials leaked (assignment pattern stopped at whitespace)");
  assert.ok(out.includes("[redacted]"), "redaction marker present");
});

test("redactSecrets: strips quoted JSON keys (code / access_token in a JSON-shaped diagnostic)", () => {
  // The key=value patterns must handle JSON's quoted-key form ("key":"value"), not
  // just form-encoded (key=value), or short values in a thrown JSON diagnostic survive.
  const out = redactSecrets('exchange failed: {"code":"ac_ABC.def-123","access_token":"ATKshort"}');
  assert.equal(out.includes("ac_ABC.def-123"), false, "JSON code value leaked");
  assert.equal(out.includes("ATKshort"), false, "JSON access_token value leaked");
  assert.ok(out.includes("[redacted]"), "redaction marker present");
});

test("redactSecrets: consumes Basic scheme + creds in header / assignment / JSON forms", () => {
  // A transport's stringifier emits the Authorization header in any of these shapes;
  // the scheme + creds must be consumed together or the short (<32) base64
  // client_secret_basic credential leaks past the assignment pattern (stops at whitespace).
  const creds = Buffer.from("mcpdc_id:shh").toString("base64"); // short (<32) so the opaque-run rule doesn't catch it
  for (const raw of [`Authorization: Basic ${creds}`, `authorization=Basic ${creds}`, `{"authorization":"Basic ${creds}"}`]) {
    assert.equal(redactSecrets(raw).includes(creds), false, `${raw}: Basic credentials leaked`);
  }
});
