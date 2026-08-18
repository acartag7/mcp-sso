import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const PROBE = readFileSync(join(ROOT, "scripts/live/probe-cloudflare.mjs"), "utf8");

test("Cloudflare probe requires out-of-band provider evidence before boot", () => {
  const requiredAt = PROBE.indexOf("CF_ACCESS_ASSERTION must provide a current provider-signed assertion");
  const buildAt = PROBE.indexOf("await buildExample(process.env)");
  assert.ok(requiredAt >= 0 && requiredAt < buildAt);
  assert.match(PROBE, /typeof providerAssertion !== "string" \|\| providerAssertion\.length === 0/);
  assert.doesNotMatch(PROBE, /CF_ACCESS_ASSERTION \?\?/);
});

test("Cloudflare positive control precedes identity negatives", () => {
  const registrationAt = PROBE.indexOf("identity fixture registers a valid client");
  const acceptedAt = PROBE.indexOf("const accepted");
  const missingAt = PROBE.indexOf("const missing");
  const forgedAt = PROBE.indexOf("const forgedResult");
  assert.ok(registrationAt >= 0 && registrationAt < acceptedAt);
  assert.ok(acceptedAt < missingAt && missingAt < forgedAt);
  assert.match(PROBE, /headers: \{ "cf-access-jwt-assertion": providerAssertion \}/);
  assert.match(PROBE, /accepted\.statusCode === 200 && accepted\.body\.includes\("Authorize access"\)/);
  assert.match(PROBE, /client_id: clientId \?\? "fixture-registration-failed"/);
});

test("Cloudflare forged negative reuses the accepted provider key ID", () => {
  assert.match(PROBE, /decodeProtectedHeader\(providerAssertion\)/);
  assert.match(PROBE, /header\.alg === "RS256"[\s\S]*?typeof header\.kid === "string"/);
  assert.match(PROBE, /kid: providerKid \?\? "fixture-no-provider-kid"/);
  assert.match(PROBE, /forgedResult\.statusCode === 401/);
  assert.doesNotMatch(PROBE, /kid: "forged-key"/);
});

test("Cloudflare credential is not printed and evidence drains before exit", () => {
  assert.doesNotMatch(PROBE, /console\.(?:log|warn|error)\([^\n]*providerAssertion/);
  assert.match(PROBE, /process\.exitCode = failures > 0 \? 1 : 0/);
  assert.doesNotMatch(PROBE, /process\.exit\(/);
});
