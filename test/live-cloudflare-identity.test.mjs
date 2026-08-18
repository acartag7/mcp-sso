import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const PROBE = readFileSync(join(ROOT, "scripts/live/probe-cloudflare.mjs"), "utf8");

test("Cloudflare probe requires out-of-band provider evidence before boot", () => {
  const requiredAt = PROBE.indexOf("CF_ACCESS_ASSERTION must provide a current provider-signed assertion");
  const buildAt = PROBE.indexOf("await buildExample(isolatedEnv)");
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
  assert.match(PROBE, /catch \{[\s\S]*?FAIL  probe aborted before completion[\s\S]*?finally \{/);
  assert.ok(PROBE.indexOf('finally {') < PROBE.indexOf('console.log(out.join("\\n"))'));
  assert.doesNotMatch(PROBE, /catch \([^)]*\)[\s\S]*?console\.(?:log|warn|error)\([^\n]*(?:error|message)/);
  assert.match(PROBE, /process\.exitCode = failures > 0 \? 1 : 0/);
  assert.doesNotMatch(PROBE, /process\.exit\(/);
});

test("Cloudflare DCR registration uses disposable state on every exit", () => {
  // The state helper's behaviour (a directory the library can create, disposed
  // with its container) is exercised in test/live-evidence-scripts.test.mjs.
  const stateAt = PROBE.indexOf('await createDisposableProbeState("mcp-sso-live-cloudflare-")');
  const buildAt = PROBE.indexOf("await buildExample(isolatedEnv)");
  const closeAt = PROBE.indexOf("await app.close()");
  const storeCloseAt = PROBE.indexOf("await store.close()");
  const removeAt = PROBE.indexOf("await disposable.dispose()");
  assert.ok(stateAt >= 0 && stateAt < buildAt);
  assert.ok(closeAt >= 0 && closeAt < storeCloseAt && storeCloseAt < removeAt);
  assert.match(PROBE, /\.\.\.process\.env,\n\s*\.\.\.disposable\.env,/);
  assert.doesNotMatch(PROBE, /mkdtemp|MCP_SSO_DIR: stateDir/);
  assert.match(PROBE, /store = built\.store/);
  assert.match(PROBE, /finally \{[\s\S]*?await app\.close\(\)[\s\S]*?await store\.close\(\)[\s\S]*?await disposable\.dispose\(\)/);
  assert.match(PROBE, /FAIL  probe store cleanup failed/);
  assert.match(PROBE, /FAIL  probe state cleanup failed/);
  assert.doesNotMatch(PROBE, /buildExample\(process\.env\)/);
});

test("Cloudflare probe validates its callback before any side effect", () => {
  const preflightAt = PROBE.indexOf("assertProbeClientRedirect(process.env.PROBE_APP_CALLBACK)");
  const buildAt = PROBE.indexOf("await buildExample(isolatedEnv)");
  assert.ok(preflightAt >= 0 && preflightAt < buildAt);
  assert.doesNotMatch(PROBE, /scope: "mcp:read"/);
  assert.match(PROBE, /const probeScope = built\.config\.scopeCatalog\[0\]/);
  assert.match(PROBE, /scope: probeScope/);
});

test("Cloudflare probe preflights its callback against the effective allowlist", () => {
  // A scheme-only check passes a valid https URL that the allowlist refuses,
  // so the probe would spend provider I/O before /oauth/register rejects it.
  assert.match(PROBE, /assertProbeClientRedirect\(process\.env\.PROBE_APP_CALLBACK\)/);
  assert.doesNotMatch(PROBE, /assertRegistrationRedirectPolicy/);
  const preflightAt = PROBE.indexOf("assertProbeClientRedirect(process.env.PROBE_APP_CALLBACK)");
  const buildAt = PROBE.indexOf("await buildExample(");
  assert.ok(preflightAt >= 0 && preflightAt < buildAt);
});
