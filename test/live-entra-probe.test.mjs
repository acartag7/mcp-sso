import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { exportJWK, generateKeyPair } from "jose";
import {
  countUsableRs256Keys, fetchJson,
} from "../scripts/live/probe-entra-support.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const PROBE = readFileSync(join(ROOT, "scripts/live/probe-entra.mjs"), "utf8");
const SUPPORT = readFileSync(join(ROOT, "scripts/live/probe-entra-support.mjs"), "utf8");

test("Entra-owned fixtures are parsed before boot or provider reads", () => {
  const denyRequiredAt = PROBE.indexOf("ENTRA_UNMAPPED_GROUP must provide the deny-fixture GUID");
  const mappingRequiredAt = PROBE.indexOf("ENTRA_GROUP_AUTHORIZATION_JSON must provide a valid group mapping");
  const mappingAbsentAt = PROBE.indexOf("ENTRA_UNMAPPED_GROUP must be absent from the group mapping");
  const redirectRequiredAt = PROBE.indexOf("PROBE_CLIENT_REDIRECT must provide a valid web redirect URL");
  const buildAt = PROBE.indexOf("await buildExample(process.env)");
  const fetchAt = PROBE.indexOf("await fetchJson(");
  assert.ok(denyRequiredAt >= 0 && denyRequiredAt < buildAt && denyRequiredAt < fetchAt);
  assert.ok(mappingRequiredAt >= 0 && mappingRequiredAt < buildAt && mappingRequiredAt < fetchAt);
  assert.ok(mappingAbsentAt >= 0 && mappingAbsentAt < buildAt && mappingAbsentAt < fetchAt);
  assert.ok(redirectRequiredAt >= 0 && redirectRequiredAt < buildAt && redirectRequiredAt < fetchAt);
  assert.match(PROBE, /typeof unmappedGroup !== "string" \|\| !guid\.test\(unmappedGroup\)/);
  assert.doesNotMatch(PROBE, /unmappedGroup !== undefined/);
  assert.doesNotMatch(PROBE, /ENTRA_UNMAPPED_GROUP \?\?/);
  assert.match(PROBE, /groupAuthorization = entraGroupAuthorizationFromEnv\(process\.env\);[\s\S]*?assertGroupAuthorizationMapping\(groupAuthorization\)/);
  assert.match(PROBE, /groupAuthorization === undefined/);
  assert.match(PROBE, /normalizedGroups\.has\(unmappedGroup\.toLowerCase\(\)\)/);
  assert.doesNotMatch(PROBE, /ENTRA_GROUP_AUTHORIZATION_JSON \?\? "\{\}"/);
  assert.match(PROBE, /redirect = assertRegistrationRedirectPolicy\(\s*process\.env\.PROBE_CLIENT_REDIRECT,\s*"web",\s*\)/);
  assert.doesNotMatch(PROBE, /const redirect = process\.env\.PROBE_CLIENT_REDIRECT/);
});

test("Entra redirect is bound to the discovered endpoint and registered client", () => {
  assert.match(PROBE, /client_id: clientId \?\? "fixture-registration-failed"/);
  assert.match(PROBE, /const probeScope = built\.config\.scopeCatalog\[0\]/);
  assert.match(PROBE, /scope: probeScope/);
  assert.doesNotMatch(PROBE, /scope: "mcp:read"/);
  assert.match(PROBE, /advertised\.username === ""[\s\S]*?advertised\.password === ""[\s\S]*?advertised\.search === ""[\s\S]*?advertised\.hash === ""/);
  assert.match(PROBE, /targetBase\.search = "";[\s\S]*?targetBase\.hash = "";/);
  assert.match(PROBE, /advertisedIsBare && targetBase\?\.href === advertised\.href/);
  assert.doesNotMatch(PROBE, /pathname[^\n]*startsWith/);
  assert.match(PROBE, /discoveryJson\.jwks_uri !== expectedJwks[\s\S]*?await fetchJson\(expectedJwks\)/);
});

test("Entra provider reads have hard deadlines", async () => {
  assert.match(SUPPORT, /redirect: "error"[\s\S]*?signal: AbortSignal\.timeout\(10_000\)[\s\S]*?body: await response\.json\(\)/);
  assert.equal((PROBE.match(/await fetchJson\(/g) ?? []).length, 2);
  assert.doesNotMatch(PROBE, /await fetch\(/);
  const originalFetch = globalThis.fetch;
  let options;
  globalThis.fetch = async (_url, init) => {
    options = init;
    return { status: 200, async json() { return { ok: true }; } };
  };
  try {
    assert.deepEqual(await fetchJson("https://provider.example.test/discovery"), {
      status: 200, body: { ok: true },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(options.redirect, "error");
  assert.equal(options.headers.accept, "application/json");
  assert.ok(options.signal instanceof AbortSignal);
});

test("Entra JWKS evidence requires a runtime-usable RS256 public key", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const publicJwk = { ...await exportJWK(publicKey), kid: "provider-key" };
  const privateJwk = { ...await exportJWK(privateKey), kid: "private-key" };
  assert.equal(await countUsableRs256Keys({ keys: [publicJwk] }), 1);
  for (const key of [
    { ...publicJwk, kid: undefined },
    { ...publicJwk, kid: "" },
    { ...publicJwk, use: "enc" },
    { ...publicJwk, alg: "RS512" },
    { ...publicJwk, key_ops: ["encrypt"] },
    { kty: "RSA", kid: "incomplete-key" },
    { ...privateJwk, key_ops: undefined },
  ]) {
    assert.equal(await countUsableRs256Keys({ keys: [key] }), 0);
  }
  assert.match(SUPPORT, /createLocalJWKSet\(\{ keys: \[key\] \}\)/);
  assert.match(SUPPORT, /typeof key\.kid !== "string" \|\| key\.kid\.length === 0\) continue/);
  assert.match(SUPPORT, /await resolveKey\(\{[\s\S]*?alg: "RS256"/);
  assert.match(SUPPORT, /kid: key\.kid/);
  assert.match(PROBE, /const usableKeys = await countUsableRs256Keys\(jwks\.body\)/);
  assert.match(PROBE, /Entra JWKS serves usable RS256 verification keys/);
  assert.match(PROBE, /jwks\.status === 200 && usableKeys > 0/);
  assert.doesNotMatch(PROBE, /\.filter\(\(key\) => key\.kty === "RSA"\)/);
});

test("Entra synthetic denial is a non-live control excluded from live counts", () => {
  assert.match(PROBE, /This does not prove that the tenant emits the group in a real token/);
  assert.match(PROBE, /groups: \[unmappedGroup\]/);
  assert.match(PROBE, /const groupOnlyAuthorization = \{\s*mapping: groupAuthorization\.mapping,\s*baseScopes: \[\],\s*\}/);
  assert.match(PROBE, /groupAuthorization: groupOnlyAuthorization/);
  assert.match(PROBE, /if \(!control\("local identity control rejects the unmapped group"/);
  assert.match(PROBE, /denied\.reason === "entra_no_mapped_groups"/);
  assert.match(PROBE, /startsWith\("CONTROL"\)/);
  assert.doesNotMatch(PROBE, /ok\("identity port rejects a verified token/);
});

test("Entra mapping preflight accepts every runtime-valid cardinality", () => {
  assert.doesNotMatch(PROBE, /at least two mapped groups/);
  assert.doesNotMatch(PROBE, /groups\.length/);
});

test("Entra probe emits no tenant identifier and drains output", () => {
  assert.doesNotMatch(PROBE, /`\$\{target\.origin\}\$\{target\.pathname\}`/);
  assert.doesNotMatch(PROBE, /console\.(?:log|warn|error)\([^\n]*(?:tenant|unmappedGroup|denyToken)/);
  assert.match(PROBE, /try \{\s*const built = await buildExample\(process\.env\)/);
  assert.match(PROBE, /catch \{[\s\S]*?FAIL  probe aborted before completion[\s\S]*?finally \{/);
  assert.match(PROBE, /catch \{\s*failures\+\+;\s*out\.push\("FAIL  probe cleanup failed"\)/);
  assert.ok(PROBE.indexOf('finally {') < PROBE.indexOf('console.log(out.join("\\n"))'));
  assert.doesNotMatch(PROBE, /catch \([^)]*\)[\s\S]*?console\.(?:log|warn|error)\([^\n]*(?:error|message)/);
  assert.match(PROBE, /process\.exitCode = failures > 0 \? 1 : 0/);
  assert.doesNotMatch(PROBE, /process\.exit\(/);
});
