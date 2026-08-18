import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { exportJWK, generateKeyPair } from "jose";
import {
  countUsableRs256Keys, fetchJson, hasExpectedSignedFlowLifetime,
  matchesUpstreamCookieProfile, upstreamCookieValue,
} from "../scripts/live/probe-entra-support.mjs";
import { signFlowToken } from "../src/adapters/upstream-flow-internals.ts";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const PROBE = readFileSync(join(ROOT, "scripts/live/probe-entra.mjs"), "utf8");
const SUPPORT = readFileSync(join(ROOT, "scripts/live/probe-entra-support.mjs"), "utf8");

test("Entra-owned fixtures are parsed before boot or provider reads", () => {
  const denyRequiredAt = PROBE.indexOf("ENTRA_UNMAPPED_GROUP must provide the deny-fixture GUID");
  const mappingRequiredAt = PROBE.indexOf("ENTRA_GROUP_AUTHORIZATION_JSON must provide a valid group mapping");
  const mappingAbsentAt = PROBE.indexOf("ENTRA_UNMAPPED_GROUP must be absent from the group mapping");
  const redirectRequiredAt = PROBE.indexOf("PROBE_CLIENT_REDIRECT must provide a valid web redirect URL");
  const buildAt = PROBE.indexOf("await buildExample(");
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

test("Entra cookie evidence accepts exactly the issuer's supported profile and signed TTL", async () => {
  const secureCookie = "__Host-mcp-sso-upstream=value; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300";
  const loopbackCookie = "mcp-sso-upstream=value; Path=/; HttpOnly; SameSite=Lax; Max-Age=300";
  assert.equal(matchesUpstreamCookieProfile(secureCookie, "https://sso.example.test", 300), true);
  assert.equal(matchesUpstreamCookieProfile(loopbackCookie, "http://127.0.0.1:3000", 300), true);
  for (const [cookie, issuer] of [
    [secureCookie.replace("; Secure", ""), "https://sso.example.test"],
    [loopbackCookie.replace("; HttpOnly", "; Secure; HttpOnly"), "http://localhost:3000"],
    [secureCookie.replace("__Host-", ""), "https://sso.example.test"],
    [loopbackCookie.replace("mcp-sso-upstream", "__Host-mcp-sso-upstream"), "http://localhost:3000"],
    [secureCookie.replace("; HttpOnly", ""), "https://sso.example.test"],
    [`${secureCookie}; Domain=example.test`, "https://sso.example.test"],
  ]) {
    assert.equal(matchesUpstreamCookieProfile(cookie, issuer, 300), false);
  }
  assert.equal(matchesUpstreamCookieProfile(secureCookie, "not a URL", 300), false);
  assert.equal(matchesUpstreamCookieProfile(loopbackCookie, "http://sso.example.test", 300), false);
  assert.equal(matchesUpstreamCookieProfile(secureCookie.replace("300", "0"), "https://sso.example.test", 300), false);
  assert.equal(matchesUpstreamCookieProfile(secureCookie.replace("300", "301"), "https://sso.example.test", 300), false);
  assert.equal(matchesUpstreamCookieProfile(secureCookie, "https://sso.example.test", 0), false);
  assert.equal(matchesUpstreamCookieProfile(secureCookie, "https://sso.example.test", 3_601), false);
  assert.equal(matchesUpstreamCookieProfile(secureCookie, "https://sso.example.test", 301), false);
  assert.match(PROBE, /matchesUpstreamCookieProfile\(cookie, built\.config\.issuer, 600\)/);
  assert.doesNotMatch(PROBE, /cookie\.includes\("__Host-"\)/);

  assert.equal(upstreamCookieValue(secureCookie), "value");
  assert.equal(upstreamCookieValue("mcp-sso-upstream=; Path=/"), undefined);
  const secret = "synthetic-flow-secret-for-live-probe-tests";
  const issuer = "https://sso.example.test";
  const callbackPath = "/oauth/callback";
  const token = await signFlowToken({
    secret, issuer, callbackPath, clock: { nowMs: () => 2_000_000_000_000 },
    jti: "upf_synthetic", state: "state", nonce: "nonce",
    codeVerifier: "V".repeat(43), params: {}, ttlSeconds: 600,
  });
  assert.equal(await hasExpectedSignedFlowLifetime(token, secret, issuer, callbackPath, 600), true);
  assert.equal(await hasExpectedSignedFlowLifetime(token, secret, issuer, callbackPath, 601), false);
  assert.equal(await hasExpectedSignedFlowLifetime(token, `${secret}-wrong`, issuer, callbackPath, 600), false);
  assert.equal(await hasExpectedSignedFlowLifetime(`${token}x`, secret, issuer, callbackPath, 600), false);
  assert.match(PROBE, /upstreamCookieValue\(cookie\), built\.config\.consentSigningSecret/);
  assert.match(PROBE, /built\.config\.issuer, callbackPath, 600/);
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

test("Entra DCR registration uses disposable state on every exit", () => {
  const stateAt = PROBE.indexOf('await mkdtemp(join(tmpdir(), "mcp-sso-live-entra-"))');
  const buildAt = PROBE.indexOf("await buildExample(isolatedEnv)");
  const closeAt = PROBE.indexOf("await app.close()");
  const storeCloseAt = PROBE.indexOf("await store.close()");
  const removeAt = PROBE.indexOf("await rm(stateDir, { recursive: true, force: true })");
  assert.ok(stateAt >= 0 && stateAt < buildAt);
  assert.ok(closeAt >= 0 && closeAt < storeCloseAt && storeCloseAt < removeAt);
  assert.match(PROBE, /MCP_SSO_DIR: stateDir,[\s\S]*?OAUTH_SQLITE_FILE: join\(stateDir, "auth\.db"\)/);
  assert.match(PROBE, /store = built\.store/);
  assert.match(PROBE, /finally \{[\s\S]*?await app\.close\(\)[\s\S]*?await store\.close\(\)[\s\S]*?await rm\(stateDir, \{ recursive: true, force: true \}\)/);
  assert.match(PROBE, /FAIL  probe store cleanup failed/);
  assert.match(PROBE, /FAIL  probe state cleanup failed/);
  assert.doesNotMatch(PROBE, /buildExample\(process\.env\)/);
});

test("Entra probe emits no tenant identifier and drains output", () => {
  assert.doesNotMatch(PROBE, /`\$\{target\.origin\}\$\{target\.pathname\}`/);
  assert.doesNotMatch(PROBE, /console\.(?:log|warn|error)\([^\n]*(?:tenant|unmappedGroup|denyToken)/);
  assert.match(PROBE, /try \{[\s\S]*?const built = await buildExample\(/);
  assert.match(PROBE, /catch \{[\s\S]*?FAIL  probe aborted before completion[\s\S]*?finally \{/);
  assert.match(PROBE, /catch \{\s*failures\+\+;\s*out\.push\("FAIL  probe cleanup failed"\)/);
  assert.ok(PROBE.indexOf('finally {') < PROBE.indexOf('console.log(out.join("\\n"))'));
  assert.doesNotMatch(PROBE, /catch \([^)]*\)[\s\S]*?console\.(?:log|warn|error)\([^\n]*(?:error|message)/);
  assert.match(PROBE, /process\.exitCode = failures > 0 \? 1 : 0/);
  assert.doesNotMatch(PROBE, /process\.exit\(/);
});
