import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { exportJWK, generateKeyPair } from "jose";
import { countUsableRs256Keys } from "../scripts/live/probe-entra-support.mjs";
import { resolveFetchedGoogleDiscovery } from "../scripts/live/probe-google-support.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const PROBE = readFileSync(join(ROOT, "scripts/live/probe-google.mjs"), "utf8");

const GOOD_DISCOVERY = {
  issuer: "https://accounts.google.com",
  authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
  token_endpoint: "https://oauth2.googleapis.com/token",
  jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
  code_challenge_methods_supported: ["S256"],
  id_token_signing_alg_values_supported: ["RS256"],
  token_endpoint_auth_methods_supported: ["client_secret_post"],
};
const response = (body, status = 200) => ({ status, async json() { return body; } });

test("Google credentials and client redirect are required before provider reads", () => {
  const credentialAt = PROBE.indexOf("const required =");
  const redirectAt = PROBE.indexOf("PROBE_CLIENT_REDIRECT must be a web redirect URL the effective allowlist admits");
  const buildAt = PROBE.indexOf("await buildExample(isolatedEnv)");
  const fetchAt = PROBE.indexOf("await defaultDiscoveryTransport.get(");
  assert.ok(credentialAt >= 0 && credentialAt < buildAt && credentialAt < fetchAt);
  assert.ok(redirectAt >= 0 && redirectAt < buildAt && redirectAt < fetchAt);
  assert.match(PROBE, /GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI"/);
  assert.match(PROBE, /typeof process\.env\[name\] !== "string" \|\| process\.env\[name\]\.length === 0/);
  assert.match(PROBE, /assertProbeClientRedirect\(process\.env\.PROBE_CLIENT_REDIRECT\)/);
});

test("Google evidence validates the exact discovery response before following JWKS", async () => {
  const factoryAt = PROBE.indexOf("await buildExample(isolatedEnv)");
  const fetchAt = PROBE.indexOf("await defaultDiscoveryTransport.get(");
  const validateAt = PROBE.indexOf("await resolveFetchedGoogleDiscovery(discoveryResponse)");
  const jwksAt = PROBE.indexOf("await fetchJson(resolved.jwksUri)");
  assert.ok(factoryAt >= 0 && factoryAt < fetchAt && fetchAt < validateAt && validateAt < jwksAt);
  assert.doesNotMatch(PROBE, /await fetch\(/);
  assert.doesNotMatch(PROBE, /dj\.jwks_uri|discoveryJson\.jwks_uri/);
  assert.equal((await resolveFetchedGoogleDiscovery(response(GOOD_DISCOVERY))).jwksUri,
    GOOD_DISCOVERY.jwks_uri);
  for (const changed of [
    { ...GOOD_DISCOVERY, issuer: "https://accounts.google.com.evil.test" },
    { ...GOOD_DISCOVERY, authorization_endpoint: "https://evil.test/authorize" },
    { ...GOOD_DISCOVERY, token_endpoint: "https://evil.test/token" },
    { ...GOOD_DISCOVERY, jwks_uri: "https://evil.test/jwks" },
    { ...GOOD_DISCOVERY, code_challenge_methods_supported: ["plain"] },
  ]) {
    await assert.rejects(resolveFetchedGoogleDiscovery(response(changed)));
  }
  await assert.rejects(resolveFetchedGoogleDiscovery(response(GOOD_DISCOVERY, 302)));
});

test("Google JWKS evidence requires a runtime-usable RS256 public key", async () => {
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
  assert.match(PROBE, /const usableKeys = await countUsableRs256Keys\(jwks\.body\)/);
  assert.match(PROBE, /jwks\.status === 200 && usableKeys > 0/);
});

test("Google redirect proof uses the deployed scope and provisioned identity", () => {
  assert.match(PROBE, /const probeScope = built\.config\.scopeCatalog\[0\]/);
  assert.match(PROBE, /scope: probeScope/);
  assert.doesNotMatch(PROBE, /scope: "mcp:read"/);
  assert.match(PROBE, /targetBase\.search = "";[\s\S]*?targetBase\.hash = "";/);
  assert.match(PROBE, /advertisedIsBare && targetBase\?\.href === advertised\.href/);
  assert.match(PROBE, /target\?\.searchParams\.get\("client_id"\) === process\.env\.GOOGLE_CLIENT_ID/);
  assert.match(PROBE, /target\?\.searchParams\.get\("redirect_uri"\) === process\.env\.GOOGLE_REDIRECT_URI/);
});

test("Google probe contains no generic OIDC or synthetic claim PASS rows", () => {
  assert.doesNotMatch(PROBE, /createGenericOidcIdentity|validateGoogleIdToken/);
  assert.doesNotMatch(PROBE, /GENERIC_ISS|idp\.example\.test|local control|CONTROL/);
});

test("Google DCR state is disposable and output is identifier-free on every exit", () => {
  const stateAt = PROBE.indexOf('await mkdtemp(join(tmpdir(), "mcp-sso-live-google-"))');
  const buildAt = PROBE.indexOf("await buildExample(isolatedEnv)");
  const closeAt = PROBE.indexOf("await app.close()");
  const storeCloseAt = PROBE.indexOf("await store.close()");
  const removeAt = PROBE.indexOf("await rm(stateDir, { recursive: true, force: true })");
  assert.ok(stateAt >= 0 && stateAt < buildAt);
  assert.ok(closeAt >= 0 && closeAt < storeCloseAt && storeCloseAt < removeAt);
  assert.match(PROBE, /MCP_SSO_DIR: stateDir,[\s\S]*?OAUTH_SQLITE_FILE: join\(stateDir, "auth\.db"\)/);
  assert.match(PROBE, /catch \{[\s\S]*?FAIL  probe aborted before completion[\s\S]*?finally \{/);
  assert.match(PROBE, /} catch \{\s*failures\+\+;\s*out\.push\("FAIL  probe aborted before completion"\)/);
  assert.match(PROBE, /catch \{\s*failures\+\+;\s*out\.push\("FAIL  probe cleanup failed"\)/);
  assert.match(PROBE, /catch \{\s*failures\+\+;\s*out\.push\("FAIL  probe store cleanup failed"\)/);
  assert.match(PROBE, /catch \{\s*failures\+\+;\s*out\.push\("FAIL  probe state cleanup failed"\)/);
  assert.ok(PROBE.indexOf("finally {") < PROBE.indexOf('console.log(out.join("\\n"))'));
  assert.doesNotMatch(PROBE, /console\.(?:log|warn|error)\([^\n]*(?:GOOGLE_|clientId|location|target|error|message)/);
  assert.match(PROBE, /process\.exitCode = failures > 0 \? 1 : 0/);
  assert.doesNotMatch(PROBE, /process\.exit\(/);
});

test("Google probe preflights its callback against the effective allowlist", () => {
  // A scheme-only check passes a valid https URL that the allowlist refuses,
  // so the probe would spend provider I/O before /oauth/register rejects it.
  assert.match(PROBE, /assertProbeClientRedirect\(process\.env\.PROBE_CLIENT_REDIRECT\)/);
  assert.doesNotMatch(PROBE, /assertRegistrationRedirectPolicy/);
  const preflightAt = PROBE.indexOf("assertProbeClientRedirect(process.env.PROBE_CLIENT_REDIRECT)");
  const buildAt = PROBE.indexOf("await buildExample(");
  assert.ok(preflightAt >= 0 && preflightAt < buildAt);
});
