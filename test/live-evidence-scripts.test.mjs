import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const PROBE = readFileSync(join(ROOT, "scripts/live/probe-e2e.mjs"), "utf8");
const CLOUDFLARE = readFileSync(join(ROOT, "scripts/live/probe-cloudflare.mjs"), "utf8");
const ENTRA = readFileSync(join(ROOT, "scripts/live/probe-entra.mjs"), "utf8");
const GOOGLE = readFileSync(join(ROOT, "scripts/live/probe-google.mjs"), "utf8");

test("live identity negative reaches verification after a valid client control", () => {
  const registerAt = CLOUDFLARE.indexOf("identity-negative fixture registers a valid client");
  const forgedAt = CLOUDFLARE.indexOf("const forgedRes");
  assert.ok(registerAt >= 0 && registerAt < forgedAt);
  assert.match(CLOUDFLARE, /const forgedRes[\s\S]*?url: `\/oauth\/authorize\?\$\{identityQuery\}`/);
  assert.match(CLOUDFLARE, /forgedRes\.statusCode === 401/);
});

test("live probe labels its machine credential as process-local", () => {
  assert.match(PROBE, /const machineRows = new Map\(\)/);
  assert.match(PROBE, /process-local MachineClientStore/);
  assert.doesNotMatch(PROBE, /provisioned into persistent SQLite/i);
  assert.doesNotMatch(PROBE, /SQLite-persisted machine credential/i);
});

test("live probes cannot turn an unexercised subject into passing evidence", () => {
  assert.doesNotMatch(PROBE, /\bSKIP\b/);
  assert.match(PROBE, /disableMachineClient\([\s\S]*?provisioned\.clientId,[\s\S]*?\);/);
  assert.doesNotMatch(PROBE, /disableMachineClient\([\s\S]*?\{\s*clientId:/);
  assert.match(PROBE, /audit-leak check has the \$\{name\} to inspect`, false/);
  assert.doesNotMatch(PROBE, /\["consent signing secret",\s*process\.env\.OAUTH_CONSENT_SIGNING_SECRET\]/);
  assert.doesNotMatch(PROBE, /OAUTH_CONSENT_SIGNING_SECRET[^\n]*(?:slice|substring|substr)/);
  assert.match(PROBE, /new StreamableHTTPClientTransport\(/);
  assert.match(PROBE, /new Client\(/);
  assert.match(PROBE, /await client\.connect\(transport\)/);
  assert.match(PROBE, /await client\.callTool\(/);
  assert.ok(PROBE.indexOf("await disableMachineClient(") < PROBE.indexOf("for (let i = 0; i < 12; i += 1)"));
  assert.match(PROBE, /afterDisable\.statusCode === 401 && afterDisableError === "invalid_client"/);
  assert.doesNotMatch(PROBE, /afterDisable\.statusCode >= 400/);
  assert.match(PROBE, /const requiredFlow = \[[\s\S]*?\["oauth\.client\.provision", "success"\][\s\S]*?\["oauth\.token\.client_credentials", "success"\][\s\S]*?\["auth\.request", "success"\][\s\S]*?\["oauth\.client\.disable", "success"\][\s\S]*?hasRequiredFlow\(fileEvents\)[\s\S]*?hasRequiredFlow\(posted\)/);
  assert.match(PROBE, /JSON\.stringify\(fileEvents\) === JSON\.stringify\(posted\)/);
});

test("Entra deny evidence is a mandatory input", () => {
  assert.match(ENTRA, /throw new Error\("ENTRA_UNMAPPED_GROUP must provide the deny-fixture GUID"\)/);
  assert.ok(ENTRA.indexOf("ENTRA_UNMAPPED_GROUP must provide the deny-fixture GUID") < ENTRA.indexOf("await buildExample(process.env)"));
  assert.doesNotMatch(ENTRA, /ENTRA_UNMAPPED_GROUP \?\? ""/);
  assert.match(ENTRA, /new Set\(groups\.map\(\(group\) => group\.toLowerCase\(\)\)\)[\s\S]*?!normalizedGroups\.has\(unmappedGroup\.toLowerCase\(\)\)/);
  assert.match(ENTRA, /createEntraRedirectIdentity[\s\S]*?groups: \[unmappedGroup\][\s\S]*?denyIdentity\.exchangeAndVerify/);
  assert.match(ENTRA, /denied\.kind === "identity_rejected" && denied\.reason === "entra_no_mapped_groups"/);
});

test("Google live metadata passes through the production preset", () => {
  assert.match(GOOGLE, /import \{ createGoogleIdentity, validateGoogleIdToken \}/);
  assert.match(GOOGLE, /createGoogleIdentity\(cfg, \{ discoveryFetch:[\s\S]*?json: async \(\) => structuredClone\(dj\)/);
  assert.match(GOOGLE, /builderDiscoveryUrl === "https:\/\/accounts\.google\.com\/\.well-known\/openid-configuration"/);
  assert.match(GOOGLE, /liveGoogle\.getAuthorizationUrl\(/);
  assert.match(GOOGLE, /"off-issuer authorization endpoint refused", \{ \.\.\.GOOD, authorization_endpoint: "https:\/\/evil\.test\/authorize" \}/);
  assert.match(GOOGLE, /"off-issuer token endpoint refused", \{ \.\.\.GOOD, token_endpoint: "https:\/\/evil\.test\/token" \}/);
  assert.match(GOOGLE, /"off-issuer JWKS endpoint refused", \{ \.\.\.GOOD, jwks_uri: "https:\/\/evil\.test\/jwks" \}/);
  assert.doesNotMatch(GOOGLE, /authorization_endpoint: "https:\/\/evil\.test\/authorize", token_endpoint:/);
  assert.match(GOOGLE, /"http authorization endpoint refused", \{ \.\.\.GOOD, authorization_endpoint: "http:\/\/accounts\.google\.com\/auth" \}/);
  assert.match(GOOGLE, /"http token endpoint refused", \{ \.\.\.GOOD, token_endpoint: "http:\/\/oauth2\.googleapis\.com\/token" \}/);
  assert.match(GOOGLE, /"http JWKS endpoint refused", \{ \.\.\.GOOD, jwks_uri: "http:\/\/www\.googleapis\.com\/oauth2\/v3\/certs" \}/);
});

test("discovered JWKS URLs are trusted before either probe follows them", () => {
  assert.ok(GOOGLE.indexOf("await createGoogleIdentity") < GOOGLE.indexOf("await fetch(dj.jwks_uri)"));
  assert.match(ENTRA, /const expectedJwks = entraJwksUrl\(tenant\);[\s\S]*?discJson\.jwks_uri !== expectedJwks[\s\S]*?await fetch\(expectedJwks\)/);
});
