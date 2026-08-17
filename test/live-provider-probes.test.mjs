import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLOUDFLARE = readFileSync(join(ROOT, "scripts/live/probe-cloudflare.mjs"), "utf8");
const ENTRA = readFileSync(join(ROOT, "scripts/live/probe-entra.mjs"), "utf8");
const GOOGLE = readFileSync(join(ROOT, "scripts/live/probe-google.mjs"), "utf8");

test("live identity negative reaches verification after a valid client control", () => {
  const registerAt = CLOUDFLARE.indexOf("identity-negative fixture registers a valid client");
  const forgedAt = CLOUDFLARE.indexOf("const forgedRes");
  assert.ok(registerAt >= 0 && registerAt < forgedAt);
  assert.match(CLOUDFLARE, /client_id: identityClientId \?\? "fixture-registration-failed"/);
  assert.match(CLOUDFLARE, /const forgedRes[\s\S]*?url: `\/oauth\/authorize\?\$\{identityQuery\}`/);
  assert.match(CLOUDFLARE, /forgedRes\.statusCode === 401/);
  assert.match(CLOUDFLARE, /statSync\(built\.dir\)/);
  assert.doesNotMatch(CLOUDFLARE, /statSync\(process\.env\.MCP_SSO_DIR\)/);
});

test("Entra deny evidence is required and exercised through the identity port", () => {
  assert.match(ENTRA, /throw new Error\("ENTRA_UNMAPPED_GROUP must provide the deny-fixture GUID"\)/);
  assert.ok(ENTRA.indexOf("ENTRA_UNMAPPED_GROUP must provide the deny-fixture GUID") < ENTRA.indexOf("await buildExample(process.env)"));
  assert.doesNotMatch(ENTRA, /ENTRA_UNMAPPED_GROUP \?\? ""/);
  assert.match(ENTRA, /new Set\(groups\.map\(\(group\) => group\.toLowerCase\(\)\)\)[\s\S]*?!normalizedGroups\.has\(unmappedGroup\.toLowerCase\(\)\)/);
  assert.match(ENTRA, /createEntraRedirectIdentity[\s\S]*?groups: \[unmappedGroup\][\s\S]*?denyIdentity\.exchangeAndVerify/);
  assert.match(ENTRA, /denied\.kind === "identity_rejected" && denied\.reason === "entra_no_mapped_groups"/);
  assert.match(ENTRA, /advertisedAuthorization[\s\S]*?u\.origin === advertisedAuthorization\.origin && u\.pathname === advertisedAuthorization\.pathname/);
  assert.doesNotMatch(ENTRA, /pathname[^\n]*startsWith\(`\/\$\{tenant\}\//);
});

test("Google production metadata checks cover each endpoint independently", () => {
  assert.match(GOOGLE, /import \{ createGoogleIdentity, validateGoogleIdToken \}/);
  assert.match(GOOGLE, /createGoogleIdentity\(cfg, \{ discoveryFetch:[\s\S]*?json: async \(\) => structuredClone\(dj\)/);
  assert.match(GOOGLE, /builderDiscoveryUrl === "https:\/\/accounts\.google\.com\/\.well-known\/openid-configuration"/);
  for (const field of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
    assert.match(GOOGLE, new RegExp(`off-issuer [^\\n]*${field.replace("_endpoint", " endpoint").replace("jwks_uri", "JWKS endpoint")}`, "i"));
  }
  assert.match(GOOGLE, /"http authorization endpoint refused"/);
  assert.match(GOOGLE, /"http token endpoint refused"/);
  assert.match(GOOGLE, /"http JWKS endpoint refused"/);
  assert.doesNotMatch(GOOGLE, /authorization_endpoint: "https:\/\/evil\.test\/authorize", token_endpoint:/);
  assert.match(GOOGLE, /const GENERIC_ISS = "https:\/\/idp\.example\.test"/);
  for (const field of ["authorization endpoint", "token endpoint", "JWKS endpoint"]) {
    assert.match(GOOGLE, new RegExp(`generic OIDC refuses an off-host ${field}`, "i"));
  }
  assert.match(GOOGLE, /generic OIDC accepts exact issuer-host endpoints/);
});

test("discovered JWKS URLs are trusted before either probe follows them", () => {
  assert.ok(GOOGLE.indexOf("await createGoogleIdentity") < GOOGLE.indexOf("await fetch(dj.jwks_uri)"));
  assert.match(ENTRA, /const expectedJwks = entraJwksUrl\(tenant\);[\s\S]*?discJson\.jwks_uri !== expectedJwks[\s\S]*?await fetch\(expectedJwks\)/);
});
