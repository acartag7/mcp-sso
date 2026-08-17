// Google + generic-OIDC legs against real provider infrastructure. No Google
// OAuth client is provisioned by the stacks, so this covers what does not need
// one: real discovery, real JWKS, the claim gate, and the discovery-host
// binding. Runs standalone — no stack values required.
import { createGoogleIdentity, validateGoogleIdToken } from "../../src/identity/google.ts";
import { createGenericOidcIdentity } from "../../src/identity/generic-oidc.ts";

const out = [];
const ok = (l, c, d = "") => { out.push(`${c ? "PASS" : "FAIL"}  ${l}${d ? " — " + d : ""}`); return c; };
let failures = 0;

const disc = await fetch("https://accounts.google.com/.well-known/openid-configuration");
const dj = await disc.json();
if (!ok("Google discovery resolves", disc.status === 200 && dj.issuer === "https://accounts.google.com", `issuer ${dj.issuer}`)) failures++;
const jwks = await fetch(dj.jwks_uri);
const jj = await jwks.json();
if (!ok("Google JWKS serves real signing keys", jwks.status === 200 && (jj.keys ?? []).length > 0, `${(jj.keys ?? []).length} keys`)) failures++;
if (!ok("Google advertises RS256", (dj.id_token_signing_alg_values_supported ?? []).includes("RS256"))) failures++;

const cfg = { clientId: "probe-client", clientSecret: "s", redirectUri: "https://app.test/cb" };
let builderDiscoveryUrl;
const liveGoogle = await createGoogleIdentity(cfg, { discoveryFetch: {
  async get(url) {
    builderDiscoveryUrl = url;
    return { status: disc.status, json: async () => structuredClone(dj) };
  },
} });
if (!ok("Google production preset requests the canonical discovery document",
  builderDiscoveryUrl === "https://accounts.google.com/.well-known/openid-configuration")) failures++;
const liveAuth = new URL(liveGoogle.getAuthorizationUrl({ state: "probe-state", nonce: "probe-nonce", codeChallenge: "A".repeat(43) }));
const advertisedAuth = new URL(dj.authorization_endpoint);
if (!ok("Google production preset accepts and uses the live authorization endpoint",
  liveAuth.origin === advertisedAuth.origin && liveAuth.pathname === advertisedAuth.pathname)) failures++;

const base = { iss: "https://accounts.google.com", aud: "probe-client", sub: "1234567890", exp: 1_900_000_000, iat: 1_800_000_000 };
for (const [label, payload] of [
  ["a lookalike Google issuer is refused", { ...base, iss: "https://accounts.google.com.evil.test" }],
  ["a token for another audience is refused", { ...base, aud: "someone-else" }],
  ["a multi-audience token is refused", { ...base, aud: ["probe-client", "other"] }],
]) {
  const r = validateGoogleIdToken(payload, cfg);
  if (!ok(label, r.ok === false, r.ok ? "ACCEPTED" : r.reason)) failures++;
}
const good = validateGoogleIdToken({ ...base, email: "a@b.test", email_verified: true, name: "Ada" }, cfg);
if (!ok("a well-formed Google token yields the raw sub as subject", good.ok && good.identity.subject === "1234567890")) failures++;
if (!ok("claims.name surfaces for a verified Google identity", good.ok && good.identity.claims?.name === "Ada")) failures++;

// Discovery-host binding. The transport shape matters: an ill-shaped mock throws
// for the wrong reason and would look like the guard firing.
const ISS = "https://accounts.google.com";
const mk = (doc) => ({ get: async () => ({ status: 200, json: async () => doc }) });
const GOOD = {
  issuer: ISS, authorization_endpoint: `${ISS}/o/oauth2/v2/auth`,
  token_endpoint: "https://oauth2.googleapis.com/token",
  jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
  code_challenge_methods_supported: ["S256"], id_token_signing_alg_values_supported: ["RS256"],
};
for (const [label, doc, mustRefuse] of [
  ["off-issuer discovery endpoints refused", { ...GOOD, authorization_endpoint: "https://evil.test/authorize", token_endpoint: "https://evil.test/token", jwks_uri: "https://evil.test/jwks" }, true],
  ["mismatched document issuer refused", { ...GOOD, issuer: "https://evil.test" }, true],
  ["http (non-https) endpoint refused", { ...GOOD, authorization_endpoint: "http://accounts.google.com/auth" }, true],
  ["discovery without PKCE S256 refused", { ...GOOD, code_challenge_methods_supported: ["plain"] }, true],
  ["a complete genuine document is accepted", GOOD, false],
]) {
  let refused = false, why = "";
  try { await createGenericOidcIdentity({ issuer: ISS, clientId: "probe", clientSecret: "s", redirectUri: "https://app.test/cb", endpoints: "discover" }, { discoveryFetch: mk(doc) }); }
  catch (e) { refused = true; why = String(e.message).slice(0, 64); }
  if (!ok(label, refused === mustRefuse, refused ? why : "accepted")) failures++;
}

console.log(out.join("\n"));
console.log(`\n${out.filter((l) => l.startsWith("PASS")).length}/${out.length} checks passed`);
process.exit(failures > 0 ? 1 : 0);
