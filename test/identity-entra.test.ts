import assert from "node:assert/strict";
import { test } from "node:test";
import { generateKeyPair, SignJWT } from "jose";
import {
  type EntraConfig, type EntraTokenTransport, createEntraIdentity, entraIssuer,
  exchangeCodeForToken, getAuthorizationUrl, subjectAllowed, validateEntraIdToken,
  verifyEntraIdToken,
} from "../src/identity/entra.ts";

const CONFIG: EntraConfig = {
  tenantId: "11111111-2222-3333-4444-555555555555",
  clientId: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  redirectUri: "https://bridge.test/oauth/entra/callback",
};
const NOW = Math.floor(Date.parse("2026-07-03T12:00:00.000Z") / 1000);
const AT = { currentDate: new Date(NOW * 1000) };

test("entra endpoints are https and tenant-derived", () => {
  assert.equal(entraIssuer(CONFIG.tenantId), `https://login.microsoftonline.com/${CONFIG.tenantId}/v2.0`);
  assert.equal(getAuthorizationUrl(CONFIG, { state: "s1", codeChallenge: "challenge-value" }),
    `https://login.microsoftonline.com/${CONFIG.tenantId}/oauth2/v2.0/authorize?client_id=${CONFIG.clientId}&response_type=code&redirect_uri=${encodeURIComponent(CONFIG.redirectUri)}&response_mode=query&scope=openid+profile+email+offline_access&state=s1&code_challenge=challenge-value&code_challenge_method=S256`);
});

test("validateEntraIdToken: iss/aud/tid gates + subject extraction", () => {
  const good = { iss: entraIssuer(CONFIG.tenantId), aud: CONFIG.clientId, tid: CONFIG.tenantId, oid: "oid-abc", exp: NOW + 3600, iat: NOW };
  const ok = validateEntraIdToken(good, CONFIG);
  assert.equal(ok.ok, true);
  assert.equal(ok.ok && ok.identity.subject, "oid-abc"); // oid preferred
  assert.equal(ok.ok && ok.identity.claims?.email, undefined);

  assert.equal(validateEntraIdToken({ ...good, iss: "https://evil/v2.0" }, CONFIG).ok, false); // bad iss
  assert.equal(validateEntraIdToken({ ...good, aud: "other-client" }, CONFIG).ok, false); // bad aud
  assert.equal(validateEntraIdToken({ ...good, tid: "other-tenant" }, CONFIG).ok, false); // bad tid
  assert.equal(validateEntraIdToken({ ...good, exp: undefined }, CONFIG).ok, false); // no exp
  const noOid = validateEntraIdToken({ ...good, oid: undefined, preferred_username: "user@example.com" }, CONFIG);
  assert.equal(noOid.ok && noOid.identity.subject, "user@example.com"); // fallback to preferred_username

  const allow = { ...CONFIG, subjectAllowlist: ["user@example.com"] };
  assert.equal(validateEntraIdToken({ ...good, oid: undefined, preferred_username: "user@example.com" }, allow).ok, true); // allowlist match
  assert.equal(validateEntraIdToken({ ...good, oid: "someone-else" }, allow).ok, false); // not in allowlist
});

test("subjectAllowed: case-insensitive over oid/preferred_username/email", () => {
  assert.equal(subjectAllowed("ignored", { oid: "OID-1" }, ["oid-1"]), true);
  assert.equal(subjectAllowed("ignored", { preferred_username: "U@x.test" }, ["u@x.test"]), true);
  assert.equal(subjectAllowed("ignored", { email: "a@b.test" }, ["c@d.test"]), false);
});

test("verifyEntraIdToken: recorded fixture (known RS256 key, no JWKS fetch)", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const sign = (claims: Record<string, unknown>, opts?: { exp?: number }) =>
    new SignJWT(claims).setProtectedHeader({ alg: "RS256", typ: "JWT" })
      .setIssuedAt(NOW).setExpirationTime(opts?.exp ?? NOW + 3600).sign(privateKey);
  const baseClaims = { iss: entraIssuer(CONFIG.tenantId), aud: CONFIG.clientId, tid: CONFIG.tenantId, oid: "oid-xyz", email: "u@x.test" };

  const good = await verifyEntraIdToken(await sign(baseClaims), publicKey, CONFIG, AT.currentDate);
  assert.equal(good.ok, true);
  assert.equal(good.ok && good.identity.subject, "oid-xyz");

  assert.equal((await verifyEntraIdToken(await sign({ ...baseClaims, iss: "https://login.microsoftonline.com/other/v2.0" }), publicKey, CONFIG, AT.currentDate)).ok, false); // bad iss
  assert.equal((await verifyEntraIdToken(await sign({ ...baseClaims, aud: "other" }), publicKey, CONFIG, AT.currentDate)).ok, false); // bad aud
  assert.equal((await verifyEntraIdToken(await sign({ ...baseClaims, tid: "other" }), publicKey, CONFIG, AT.currentDate)).ok, false); // bad tid
  assert.equal((await verifyEntraIdToken(await sign(baseClaims, { exp: NOW - 120 }), publicKey, CONFIG, AT.currentDate)).ok, false); // expired
  assert.equal((await verifyEntraIdToken((await sign(baseClaims)).slice(0, -3) + "xxx", publicKey, CONFIG, AT.currentDate)).ok, false); // tampered
});

test("exchangeCodeForToken: posts to the token endpoint and returns the id_token", async () => {
  const fakeIdToken = "header.payload.sig";
  const transport: EntraTokenTransport = {
    async postForm(url, body) {
      assert.match(url, /\/oauth2\/v2\.0\/token$/);
      assert.equal(body.get("grant_type"), "authorization_code");
      assert.equal(body.get("code_verifier"), "verifier-123");
      return { status: 200, async text() { return JSON.stringify({ id_token: fakeIdToken }); } };
    },
  };
  const idToken = await exchangeCodeForToken(CONFIG, { code: "code-1", codeVerifier: "verifier-123" }, transport);
  assert.equal(idToken, fakeIdToken);
  const failing: EntraTokenTransport = { async postForm() { return { status: 400, async text() { return "{}"; } }; } };
  await assert.rejects(exchangeCodeForToken(CONFIG, { code: "c", codeVerifier: "v" }, failing));
});

test("createEntraIdentity: exposes the port and rejects a non-string id_token (no network)", async () => {
  const entra = createEntraIdentity(CONFIG);
  assert.match(entra.getAuthorizationUrl({ state: "s", codeChallenge: "c" }), /login\.microsoftonline\.com/);
  assert.equal((await entra.verify(undefined)).ok, false); // non-string id_token — returns before any JWKS fetch
});
