import assert from "node:assert/strict";
import { test } from "node:test";
import { generateKeyPair, SignJWT } from "jose";
import {
  type CloudflareAccessConfig, assertHttpsTrustRoot, createCloudflareAccessIdentity,
  emailAllowed, validateCloudflareAccessClaims, verifyCloudflareAccessToken,
} from "../src/identity/cloudflare-access.ts";

const CONFIG: CloudflareAccessConfig = {
  audience: "aud-123",
  certsUrl: "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
  issuer: "https://team.cloudflareaccess.com",
};

const NOW = Math.floor(Date.parse("2026-07-03T12:00:00.000Z") / 1000);
// fixed verification time (well before the fixture token's exp) so the test is
// deterministic and independent of the wall clock.
const AT = { currentDate: new Date(NOW * 1000) };

test("createCloudflareAccessIdentity rejects an empty audience (fail-closed: jose skips the value match on a falsy audience)", () => {
  assert.throws(
    () => createCloudflareAccessIdentity({ audience: "", certsUrl: CONFIG.certsUrl, issuer: CONFIG.issuer }),
    /audience is required/,
  );
});

test("emailAllowed: case-insensitive, trimmed, rejects empty", () => {
  assert.equal(emailAllowed("user@example.com", ["user@example.com"]), true);
  assert.equal(emailAllowed("USER@Example.com", ["user@example.com"]), true);
  assert.equal(emailAllowed("  user@example.com  ", ["user@example.com"]), true);
  assert.equal(emailAllowed("other@example.com", ["user@example.com"]), false);
  assert.equal(emailAllowed("", ["user@example.com"]), false);
});

test("validateCloudflareAccessClaims: gates", () => {
  assert.equal(validateCloudflareAccessClaims({ email: "u@x.test", exp: NOW }, CONFIG).ok, true);
  const ok = validateCloudflareAccessClaims({ email: "u@x.test", exp: NOW, sub: "sub-1" }, CONFIG);
  assert.equal(ok.ok && ok.identity.subject, "sub-1"); // sub preferred over email
  const noSub = validateCloudflareAccessClaims({ email: "u@x.test", exp: NOW }, CONFIG);
  assert.equal(noSub.ok && noSub.identity.subject, "u@x.test"); // falls back to email
  assert.equal(validateCloudflareAccessClaims({ email: "u@x.test" }, CONFIG).ok, false); // no exp
  assert.equal(validateCloudflareAccessClaims({ exp: NOW }, CONFIG).ok, false); // no email
  const allowOk = validateCloudflareAccessClaims({ email: "u@x.test", exp: NOW }, { ...CONFIG, emailAllowlist: ["U@X.test"] });
  assert.equal(allowOk.ok, true); // case-insensitive allowlist
  const allowNo = validateCloudflareAccessClaims({ email: "u@x.test", exp: NOW }, { ...CONFIG, emailAllowlist: ["other@x.test"] });
  assert.equal(allowNo.ok, false); // not in allowlist
});

test("assertHttpsTrustRoot: raw prefix check before URL parsing (addendum 11)", () => {
  assert.doesNotThrow(() => assertHttpsTrustRoot("https://team.cloudflareaccess.com/certs", "certsUrl"));
  assert.throws(() => assertHttpsTrustRoot("http://team.cloudflareaccess.com/certs", "certsUrl"));
  assert.throws(() => assertHttpsTrustRoot("https:/team.cloudflareaccess.com", "certsUrl")); // Node would normalize this
});

test("createCloudflareAccessIdentity: rejects http trust roots at factory time", () => {
  assert.throws(() => createCloudflareAccessIdentity({ ...CONFIG, certsUrl: "http://team.cloudflareaccess.com/certs" }));
  assert.throws(() => createCloudflareAccessIdentity({ ...CONFIG, issuer: "http://team.cloudflareaccess.com" }));
  assert.doesNotThrow(() => createCloudflareAccessIdentity(CONFIG));
});

test("verifyCloudflareAccessToken: recorded fixture (known RS256 key, no JWKS fetch)", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const sign = (payload: Record<string, unknown>, opts: { aud?: string; iss?: string; exp?: number } = {}) =>
    new SignJWT(payload)
      .setProtectedHeader({ alg: "RS256", typ: "JWT" })
      .setAudience(opts.aud ?? CONFIG.audience)
      .setIssuer(opts.iss ?? CONFIG.issuer)
      .setIssuedAt(NOW)
      .setExpirationTime(opts.exp ?? NOW + 3600)
      .sign(privateKey);

  const good = await verifyCloudflareAccessToken(await sign({ email: "u@x.test", sub: "sub-1" }), publicKey, CONFIG, AT);
  assert.equal(good.ok, true);
  assert.equal(good.ok && good.identity.subject, "sub-1");
  assert.equal(good.ok && good.identity.claims?.email, "u@x.test");

  assert.equal((await verifyCloudflareAccessToken(await sign({ email: "u@x.test" }, { aud: "wrong" }), publicKey, CONFIG, AT)).ok, false); // wrong aud
  assert.equal((await verifyCloudflareAccessToken(await sign({ email: "u@x.test" }, { iss: "https://evil.test" }), publicKey, CONFIG, AT)).ok, false); // wrong iss
  assert.equal((await verifyCloudflareAccessToken(await sign({ email: "u@x.test" }, { exp: NOW - 120 }), publicKey, CONFIG, AT)).ok, false); // expired (> 60s clockTolerance)
  assert.equal((await verifyCloudflareAccessToken((await sign({ email: "u@x.test" })).slice(0, -3) + "xxx", publicKey, CONFIG, AT)).ok, false); // tampered
  assert.equal((await verifyCloudflareAccessToken(await sign({ sub: "sub-1" }), publicKey, CONFIG, AT)).ok, false); // missing email claim
  const allowCfg = { ...CONFIG, emailAllowlist: ["other@x.test"] };
  assert.equal((await verifyCloudflareAccessToken(await sign({ email: "u@x.test" }), publicKey, allowCfg, AT)).ok, false); // allowlist mismatch
});
