import assert from "node:assert/strict";
import { test } from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
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
  assert.throws( // whitespace-only == missing config (contracts §6.5)
    () => createCloudflareAccessIdentity({ audience: "   ", certsUrl: CONFIG.certsUrl, issuer: CONFIG.issuer }),
    /audience is required/,
  );
});

test("verifyCloudflareAccessToken also rejects an empty audience (direct-library reuse — Codex P2 on PR #26)", async () => {
  // A VALID CF token (correct signature/iss/aud/email). Without the guard, jose with
  // audience:"" enforces aud-presence but skips the value match → accepts it (the bug).
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const token = await new SignJWT({ sub: "sub-1", email: "user@example.com" })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(CONFIG.issuer).setAudience("aud-123").setIssuedAt(NOW).setExpirationTime(NOW + 3600)
    .sign(privateKey);
  const result = await verifyCloudflareAccessToken(token, publicKey, { ...CONFIG, audience: "" });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, "access_jwt_verify_failed");
  const ws = await verifyCloudflareAccessToken(token, publicKey, { ...CONFIG, audience: "   " });
  assert.equal(ws.ok, false); // whitespace-only audience is also rejected
});

test("emailAllowed: case-insensitive, trimmed, rejects empty", () => {
  assert.equal(emailAllowed("user@example.com", ["user@example.com"]), true);
  assert.equal(emailAllowed("USER@Example.com", ["user@example.com"]), true);
  assert.equal(emailAllowed("  user@example.com  ", ["user@example.com"]), true);
  assert.equal(emailAllowed("other@example.com", ["user@example.com"]), false);
  assert.equal(emailAllowed("", ["user@example.com"]), false);
});

test("validateCloudflareAccessClaims: gates", () => {
  const claims = (value: Record<string, unknown>) => ({
    iss: CONFIG.issuer, aud: CONFIG.audience, ...value,
  });
  assert.equal(validateCloudflareAccessClaims(claims({ email: "u@x.test", exp: NOW }), CONFIG).ok, true);
  const ok = validateCloudflareAccessClaims(claims({ email: "u@x.test", exp: NOW, sub: "sub-1" }), CONFIG);
  assert.equal(ok.ok && ok.identity.subject, "sub-1"); // sub preferred over email
  const noSub = validateCloudflareAccessClaims(claims({ email: "u@x.test", exp: NOW }), CONFIG);
  assert.equal(noSub.ok && noSub.identity.subject, "u@x.test"); // falls back to email
  assert.equal(validateCloudflareAccessClaims(claims({ email: "u@x.test" }), CONFIG).ok, false); // no exp
  assert.equal(validateCloudflareAccessClaims(claims({ exp: NOW }), CONFIG).ok, false); // no email
  const allowOk = validateCloudflareAccessClaims(claims({ email: "u@x.test", exp: NOW }), { ...CONFIG, emailAllowlist: ["U@X.test"] });
  assert.equal(allowOk.ok, true); // case-insensitive allowlist
  const allowNo = validateCloudflareAccessClaims(claims({ email: "u@x.test", exp: NOW }), { ...CONFIG, emailAllowlist: ["other@x.test"] });
  assert.equal(allowNo.ok, false); // not in allowlist
});

test("validateCloudflareAccessClaims: claim and config decisions use own data only", () => {
  const inheritedClaims = Object.assign(
    Object.create({ email: "u@x.test", sub: "inherited-sub" }),
    { iss: CONFIG.issuer, aud: CONFIG.audience, exp: NOW },
  ) as never;
  const inheritedResult = validateCloudflareAccessClaims(inheritedClaims, CONFIG);
  assert.equal(inheritedResult.ok, false);
  if (!inheritedResult.ok) assert.equal(inheritedResult.reason, "access_jwt_email_not_allowed");

  let reads = 0;
  const accessorClaims = { iss: CONFIG.issuer, aud: CONFIG.audience, exp: NOW } as Record<string, unknown>;
  Object.defineProperty(accessorClaims, "email", {
    enumerable: true,
    get() { reads += 1; return "u@x.test"; },
  });
  const accessorResult = validateCloudflareAccessClaims(accessorClaims as never, CONFIG);
  assert.equal(accessorResult.ok, false);
  assert.equal(reads, 0);

  const inheritedAllowlist = Object.assign(Object.create({ emailAllowlist: ["u@x.test"] }), CONFIG);
  assert.equal(validateCloudflareAccessClaims(
    { iss: CONFIG.issuer, aud: CONFIG.audience, exp: NOW, email: "other@x.test" },
    inheritedAllowlist,
  ).ok, true);
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

test("createCloudflareAccessIdentity classifies an unusable remote key as a verification failure", async () => {
  const rsa = await generateKeyPair("RS256", { extractable: true });
  const token = await new SignJWT({ email: "u@x.test", sub: "sub-1" })
    .setProtectedHeader({ alg: "RS256", kid: "selected-key" })
    .setIssuer(CONFIG.issuer).setAudience(CONFIG.audience)
    .setIssuedAt(NOW).setExpirationTime(NOW + 3600).sign(rsa.privateKey);
  const nonPublicJwk = { ...await exportJWK(rsa.privateKey), kid: "selected-key", alg: "RS256" };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({ keys: [nonPublicJwk] }), { status: 200 })) as typeof fetch;
  try {
    const result = await createCloudflareAccessIdentity(CONFIG).verify(token);
    assert.deepEqual(result, { ok: false, reason: "access_jwt_verify_failed" });
  } finally {
    globalThis.fetch = realFetch;
  }
});
