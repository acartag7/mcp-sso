import assert from "node:assert/strict";
import { test } from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import {
  type EntraConfig, type EntraTokenTransport, createEntraIdentity, entraIssuer,
  exchangeCodeForToken, getAuthorizationUrl, subjectAllowed, validateEntraIdToken,
  verifyEntraIdToken,
} from "../src/identity/entra.ts";

const TENANT = "11111111-2222-3333-4444-555555555555";
const OTHER_TENANT = "99999999-8888-7777-6666-555555555555";
const CONFIG: EntraConfig = {
  tenantId: TENANT,
  clientId: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  redirectUri: "https://bridge.test/oauth/entra/callback",
};
const NOW = Math.floor(Date.parse("2026-07-03T12:00:00.000Z") / 1000);

function payload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { iss: entraIssuer(TENANT), aud: CONFIG.clientId, tid: TENANT, oid: "oid-abc", exp: NOW + 3600, iat: NOW, ...overrides };
}

test("getAuthorizationUrl: tenant-derived, PKCE S256, optional nonce", () => {
  const url = getAuthorizationUrl(CONFIG, { state: "s1", codeChallenge: "challenge-value" });
  assert.match(url, /^https:\/\/login\.microsoftonline\.com\/11111111-2222-3333-4444-555555555555\/oauth2\/v2\.0\/authorize\?/);
  assert.match(url, /code_challenge_method=S256/);
  assert.equal(url.includes("nonce="), false);
  const withNonce = getAuthorizationUrl(CONFIG, { state: "s1", codeChallenge: "c", nonce: "n-1" });
  assert.match(withNonce, /nonce=n-1/);
});

test("getAuthorizationUrl: PKCE S256 is enforced on the primitive (a non-S256 method is rejected, not honored)", () => {
  // an `as any` "plain" must throw at the primitive (sibling of the generic port), not serialize it.
  assert.throws(() => getAuthorizationUrl(CONFIG, { state: "s1", codeChallenge: "c", codeChallengeMethod: "plain" } as never));
});

test("validateEntraIdToken: single-tenant iss/aud/tid/exp gates + exact oid subject", () => {
  assert.equal(validateEntraIdToken(payload() as never, CONFIG).ok, true);
  assert.equal(validateEntraIdToken(payload({ iss: "https://evil/v2.0" }) as never, CONFIG).ok, false); // bad iss
  assert.equal(validateEntraIdToken(payload({ aud: "other" }) as never, CONFIG).ok, false); // bad aud
  assert.equal(validateEntraIdToken(payload({ tid: OTHER_TENANT }) as never, CONFIG).ok, false); // foreign tid
  assert.equal(validateEntraIdToken(payload({ exp: undefined }) as never, CONFIG).ok, false); // no exp
  const oid = validateEntraIdToken(payload({ oid: "oid-exact", sub: "sub-ignored" }) as never, CONFIG);
  assert.equal(oid.ok && oid.identity.subject, "oid-exact");
});

test("validateEntraIdToken: no-oid subject is exact accepted issuer|sub and never a mutable claim", () => {
  const issuer = entraIssuer(TENANT);
  for (const unusableOid of [undefined, "", "   ", 42, false, {}]) {
    const result = validateEntraIdToken(payload({ oid: unusableOid, sub: "sub-exact", preferred_username: "shared@example.test", email: "shared@example.test" }) as never, CONFIG);
    assert.equal(result.ok && result.identity.subject, `${issuer}|sub-exact`);
  }
  for (const unusableSub of [undefined, "", "   ", 42, false, {}]) {
    const result = validateEntraIdToken(payload({ oid: undefined, sub: unusableSub, preferred_username: "shared@example.test", email: "shared@example.test" }) as never, CONFIG);
    assert.deepEqual(result, { ok: false, reason: "entra_no_subject" });
  }
});

test("validateEntraIdToken: equal sub values are namespaced by the exact accepted issuer", () => {
  const mt: EntraConfig = { ...CONFIG, allowedTenantIds: [TENANT, OTHER_TENANT] };
  const first = validateEntraIdToken(payload({ oid: undefined, sub: "same-sub" }) as never, mt);
  const otherIssuer = entraIssuer(OTHER_TENANT);
  const second = validateEntraIdToken(payload({ oid: undefined, sub: "same-sub", tid: OTHER_TENANT, iss: otherIssuer }) as never, mt);
  assert.equal(first.ok && first.identity.subject, `${entraIssuer(TENANT)}|same-sub`);
  assert.equal(second.ok && second.identity.subject, `${otherIssuer}|same-sub`);
  assert.notEqual(first.ok && first.identity.subject, second.ok && second.identity.subject);
});

test("validateEntraIdToken: multi-tenant — tid allowlisted, iss follows the token's tid", () => {
  const mt: EntraConfig = { ...CONFIG, allowedTenantIds: [TENANT, OTHER_TENANT] };
  // a token from OTHER_TENANT: tid allowlisted, iss = entraIssuer(OTHER_TENANT) -> ok
  const foreign = payload({ tid: OTHER_TENANT, iss: entraIssuer(OTHER_TENANT) });
  assert.equal(validateEntraIdToken(foreign as never, mt).ok, true);
  // iss not matching the token's own tid -> rejected
  assert.equal(validateEntraIdToken(payload({ tid: OTHER_TENANT, iss: entraIssuer(TENANT) }) as never, mt).ok, false);
  // tid not in allowlist -> rejected
  assert.equal(validateEntraIdToken(payload({ tid: "deadbeef-0000-0000-0000-000000000000" }) as never, mt).ok, false);
});

test("validateEntraIdToken: nonce binding", () => {
  assert.equal(validateEntraIdToken(payload({ nonce: "n-1" }) as never, CONFIG, "n-1").ok, true);
  assert.equal(validateEntraIdToken(payload({ nonce: "n-1" }) as never, CONFIG, "other").ok, false); // mismatch
});

test("subjectAllowed: oid is exact; mutable claims are explicit, case-insensitive, and not trimmed", () => {
  assert.equal(subjectAllowed({ oid: "OID-1" }, ["OID-1"]), true);
  assert.equal(subjectAllowed({ oid: "OID-1" }, ["oid-1"]), false);
  assert.equal(subjectAllowed({ oid: "OID-1" }, [" OID-1 "]), false);
  // email/preferred_username do NOT match by default (mutable)
  assert.equal(subjectAllowed({ preferred_username: "u@x.test", email: "u@x.test" }, ["u@x.test"]), false);
  // opt-in -> mutable claims match (case-insensitive)
  assert.equal(subjectAllowed({ preferred_username: "U@X.test" }, ["u@x.test"], true), true);
  assert.equal(subjectAllowed({ email: "a@b.test" }, ["a@b.test"], true), true);
  assert.equal(subjectAllowed({ email: "a@b.test" }, [" a@b.test "], true), false);
  assert.equal(subjectAllowed({ email: " a@b.test " }, ["a@b.test"], true), false);
  assert.equal(subjectAllowed({ email: "a@b.test" }, ["a@b.test"], "true" as never), false);
});

test("subjectAllowed: no-oid matches only the exact issuer-namespaced immutable subject", () => {
  const issuer = entraIssuer(TENANT);
  const noOid = payload({ oid: undefined, sub: "stable-sub", preferred_username: "mutable@example.test" });
  assert.equal(subjectAllowed(noOid as never, [`${issuer}|stable-sub`]), true);
  assert.equal(subjectAllowed(noOid as never, ["stable-sub"]), false);
  assert.equal(subjectAllowed(noOid as never, [`${entraIssuer(OTHER_TENANT)}|stable-sub`]), false);
  assert.equal(subjectAllowed(noOid as never, [`${issuer}|Stable-Sub`]), false);
  assert.equal(subjectAllowed(noOid as never, [` ${issuer}|stable-sub `]), false);
});

test("validateEntraIdToken: subjectAllowlist matches oid by default, mutable only when opted in", () => {
  const allowOid: EntraConfig = { ...CONFIG, subjectAllowlist: ["oid-abc"] };
  assert.equal(validateEntraIdToken(payload() as never, allowOid).ok, true); // oid matches
  assert.equal(validateEntraIdToken(payload({ oid: "other" }) as never, allowOid).ok, false); // oid not in list
  // preferred_username/email do NOT satisfy the allowlist without allowMutableClaims
  const allowEmail: EntraConfig = { ...CONFIG, subjectAllowlist: ["user@example.com"] };
  assert.equal(validateEntraIdToken(payload({ oid: undefined, sub: "stable-sub", preferred_username: "user@example.com" }) as never, allowEmail).ok, false);
  const allowEmailMutable: EntraConfig = { ...CONFIG, subjectAllowlist: ["user@example.com"], allowMutableClaims: true };
  const mutableMatch = validateEntraIdToken(payload({ oid: undefined, sub: "stable-sub", preferred_username: "USER@example.com" }) as never, allowEmailMutable);
  assert.equal(mutableMatch.ok && mutableMatch.identity.subject, `${entraIssuer(TENANT)}|stable-sub`);
  const immutableFallback: EntraConfig = { ...CONFIG, subjectAllowlist: [`${entraIssuer(TENANT)}|stable-sub`] };
  const fallbackMatch = validateEntraIdToken(payload({ oid: undefined, sub: "stable-sub", preferred_username: "ignored@example.test" }) as never, immutableFallback);
  assert.equal(fallbackMatch.ok && fallbackMatch.identity.subject, `${entraIssuer(TENANT)}|stable-sub`);
  for (const entry of [`${entraIssuer(TENANT)}|Stable-Sub`, ` ${entraIssuer(TENANT)}|stable-sub `]) {
    assert.equal(validateEntraIdToken(payload({ oid: undefined, sub: "stable-sub" }) as never, { ...CONFIG, subjectAllowlist: [entry] }).ok, false);
  }
});

test("verifyEntraIdToken: recorded fixture (known RS256 key, no JWKS fetch)", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const sign = (claims: Record<string, unknown>, opts?: { exp?: number }) =>
    new SignJWT(claims).setProtectedHeader({ alg: "RS256", typ: "JWT" })
      .setIssuedAt(NOW).setExpirationTime(opts?.exp ?? NOW + 3600).sign(privateKey);

  const good = await verifyEntraIdToken(await sign(payload()), publicKey, CONFIG, { currentDate: new Date(NOW * 1000) });
  assert.equal(good.ok, true);
  assert.equal(good.ok && good.identity.subject, "oid-abc");

  const noOid = await verifyEntraIdToken(await sign(payload({ oid: undefined, sub: "verified-sub", preferred_username: "mutable@example.test" })), publicKey, CONFIG, { currentDate: new Date(NOW * 1000) });
  assert.equal(noOid.ok && noOid.identity.subject, `${entraIssuer(TENANT)}|verified-sub`);
  const mutableOnly = await verifyEntraIdToken(await sign(payload({ oid: undefined, sub: undefined, preferred_username: "mutable@example.test", email: "mutable@example.test" })), publicKey, CONFIG, { currentDate: new Date(NOW * 1000) });
  assert.deepEqual(mutableOnly, { ok: false, reason: "entra_no_subject" });

  assert.equal((await verifyEntraIdToken(await sign(payload({ iss: entraIssuer(OTHER_TENANT), tid: OTHER_TENANT })), publicKey, CONFIG, { currentDate: new Date(NOW * 1000) })).ok, false); // foreign tenant, single-tenant config
  assert.equal((await verifyEntraIdToken(await sign(payload(), { exp: NOW - 120 }), publicKey, CONFIG, { currentDate: new Date(NOW * 1000) })).ok, false); // expired
  // nonce binding
  assert.equal((await verifyEntraIdToken(await sign(payload({ nonce: "n-1" })), publicKey, CONFIG, { currentDate: new Date(NOW * 1000), expectedNonce: "n-1" })).ok, true);
  assert.equal((await verifyEntraIdToken(await sign(payload({ nonce: "n-1" })), publicKey, CONFIG, { currentDate: new Date(NOW * 1000), expectedNonce: "other" })).ok, false);
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

test("createEntraIdentity: fails closed on blank tenantId/clientId (empty == missing config)", () => {
  assert.throws(() => createEntraIdentity({ ...CONFIG, tenantId: "" }), /tenantId is required/);
  assert.throws(() => createEntraIdentity({ ...CONFIG, tenantId: "   " }), /tenantId is required/);
  assert.throws(() => createEntraIdentity({ ...CONFIG, clientId: "" }), /clientId is required/);
  assert.throws(() => createEntraIdentity({ ...CONFIG, clientId: "   " }), /clientId is required/);
});

test("createEntraIdentity: exposes the port; getAuthorizationUrl carries nonce; verify rejects non-string", async () => {
  const entra = createEntraIdentity(CONFIG);
  assert.match(entra.getAuthorizationUrl({ state: "s", codeChallenge: "c", nonce: "n" }), /nonce=n/);
  assert.equal((await entra.verify(undefined)).ok, false); // non-string id_token — no JWKS fetch
});

test("createEntraIdentity: remote JWKS uses issuer|sub and rejects mutable-only identity", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const publicJwk = { ...await exportJWK(publicKey), alg: "RS256", kid: "remote-k1", use: "sig" };
  const now = Math.floor(Date.now() / 1000);
  const sign = (claims: Record<string, unknown>) => new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: "remote-k1" })
    .setIssuer(entraIssuer(TENANT)).setAudience(CONFIG.clientId)
    .setIssuedAt(now).setExpirationTime(now + 3600).sign(privateKey);
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ keys: [publicJwk] }), {
    status: 200, headers: { "content-type": "application/json" },
  })) as typeof fetch;
  try {
    const identity = createEntraIdentity(CONFIG);
    const noOid = await identity.verify(await sign({ tid: TENANT, sub: "factory-sub", preferred_username: "shared@example.test" }));
    assert.equal(noOid.ok && noOid.identity.subject, `${entraIssuer(TENANT)}|factory-sub`);
    const mutableOnly = await identity.verify(await sign({ tid: TENANT, preferred_username: "shared@example.test", email: "shared@example.test" }));
    assert.deepEqual(mutableOnly, { ok: false, reason: "entra_no_subject" });
  } finally {
    globalThis.fetch = realFetch;
  }
});
