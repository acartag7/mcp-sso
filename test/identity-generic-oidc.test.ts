// GenericOidcIdentity (contracts §17.6) — pure claim-validation + primitives +
// the RedirectIdentityPort wrapper. All zero-network: injected transports +
// jose synthetic keys (addendum 12: the pure validator is fed payloads directly;
// the jose path uses known RS256/ES256 keys, no JWKS fetch). Mirrors the Entra
// test patterns (identity-entra.test.ts) plus the §17.6-specific gates: discovery
// boot rules, multi-audience rejection, at_hash, allowEmailAllowlist strict,
// alg:none / HS256-confusion rejection.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { generateKeyPair, SignJWT, type CryptoKey, type JWK } from "jose";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig } from "../src/config.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { noopAudit } from "../src/ports/audit.ts";
import { createUpstreamRedirectFlow } from "../src/adapters/upstream-flow.ts";
import {
  validateGenericOidcIdToken, computeAtHash, subjectAllowedGeneric, resolveAllowedAlgs,
  verifyGenericOidcIdToken, getAuthorizationUrl, exchangeCodeForToken, createGenericOidcIdentity,
  resolveEndpoints, createGenericOidcRedirectIdentity,
  type GenericOidcConfig, type GenericOidcIdTokenPayload, type ResolvedEndpoints,
  type DiscoveryTransport, type GenericOidcTokenTransport,
} from "../src/identity/generic-oidc.ts";

const ISSUER = "https://idp.example.com";
const CLIENT_ID = "generic-test-client-id";
const REDIRECT_URI = "https://bridge.test/oauth/callback";
const NOW = Math.floor(Date.parse("2026-07-03T12:00:00.000Z") / 1000);
const MANUAL = {
  authorizationEndpoint: `${ISSUER}/oauth2/authorize`,
  tokenEndpoint: `${ISSUER}/oauth2/token`,
  jwksUri: `${ISSUER}/jwks`,
};
const CONFIG: GenericOidcConfig = { issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, endpoints: MANUAL };
const RESOLVED: ResolvedEndpoints = { ...MANUAL, allowedAlgs: ["RS256", "ES256"], tokenAuthMethod: "client_secret_post" };

function payload(overrides: Record<string, unknown> = {}): GenericOidcIdTokenPayload {
  return { iss: ISSUER, aud: CLIENT_ID, sub: "sub-123", exp: NOW + 3600, iat: NOW, ...overrides } as GenericOidcIdTokenPayload;
}
const b64u = (obj: unknown): string => Buffer.from(JSON.stringify(obj)).toString("base64url");

// --- pure validator -----------------------------------------------------------

test("validateGenericOidcIdToken: happy path + subject canonicalized as (issuer, sub)", () => {
  const r = validateGenericOidcIdToken(payload(), CONFIG);
  assert.equal(r.ok, true);
  assert.equal(r.ok && r.identity.subject, `${ISSUER}|sub-123`);
});

test("validateGenericOidcIdToken: subject is namespaced by issuer (same sub + different issuer ⇒ different keys)", () => {
  // defends a stored-DCR store reused after changing issuers: approve keys grants by
  // the subject string, so a colliding opaque sub must not inherit another issuer's grants.
  const otherIssuer: GenericOidcConfig = { ...CONFIG, issuer: "https://other-idp.test", endpoints: { authorizationEndpoint: "https://other-idp.test/auth", tokenEndpoint: "https://other-idp.test/token", jwksUri: "https://other-idp.test/jwks" } };
  const a = validateGenericOidcIdToken(payload(), CONFIG);
  const b = validateGenericOidcIdToken(payload({ iss: "https://other-idp.test" }), otherIssuer);
  assert.notEqual(a.ok && a.identity.subject, b.ok && b.identity.subject);
});

test("validateGenericOidcIdToken: iss exact-match; aud contains clientId; multi-audience rejected", () => {
  assert.equal(validateGenericOidcIdToken(payload({ iss: "https://evil.test" }), CONFIG).ok, false); // bad iss
  assert.equal(validateGenericOidcIdToken(payload({ aud: "other" }), CONFIG).ok, false); // bad aud
  assert.equal(validateGenericOidcIdToken(payload({ aud: undefined }), CONFIG).ok, false); // aud absent
  assert.equal(validateGenericOidcIdToken(payload({ aud: [] }), CONFIG).ok, false); // empty array
  assert.equal(validateGenericOidcIdToken(payload({ aud: [CLIENT_ID] }), CONFIG).ok, true); // array-of-one accepted
  assert.equal(validateGenericOidcIdToken(payload({ aud: [CLIENT_ID, "other"] }), CONFIG).ok, false); // multi-audience rejected
  assert.equal(validateGenericOidcIdToken(payload({ aud: ["other", CLIENT_ID] }), CONFIG).ok, false); // multi-aud rejected even when clientId present
});

test("validateGenericOidcIdToken: exp + iat presence required", () => {
  assert.equal(validateGenericOidcIdToken(payload({ exp: undefined }), CONFIG).ok, false); // missing exp
  assert.equal(validateGenericOidcIdToken(payload({ iat: undefined }), CONFIG).ok, false); // missing iat (stricter than Entra)
});

test("validateGenericOidcIdToken: nonce mandatory when expected; at_hash code-flow only", () => {
  // nonce
  assert.equal(validateGenericOidcIdToken(payload({ nonce: "n1" }), CONFIG, { expectedNonce: "n1" }).ok, true);
  assert.equal(validateGenericOidcIdToken(payload({ nonce: "n1" }), CONFIG, { expectedNonce: "other" }).ok, false); // mismatch
  assert.equal(validateGenericOidcIdToken(payload({ nonce: undefined }), CONFIG, { expectedNonce: "n1" }).ok, false); // missing ⇒ hard fail
  // at_hash: present + correct access_token ⇒ accept
  const at = "ACCESS-TOKEN-VALUE";
  const goodHash = computeAtHash(at, "RS256")!;
  assert.ok(goodHash, "computeAtHash produces a value for RS256");
  assert.equal(validateGenericOidcIdToken(payload({ at_hash: goodHash }), CONFIG, { accessToken: at, alg: "RS256" }).ok, true);
  assert.equal(validateGenericOidcIdToken(payload({ at_hash: "wrong" }), CONFIG, { accessToken: at, alg: "RS256" }).ok, false); // wrong hash
  // at_hash absent + access_token ⇒ accept (code flow)
  assert.equal(validateGenericOidcIdToken(payload({ at_hash: undefined }), CONFIG, { accessToken: at, alg: "RS256" }).ok, true);
  // at_hash present + NO access_token (header mode) ⇒ SKIP, not reject (residual)
  assert.equal(validateGenericOidcIdToken(payload({ at_hash: "anything" }), CONFIG).ok, true);
});

test("computeAtHash: RS256/ES256 → sha256 half; other alg → null", () => {
  assert.ok(computeAtHash("x", "RS256"));
  assert.equal(computeAtHash("x", "RS256"), computeAtHash("x", "ES256")); // both sha256
  assert.equal(computeAtHash("x", "none"), null);
  assert.equal(computeAtHash("x", "HS256"), null);
});

test("validateGenericOidcIdToken: sub required; allowlist (sub + verified-email opt-in, strict)", () => {
  assert.equal(validateGenericOidcIdToken(payload({ sub: undefined }), CONFIG).ok, false); // no subject
  const allowSub: GenericOidcConfig = { ...CONFIG, subjectAllowlist: ["sub-123"] };
  assert.equal(validateGenericOidcIdToken(payload(), allowSub).ok, true); // sub matches
  assert.equal(validateGenericOidcIdToken(payload({ sub: "other" }), allowSub).ok, false); // sub not in list
  const allowEmail: GenericOidcConfig = { ...CONFIG, subjectAllowlist: ["user@example.com"], allowEmailAllowlist: true };
  assert.equal(validateGenericOidcIdToken(payload({ sub: "s", email: "user@example.com", email_verified: true }), allowEmail).ok, true); // verified email matches
  assert.equal(validateGenericOidcIdToken(payload({ sub: "s", email: "user@example.com", email_verified: false }), allowEmail).ok, false); // unverified ⇒ no match
  assert.equal(validateGenericOidcIdToken(payload({ sub: "s", email: "user@example.com", email_verified: "true" }), allowEmail).ok, false); // string "true" ⇒ no match (strict)
  assert.equal(validateGenericOidcIdToken(payload({ sub: "s", email: "user@example.com" }), allowEmail).ok, false); // absent ⇒ no match
  // sub-in-list always accepts regardless of email_verified
  const allowBoth: GenericOidcConfig = { ...CONFIG, subjectAllowlist: ["sub-123"], allowEmailAllowlist: true };
  assert.equal(validateGenericOidcIdToken(payload({ email_verified: false }), allowBoth).ok, true);
  // a non-string email (e.g. 123) does NOT throw — it just doesn't match ⇒ fail-closed
  // identity_rejected (subject_not_allowed), not exchange_failed.
  const r = validateGenericOidcIdToken(payload({ sub: "s", email: 123, email_verified: true }), { ...CONFIG, subjectAllowlist: ["user@example.com"], allowEmailAllowlist: true });
  assert.equal(r.ok, false);
  assert.equal(r.ok === false && r.reason, "generic_oidc_subject_not_allowed");
});

test("subjectAllowedGeneric + resolveAllowedAlgs units", () => {
  // sub is matched EXACTLY (opaque, case-sensitive) — `S1` does NOT match `s1`.
  assert.equal(subjectAllowedGeneric("s1", undefined, false, ["s1"], false), true);
  assert.equal(subjectAllowedGeneric("S1", undefined, false, ["s1"], false), false);
  assert.equal(subjectAllowedGeneric("S1", "e@x.test", true, ["e@x.test"], true), true); // verified email (case-insensitive)
  assert.equal(subjectAllowedGeneric("S1", "e@x.test", false, ["e@x.test"], true), false); // unverified email
  assert.deepEqual(resolveAllowedAlgs(undefined), ["RS256", "ES256"]); // missing metadata ⇒ default pin
  assert.deepEqual(resolveAllowedAlgs(["RS256", "PS256"]), ["RS256"]); // intersect
  assert.throws(() => resolveAllowedAlgs(["HS256", "none"])); // empty intersection ⇒ throw
});

// --- jose verify path (known keys, no JWKS) ----------------------------------

async function sign(claims: Record<string, unknown>, alg: "RS256" | "ES256", privateKey: CryptoKey, header?: Record<string, unknown>): Promise<string> {
  return await new SignJWT(claims).setProtectedHeader({ alg, typ: "JWT", ...header }).sign(privateKey);
}

test("verifyGenericOidcIdToken: RS256 + ES256 accept; expired/bad-claim/alg-none/HS256 rejected", async () => {
  const rsa = await generateKeyPair("RS256");
  const es = await generateKeyPair("ES256");
  const now = new Date(NOW * 1000);
  const claims = { iss: ISSUER, aud: CLIENT_ID, sub: "sub-123", exp: NOW + 3600, iat: NOW };
  // accept both algs
  assert.equal((await verifyGenericOidcIdToken(await sign(claims, "RS256", rsa.privateKey), rsa.publicKey, CONFIG, { currentDate: now })).ok, true);
  assert.equal((await verifyGenericOidcIdToken(await sign(claims, "ES256", es.privateKey), es.publicKey, CONFIG, { currentDate: now, allowedAlgs: ["RS256", "ES256"] })).ok, true);
  // expired
  assert.equal((await verifyGenericOidcIdToken(await sign({ ...claims, exp: NOW - 10 }, "RS256", rsa.privateKey), rsa.publicKey, CONFIG, { currentDate: now })).ok, false);
  // bad iss (caught by the pure validator)
  assert.equal((await verifyGenericOidcIdToken(await sign({ ...claims, iss: "https://evil.test" }, "RS256", rsa.privateKey), rsa.publicKey, CONFIG, { currentDate: now })).ok, false);
  // alg:none rejected (the alg pin — jose JOSEAlgNotAllowed)
  const noneToken = `${b64u({ alg: "none", typ: "JWT" })}.${b64u(claims)}.`;
  assert.equal((await verifyGenericOidcIdToken(noneToken, rsa.publicKey, CONFIG, { currentDate: now })).ok, false);
  // HS256-confusion rejected (sign with HS256; the alg pin excludes it)
  const hsToken = await new SignJWT(claims).setProtectedHeader({ alg: "HS256" }).sign(new TextEncoder().encode("confusion-secret"));
  assert.equal((await verifyGenericOidcIdToken(hsToken, rsa.publicKey, CONFIG, { currentDate: now })).ok, false);
  // tampered signature rejected
  const good = await sign(claims, "RS256", rsa.privateKey);
  const tampered = good.slice(0, -4) + "AAAA";
  assert.equal((await verifyGenericOidcIdToken(tampered, rsa.publicKey, CONFIG, { currentDate: now })).ok, false);
  // nonce binding
  assert.equal((await verifyGenericOidcIdToken(await sign({ ...claims, nonce: "n1" }, "RS256", rsa.privateKey), rsa.publicKey, CONFIG, { currentDate: now, expectedNonce: "n1" })).ok, true);
  assert.equal((await verifyGenericOidcIdToken(await sign({ ...claims, nonce: "n1" }, "RS256", rsa.privateKey), rsa.publicKey, CONFIG, { currentDate: now, expectedNonce: "x" })).ok, false);
});

// --- primitives --------------------------------------------------------------

test("getAuthorizationUrl: PKCE S256, required nonce, response_mode=query, state/redirect_uri/scope, no client_secret", () => {
  const url = getAuthorizationUrl(CONFIG, RESOLVED, { state: "s1", nonce: "n1", codeChallenge: "cc" });
  assert.ok(url.startsWith(`${MANUAL.authorizationEndpoint}?`));
  assert.match(url, /response_type=code/);
  assert.match(url, /response_mode=query/);
  assert.match(url, /code_challenge_method=S256/);
  assert.match(url, /nonce=n1/);
  assert.match(url, /state=s1/);
  assert.match(url, /client_id=generic-test-client-id/);
  assert.match(url, /redirect_uri=https%3A%2F%2Fbridge.test%2Foauth%2Fcallback/);
  assert.match(url, /scope=openid\+profile\+email/);
  assert.equal(url.includes("client_secret"), false);
});

test("getAuthorizationUrl: preserves an existing authorization_endpoint query (no second '?')", () => {
  const withQuery: ResolvedEndpoints = { ...RESOLVED, authorizationEndpoint: `${ISSUER}/oauth2/authorize?tenant=acme` };
  const u = new URL(getAuthorizationUrl(CONFIG, withQuery, { state: "s1", nonce: "n1", codeChallenge: "cc" }));
  assert.equal(u.searchParams.get("tenant"), "acme", "existing endpoint query preserved");
  assert.equal(u.searchParams.get("client_id"), CLIENT_ID);
  assert.equal(u.searchParams.get("state"), "s1");
  assert.equal(u.searchParams.get("nonce"), "n1");
  assert.equal(u.searchParams.get("code_challenge_method"), "S256");
});

test("getAuthorizationUrl: PKCE S256 is enforced on the primitive (a non-S256 method is rejected, never honored)", () => {
  assert.match(getAuthorizationUrl(CONFIG, RESOLVED, { state: "s", nonce: "n", codeChallenge: "c" }), /code_challenge_method=S256/);
  // an `as any` "plain" must throw at the primitive, not serialize code_challenge_method=plain.
  assert.throws(() => getAuthorizationUrl(CONFIG, RESOLVED, { state: "s", nonce: "n", codeChallenge: "c", codeChallengeMethod: "plain" } as never));
});

test("exchangeCodeForToken: returns id_token + access_token; non-200 rejects; missing id_token/access_token reject (OIDC §3.1.3.3)", async () => {
  const ok: GenericOidcTokenTransport = { async postForm() { return { status: 200, async text() { return JSON.stringify({ id_token: "idt", access_token: "atk" }); } }; } };
  const tokens = await exchangeCodeForToken(CONFIG, RESOLVED, { code: "c", codeVerifier: "v" }, ok);
  assert.equal(tokens.id_token, "idt");
  assert.equal(tokens.access_token, "atk");
  const badStatus: GenericOidcTokenTransport = { async postForm() { return { status: 400, async text() { return "{}"; } }; } };
  await assert.rejects(exchangeCodeForToken(CONFIG, RESOLVED, { code: "c", codeVerifier: "v" }, badStatus));
  const noIdToken: GenericOidcTokenTransport = { async postForm() { return { status: 200, async text() { return JSON.stringify({ access_token: "atk" }); } }; } };
  await assert.rejects(exchangeCodeForToken(CONFIG, RESOLVED, { code: "c", codeVerifier: "v" }, noIdToken));
  // access_token is REQUIRED in the code flow (guarantees a present at_hash is validated).
  const noAccessToken: GenericOidcTokenTransport = { async postForm() { return { status: 200, async text() { return JSON.stringify({ id_token: "idt" }); } }; } };
  await assert.rejects(exchangeCodeForToken(CONFIG, RESOLVED, { code: "c", codeVerifier: "v" }, noAccessToken), /access_token/);
  // a non-string id_token (e.g. {}) is truthy but invalid — reject at the exchange.
  const nonStringIdToken: GenericOidcTokenTransport = { async postForm() { return { status: 200, async text() { return JSON.stringify({ id_token: {}, access_token: "atk" }); } }; } };
  await assert.rejects(exchangeCodeForToken(CONFIG, RESOLVED, { code: "c", codeVerifier: "v" }, nonStringIdToken));
  // operability: the upstream OAuth error code (+ a bounded, newline-stripped description) now
  // travels in the thrown error so upstream-flow can log it — it was previously discarded.
  const invalidClient: GenericOidcTokenTransport = { async postForm() { return { status: 401, async text() { return JSON.stringify({ error: "invalid_client", error_description: "Unauthorized" }); } }; } };
  await assert.rejects(exchangeCodeForToken(CONFIG, RESOLVED, { code: "c", codeVerifier: "v" }, invalidClient), /HTTP 401: invalid_client — Unauthorized/);
});

// --- resolveEndpoints (discover + manual) -----------------------------------

function discoveryDoc(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { issuer: ISSUER, authorization_endpoint: MANUAL.authorizationEndpoint, token_endpoint: MANUAL.tokenEndpoint, jwks_uri: MANUAL.jwksUri, id_token_signing_alg_values_supported: ["RS256"], code_challenge_methods_supported: ["S256"], ...overrides };
}
function fakeDiscovery(doc: Record<string, unknown>, status = 200): DiscoveryTransport {
  return { async get() { return { status, async json() { return doc; } }; } };
}

test("resolveEndpoints: discover happy path; manual mode (no fetch, default algs)", async () => {
  const d = await resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc()));
  assert.deepEqual(d.allowedAlgs, ["RS256"]);
  // manual: no fetch, https-checked, default pin algs
  const m = await resolveEndpoints({ issuer: ISSUER, endpoints: MANUAL });
  assert.deepEqual(m.allowedAlgs, ["RS256", "ES256"]);
});

test("resolveEndpoints: discover boot failures (issuer mismatch, http endpoints, 3xx, non-200, malformed, missing PKCE)", async () => {
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc({ issuer: "https://evil.test" })))); // issuer mismatch
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc({ authorization_endpoint: "http://insecure.test/auth" })))); // http endpoint
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc({ jwks_uri: "http://insecure.test/jwks" })))); // http jwks
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc(), 302))); // 3xx not followed
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc(), 500))); // non-200
  const malformed: DiscoveryTransport = { async get() { return { status: 200, async json() { throw new SyntaxError("bad json"); } }; } };
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, malformed)); // malformed JSON
  // missing PKCE ⇒ boot-fail unless allowProviderWithoutPkce
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc({ code_challenge_methods_supported: undefined }))));
  const allowed = await resolveEndpoints({ issuer: ISSUER, endpoints: "discover", allowProviderWithoutPkce: true }, fakeDiscovery(discoveryDoc({ code_challenge_methods_supported: undefined })));
  assert.ok(allowed); // boots with the flag (loud)
  // missing alg metadata ⇒ default pin; empty intersection ⇒ throw
  assert.deepEqual((await resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc({ id_token_signing_alg_values_supported: undefined })))).allowedAlgs, ["RS256", "ES256"]);
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc({ id_token_signing_alg_values_supported: ["HS256"] }))));
  // present-but-MALFORMED security arrays ⇒ boot-fail (not silently defaulted)
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc({ id_token_signing_alg_values_supported: ["RS256", 7] }))));
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover", clientSecret: "s" }, fakeDiscovery(discoveryDoc({ token_endpoint_auth_methods_supported: ["client_secret_basic", 5] }))));
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc({ code_challenge_methods_supported: "S256" })))); // not an array
});

test("resolveEndpoints: manual-mode http endpoint boot-fails (addendum 11 not discovery-scoped)", async () => {
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: { authorizationEndpoint: "http://insecure.test/auth", tokenEndpoint: MANUAL.tokenEndpoint, jwksUri: MANUAL.jwksUri } }));
});

test("createGenericOidcIdentity: async build; verify rejects non-string; manual mode (no fetch)", async () => {
  const id = await createGenericOidcIdentity(CONFIG);
  assert.equal(id.redirectUri, REDIRECT_URI);
  assert.equal((await id.verify(undefined)).ok, false); // non-string id_token — no JWKS fetch
  assert.match(id.getAuthorizationUrl({ state: "s", nonce: "n", codeChallenge: "c" }), /nonce=n/);
});

// --- RedirectIdentityPort wrapper (outcome mapping, no JWKS via verifyKey) ----

test("createGenericOidcRedirectIdentity: exchangeAndVerify outcome mapping (exchange_failed / identity_rejected / ok)", async () => {
  const rsa = await generateKeyPair("RS256");
  const now = new Date(NOW * 1000);
  const claims = { iss: ISSUER, aud: CLIENT_ID, sub: "sub-123", exp: NOW + 3600, iat: NOW };
  const signClaim = (extra: Record<string, unknown> = {}) => sign({ ...claims, ...extra }, "RS256", rsa.privateKey);

  // ok: good token → identity; access_token never leaks into IdentityClaims
  const port2 = await createGenericOidcRedirectIdentity(CONFIG, {
    verifyKey: rsa.publicKey, currentDate: now,
    transport: { async postForm() { return { status: 200, async text() { return JSON.stringify({ id_token: await signClaim({ nonce: "n" }), access_token: "SECRET_ATK" }); } }; } },
  });
  const ok = await port2.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
  assert.equal(ok.ok, true);
  assert.equal(ok.ok && ok.identity.subject, `${ISSUER}|sub-123`);
  assert.equal(JSON.stringify(ok.ok ? ok.identity : {}).includes("SECRET_ATK"), false, "access_token must not leak into IdentityClaims");

  // exchange_failed: token endpoint non-200
  const portFail = await createGenericOidcRedirectIdentity(CONFIG, {
    verifyKey: rsa.publicKey, currentDate: now,
    transport: { async postForm() { return { status: 500, async text() { return "{}"; } }; } },
  });
  const ef = await portFail.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
  assert.equal(ef.ok, false);
  assert.ok(!ef.ok && ef.kind === "exchange_failed");

  // exchange_failed: the upstream error code propagates through the wrapper (operability —
  // upstream-flow logs exchange.reason; the cause must not be swallowed at the wrapper).
  const portInvalidClient = await createGenericOidcRedirectIdentity(CONFIG, {
    verifyKey: rsa.publicKey, currentDate: now,
    transport: { async postForm() { return { status: 401, async text() { return JSON.stringify({ error: "invalid_client", error_description: "Unauthorized" }); } }; } },
  });
  const ic = await portInvalidClient.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
  assert.ok(!ic.ok && ic.kind === "exchange_failed" && ic.reason.includes("invalid_client"), "wrapper propagates the upstream error code into exchange.reason");

  // exchange_failed: transport throws
  const portThrow = await createGenericOidcRedirectIdentity(CONFIG, {
    verifyKey: rsa.publicKey, currentDate: now,
    transport: { async postForm() { throw new Error("network down"); } },
  });
  const et = await portThrow.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
  assert.ok(!et.ok && et.kind === "exchange_failed");

  // identity_rejected: bad iss (verified-context denial)
  const portBadIss = await createGenericOidcRedirectIdentity(CONFIG, {
    verifyKey: rsa.publicKey, currentDate: now,
    transport: { async postForm() { return { status: 200, async text() { return JSON.stringify({ id_token: await signClaim({ iss: "https://evil.test", nonce: "n" }), access_token: "atk" }); } }; } },
  });
  const ir = await portBadIss.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
  assert.ok(!ir.ok && ir.kind === "identity_rejected");

  // identity_rejected: nonce mismatch
  const portBadNonce = await createGenericOidcRedirectIdentity(CONFIG, {
    verifyKey: rsa.publicKey, currentDate: now,
    transport: { async postForm() { return { status: 200, async text() { return JSON.stringify({ id_token: await signClaim({ nonce: "other" }), access_token: "atk" }); } }; } },
  });
  const irn = await portBadNonce.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
  assert.ok(!irn.ok && irn.kind === "identity_rejected");
});

// --- orchestrator boot-assert (the port satisfies createUpstreamRedirectFlow) ---

class FakeClock implements ClockPort { private ms: number; constructor(ms: number) { this.ms = ms; } nowMs(): number { return this.ms; } }
class MemoryAudit implements AuditPort { readonly events: AuthAuditEvent[] = []; async writeAuthEvent(e: AuthAuditEvent): Promise<void> { this.events.push(e); } }
function bridgeJwk(): JWK { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK; }

test("createUpstreamRedirectFlow: accepts a generic redirect identity whose redirectUri === issuerOrigin + callbackPath; rejects a mismatch", async () => {
  const cfg = createBridgeConfig({
    issuer: "https://bridge.test", resource: "https://bridge.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: bridgeJwk(), signingKeyId: "k",
    redirectAllowlist: ["https://client.test/cb"], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://bridge.test"], dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const store = new MemoryStore();
  const clock = new FakeClock(NOW * 1000);
  const audit = new MemoryAudit();
  const bridge = new Bridge({ config: cfg, store, clock, audit });
  const identity = await createGenericOidcRedirectIdentity({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: "https://bridge.test/oauth/callback", endpoints: MANUAL });
  // boot-asserts pass (redirectUri === issuerOrigin + callbackPath)
  const flow = createUpstreamRedirectFlow({ bridge, identity, store, clock, audit, callbackPath: "/oauth/callback" });
  assert.equal(flow.callbackPath, "/oauth/callback");
  assert.equal(identity.redirectUri, "https://bridge.test/oauth/callback");
  // a redirectUri that does NOT equal issuerOrigin + callbackPath ⇒ boot-fail
  const badIdentity = await createGenericOidcRedirectIdentity({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: "https://bridge.test/wrong", endpoints: MANUAL });
  assert.throws(() => createUpstreamRedirectFlow({ bridge, identity: badIdentity, store, clock, audit, callbackPath: "/oauth/callback" }));
  void noopAudit; void SystemClock;
});

// --- pre-push review coverage (P1/P2/P3 gaps the workflow caught) -----------

test("createGenericOidcIdentity: rejects an empty clientId (the aud check would be vacuous) + empty redirectUri", async () => {
  await assert.rejects(createGenericOidcIdentity({ ...CONFIG, clientId: "" }));
  await assert.rejects(createGenericOidcIdentity({ ...CONFIG, redirectUri: "" }));
});

test("createGenericOidcIdentity: rejects a malformed manual-mode issuer structurally (the exact-match trust root)", async () => {
  await assert.rejects(createGenericOidcIdentity({ ...CONFIG, issuer: "https://" })); // no host
});

test("createGenericOidcIdentity: rejects a defined-but-blank clientSecret (no silent public-client downgrade)", async () => {
  await assert.rejects(createGenericOidcIdentity({ ...CONFIG, clientSecret: "" }));
  await assert.rejects(createGenericOidcIdentity({ ...CONFIG, clientSecret: "   " }));
});

test("createGenericOidcIdentity: scopes must be non-blank + include openid (or omitted for the default)", async () => {
  await assert.rejects(createGenericOidcIdentity({ ...CONFIG, scopes: "" }));
  await assert.rejects(createGenericOidcIdentity({ ...CONFIG, scopes: "   " }));
  await assert.rejects(createGenericOidcIdentity({ ...CONFIG, scopes: "profile email" })); // no openid ⇒ no id_token
  const id = await createGenericOidcIdentity({ ...CONFIG, scopes: "openid email" });
  assert.match(id.getAuthorizationUrl({ state: "s", nonce: "n", codeChallenge: "c" }), /scope=openid\+email/);
});

test("validateGenericOidcIdToken: at_hash present + accessToken but no alg ⇒ fail-closed (cannot compute)", () => {
  // alg always comes from the jose protectedHeader in the verify path; this guards
  // a direct pure-validator call that supplies an access_token without an alg.
  assert.equal(validateGenericOidcIdToken(payload({ at_hash: "x" }), CONFIG, { accessToken: "atk" }).ok, false);
});

test("verifyGenericOidcIdToken: a far-future iat is ACCEPTED (exp bounds the token; jose does not validate iat value)", async () => {
  const rsa = await generateKeyPair("RS256");
  const now = new Date(NOW * 1000);
  const token = await sign({ iss: ISSUER, aud: CLIENT_ID, sub: "s", exp: NOW + 3600, iat: NOW + 600 }, "RS256", rsa.privateKey);
  assert.equal((await verifyGenericOidcIdToken(token, rsa.publicKey, CONFIG, { currentDate: now })).ok, true);
});

test("exchangeCodeForToken: a confidential client sends client_secret in the body", async () => {
  let seen: URLSearchParams | undefined;
  const transport: GenericOidcTokenTransport = { async postForm(_url, body) { seen = body; return { status: 200, async text() { return JSON.stringify({ id_token: "idt", access_token: "atk" }); } }; } };
  await exchangeCodeForToken({ ...CONFIG, clientSecret: "shh" }, RESOLVED, { code: "c", codeVerifier: "v" }, transport);
  assert.equal(seen?.get("client_secret"), "shh");
  assert.equal(seen?.get("client_id"), CLIENT_ID, "post: client_id IS in the body");
});

test("exchangeCodeForToken: client_secret_basic sends an Authorization header (secret never in the body)", async () => {
  let seenHeaders: Record<string, string> | undefined;
  let seenBody: URLSearchParams | undefined;
  const transport: GenericOidcTokenTransport = {
    async postForm(_url, body, headers) { seenHeaders = headers; seenBody = body; return { status: 200, async text() { return JSON.stringify({ id_token: "idt", access_token: "atk" }); } }; },
  };
  const basicResolved: ResolvedEndpoints = { ...RESOLVED, tokenAuthMethod: "client_secret_basic" };
  await exchangeCodeForToken({ ...CONFIG, clientSecret: "shh" }, basicResolved, { code: "c", codeVerifier: "v" }, transport);
  const expected = `Basic ${Buffer.from(`${CLIENT_ID}:shh`).toString("base64")}`;
  assert.equal(seenHeaders?.authorization, expected);
  assert.equal(seenBody?.get("client_secret"), null, "the secret is NOT in the body under client_secret_basic");
  assert.equal(seenBody?.get("client_id"), null, "client_id is NOT in the body under client_secret_basic (it's in the header — RFC 6749 §2.3.1)");
});

test("exchangeCodeForToken: client_secret_basic form-encodes the credentials (RFC 6749 §2.3.1 — space ⇒ '+')", async () => {
  let seenHeaders: Record<string, string> | undefined;
  const transport: GenericOidcTokenTransport = { async postForm(_u, _b, h) { seenHeaders = h; return { status: 200, async text() { return JSON.stringify({ id_token: "idt", access_token: "atk" }); } }; } };
  const basicResolved: ResolvedEndpoints = { ...RESOLVED, tokenAuthMethod: "client_secret_basic" };
  await exchangeCodeForToken({ issuer: ISSUER, clientId: "a:b+c", clientSecret: "s s%", redirectUri: REDIRECT_URI, endpoints: MANUAL }, basicResolved, { code: "c", codeVerifier: "v" }, transport);
  // application/x-www-form-urlencoded: space ⇒ '+' (not %20)
  const enc = (s: string): string => encodeURIComponent(s).replace(/%20/g, "+");
  const expected = `Basic ${Buffer.from(`${enc("a:b+c")}:${enc("s s%")}`).toString("base64")}`;
  assert.equal(seenHeaders?.authorization, expected);
  assert.ok(enc("s s%").includes("+"), "the space in the secret form-encodes to '+' (not %20)");
});

test("resolveEndpoints: token-endpoint auth method — honors advertised, OIDC-default basic when omitted, boot-fails on neither", async () => {
  const confidential = (doc?: Record<string, unknown>) => resolveEndpoints({ issuer: ISSUER, endpoints: "discover", clientSecret: "shh" }, doc ? fakeDiscovery(doc) : undefined);
  // advertised only basic ⇒ basic
  assert.equal((await confidential(discoveryDoc({ token_endpoint_auth_methods_supported: ["client_secret_basic"] }))).tokenAuthMethod, "client_secret_basic");
  // advertised post+basic ⇒ post (preferred)
  assert.equal((await confidential(discoveryDoc({ token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"] }))).tokenAuthMethod, "client_secret_post");
  // omitted ⇒ OIDC default basic
  assert.equal((await confidential(discoveryDoc())).tokenAuthMethod, "client_secret_basic");
  // advertised neither (e.g. private_key_jwt only) ⇒ boot-fail for a confidential client
  await assert.rejects(confidential(discoveryDoc({ token_endpoint_auth_methods_supported: ["private_key_jwt"] })));
  // public client (no secret) ⇒ post (moot)
  assert.equal((await resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc()))).tokenAuthMethod, "client_secret_post");
  // deployer override is trusted
  assert.equal((await resolveEndpoints({ issuer: ISSUER, endpoints: "discover", clientSecret: "shh", tokenEndpointAuthMethod: "client_secret_basic" }, fakeDiscovery(discoveryDoc({ token_endpoint_auth_methods_supported: ["client_secret_post"] })))).tokenAuthMethod, "client_secret_basic");
  // manual mode + confidential + no override ⇒ OIDC default Basic (consistent with discovery-omitted)
  assert.equal((await resolveEndpoints({ issuer: ISSUER, endpoints: MANUAL, clientSecret: "shh" })).tokenAuthMethod, "client_secret_basic");
});

test("resolveEndpoints: malformed endpoint URLs (no host) boot-fail in both modes (not just the https prefix)", async () => {
  // "https://" is not a valid URL (no host) — fails at boot, not at the first authorize/exchange.
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc({ authorization_endpoint: "https://" }))));
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: { authorizationEndpoint: "https://", tokenEndpoint: MANUAL.tokenEndpoint, jwksUri: MANUAL.jwksUri } }));
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: { authorizationEndpoint: MANUAL.authorizationEndpoint, tokenEndpoint: "https://", jwksUri: MANUAL.jwksUri } }));
});

test("fail-closed sweep: null discovery arrays, non-object doc, bad override, bad subjectAllowlist", async () => {
  // explicit null security arrays ⇒ boot-fail (not treated as omitted)
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc({ id_token_signing_alg_values_supported: null as never }))));
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover", clientSecret: "s" }, fakeDiscovery(discoveryDoc({ token_endpoint_auth_methods_supported: null as never }))));
  // non-object discovery doc (JSON null / array) ⇒ boot-fail (not a crash)
  const nullDoc: DiscoveryTransport = { async get() { return { status: 200, async json() { return null; } }; } };
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, nullDoc));
  const arrayDoc: DiscoveryTransport = { async get() { return { status: 200, async json() { return []; } }; } };
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, arrayDoc));
  // misspelled tokenEndpointAuthMethod override ⇒ boot-fail (not a silent fall-through to post)
  await assert.rejects(createGenericOidcIdentity({ ...CONFIG, clientSecret: "s", tokenEndpointAuthMethod: "basic" as never }));
  // subjectAllowlist must be an array of strings (a non-array / non-string entry would crash the matcher)
  await assert.rejects(createGenericOidcIdentity({ ...CONFIG, subjectAllowlist: "sub-123" as never }));
  await assert.rejects(createGenericOidcIdentity({ ...CONFIG, subjectAllowlist: ["ok", 5] as never }));
});

test("resolveEndpoints: every http endpoint rejected across both modes (addendum 11 exhaustive — discovery token_endpoint + manual tokenEndpoint/jwksUri)", async () => {
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: "discover" }, fakeDiscovery(discoveryDoc({ token_endpoint: "http://insecure.test/token" }))));
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: { authorizationEndpoint: MANUAL.authorizationEndpoint, tokenEndpoint: "http://insecure.test/token", jwksUri: MANUAL.jwksUri } }));
  await assert.rejects(resolveEndpoints({ issuer: ISSUER, endpoints: { authorizationEndpoint: MANUAL.authorizationEndpoint, tokenEndpoint: MANUAL.tokenEndpoint, jwksUri: "http://insecure.test/jwks" } }));
});

test("createGenericOidcRedirectIdentity: a JWKS HTTP 500 (jose base JOSEError, ERR_JOSE_GENERIC) is exchange_failed, NOT identity_rejected (§17.11 — no identity decision)", async () => {
  const rsa = await generateKeyPair("RS256");
  const now = new Date(NOW * 1000);
  const idToken = await sign({ iss: ISSUER, aud: CLIENT_ID, sub: "s", exp: NOW + 3600, iat: NOW, nonce: "n" }, "RS256", rsa.privateKey);
  const transport: GenericOidcTokenTransport = { async postForm() { return { status: 200, async text() { return JSON.stringify({ id_token: idToken, access_token: "atk" }); } }; } };
  const realFetch = globalThis.fetch;
  // The JWKS path is live (no verifyKey); jose throws base JOSEError on a non-200
  // JWKS. Before the jwtErrorReason fix this was generic_oidc_token_invalid ⇒
  // identity_rejected (a false "user refused"); now it routes to
  // generic_oidc_verify_failed ⇒ exchange_failed.
  globalThis.fetch = (async () => new Response("upstream gone", { status: 500 })) as typeof fetch;
  try {
    const port = await createGenericOidcRedirectIdentity(CONFIG, { transport });
    const r = await port.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
    assert.equal(r.ok, false, "verify did not succeed (JWKS returned 500)");
    assert.ok(!r.ok && r.kind === "exchange_failed", "a JWKS HTTP 500 is infrastructure ⇒ exchange_failed (never identity_rejected)");
  } finally { globalThis.fetch = realFetch; }
});

test("createGenericOidcRedirectIdentity: code-flow response with at_hash but NO access_token ⇒ exchange_failed (fail-closed — Codex P2: at_hash must be validatable, never header-mode-skipped in the code flow)", async () => {
  const rsa = await generateKeyPair("RS256");
  const now = new Date(NOW * 1000);
  const idToken = await sign({ iss: ISSUER, aud: CLIENT_ID, sub: "s", exp: NOW + 3600, iat: NOW, nonce: "n", at_hash: "somehash" }, "RS256", rsa.privateKey);
  const port = await createGenericOidcRedirectIdentity(CONFIG, {
    verifyKey: rsa.publicKey, currentDate: now,
    transport: { async postForm() { return { status: 200, async text() { return JSON.stringify({ id_token: idToken }); } }; } }, // no access_token
  });
  const r = await port.exchangeAndVerify({ code: "c", codeVerifier: "v", nonce: "n" });
  assert.ok(!r.ok && r.kind === "exchange_failed", "missing access_token in the code flow ⇒ exchange_failed (never accepted/skipped)");
});
