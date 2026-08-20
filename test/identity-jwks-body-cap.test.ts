import assert from "node:assert/strict";
import { test } from "node:test";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from "jose";
import {
  type CloudflareAccessConfig,
  createCloudflareAccessIdentity,
} from "../src/identity/cloudflare-access.ts";
import {
  type EntraConfig,
  type EntraTokenTransport,
  createEntraIdentity,
  createEntraRedirectIdentity,
  entraIssuer,
} from "../src/identity/entra.ts";
import {
  type GenericOidcConfig,
  type GenericOidcTokenTransport,
  createGenericOidcIdentity,
  createGenericOidcRedirectIdentity,
} from "../src/identity/generic-oidc.ts";
import { remoteJwksOptions } from "../src/identity/jwks-fetch.ts";

const NOW = Math.floor(Date.now() / 1_000);
const CAP = 1_024;
const CF_CONFIG: CloudflareAccessConfig = {
  audience: "cf-audience",
  certsUrl: "https://team.cloudflareaccess.test/certs",
  issuer: "https://team.cloudflareaccess.test",
};
const TENANT = "11111111-2222-3333-4444-555555555555";
const ENTRA_CONFIG: EntraConfig = {
  tenantId: TENANT,
  clientId: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  redirectUri: "https://bridge.test/oauth/entra/callback",
};
const OIDC_CONFIG: GenericOidcConfig = {
  issuer: "https://idp.test",
  clientId: "oidc-client",
  redirectUri: "https://bridge.test/oauth/oidc/callback",
  endpoints: {
    authorizationEndpoint: "https://idp.test/authorize",
    tokenEndpoint: "https://idp.test/token",
    jwksUri: "https://idp.test/jwks",
  },
};

async function keyFixture(): Promise<{ privateKey: CryptoKey; jwk: JWK }> {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  return { privateKey, jwk: { ...jwk, alg: "RS256", kid: "test-key", use: "sig" } };
}

function jwksResponse(jwk: JWK, padding = 0): Response {
  return new Response(JSON.stringify({ keys: [jwk], padding: "x".repeat(padding) }), {
    status: 200,
    headers: { "content-type": "application/jwk-set+json" },
  });
}

async function withFetch<T>(fetchImpl: typeof fetch, action: () => Promise<T>): Promise<T> {
  const realFetch = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  try {
    return await action();
  } finally {
    globalThis.fetch = realFetch;
  }
}

function unavailableFetch(): typeof fetch {
  return (async () => { throw new Error("JWKS unavailable"); }) as typeof fetch;
}

test("Cloudflare Access verifies through a normal remote JWKS body", async () => {
  const { privateKey, jwk } = await keyFixture();
  const token = await new SignJWT({ email: "user@example.test", sub: "cf-sub" })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(CF_CONFIG.issuer).setAudience(CF_CONFIG.audience)
    .setIssuedAt(NOW).setExpirationTime(NOW + 3_600).sign(privateKey);
  const result = await withFetch(
    (async () => jwksResponse(jwk)) as typeof fetch,
    () => createCloudflareAccessIdentity(CF_CONFIG).verify(token),
  );
  assert.ok(result.ok && result.identity.subject === "cf-sub");
});

test("Entra verifies through a normal remote JWKS body", async () => {
  const { privateKey, jwk } = await keyFixture();
  const token = await new SignJWT({ tid: TENANT, oid: "entra-oid" })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(entraIssuer(TENANT)).setAudience(ENTRA_CONFIG.clientId)
    .setIssuedAt(NOW).setExpirationTime(NOW + 3_600).sign(privateKey);
  const result = await withFetch(
    (async () => jwksResponse(jwk)) as typeof fetch,
    () => createEntraIdentity(ENTRA_CONFIG).verify(token),
  );
  assert.ok(result.ok && result.identity.subject === "entra-oid");
});

test("generic OIDC verifies through a normal remote JWKS body", async () => {
  const { privateKey, jwk } = await keyFixture();
  const token = await new SignJWT({ sub: "oidc-sub" })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(OIDC_CONFIG.issuer).setAudience(OIDC_CONFIG.clientId)
    .setIssuedAt(NOW).setExpirationTime(NOW + 3_600).sign(privateKey);
  const result = await withFetch(
    (async () => jwksResponse(jwk)) as typeof fetch,
    async () => (await createGenericOidcIdentity(OIDC_CONFIG)).verify(token),
  );
  assert.ok(result.ok && result.identity.subject === `${OIDC_CONFIG.issuer}|oidc-sub`);
});

test("Cloudflare Access rejects an over-cap JWKS as the existing infrastructure failure", async () => {
  const { privateKey, jwk } = await keyFixture();
  const token = await new SignJWT({ email: "user@example.test", sub: "cf-sub" })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(CF_CONFIG.issuer).setAudience(CF_CONFIG.audience)
    .setIssuedAt(NOW).setExpirationTime(NOW + 3_600).sign(privateKey);
  const unreachable = await withFetch(unavailableFetch(), () =>
    createCloudflareAccessIdentity(CF_CONFIG).verify(token));
  const oversized = await withFetch(
    (async () => jwksResponse(jwk, 2_000)) as typeof fetch,
    () => createCloudflareAccessIdentity({ ...CF_CONFIG, maxJwksDocumentBytes: CAP }).verify(token),
  );
  assert.deepEqual(oversized, unreachable);
  assert.deepEqual(oversized, { ok: false, reason: "access_jwt_verify_failed" });
});

test("Entra rejects an over-cap JWKS as exchange_failed like an unreachable JWKS", async () => {
  const { privateKey, jwk } = await keyFixture();
  const idToken = await new SignJWT({ tid: TENANT, oid: "entra-oid", nonce: "nonce" })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(entraIssuer(TENANT)).setAudience(ENTRA_CONFIG.clientId)
    .setIssuedAt(NOW).setExpirationTime(NOW + 3_600).sign(privateKey);
  const transport: EntraTokenTransport = {
    async postForm() { return { status: 200, async text() { return JSON.stringify({ id_token: idToken }); } }; },
  };
  const run = (config: EntraConfig) => createEntraRedirectIdentity(config, { transport })
    .exchangeAndVerify({ code: "code", codeVerifier: "verifier", nonce: "nonce" });
  const unreachable = await withFetch(unavailableFetch(), () => run(ENTRA_CONFIG));
  const oversized = await withFetch(
    (async () => jwksResponse(jwk, 2_000)) as typeof fetch,
    () => run({ ...ENTRA_CONFIG, maxJwksDocumentBytes: CAP }),
  );
  assert.deepEqual(oversized, unreachable);
  assert.equal(unreachable.ok, false);
  assert.ok(!unreachable.ok && unreachable.kind === "exchange_failed");
  assert.equal(oversized.ok, false);
  assert.ok(!oversized.ok && oversized.kind === "exchange_failed");
});

test("generic OIDC rejects an over-cap JWKS as exchange_failed like an unreachable JWKS", async () => {
  const { privateKey, jwk } = await keyFixture();
  const idToken = await new SignJWT({ sub: "oidc-sub", nonce: "nonce" })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(OIDC_CONFIG.issuer).setAudience(OIDC_CONFIG.clientId)
    .setIssuedAt(NOW).setExpirationTime(NOW + 3_600).sign(privateKey);
  const transport: GenericOidcTokenTransport = {
    async postForm() { return { status: 200, async text() { return JSON.stringify({ id_token: idToken, access_token: "access" }); } }; },
  };
  const run = async (config: GenericOidcConfig) =>
    (await createGenericOidcRedirectIdentity(config, { transport }))
      .exchangeAndVerify({ code: "code", codeVerifier: "verifier", nonce: "nonce" });
  const unreachable = await withFetch(unavailableFetch(), () => run(OIDC_CONFIG));
  const oversized = await withFetch(
    (async () => jwksResponse(jwk, 2_000)) as typeof fetch,
    () => run({ ...OIDC_CONFIG, maxJwksDocumentBytes: CAP }),
  );
  assert.deepEqual(oversized, unreachable);
  assert.equal(unreachable.ok, false);
  assert.ok(!unreachable.ok && unreachable.kind === "exchange_failed");
  assert.equal(oversized.ok, false);
  assert.ok(!oversized.ok && oversized.kind === "exchange_failed");
});

test("all identity factories boot-validate maxJwksDocumentBytes", async () => {
  const invalid = [null, 1_023, 1_024.5, Number.NaN, Infinity, 1_048_577];
  for (const value of invalid) {
    assert.throws(() => createCloudflareAccessIdentity({ ...CF_CONFIG, maxJwksDocumentBytes: value as number }));
    assert.throws(() => createEntraIdentity({ ...ENTRA_CONFIG, maxJwksDocumentBytes: value as number }));
    await assert.rejects(createGenericOidcIdentity({ ...OIDC_CONFIG, maxJwksDocumentBytes: value as number }));
  }
  for (const value of [1_024, 1_048_576]) {
    assert.doesNotThrow(() => createCloudflareAccessIdentity({ ...CF_CONFIG, maxJwksDocumentBytes: value }));
    assert.doesNotThrow(() => createEntraIdentity({ ...ENTRA_CONFIG, maxJwksDocumentBytes: value }));
    await assert.doesNotReject(createGenericOidcIdentity({ ...OIDC_CONFIG, maxJwksDocumentBytes: value }));
  }
});

test("the shared remote-JWKS options retain jose's five-minute cacheMaxAge", () => {
  assert.equal(remoteJwksOptions(undefined).cacheMaxAge, 5 * 60 * 1_000);
});
