import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { test, type TestContext } from "node:test";
import { importJWK, jwtVerify } from "jose";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { publicJwk, signAccessToken } from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import { noopAudit } from "../src/ports/audit.ts";
import { RequestAuthorizer } from "../src/verifier.ts";

const clock = { nowMs: () => Date.parse("2026-08-26T12:00:00.000Z") };
const claims = (subject: string) => ({ subject, clientId: "test-client", scopes: ["mcp:read"] });

function config(): BridgeConfig {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return createBridgeConfig({
    issuer: "https://api.example.com", resource: "https://api.example.com/mcp",
    consentSigningSecret: randomBytes(32).toString("hex"),
    signingPrivateJwk: privateKey.export({ format: "jwk" }), signingKeyId: "test-key",
    redirectAllowlist: ["https://client.example.com/callback"], redirectAllowlistMode: "replace",
    scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://api.example.com"], dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 300, refreshTokenTtlSeconds: 3600,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

// Observe native imports while preserving their real results and promises.
// The production caches and the signer/verifier remain unmocked.
function importCount(t: TestContext, usage: "sign" | "verify"): () => number {
  const subtle = globalThis.crypto.subtle;
  const original = subtle.importKey;
  let count = 0;
  t.mock.method(subtle, "importKey", (...args: Parameters<typeof original>) => {
    if (args[4].includes(usage)) count += 1;
    return Reflect.apply(original, subtle, args);
  });
  return () => count;
}

test("authorization reuses one verification import per stable key reference", { concurrency: false }, async (t) => {
  const first = config(); const second = config();
  assert.notEqual(first.signingPrivateJwk.x, second.signingPrivateJwk.x);
  const firstToken = await signAccessToken(claims("first-subject"), first, clock);
  const secondToken = await signAccessToken(claims("second-subject"), second, clock);
  const imports = importCount(t, "verify");
  const firstVerifier = new RequestAuthorizer({ config: first, clock, audit: noopAudit });
  const secondVerifier = new RequestAuthorizer({ config: second, clock, audit: noopAudit });
  const request = (token: string) => ({ authorization: `Bearer ${token}`, requiredScope: "mcp:read" });
  const results = await Promise.all(Array.from({ length: 6 }, () => firstVerifier.authorize(request(firstToken))));
  assert.deepEqual(results.map(result => result.subject), Array(6).fill("first-subject"));
  assert.equal(imports(), 1);
  assert.equal((await firstVerifier.authorize(request(firstToken))).subject, "first-subject");
  assert.equal(imports(), 1);
  const sameKeyVerifier = new RequestAuthorizer({ config: first, clock, audit: noopAudit });
  assert.equal((await sameKeyVerifier.authorize(request(firstToken))).subject, "first-subject");
  assert.equal(imports(), 1);
  assert.equal((await secondVerifier.authorize(request(secondToken))).subject, "second-subject");
  assert.equal(imports(), 2);
  await assert.rejects(secondVerifier.authorize(request(firstToken)),
    (error: unknown) => error instanceof OAuthError && error.code === "invalid_token" && error.status === 401);
  assert.equal(imports(), 2);
  assert.equal((await firstVerifier.authorize(request(firstToken))).subject, "first-subject");
  assert.equal(imports(), 2);
});

test("access signing reuses its own import per key and preserves the second key", { concurrency: false }, async (t) => {
  const first = config(); const second = config();
  const firstPublic = await importJWK(publicJwk(first), "ES256");
  const secondPublic = await importJWK(publicJwk(second), "ES256");
  const imports = importCount(t, "sign");
  const options = { algorithms: ["ES256"], issuer: first.issuer, audience: first.resource,
    currentDate: new Date(clock.nowMs()) };
  const firstTokens = await Promise.all(Array.from({ length: 6 }, () => signAccessToken(claims("first-subject"), first, clock)));
  assert.equal(imports(), 1);
  for (const token of firstTokens) assert.equal((await jwtVerify(token, firstPublic, options)).payload.sub, "first-subject");
  const secondToken = await signAccessToken(claims("second-subject"), second, clock);
  assert.equal(imports(), 2);
  assert.equal((await jwtVerify(secondToken, secondPublic, options)).payload.sub, "second-subject");
  await assert.rejects(jwtVerify(secondToken, firstPublic, options));
  const again = await signAccessToken(claims("first-again"), first, clock);
  assert.equal((await jwtVerify(again, firstPublic, options)).payload.sub, "first-again");
  assert.equal(imports(), 2);
});
