import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { CimdSuccessCache, computeCacheExpiryMs } from "../src/cimd/cache.ts";
import { createBridgeConfig } from "../src/config.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { pkceChallenge } from "../src/crypto.ts";

const view = (cacheControl: string, extra: Record<string, readonly string[] | undefined> = {}) => ({
  cacheControl: [cacheControl], age: undefined, date: undefined, expires: undefined, vary: undefined, ...extra,
});

test("shared cache refuses private, s-maxage-limited, Age-exhausted, Date-stale, and Vary-star responses", () => {
  assert.equal(computeCacheExpiryMs(view("private, max-age=3600"), 3600, 0, 0), null);
  assert.equal(computeCacheExpiryMs(view("max-age=3600, s-maxage=0"), 3600, 0, 0), null);
  assert.equal(computeCacheExpiryMs(view("max-age=60", { age: ["60"] }), 3600, 0, 0), null);
  assert.equal(computeCacheExpiryMs(view("max-age=60", { date: [new Date(-60_000).toUTCString()] }), 3600, 0, 0), null);
  assert.equal(computeCacheExpiryMs(view("max-age=3600", { vary: ["*"] }), 3600, 0, 0), null);
});

test("shared cache uses s-maxage and RFC 9111 corrected initial age while preserving a fresh hit", () => {
  assert.equal(computeCacheExpiryMs(view("max-age=3600, s-maxage=60"), 3600, 0, 0), 60_000);
  // apparent age is 80 seconds, larger than Age=10; observed response delay is 5 seconds.
  assert.equal(computeCacheExpiryMs(view("max-age=100", { age: ["10"], date: [new Date(-75_000).toUTCString()] }), 3600, 0, 5_000), 25_000);
  const cache = new CimdSuccessCache();
  const one = { client_id: "https://one.example/cimd", client_name: "one", redirect_uris: ["https://one.example/cb"], allRedirectsLoopback: false };
  const two = { ...one, client_id: "https://two.example/cimd" };
  cache.set(one.client_id, one, 60_000);
  cache.set(two.client_id, two, 60_000);
  assert.equal(cache.get(one.client_id, 1), one);
  assert.equal(cache.get(two.client_id, 1), two);
  assert.equal(cache.get(one.client_id, 60_000), undefined);
  cache.set(two.client_id, two, 60_000, 59_000);
  assert.equal(cache.get(two.client_id, 61_000), undefined);
  assert.equal(cache.get(two.client_id, 0), undefined, "clock rollback cannot resurrect an expired entry");
});

const ID = "https://cdn.example.com/client";
const REDIRECT = "https://app.example.com/cb";
const body = JSON.stringify({ client_id: ID, client_name: "Example", redirect_uris: [REDIRECT] });
const bytes = new TextEncoder().encode(body);
const jwk = () => ({ ...generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" });
const config = () => createBridgeConfig({ issuer: "https://auth.test", resource: "https://api.test/mcp", consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k", redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"], allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" }, cimd: { enabled: true }, accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300 });
const request = { query: { response_type: "code", client_id: ID, redirect_uri: REDIRECT, code_challenge: pkceChallenge("correct-horse-battery-staple-0123456789abcdef0123"), code_challenge_method: "S256", scope: "mcp:read", state: "s" }, body: undefined, headers: {}, ip: "203.0.113.3" };
async function* one() { yield bytes; }
function bridgeFor(headersDistinct: Record<string, string[]>) {
  let calls = 0;
  const transport = { async connectAndGet() { calls += 1; return { status: 200, redirected: false, finalUrl: ID, headersDistinct, encodedBody: one() }; } };
  const bridge = new Bridge({ config: config(), store: new MemoryStore(), clock: { nowMs: () => 0 }, audit: { async writeAuthEvent() {} }, cimdTransport: transport, cimdResolver: { async resolve() { return [{ address: "93.184.216.34", family: 4 as const }]; } } });
  return { bridge, calls: () => calls };
}

test("resolver fetch counts prove shared-cache refusals and a normal fresh hit", async () => {
  for (const headers of [
    { "content-type": ["application/json"], "cache-control": ["private, max-age=3600"] },
    { "content-type": ["application/json"], "cache-control": ["max-age=3600, s-maxage=0"] },
    { "content-type": ["application/json"], "cache-control": ["max-age=60"], age: ["60"] },
    { "content-type": ["application/json"], "cache-control": ["max-age=60"], date: [new Date(-60_000).toUTCString()] },
  ]) {
    const s = bridgeFor(headers as unknown as Record<string, string[]>);
    assert.equal((await s.bridge.handleAuthorize(request, { subject: "user" })).status, 200);
    assert.equal((await s.bridge.handleAuthorize(request, { subject: "user" })).status, 200);
    assert.equal(s.calls(), 2);
  }
  const fresh = bridgeFor({ "content-type": ["application/json"], "cache-control": ["max-age=3600"] });
  await fresh.bridge.handleAuthorize(request, { subject: "user" });
  await fresh.bridge.handleAuthorize(request, { subject: "user" });
  assert.equal(fresh.calls(), 1);
});
