import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { CimdSuccessCache, computeCacheExpiryMs } from "../src/cimd/cache.ts";
import { createBridgeConfig } from "../src/config.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { pkceChallenge } from "../src/crypto.ts";

const view = (cacheControl: string, extra: Record<string, readonly string[] | undefined> = {}) => ({
  valid: true, cacheControl: [cacheControl], age: undefined, date: undefined, vary: undefined, ...extra,
});

test("shared cache refuses private, no-store/no-cache, s-maxage-limited, Age-exhausted, Date-stale, and Vary-star responses", () => {
  assert.equal(computeCacheExpiryMs(view("private, max-age=3600"), 3600, 0, 0), null);
  assert.equal(computeCacheExpiryMs(view("no-store, max-age=3600"), 3600, 0, 0), null);
  assert.equal(computeCacheExpiryMs(view("no-cache, max-age=3600"), 3600, 0, 0), null);
  assert.equal(computeCacheExpiryMs(view("max-age=3600, s-maxage=0"), 3600, 0, 0), null);
  assert.equal(computeCacheExpiryMs(view("max-age=60", { age: ["60"] }), 3600, 0, 0), null);
  assert.equal(computeCacheExpiryMs(view("max-age=60", { date: [new Date(-60_000).toUTCString()] }), 3600, 0, 0), null);
  assert.equal(computeCacheExpiryMs(view("max-age=3600", { vary: ["*"] }), 3600, 0, 0), null);
});

test("shared cache uses s-maxage and RFC 9111 corrected initial age while preserving raw-key hits", () => {
  assert.equal(computeCacheExpiryMs(view("max-age=3600, s-maxage=60"), 3600, 0, 0), 60_000);
  // Apparent age is 80 seconds, larger than Age=10 plus the observed 5-second delay.
  assert.equal(computeCacheExpiryMs(view("max-age=100", { age: ["10"], date: [new Date(-75_000).toUTCString()] }), 3600, 0, 5_000), 25_000);
  assert.equal(computeCacheExpiryMs(view("max-age=100", { age: ["80"] }), 3600, 0, 5_000), 20_000, "response delay adds to Age");
  assert.equal(computeCacheExpiryMs(view("max-age=60"), 3600, 1, 1_000), 60_001, "freshness keeps millisecond precision");
  const cache = new CimdSuccessCache();
  const one = { client_id: "https://one.example/cimd", client_name: "one", redirect_uris: ["https://one.example/cb"], allRedirectsLoopback: false };
  const two = { ...one, client_id: "https://two.example/cimd" };
  cache.set(one.client_id, one, 60_000, 0);
  cache.set(two.client_id, two, 60_000, 0);
  assert.equal(cache.get(one.client_id, 1), one);
  assert.equal(cache.get(two.client_id, 1), two);
  assert.equal(cache.get(one.client_id, 60_000), undefined);
});

test("Date accepts only HTTP-date formats", () => {
  const responseTime = Date.UTC(1994, 10, 6, 8, 49, 37);
  for (const date of [
    "Sun, 06 Nov 1994 08:49:37 GMT",
    "Sunday, 06-Nov-94 08:49:37 GMT",
    "Sun Nov  6 08:49:37 1994",
    "Sat, 31 Dec 2016 23:59:60 GMT",
  ]) {
    assert.notEqual(computeCacheExpiryMs(view("max-age=60", { date: [date] }), 3600, responseTime, responseTime), null);
  }
  for (const date of ["9999-12-31", "01/01/3000", "Sun, 06 Nov 1994 08:49:37 UTC"]) {
    assert.equal(computeCacheExpiryMs(view("max-age=60", { date: [date] }), 3600, responseTime, responseTime), null);
  }
});

test("clock rollback clears old entries and recovers from a spurious future reading", () => {
  const cache = new CimdSuccessCache();
  const old = { client_id: "https://old.example/cimd", client_name: "old", redirect_uris: ["https://old.example/cb"], allRedirectsLoopback: false };
  const recovered = { ...old, client_id: "https://recovered.example/cimd" };
  cache.set(old.client_id, old, 60_000, 0);
  assert.equal(cache.get("cache-miss", 100_000), undefined, "future observation does not delete old key");
  assert.equal(cache.get(old.client_id, 0), undefined, "rollback clears instead of resurrecting old entry");
  cache.set(recovered.client_id, recovered, 61_000, 1_000);
  assert.equal(cache.get(recovered.client_id, 2_000), recovered, "a new entry caches after clock recovery");
  assert.equal(cache.get(old.client_id, 2_000), undefined, "cleared old entry cannot return after recovery");
});

const ID = "https://cdn.example.com/client";
const REDIRECT = "https://app.example.com/cb";
const body = JSON.stringify({ client_id: ID, client_name: "Example", redirect_uris: [REDIRECT] });
const bytes = new TextEncoder().encode(body);
const jwk = () => ({ ...generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" });
const config = () => createBridgeConfig({ issuer: "https://auth.test", resource: "https://api.test/mcp", consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k", redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"], allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" }, cimd: { enabled: true }, accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300 });
const request = { query: { response_type: "code", client_id: ID, redirect_uri: REDIRECT, code_challenge: pkceChallenge("correct-horse-battery-staple-0123456789abcdef0123"), code_challenge_method: "S256", scope: "mcp:read", state: "s" }, body: undefined, headers: {}, ip: "203.0.113.3" };
async function* one() { yield bytes; }
function bridgeFor(headersDistinct: unknown, throwAfterFirst = false) {
  let calls = 0;
  const clock = { ms: 0, nowMs() { return this.ms; } };
  const transport = { async connectAndGet() { calls += 1; if (throwAfterFirst && calls > 1) throw new Error("refetch failed"); return { status: 200, redirected: false, finalUrl: ID, headersDistinct: headersDistinct as any, encodedBody: one() }; } };
  const bridge = new Bridge({ config: config(), store: new MemoryStore(), clock, audit: { async writeAuthEvent() {} }, cimdTransport: transport, cimdResolver: { async resolve() { return [{ address: "93.184.216.34", family: 4 as const }]; } } });
  return { bridge, clock, calls: () => calls };
}

test("resolver fetch counts prove shared-cache refusals and a normal fresh hit", async () => {
  for (const headers of [
    { "content-type": ["application/json"], "cache-control": ["private, max-age=3600"] },
    { "content-type": ["application/json"], "cache-control": ["max-age=3600, s-maxage=0"] },
    { "content-type": ["application/json"], "cache-control": ["max-age=60"], age: ["60"] },
    { "content-type": ["application/json"], "cache-control": ["max-age=60"], date: [new Date(-60_000).toUTCString()] },
    { "content-type": ["application/json"], expires: [new Date(3_600_000).toUTCString()] },
  ]) {
    const s = bridgeFor(headers);
    assert.equal((await s.bridge.handleAuthorize(request, { subject: "user" })).status, 200);
    assert.equal((await s.bridge.handleAuthorize(request, { subject: "user" })).status, 200);
    assert.equal(s.calls(), 2);
  }
  const fresh = bridgeFor({ "content-type": ["application/json"], "cache-control": ["max-age=3600"] });
  await fresh.bridge.handleAuthorize(request, { subject: "user" });
  await fresh.bridge.handleAuthorize(request, { subject: "user" });
  assert.equal(fresh.calls(), 1);
});

test("malformed runtime Vary and stale refetch failure never reuse CIMD metadata", async () => {
  const malformed = bridgeFor({ "content-type": ["application/json"], "cache-control": ["max-age=3600"], vary: "*" });
  assert.equal((await malformed.bridge.handleAuthorize(request, { subject: "user" })).status, 200);
  assert.equal((await malformed.bridge.handleAuthorize(request, { subject: "user" })).status, 200);
  assert.equal(malformed.calls(), 2, "bare Vary is malformed and cannot be cached");
  const emptyVary = bridgeFor({ "content-type": ["application/json"], "cache-control": ["max-age=3600"], vary: [] });
  assert.equal((await emptyVary.bridge.handleAuthorize(request, { subject: "user" })).status, 200);
  assert.equal((await emptyVary.bridge.handleAuthorize(request, { subject: "user" })).status, 200);
  assert.equal(emptyVary.calls(), 2, "empty Vary is malformed and cannot be cached");
  const stale = bridgeFor({ "content-type": ["application/json"], "cache-control": ["max-age=60"] }, true);
  assert.equal((await stale.bridge.handleAuthorize(request, { subject: "user" })).status, 200);
  stale.clock.ms = 60_000;
  assert.equal((await stale.bridge.handleAuthorize(request, { subject: "user" })).status, 401);
  assert.equal(stale.calls(), 2, "expired metadata is refetched and the fetch failure is not served stale");
});
