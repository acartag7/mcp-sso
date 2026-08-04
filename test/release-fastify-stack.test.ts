import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { Redis } from "ioredis";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { createCloudflareAccessIdentity } from "../src/identity/cloudflare-access.ts";
import type { AuthAuditEvent, AuditPort } from "../src/ports/audit.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { STORED_DCR_GRANT_GENERATION } from "../src/ports/store.ts";
import { RedisRateLimit } from "../src/rate-limit/redis.ts";
import { openSqliteStore } from "../src/store/sqlite.ts";
import { RequestAuthorizer } from "../src/verifier.ts";
import { attemptCleanup, fetchLoopbackOnly, http, mountStack, sdkPing } from "./lib/release-http-stack.ts";

const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;
const ISSUER = "http://localhost", RESOURCE = "http://localhost/mcp", REDIRECT = "http://localhost:4321/callback";

class Clients implements ClientStore {
  readonly rows = new Map<string, ClientRegistration>();
  async save(client: ClientRegistration): Promise<void> { this.rows.set(client.clientId, structuredClone(client)); }
  async find(id: string): Promise<ClientRegistration | null> { return structuredClone(this.rows.get(id) ?? null); }
}
class Audit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(structuredClone(event)); }
}
function signingJwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "release" } as JWK;
}
function hidden(html: string): string { const value = /name="consent_token" value="([^"]+)"/.exec(html)?.[1]; assert.ok(value); return value; }

releaseTest("RM.2 composes Fastify, Cloudflare, SQLite, stored DCR, Redis, SDK, Origin, and restart", async () => {
  assert.ok(process.env.REDIS_URL);
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-release-fastify-"));
  const sqliteFile = join(dir, "oauth.db");
  const realFetch = globalThis.fetch;
  let redis: Redis | undefined;
  let store: ReturnType<typeof openSqliteStore> | undefined;
  let mounted: Awaited<ReturnType<typeof mountStack>> | undefined;
  let prefix = "";
  try {
  const clients = new Clients(); const audit = new Audit(); const clock = new SystemClock();
  redis = new Redis(process.env.REDIS_URL);
  prefix = `release:${process.pid}:${Date.now()}:`;
  const realLimiter = new RedisRateLimit(redis, { windowSeconds: 60, limit: 100, keyPrefix: prefix });
  const denialLimiter = new RedisRateLimit(redis, { windowSeconds: 60, limit: 1, keyPrefix: `${prefix}deny:` });
  const limiterKeys: string[] = [];
  let denyMode = false;
  const limiter = { async check(key: string): Promise<boolean> {
    limiterKeys.push(key); return (denyMode ? denialLimiter : realLimiter).check(key);
  } };
  const config = createBridgeConfig({ issuer: ISSUER, resource: RESOURCE, consentSigningSecret: "f".repeat(40),
    signingPrivateJwk: signingJwk(), signingKeyId: "release", redirectAllowlist: [REDIRECT],
    scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"], allowedOrigins: [ISSUER],
    dcr: { mode: "stored", store: clients }, dev: { allowInsecureLocalhost: true }, accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 3600, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300 });
  const cfKeys = await generateKeyPair("RS256");
  const publicJwk = { ...(await exportJWK(cfKeys.publicKey)), kid: "cf-release", alg: "RS256", use: "sig" };
  const certsUrl = "https://cf.release.test/certs", cfIssuer = "https://cf.release.test", audience = "release-audience";
  globalThis.fetch = (async (input: URL | Request | string, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    return url === certsUrl
      ? new Response(JSON.stringify({ keys: [publicJwk] }), { headers: { "content-type": "application/json" } })
      : fetchLoopbackOnly(realFetch, input, init);
  }) as typeof fetch;
  const cf = createCloudflareAccessIdentity({ audience, certsUrl, issuer: cfIssuer });
  let allowedScopes = ["mcp:read"];
  const identity = { async verify(input: unknown) {
    const result = await cf.verify(input);
    return result.ok ? { ok: true as const, identity: { ...result.identity, allowedScopes } } : result;
  } };
  store = openSqliteStore(sqliteFile);
    const bridge = new Bridge({ config, store, clock, audit, rateLimit: limiter });
    mounted = await mountStack("fastify", bridge, new RequestAuthorizer({ config, clock, audit }), config,
      { identity, identityHeader: "cf-access-jwt-assertion" });
    const registration = await http.postJson(mounted.base, "/oauth/register", { redirect_uris: [REDIRECT], application_type: "native" });
    assert.equal(registration.status, 201); const clientId = JSON.parse(registration.body).client_id as string;
    const now = Math.floor(Date.now() / 1000);
    const cfToken = await new SignJWT({ sub: "cf-release-user", email: "release@example.test" }).setProtectedHeader({ alg: "RS256", kid: "cf-release" })
      .setIssuer(cfIssuer).setAudience(audience).setIssuedAt(now).setExpirationTime(now + 3600).sign(cfKeys.privateKey);
    const verifier = "release-fastify-verifier-0123456789abcdef012345678901";
    const query = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
      code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read mcp:write", state: "release" });
    const authorize = await http.get(mounted.base, `/oauth/authorize?${query}`, { "cf-access-jwt-assertion": cfToken });
    assert.equal(authorize.status, 200);
    const approve = await http.postForm(mounted.base, "/oauth/authorize/approve", { consent_token: hidden(authorize.body), approved: "true" }, { origin: ISSUER });
    assert.equal(approve.status, 302); const code = new URL(String(approve.headers.location)).searchParams.get("code"); assert.ok(code);
    const token = await http.postForm(mounted.base, "/oauth/token", { grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier });
    assert.equal(token.status, 200); const tokens = JSON.parse(token.body) as { access_token: string; refresh_token: string };
    await sdkPing(mounted.base, tokens.access_token, "pong: cf-release-user");
    allowedScopes = ["mcp:read", "mcp:write"];
    const writeVerifier = "release-fastify-write-verifier-0123456789abcdef012345";
    const writeQuery = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
      code_challenge: pkceChallenge(writeVerifier), code_challenge_method: "S256", scope: "mcp:write", state: "write" });
    const writeAuthorize = await http.get(mounted.base, `/oauth/authorize?${writeQuery}`, { "cf-access-jwt-assertion": cfToken });
    assert.equal(writeAuthorize.status, 200);
    const writeApprove = await http.postForm(mounted.base, "/oauth/authorize/approve",
      { consent_token: hidden(writeAuthorize.body), approved: "true" }, { origin: ISSUER });
    const writeCode = new URL(String(writeApprove.headers.location)).searchParams.get("code"); assert.ok(writeCode);
    const writeToken = await http.postForm(mounted.base, "/oauth/token", { grant_type: "authorization_code", code: writeCode,
      redirect_uri: REDIRECT, client_id: clientId, code_verifier: writeVerifier });
    assert.equal(writeToken.status, 200);
    const foreign = await http.postJson(mounted.base, "/mcp", { jsonrpc: "2.0", method: "tools/list", id: 1 },
      { authorization: `Bearer ${tokens.access_token}`, origin: "https://evil.test" });
    assert.equal(foreign.status, 403);
    assert.ok(limiterKeys.some((key) => key.startsWith("authorize:")), "real Redis limiter ran in the composed route");
    assert.deepEqual(await store.findGrantedScopes("cf-release-user", clientId, new Date().toISOString(), STORED_DCR_GRANT_GENERATION, RESOURCE),
      ["mcp:read", "mcp:write"], "stored grants accumulated across two real authorization-code exchanges");
    denyMode = true;
    assert.equal((await http.get(mounted.base, `/oauth/authorize?${writeQuery}`, { "cf-access-jwt-assertion": cfToken })).status, 200);
    assert.equal((await http.get(mounted.base, `/oauth/authorize?${writeQuery}`, { "cf-access-jwt-assertion": cfToken })).status, 429,
      "the shipped Fastify route enforced a false admission from Redis");
    denyMode = false;
    const authorizeKey = limiterKeys.findLast((key) => key.startsWith("authorize:")); assert.ok(authorizeKey);
    const collisionKey = `${prefix}${authorizeKey}`;
    await redis.del(collisionKey); await redis.rpush(collisionKey, "wrongtype");
    await assert.rejects(realLimiter.check(authorizeKey), /WRONGTYPE/, "the real Redis adapter surfaced the collision error");
    const limiterCalls = limiterKeys.length;
    assert.equal((await http.get(mounted.base, `/oauth/authorize?${writeQuery}`, { "cf-access-jwt-assertion": cfToken })).status, 200,
      "the shipped Fastify route failed open on the real Redis error");
    assert.equal(limiterKeys.length, limiterCalls + 1, "the fail-open route still called the real Redis limiter");
    await mounted.close(); mounted = undefined; await store.close();

    store = openSqliteStore(sqliteFile);
    const restartedBridge = new Bridge({ config, store, clock, audit, rateLimit: limiter });
    mounted = await mountStack("fastify", restartedBridge, new RequestAuthorizer({ config, clock, audit }), config,
      { identity, identityHeader: "cf-access-jwt-assertion" });
    const refreshed = await http.postForm(mounted.base, "/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId });
    assert.equal(refreshed.status, 200, "the SQLite-backed flow survived restart");
  } finally {
    globalThis.fetch = realFetch;
    const errors: Error[] = [];
    await attemptCleanup("Fastify", async () => mounted?.close(), errors);
    await attemptCleanup("SQLite", async () => store?.close(), errors);
    await attemptCleanup("Redis keys", async () => {
      if (!redis) return; const keys = await redis.keys(`${prefix}*`); if (keys.length > 0) await redis.del(...keys);
    }, errors);
    await attemptCleanup("Redis client", async () => redis?.quit(), errors);
    await attemptCleanup("temporary directory", () => rm(dir, { recursive: true, force: true }), errors);
    if (errors.length > 0) throw new AggregateError(errors, "RM.2 cleanup failed");
  }
});
