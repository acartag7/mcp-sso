import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import type { Context } from "hono";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { RateLimitPort } from "../src/ports/rate-limit.ts";
import type { IdentityPort } from "../src/ports/identity.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { createOAuthApp } from "../src/adapters/hono.ts";
import { runAdapterFlow, type AdapterClient, type AdapterResp } from "./lib/adapter-flow.ts";

runAdapterFlow("hono", async (bridge, identity) => {
  const app = createOAuthApp({ bridge, identity });
  const client: AdapterClient = {
    async get(path, headers) {
      const r = await app.request(path, { method: "GET", headers: headers ?? {} });
      return { status: r.status, headers: Object.fromEntries(r.headers), body: await r.text() } as AdapterResp;
    },
    async postForm(path, body, headers) {
      const r = await app.request(path, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, body: new URLSearchParams(body).toString() });
      return { status: r.status, headers: Object.fromEntries(r.headers), body: await r.text() } as AdapterResp;
    },
    async postJson(path, body, headers) {
      const r = await app.request(path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
      return { status: r.status, headers: Object.fromEntries(r.headers), body: await r.text() } as AdapterResp;
    },
  };
  return client;
});

// §6.7: the hono adapter must NEVER derive the client IP from X-Forwarded-For on
// its own — an attacker-chosen header would select the rate-limit bucket
// (bucket-per-request = limiter bypass) and forge the audit `ip`.
function jwk(): JWK { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK; }
function honoSetup(clientIp?: (c: Context) => string | undefined): { app: ReturnType<typeof createOAuthApp>; keys: string[]; events: AuthAuditEvent[] } {
  const config = createBridgeConfig({
    issuer: "https://auth.test", resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k",
    redirectAllowlist: ["https://client.test/callback"], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const keys: string[] = [];
  const events: AuthAuditEvent[] = [];
  const rateLimit: RateLimitPort = { async check(key: string) { keys.push(key); return true; } };
  const audit: AuditPort = { async writeAuthEvent(e: AuthAuditEvent) { events.push(e); } };
  const bridge = new Bridge({ config, store: new MemoryStore(), clock: { nowMs: () => Date.parse("2026-07-03T12:00:00.000Z") }, audit, rateLimit });
  const identity: IdentityPort = { async verify() { return { ok: true, identity: { subject: "s@test" } }; } };
  const app = createOAuthApp({ bridge, identity, clientIp });
  return { app, keys, events };
}

test("hono: X-Forwarded-For does NOT select the rate-limit bucket or the audit ip (default: no client IP)", async () => {
  const { app, keys, events } = honoSetup();
  for (const forged of ["6.6.6.1", "6.6.6.2"]) {
    await app.request("/oauth/token", {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": forged },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: "rt.x.y", client_id: "c" }).toString(),
    });
  }
  assert.deepEqual(keys, ["token:unknown", "token:unknown"], "every request shares ONE bucket — a forged XFF must not create per-attacker buckets");
  await app.request("/oauth/authorize?x=1", { headers: { "cf-access-jwt-assertion": "t", "x-forwarded-for": "6.6.6.3" } });
  const verify = events.find((e) => e.event === "identity.verify");
  assert.ok(verify, "identity.verify emitted");
  assert.equal(verify.ip, undefined, "audit ip is absent, never the forged XFF value");
});

test("hono: a deployer-supplied clientIp extractor keys the rate limit and audit ip", async () => {
  const { app, keys, events } = honoSetup(() => "9.9.9.9");
  await app.request("/oauth/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": "6.6.6.1" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: "rt.x.y", client_id: "c" }).toString(),
  });
  assert.deepEqual(keys, ["token:9.9.9.9"]);
  await app.request("/oauth/authorize?x=1", { headers: { "cf-access-jwt-assertion": "t" } });
  const verify = events.find((e) => e.event === "identity.verify");
  assert.equal(verify?.ip, "9.9.9.9");
});

test("hono: raw query parsing preserves every duplicate-sensitive authorization parameter", async () => {
  const duplicateSensitive = [
    "response_type", "client_id", "redirect_uri", "code_challenge",
    "code_challenge_method", "resource", "scope", "state",
  ] as const;
  const base = {
    response_type: "code",
    client_id: "c",
    redirect_uri: "https://client.test/callback",
    code_challenge: pkceChallenge("v".repeat(43)),
    code_challenge_method: "S256",
    resource: "https://api.test/mcp",
    scope: "mcp:read",
    state: "client-state",
  };
  const { app } = honoSetup();
  for (const key of duplicateSensitive) {
    const query = new URLSearchParams(base);
    query.append(key, "duplicate");
    const response = await app.request(`/oauth/authorize?${query}`, {
      headers: { "cf-access-jwt-assertion": "token" },
    });
    assert.equal(response.status, 400, `${key} was collapsed instead of preserved`);
    assert.equal(response.headers.get("location"), null);
    assert.equal((await response.json() as { error: string }).error, "invalid_request");
  }
});

test("hono: raw query accumulation does not consult inherited parameter values", async () => {
  let reads = 0;
  const previous = Object.getOwnPropertyDescriptor(Object.prototype, "client_id");
  Object.defineProperty(Object.prototype, "client_id", {
    configurable: true,
    get() { reads += 1; return "inherited-client"; },
  });
  try {
    const { app } = honoSetup();
    await app.request("/oauth/authorize?client_id=client&response_type=code", {
      headers: { "cf-access-jwt-assertion": "token" },
    });
    assert.equal(reads, 0);
  } finally {
    if (previous === undefined) delete (Object.prototype as Record<string, unknown>).client_id;
    else Object.defineProperty(Object.prototype, "client_id", previous);
  }
});

test("hono: request header accumulation does not invoke inherited setters", async () => {
  let writes = 0;
  const previous = Object.getOwnPropertyDescriptor(Object.prototype, "authorization");
  const request = new Request("http://localhost/oauth/token", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: "Basic harmless-test-value",
    },
    body: "grant_type=authorization_code",
  });
  Object.defineProperty(Object.prototype, "authorization", {
    configurable: true,
    set() { writes += 1; },
  });
  try {
    const { app } = honoSetup();
    await app.request(request);
    assert.equal(writes, 0);
  } finally {
    if (previous === undefined) delete (Object.prototype as Record<string, unknown>).authorization;
    else Object.defineProperty(Object.prototype, "authorization", previous);
  }
});
