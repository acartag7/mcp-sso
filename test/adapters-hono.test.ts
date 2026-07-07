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
