import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import { test } from "node:test";
import type { JWK } from "jose";
import type { Context } from "hono";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { RateLimitPort } from "../src/ports/rate-limit.ts";
import type { IdentityPort } from "../src/ports/identity.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { AuthConfigError, createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { createOAuthApp } from "../src/adapters/hono.ts";
import { runAdapterFlow, type AdapterClient, type AdapterResp } from "./lib/adapter-flow.ts";
import { rawOccurrenceCall } from "./lib/adapter-header-flow.ts";

runAdapterFlow("hono", async (bridge, identity) => {
  // §6.7: the flow's stored-DCR leg needs an extractor to construct at all.
  // This harness rebuilds Requests from a buffered node socket, so no stable
  // runtime IP survives to extract — returning undefined keeps the per-request
  // "unknown" keys this flow asserts for hono.
  const app = createOAuthApp({ bridge, identity, clientIp: () => undefined });
  const server = createServer(async (incoming, outgoing) => {
    try {
      const chunks: Buffer[] = [];
      for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
      const headers = new Headers();
      for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
        headers.append(incoming.rawHeaders[index]!, incoming.rawHeaders[index + 1]!);
      }
      const init: RequestInit = { method: incoming.method, headers };
      if (incoming.method !== "GET" && incoming.method !== "HEAD") init.body = Buffer.concat(chunks);
      const response = await app.fetch(new Request(`http://localhost${incoming.url ?? "/"}`, init));
      outgoing.statusCode = response.status;
      response.headers.forEach((value, name) => outgoing.setHeader(name, value));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      outgoing.statusCode = 500;
      outgoing.end("request failed");
    }
  });
  server.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Hono test server did not bind a TCP port");
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
    requestOccurrences: (method, path, headers, body) =>
      rawOccurrenceCall(address.port, method, path, headers, body),
    async close() { await new Promise<void>((resolve) => server.close(() => resolve())); },
  };
  return client;
});

// §6.7: the hono adapter must NEVER derive the client IP from X-Forwarded-For on
// its own — an attacker-chosen header would select the rate-limit bucket
// (bucket-per-request = limiter bypass) and forge the audit `ip`.
function jwk(): JWK { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK; }
function honoSetup(
  clientIp?: (c: Context) => string | undefined,
  dcr: BridgeConfig["dcr"] = { mode: "stateless" },
): { app: ReturnType<typeof createOAuthApp>; keys: string[]; events: AuthAuditEvent[] } {
  const config = createBridgeConfig({
    issuer: "https://auth.test", resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k",
    redirectAllowlist: ["https://client.test/callback"], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr,
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

// §6.7/§9.6 boot rule: stored-DCR registration needs per-client limiter keys.
// Without an extractor every request shares the one "unknown" bucket, so one
// client could exhaust the anonymous durable-write budget for everyone.
const storedClients = { async save() {}, async find() { return null; } };

test("hono: stored DCR without a clientIp extractor refuses at createOAuthApp", () => {
  assert.throws(
    () => honoSetup(undefined, { mode: "stored", store: storedClients }),
    (error: unknown) => error instanceof AuthConfigError
      && /clientIp/.test(error.message)
      && /stored DCR/.test(error.message),
  );
});

test("hono: stateless DCR without clientIp boots and warns once about the shared unknown bucket", () => {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => { warnings.push(args.map(String).join(" ")); };
  let app: ReturnType<typeof createOAuthApp> | undefined;
  try {
    ({ app } = honoSetup());
  } finally {
    console.warn = original;
  }
  assert.ok(app, "stateless app constructs without clientIp");
  const bucketWarnings = warnings.filter((warning) => warning.includes("clientIp") && warning.includes("unknown"));
  assert.equal(bucketWarnings.length, 1);
  assert.match(bucketWarnings[0]!, /shares the one "unknown" rate-limit key/);
});

test("hono: stored DCR with a clientIp extractor boots silently and keeps per-client keys", async () => {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => { warnings.push(args.map(String).join(" ")); };
  let setup: ReturnType<typeof honoSetup>;
  try {
    setup = honoSetup(() => "9.9.9.9", { mode: "stored", store: storedClients });
  } finally {
    console.warn = original;
  }
  assert.equal(warnings.length, 0, "a supplied extractor emits no boot warning");
  const response = await setup.app.request("/oauth/register", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: ["https://client.test/callback"] }),
  });
  assert.equal(response.status, 201);
  assert.deepEqual(setup.keys, ["register:9.9.9.9"], "stored registration keys on the extracted client IP");
});
