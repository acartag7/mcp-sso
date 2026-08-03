import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { Hono } from "hono";
import type { Bridge } from "../src/adapters/bridge.ts";
import { Bridge as RealBridge } from "../src/adapters/bridge.ts";
import { createOAuthApp, honoOAuthBodyLimit } from "../src/adapters/hono.ts";
import type { NormRequest, NormResponse } from "../src/adapters/http.ts";
import { createBridgeConfig } from "../src/config.ts";
import { MemoryStore } from "../src/store/memory.ts";

const LIMIT = 256 * 1024;
const ROUTES = [
  "/oauth/register",
  "/oauth/authorize/approve",
  "/oauth/token",
  "/oauth/revoke",
] as const;

type Handler = "register" | "approve" | "token" | "revoke";

function ok(body: unknown = { ok: true }): NormResponse {
  return { status: 200, headers: {}, body };
}

function harness(clientIp?: Parameters<typeof createOAuthApp>[0]["clientIp"]): {
  app: ReturnType<typeof createOAuthApp>;
  calls: Handler[];
  requests: NormRequest[];
} {
  const calls: Handler[] = [];
  const requests: NormRequest[] = [];
  const receive = (name: Handler) => async (request: NormRequest): Promise<NormResponse> => {
    calls.push(name);
    requests.push(request);
    return ok();
  };
  const bridge = {
    config: { resource: "https://api.test/mcp" },
    handleRegister: receive("register"),
    handleApprove: receive("approve"),
    handleToken: receive("token"),
    handleRevoke: receive("revoke"),
  } as unknown as Bridge;
  return { app: createOAuthApp({ bridge, skipAuthorize: true, clientIp }), calls, requests };
}

function realApp(redirectAllowlist = ["https://client.test/callback"]): ReturnType<typeof createOAuthApp> {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const config = createBridgeConfig({
    issuer: "https://auth.test",
    resource: "https://api.test/mcp",
    consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK,
    signingKeyId: "k",
    redirectAllowlist,
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
  const bridge = new RealBridge({
    config,
    store: new MemoryStore(),
    clock: { nowMs: () => Date.parse("2026-08-03T12:00:00.000Z") },
    audit: { async writeAuthEvent() {} },
  });
  return createOAuthApp({ bridge, skipAuthorize: true });
}

function sideEffectHarness(): {
  app: ReturnType<typeof createOAuthApp>;
  effects: { limiter: number; storeWrites: number; successAudits: number };
} {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const effects = { limiter: 0, storeWrites: 0, successAudits: 0 };
  const clientStore = {
    async save() { effects.storeWrites += 1; },
    async find() { return null; },
  };
  const config = createBridgeConfig({
    issuer: "https://auth.test", resource: "https://api.test/mcp",
    consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK,
    signingKeyId: "k", redirectAllowlist: ["https://client.test/callback"],
    scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"], allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stored", store: clientStore }, accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const bridge = new RealBridge({
    config, store: new MemoryStore(), clock: { nowMs: () => Date.parse("2026-08-03T12:00:00.000Z") },
    rateLimit: { async check() { effects.limiter += 1; return true; } },
    audit: { async writeAuthEvent(event) { if (event.status === "success") effects.successAudits += 1; } },
  });
  return { app: createOAuthApp({ bridge, skipAuthorize: true }), effects };
}

function streamRequest(
  path: string,
  totalBytes: number,
  chunkBytes: number,
  extraHeaders: Record<string, string> = {},
): { request: Request; produced: () => number } {
  let produced = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (produced === totalBytes) {
        controller.close();
        return;
      }
      const size = Math.min(chunkBytes, totalBytes - produced);
      produced += size;
      controller.enqueue(new Uint8Array(size));
    },
  }, { highWaterMark: 0 });
  const request = new Request(`http://localhost${path}`, {
    method: "POST",
    headers: { "content-type": "application/octet-stream", ...extraHeaders },
    body,
    duplex: "half",
  });
  return { request, produced: () => produced };
}

function failedStreamRequest(
  path: string,
  mode: "error" | "chunk-then-throw",
  extraHeaders: Record<string, string> = {},
): Request {
  let pulls = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls += 1;
      if (mode === "chunk-then-throw" && pulls === 1) {
        controller.enqueue(new Uint8Array(32));
        return;
      }
      if (mode === "error") {
        controller.error(new Error());
        return;
      }
      throw new Error();
    },
  }, { highWaterMark: 0 });
  return new Request(`http://localhost${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...extraHeaders },
    body,
    duplex: "half",
  });
}

test("hono body cap: small JSON, form, and multipart bodies reach real routes", async () => {
  const { app, calls, requests } = harness();

  const json = await app.request("/oauth/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: ["https://client.test/callback"] }),
  });
  assert.equal(json.status, 200);
  assert.deepEqual(requests.at(-1)?.body, { redirect_uris: ["https://client.test/callback"] });

  const form = await app.request("/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=refresh_token&refresh_token=small",
  });
  assert.equal(form.status, 200);
  assert.equal((requests.at(-1)?.body as Record<string, unknown>).grant_type, "refresh_token");

  const multipartBody = new FormData();
  multipartBody.set("redirect_uris", "https://client.test/callback");
  const multipart = await app.request("/oauth/register", { method: "POST", body: multipartBody });
  assert.equal(multipart.status, 200);
  assert.equal((requests.at(-1)?.body as Record<string, unknown>).redirect_uris, "https://client.test/callback");
  assert.deepEqual(calls, ["register", "token", "register"]);
});

test("hono body cap: a fully JSON-escaped largest valid registration is admitted", async () => {
  const redirectUri = "https://client.test/" + "a".repeat(2048 - Buffer.byteLength("https://client.test/"));
  const escapedUri = [...redirectUri]
    .map((character) => `\\u${character.codePointAt(0)!.toString(16).padStart(4, "0")}`)
    .join("");
  const redirectUris = Array(16).fill(redirectUri);
  const body = `{"redirect_uris":[${Array(16).fill(`"${escapedUri}"`).join(",")}]}`;
  assert.ok(Buffer.byteLength(body) > 128 * 1024);
  assert.ok(Buffer.byteLength(body) <= LIMIT);

  const response = await realApp(["https://client.test"]).request("/oauth/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
  assert.equal(response.status, 201);
  assert.deepEqual((await response.json() as { redirect_uris: string[] }).redirect_uris, redirectUris);
});

test("hono body cap: exactly-at-cap passes and one byte over returns fixed 413", async () => {
  const { app, calls } = harness();
  const exact = streamRequest("/oauth/revoke", LIMIT, 16 * 1024);
  const exactResponse = await app.fetch(exact.request);
  assert.equal(exactResponse.status, 200);
  assert.equal(exact.produced(), LIMIT);
  assert.deepEqual(calls, ["revoke"]);

  const over = streamRequest("/oauth/revoke", LIMIT + 1, 16 * 1024);
  const overResponse = await app.fetch(over.request);
  assert.equal(overResponse.status, 413);
  assert.equal(await overResponse.text(), "Payload Too Large");
  assert.equal(overResponse.headers.get("location"), null);
  assert.equal(over.produced(), LIMIT + 1);
  assert.deepEqual(calls, ["revoke"], "one-byte-over request must not invoke Bridge");
});

test("hono body cap: a small declared length cannot hide a larger stream", async () => {
  const { app, calls } = harness();
  const hidden = streamRequest("/oauth/token", LIMIT + 1, 16 * 1024, { "content-length": "1" });
  const response = await app.fetch(hidden.request);
  assert.equal(response.status, 413);
  assert.equal(hidden.produced(), LIMIT + 1);
  assert.deepEqual(calls, []);
});

test("hono body cap: malformed and ambiguous length framing fails before consumption", async () => {
  for (const contentLength of ["12x", "+12", "-1", "01", "1, 2", "9".repeat(400)]) {
    const { app, calls } = harness();
    const streamed = streamRequest("/oauth/register", 1024, 128, { "content-length": contentLength });
    const response = await app.fetch(streamed.request);
    assert.equal(response.status, 413, contentLength);
    assert.equal(streamed.produced(), 0, contentLength);
    assert.deepEqual(calls, [], contentLength);
  }

  const { app, calls } = harness();
  const conflicting = streamRequest("/oauth/register", 1024, 128, {
    "content-length": "1024",
    "transfer-encoding": "chunked",
  });
  const response = await app.fetch(conflicting.request);
  assert.equal(response.status, 413);
  assert.equal(conflicting.produced(), 0);
  assert.deepEqual(calls, []);
});

test("hono body cap: every shipped OAuth POST route rejects before Bridge", async () => {
  const { app, calls } = harness();
  for (const route of ROUTES) {
    const response = await app.fetch(new Request(`http://localhost${route}`, {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": String(LIMIT + 1) },
      body: "{}",
    }));
    assert.equal(response.status, 413, route);
    assert.equal(await response.text(), "Payload Too Large", route);
  }
  assert.deepEqual(calls, []);
});

test("hono body cap: over-cap registration has no limiter, store, or success-audit effects", async () => {
  const { app, effects } = sideEffectHarness();
  const body = JSON.stringify({
    redirect_uris: ["https://client.test/callback"],
    padding: "x".repeat(LIMIT),
  });
  const response = await app.request("/oauth/register", {
    method: "POST", headers: { "content-type": "application/json" }, body,
  });
  assert.equal(response.status, 413);
  assert.deepEqual(effects, { limiter: 0, storeWrites: 0, successAudits: 0 });
});

test("hono body cap: middleware stops pulling a demand-driven 2 MiB stream after the crossing chunk", async () => {
  const { app, calls } = harness();
  const hostile = streamRequest("/oauth/token", 2 * 1024 * 1024, 16 * 1024, {
    "transfer-encoding": "chunked",
  });
  const response = await app.fetch(hostile.request);
  assert.equal(response.status, 413);
  assert.equal(hostile.produced(), LIMIT + 16 * 1024);
  assert.ok(hostile.produced() < 2 * 1024 * 1024, "producer must not be fully consumed");
  assert.deepEqual(calls, []);
});

test("hono body cap: Request own-property extensions remain visible to clientIp", async () => {
  type RuntimeRequest = Request & { runtimeIp?: string };
  const { app, requests } = harness((c) => (c.req.raw as RuntimeRequest).runtimeIp);
  for (const contentLength of [undefined, "1024"]) {
    const streamed = streamRequest("/oauth/token", 1024, 256,
      contentLength === undefined ? {} : { "content-length": contentLength });
    Object.defineProperty(streamed.request, "runtimeIp", { value: "203.0.113.41" });
    const response = await app.fetch(streamed.request);
    assert.equal(response.status, 200);
    assert.equal(requests.at(-1)?.ip, "203.0.113.41");
  }
});

test("hono body cap: failed under-cap streams are sanitized before all downstream work", async () => {
  const logged: unknown[][] = [];
  const originalConsoleError = console.error;
  console.error = (...args: unknown[]) => { logged.push(args); };
  try {
    const custom = new Hono();
    let parserCalls = 0;
    custom.post("/oauth/authorize", honoOAuthBodyLimit, async (c) => {
      parserCalls += 1;
      await c.req.json();
      return c.text("unreachable");
    });
    const errored = await custom.fetch(failedStreamRequest("/oauth/authorize", "error"));
    assert.equal(errored.status, 400);
    assert.deepEqual(await errored.json(), {
      error: "invalid_request", error_description: "Invalid request",
    });
    assert.equal(errored.headers.get("location"), null);
    assert.equal(parserCalls, 0);

    const bridgeHarness = harness();
    const thrown = await bridgeHarness.app.fetch(failedStreamRequest(
      "/oauth/token", "chunk-then-throw", { "content-length": "64" },
    ));
    assert.equal(thrown.status, 400);
    assert.deepEqual(bridgeHarness.calls, []);

    const sideEffects = sideEffectHarness();
    const failed = await sideEffects.app.fetch(failedStreamRequest("/oauth/register", "error"));
    assert.equal(failed.status, 400);
    assert.deepEqual(sideEffects.effects, { limiter: 0, storeWrites: 0, successAudits: 0 });
  } finally {
    console.error = originalConsoleError;
  }
  assert.deepEqual(logged, []);
});

test("hono body cap: downstream failures keep the existing Hono error path", async () => {
  const app = new Hono();
  const nonErrorThrowable = { kind: "downstream-non-error" };
  app.post("/oauth/token", honoOAuthBodyLimit, () => {
    throw new Error("DOWNSTREAM_HANDLER_DETAIL");
  });
  app.post("/oauth/revoke", honoOAuthBodyLimit, () => {
    throw nonErrorThrowable;
  });
  const logged: unknown[][] = [];
  const originalConsoleError = console.error;
  console.error = (...args: unknown[]) => { logged.push(args); };
  try {
    const response = await app.request("/oauth/token", { method: "POST", body: "small" });
    assert.equal(response.status, 500);
    assert.equal(await response.text(), "Internal Server Error");
    await assert.rejects(
      async () => app.request("/oauth/revoke", { method: "POST", body: "small" }),
      (error: unknown) => error === nonErrorThrowable,
    );
  } finally {
    console.error = originalConsoleError;
  }
  assert.ok(logged.length > 0, "Hono's existing downstream error path must run");
});

test("hono body cap: own extensions shadowing Request prototype keys survive", async () => {
  const { app, requests } = harness((c) => Object.hasOwn(c.req.raw, "toString") ? "preserved" : undefined);
  const streamed = streamRequest("/oauth/token", 1024, 256, { "content-length": "1024" });
  Object.defineProperty(streamed.request, "toString", { value: () => "runtime-extension" });
  const response = await app.fetch(streamed.request);
  assert.equal(response.status, 200);
  assert.equal(requests.at(-1)?.ip, "preserved");
});

test("hono body cap: caller-owned pairing POST can reuse the pre-parse guard", async () => {
  const app = new Hono();
  let parses = 0;
  let verifies = 0;
  app.post("/oauth/authorize", honoOAuthBodyLimit, async (c) => {
    parses += 1;
    await c.req.parseBody();
    verifies += 1;
    return c.text("ok");
  });
  const hostile = streamRequest("/oauth/authorize", 2 * 1024 * 1024, 16 * 1024, {
    "content-type": "application/x-www-form-urlencoded",
    "transfer-encoding": "chunked",
  });
  const response = await app.fetch(hostile.request);
  assert.equal(response.status, 413);
  assert.equal(hostile.produced(), LIMIT + 16 * 1024);
  assert.equal(parses, 0);
  assert.equal(verifies, 0);
});

test("hono body cap: one pre-materialized hostile chunk never reaches parsing", async () => {
  const app = new Hono();
  let parses = 0;
  app.post("/oauth/authorize", honoOAuthBodyLimit, async (c) => {
    parses += 1;
    await c.req.parseBody();
    return c.text("ok");
  });
  const hostile = streamRequest("/oauth/authorize", 2 * 1024 * 1024, 2 * 1024 * 1024);
  const response = await app.fetch(hostile.request);
  assert.equal(response.status, 413);
  assert.equal(hostile.produced(), 2 * 1024 * 1024);
  assert.equal(parses, 0, "the host-created crossing chunk must not reach a body parser");
});

test("hono body cap: below-cap parser failure keeps the fail-closed path", async () => {
  const app = realApp();
  const response = await app.request("/oauth/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{not-json",
  });
  assert.equal(response.status, 400);
  assert.equal((await response.json() as { error: string }).error, "invalid_request");
});
