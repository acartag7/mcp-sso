import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import Fastify from "fastify";
import express from "express";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { RedirectExchangeResult, RedirectIdentityPort } from "../src/ports/identity.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { createUpstreamRedirectFlow } from "../src/adapters/upstream-flow.ts";
import { assertDistinctUpstreamFlowRoutes } from "../src/adapters/upstream-flow-routes.ts";
import type { NormRequest, NormResponse } from "../src/adapters/http.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import { createOAuthRouter } from "../src/adapters/express.ts";
import { createOAuthApp } from "../src/adapters/hono.ts";

const NOW = Date.parse("2026-08-22T10:00:00.000Z");
const IP = "203.0.113.9";
class Clock { nowMs(): number { return NOW; } }
class Audit implements AuditPort {
  events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(event); }
}

function config(): BridgeConfig {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return createBridgeConfig({
    issuer: "https://auth.test", resource: "https://auth.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy-0123456789",
    signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK,
    signingKeyId: "k", redirectAllowlist: ["https://client.test/callback"],
    scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"], allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" }, accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

function harness(options: {
  result?: RedirectExchangeResult;
  onIdentity?: (identity: { subject: string; claims?: Record<string, unknown> }) => NormResponse | Promise<NormResponse>;
  keys?: string[];
  completionTimeoutMs?: number;
} = {}) {
  const cfg = config(), store = new MemoryStore(), clock = new Clock(), audit = new Audit();
  let exchanges = 0, completions = 0;
  const identity: RedirectIdentityPort = {
    redirectUri: "https://auth.test/login/callback",
    buildAuthorizationUrl(args) { return `https://idp.test/authorize?state=${args.state}`; },
    async exchangeAndVerify() {
      exchanges += 1;
      return options.result ?? { ok: true, identity: { subject: "person-1", claims: { email: "p@example.test" } } };
    },
  };
  const bridge = new Bridge({ config: cfg, store, clock, audit });
  const flow = createUpstreamRedirectFlow({
    bridge, identity, store, clock, audit, complete: "identity",
    completionTimeoutMs: options.completionTimeoutMs,
    rateLimit: { async check(key) { options.keys?.push(key); return true; } },
    onIdentity: async (claims) => {
      completions += 1;
      return options.onIdentity ? options.onIdentity(claims) : { status: 204, headers: {}, setCookies: ["session=host; Path=/; Secure; HttpOnly"] };
    },
  });
  return { bridge, flow, audit, store, clock, identity, exchanges: () => exchanges, completions: () => completions };
}

async function start(flow: ReturnType<typeof harness>["flow"]): Promise<{ state: string; cookie: string }> {
  const response = await flow.handleAuthorize({ query: { ignored: "caller-data" }, body: undefined, headers: {}, ip: IP });
  assert.equal(response.status, 302);
  assert.match(response.headers["set-cookie"] ?? "", /^__Host-mcp-sso-identity=/);
  assert.doesNotMatch(response.headers["set-cookie"] ?? "", /caller-data/);
  return {
    state: new URL(response.redirect as string).searchParams.get("state") as string,
    cookie: (response.headers["set-cookie"] as string).split(";", 1)[0] as string,
  };
}

function callback(state: string, cookie: string, extra: Record<string, string | string[]> = {}): NormRequest {
  return { query: { state, code: "upstream-code", ...extra }, body: undefined, headers: { cookie }, ip: IP };
}

test("RM.17 claims-only completion returns verified claims and remains single-use", async () => {
  let observed: unknown;
  const h = harness({ onIdentity(identity) { observed = identity; return { status: 204, headers: {}, setCookies: ["session=host; Path=/; Secure; HttpOnly"] }; } });
  const begun = await start(h.flow);
  const response = await h.flow.handleCallback(callback(begun.state, begun.cookie));
  assert.equal(response.status, 204); assert.equal(response.body, undefined);
  assert.deepEqual(response.setCookies?.map((cookie) => cookie.split(";", 1)[0]), ["session=host", "__Host-mcp-sso-identity="]);
  assert.equal((observed as { subject: string }).subject, "person-1");
  assert.equal(Object.isFrozen(observed), true); assert.equal(h.completions(), 1);
  const replay = await h.flow.handleCallback(callback(begun.state, begun.cookie));
  assert.equal(replay.status, 400); assert.equal(h.exchanges(), 1); assert.equal(h.completions(), 1);
});

test("RM.17 claims-only authorize and callback charge only website-login", async () => {
  const keys: string[] = []; const h = harness({ keys }); const begun = await start(h.flow);
  await h.flow.handleCallback(callback(begun.state, begun.cookie));
  assert.deepEqual(keys, [`website-login:${IP}`, `website-login:${IP}`]);
  assert.equal(keys.some((key) => key.startsWith("upstream:")), false);
});

test("RM.17 onIdentity throw is redacted, consumes the jti, and returns no host cookie", async () => {
  const poison = "private transaction detail";
  const h = harness({ onIdentity() { throw new Error(poison); } });
  const begun = await start(h.flow); const stderr: string[] = []; const saved = console.error;
  console.error = (...values: unknown[]) => { stderr.push(values.join(" ")); };
  let response: NormResponse;
  try { response = await h.flow.handleCallback(callback(begun.state, begun.cookie)); } finally { console.error = saved; }
  assert.equal(response.status, 500); assert.deepEqual(response.setCookies?.map((cookie) => cookie.split(";", 1)[0]), ["__Host-mcp-sso-identity="]);
  assert.equal(JSON.stringify(response).includes(poison), false); assert.equal(JSON.stringify(h.audit.events).includes(poison), false); assert.equal(stderr.join("\n").includes(poison), false);
  assert.equal(h.audit.events.at(-1)?.reason, "completion_failed");
  const replay = await h.flow.handleCallback(callback(begun.state, begun.cookie));
  assert.equal(replay.status, 400); assert.equal(h.completions(), 1);
});

test("RM.17 a yielding onIdentity timeout takes completion_failed and discards its late cookie", async () => {
  let settle!: (response: NormResponse) => void;
  const pending = new Promise<NormResponse>((resolve) => { settle = resolve; });
  const h = harness({ completionTimeoutMs: 1000, onIdentity: () => pending }); const begun = await start(h.flow);
  const response = await h.flow.handleCallback(callback(begun.state, begun.cookie));
  assert.equal(response.status, 500); assert.equal(response.setCookies?.some((cookie) => cookie.startsWith("late=")), false);
  assert.equal(h.audit.events.at(-1)?.reason, "completion_failed");
  settle({ status: 204, headers: {}, setCookies: ["late=session; Path=/"] }); await new Promise((resolve) => setImmediate(resolve));
  assert.equal(response.setCookies?.some((cookie) => cookie.startsWith("late=")), false);
  const fresh = await start(h.flow); const freshResponse = await h.flow.handleCallback(callback(fresh.state, fresh.cookie));
  assert.equal(h.completions(), 2); assert.equal(freshResponse.setCookies?.some((cookie) => cookie.startsWith("late=")), true);
});

test("RM.17 a malformed host response cannot escape the fixed completion failure", async () => {
  const poison = "hostile-header-value";
  const h = harness({ onIdentity: () => ({ status: 200, headers: { "x-test": `${poison}\r\nset-cookie: stolen=1` } }) });
  const begun = await start(h.flow); const response = await h.flow.handleCallback(callback(begun.state, begun.cookie));
  assert.equal(response.status, 500); assert.equal(JSON.stringify(response).includes(poison), false);
  assert.equal(h.audit.events.at(-1)?.reason, "completion_failed");
});

test("RM.17 identity denial and rejection share one direct anti-oracle response", async () => {
  const denied = harness(); const deniedStart = await start(denied.flow);
  const denial = await denied.flow.handleCallback(callback(deniedStart.state, deniedStart.cookie, { error: "access_denied", code: "" }));
  const rejected = harness({ result: { ok: false, kind: "identity_rejected", reason: "group policy detail" } });
  const rejectedStart = await start(rejected.flow); const rejection = await rejected.flow.handleCallback(callback(rejectedStart.state, rejectedStart.cookie));
  assert.deepEqual({ status: denial.status, body: denial.body }, { status: rejection.status, body: rejection.body });
  assert.equal(denial.redirect, undefined); assert.equal(rejection.redirect, undefined);
});

test("RM.17 Fastify, Express, and Hono each deliver both Set-Cookie values", async () => {
  {
    const h = harness(); const app = Fastify(); await registerOAuthRoutes(app, { bridge: h.bridge, skipAuthorize: true, identityFlow: h.flow });
    const begin = await app.inject({ method: "GET", url: "/login" }); const state = new URL(begin.headers.location as string).searchParams.get("state") as string;
    const done = await app.inject({ method: "GET", url: `/login/callback?state=${state}&code=c`, headers: { cookie: String(begin.headers["set-cookie"]).split(";", 1)[0] } });
    assert.equal((done.headers["set-cookie"] as string[]).length, 2); await app.close();
  }
  {
    const h = harness(); const app = express(); app.use(createOAuthRouter({ bridge: h.bridge, skipAuthorize: true, identityFlow: h.flow }));
    const server = app.listen(0, "127.0.0.1"); await new Promise<void>((resolve) => server.once("listening", resolve));
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    try {
      const begin = await fetch(base + "/login", { redirect: "manual" }); const state = new URL(begin.headers.get("location") as string).searchParams.get("state") as string;
      const done = await fetch(base + `/login/callback?state=${state}&code=c`, { headers: { cookie: begin.headers.get("set-cookie")?.split(";", 1)[0] as string } });
      assert.equal(done.headers.getSetCookie().length, 2);
    } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
  }
  {
    const h = harness(); const app = createOAuthApp({ bridge: h.bridge, skipAuthorize: true, identityFlow: h.flow, clientIp: () => IP });
    const begin = await app.request("/login"); const state = new URL(begin.headers.get("location") as string).searchParams.get("state") as string;
    const done = await app.request(`/login/callback?state=${state}&code=c`, { headers: { cookie: begin.headers.get("set-cookie")?.split(";", 1)[0] as string } });
    assert.equal(done.headers.getSetCookie().length, 2);
  }
});

test("route-set assertion admits one bridge plus one identity flow and rejects wrong ownership or duplicates", () => {
  const h = harness();
  const bridgeIdentity: RedirectIdentityPort = {
    redirectUri: "https://auth.test/oauth/callback",
    buildAuthorizationUrl(args) { return `https://idp.test/authorize?state=${args.state}`; },
    async exchangeAndVerify() { return { ok: true, identity: { subject: "person-1" } }; },
  };
  const bridgeFlow = createUpstreamRedirectFlow({ bridge: h.bridge, identity: bridgeIdentity, store: h.store, clock: h.clock, audit: h.audit });
  assert.doesNotThrow(() => assertDistinctUpstreamFlowRoutes(h.bridge, [bridgeFlow, h.flow]));
  assert.throws(() => assertDistinctUpstreamFlowRoutes(h.bridge, [h.flow, h.flow]));
  assert.throws(() => assertDistinctUpstreamFlowRoutes(harness().bridge, [h.flow]));
  assert.throws(() => assertDistinctUpstreamFlowRoutes(h.bridge, [{ ...h.flow }] as never));
});

test("identity completion rejects malformed subjects and claims before onIdentity", async () => {
  const identities = [
    { subject: "" }, { subject: " person" }, { subject: "person " }, { subject: "bad\uFFFD" },
    { subject: "\uD800" }, { subject: "\uDC00" }, { subject: "x".repeat(385) }, { subject: "😀".repeat(385) },
    { subject: "person", claims: { value: Number.NaN } },
    { subject: "person", claims: { value: BigInt(1) } },
    { subject: "person", claims: { value: [, "sparse"] } },
  ];
  for (const [index, identity] of identities.entries()) {
    const h = harness({ result: { ok: true, identity } as never }); const begun = await start(h.flow);
    const response = await h.flow.handleCallback(callback(begun.state, begun.cookie));
    assert.equal(response.status, 500, `malformed identity ${index}`); assert.equal(h.completions(), 0);
    assert.equal(h.audit.events.some((event) => event.event === "identity.verify"), false);
    assert.equal(h.audit.events.at(-1)?.reason, "exchange_failed");
  }
});

test("identity subject accepts one and exactly 384 Unicode scalars", async () => {
  for (const subject of ["x", "x".repeat(384), "😀".repeat(384)]) {
    const h = harness({ result: { ok: true, identity: { subject } } }); const begun = await start(h.flow);
    assert.equal((await h.flow.handleCallback(callback(begun.state, begun.cookie))).status, 204);
  }
});

test("identity completion rejects each host response shape at the boundary", async () => {
  const accessor = Object.create(null) as Record<string, unknown>;
  Object.defineProperty(accessor, "status", { enumerable: true, get() { throw new Error("getter poison"); } });
  Object.defineProperty(accessor, "headers", { enumerable: true, value: {} });
  const bad: unknown[] = [
    null, { status: 200, headers: {}, extra: true }, { status: 200.5, headers: {} },
    { status: 302, headers: {}, body: "x" }, { status: 200, headers: {}, body: "untyped" },
    { status: 204, headers: {}, body: "" }, { status: 200, headers: { connection: "close" } },
    { status: 200, headers: { "x-test": " leading" } }, { status: 200, headers: { "x-test": "café" } },
    { status: 302, headers: {}, redirect: "https://example.test/a b" },
    { status: 302, headers: { location: "/other" }, redirect: "/account" },
    { status: 204, headers: {}, setCookies: Array.from({ length: 16 }, (_, index) => `s${index}=x`) },
    accessor,
  ];
  for (const value of bad) {
    const h = harness({ onIdentity: () => value as NormResponse }); const begun = await start(h.flow);
    const response = await h.flow.handleCallback(callback(begun.state, begun.cookie));
    assert.equal(response.status, 500); assert.equal(h.audit.events.at(-1)?.reason, "completion_failed");
  }
});

test("claims and completion header projections preserve inert keys on null-prototype frozen records", async () => {
  const claims = Object.create(null) as Record<string, unknown>;
  for (const key of ["__proto__", "constructor", "prototype"]) Object.defineProperty(claims, key, { value: key, enumerable: true });
  let observed: { claims?: Record<string, unknown> } | undefined;
  const h = harness({
    result: { ok: true, identity: { subject: "person", claims } },
    onIdentity(identity) {
      observed = identity;
      const headers = Object.create(null) as Record<string, string>;
      for (const key of ["__proto__", "constructor", "prototype"]) Object.defineProperty(headers, key, { value: key, enumerable: true });
      return { status: 204, headers };
    },
  });
  const begun = await start(h.flow); const response = await h.flow.handleCallback(callback(begun.state, begun.cookie));
  assert.equal(response.status, 204); assert.equal(Object.getPrototypeOf(observed?.claims), null); assert.equal(Object.isFrozen(observed?.claims), true);
  assert.equal(Object.getPrototypeOf(response.headers), null);
  for (const key of ["__proto__", "constructor", "prototype"]) assert.equal(Object.hasOwn(response.headers, key), true);
});
