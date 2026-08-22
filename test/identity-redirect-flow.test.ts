import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { decodeJwt, type JWK } from "jose";
import Fastify from "fastify";
import express from "express";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { RedirectExchangeResult, RedirectIdentityPort } from "../src/ports/identity.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { createUpstreamRedirectFlow } from "../src/adapters/upstream-flow.ts";
import { assertDistinctUpstreamFlowRoutes } from "../src/adapters/upstream-flow-routes.ts";
import { registerUpstreamFlowMetadata } from "../src/adapters/upstream-flow-routes.ts";
import type { NormRequest, NormResponse } from "../src/adapters/http.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import { createOAuthRouter } from "../src/adapters/express.ts";
import { createOAuthApp } from "../src/adapters/hono.ts";
import { pkceChallenge } from "../src/crypto.ts";
import {
  changingIdentitySubject, INVALID_IDENTITY_SUBJECTS, VALID_IDENTITY_SUBJECTS,
} from "./lib/identity-subject-cases.ts";

const NOW = Date.parse("2026-08-22T10:00:00.000Z");
const IP = "203.0.113.9";
class Clock { private ms = NOW; nowMs(): number { return this.ms; } advance(seconds: number): void { this.ms += seconds * 1000; } }
class Audit implements AuditPort {
  events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(event); }
}

function config(resourcePath = "/mcp"): BridgeConfig {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return createBridgeConfig({
    issuer: "https://auth.test", resource: `https://auth.test${resourcePath}`,
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

function flowFor(
  h: ReturnType<typeof harness>, complete: "bridge" | "identity", callbackPath: string,
) {
  const identity: RedirectIdentityPort = {
    redirectUri: `https://auth.test${callbackPath}`,
    buildAuthorizationUrl(args) { return `https://idp.test/authorize?state=${args.state}`; },
    async exchangeAndVerify() { return { ok: true, identity: { subject: "person" } }; },
  };
  return createUpstreamRedirectFlow({
    bridge: h.bridge, identity, store: h.store, clock: h.clock, audit: h.audit,
    complete, callbackPath, ...(complete === "identity" ? { onIdentity: () => ({ status: 204, headers: {} }) } : {}),
  } as never);
}

test("identity completion boot options fail closed and are snapshotted", () => {
  const h = harness();
  const base = { bridge: h.bridge, identity: h.identity, store: h.store, clock: h.clock, audit: h.audit };
  assert.throws(() => createUpstreamRedirectFlow({ ...base, complete: "unknown" } as never));
  assert.throws(() => createUpstreamRedirectFlow({ ...base, complete: "bridge", onIdentity: () => ({ status: 204, headers: {} }) } as never));
  assert.throws(() => createUpstreamRedirectFlow({ ...base, complete: "bridge", completionTimeoutMs: 1000 } as never));
  assert.throws(() => createUpstreamRedirectFlow({ ...base, complete: "identity" } as never));
  assert.throws(() => createUpstreamRedirectFlow({ ...base, complete: "identity", onIdentity: "not-callable" } as never));
  for (const completionTimeoutMs of [999, 1000.5, 30_001, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(() => createUpstreamRedirectFlow({ ...base, complete: "identity", completionTimeoutMs, onIdentity: () => ({ status: 204, headers: {} }) }));
  }
  let reads = 0;
  const deps = { ...base, complete: "identity" } as Record<string, unknown>;
  Object.defineProperty(deps, "onIdentity", { enumerable: true, get() { reads += 1; return () => ({ status: 204, headers: {} }); } });
  const flow = createUpstreamRedirectFlow(deps as never);
  assert.equal(reads, 1); assert.equal(flow.complete, "identity"); assert.equal(flow.callbackPath, "/login/callback"); assert.equal(Object.isFrozen(flow), true);
  for (const completionTimeoutMs of [1000, 10_000, 30_000]) {
    assert.doesNotThrow(() => createUpstreamRedirectFlow({ ...base, complete: "identity", completionTimeoutMs, onIdentity: () => ({ status: 204, headers: {} }) }));
  }
});

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

test("default bridge and identity flows coexist with distinct cookies and audiences", async () => {
  const h = harness(); const bridgeFlow = flowFor(h, "bridge", "/oauth/callback");
  const bridgeStart = await startBridge(bridgeFlow); const identityStart = await start(h.flow);
  assert.match(bridgeStart.cookie, /^__Host-mcp-sso-upstream=/); assert.match(identityStart.cookie, /^__Host-mcp-sso-identity=/);
  assert.equal(decodeJwt(bridgeStart.cookie.split("=", 2)[1] as string).aud, "mcp-sso/upstream-flow/oauth/callback");
  assert.equal(decodeJwt(identityStart.cookie.split("=", 2)[1] as string).aud, "mcp-sso/identity-flow/login/callback");
  const cookies = `${bridgeStart.cookie}; ${identityStart.cookie}`;
  const bridgeResponse = await bridgeFlow.handleCallback({ ...callback(bridgeStart.state, cookies), headers: { cookie: cookies } });
  const identityResponse = await h.flow.handleCallback({ ...callback(identityStart.state, cookies), headers: { cookie: cookies } });
  assert.equal(bridgeResponse.status, 200); assert.equal(identityResponse.status, 204);
  assert.match(bridgeResponse.headers["set-cookie"] ?? "", /^__Host-mcp-sso-upstream=/);
  assert.equal(identityResponse.setCookies?.some((cookie) => cookie.startsWith("__Host-mcp-sso-identity=")), true);
});

test("Fastify, Express, and Hono mount both default flows and preserve each flow cookie", async () => {
  const assertCookies = (bridgeCookie: string | null | undefined, identityCookie: string | null | undefined) => {
    assert.match(String(bridgeCookie), /^__Host-mcp-sso-upstream=/);
    assert.match(String(identityCookie), /^__Host-mcp-sso-identity=/);
  };
  {
    const h = harness(); const bridgeFlow = flowFor(h, "bridge", "/oauth/callback"); const app = Fastify();
    await registerOAuthRoutes(app, { bridge: h.bridge, upstream: bridgeFlow, identityFlow: h.flow });
    const bridgeStart = await app.inject({ method: "GET", url: "/oauth/authorize", query: { response_type: "code", client_id: "client", redirect_uri: "https://client.test/callback", code_challenge: pkceChallenge("v".repeat(43)), code_challenge_method: "S256" } });
    const identityStart = await app.inject({ method: "GET", url: "/login" });
    assertCookies(String(bridgeStart.headers["set-cookie"]), String(identityStart.headers["set-cookie"])); await app.close();
  }
  {
    const h = harness(); const bridgeFlow = flowFor(h, "bridge", "/oauth/callback"); const app = express();
    app.use(createOAuthRouter({ bridge: h.bridge, upstream: bridgeFlow, identityFlow: h.flow }));
    const server = app.listen(0, "127.0.0.1"); await new Promise<void>((resolve) => server.once("listening", resolve));
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    try {
      const bridgeStart = await fetch(base + `/oauth/authorize?response_type=code&client_id=client&redirect_uri=${encodeURIComponent("https://client.test/callback")}&code_challenge=${pkceChallenge("v".repeat(43))}&code_challenge_method=S256`, { redirect: "manual" });
      const identityStart = await fetch(base + "/login", { redirect: "manual" });
      assertCookies(bridgeStart.headers.get("set-cookie"), identityStart.headers.get("set-cookie"));
    } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
  }
  {
    const h = harness(); const bridgeFlow = flowFor(h, "bridge", "/oauth/callback");
    const app = createOAuthApp({ bridge: h.bridge, upstream: bridgeFlow, identityFlow: h.flow, clientIp: () => IP });
    const query = `/oauth/authorize?response_type=code&client_id=client&redirect_uri=${encodeURIComponent("https://client.test/callback")}&code_challenge=${pkceChallenge("v".repeat(43))}&code_challenge_method=S256`;
    const bridgeStart = await app.request(query); const identityStart = await app.request("/login");
    assertCookies(bridgeStart.headers.get("set-cookie"), identityStart.headers.get("set-cookie"));
  }
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

test("prompt identity completion clears the losing timeout on success and failure", async () => {
  for (const fails of [false, true]) {
    const h = harness({ onIdentity() { if (fails) throw new Error("fixed test failure"); return { status: 204, headers: {} }; } });
    const begun = await start(h.flow); const originalSet = globalThis.setTimeout; const originalClear = globalThis.clearTimeout;
    let scheduled = 0, cleared = 0;
    globalThis.setTimeout = ((...args: Parameters<typeof setTimeout>) => {
      scheduled += 1; return originalSet(...args);
    }) as typeof setTimeout;
    globalThis.clearTimeout = ((...args: Parameters<typeof clearTimeout>) => { cleared += 1; return originalClear(...args); }) as typeof clearTimeout;
    try { assert.equal((await h.flow.handleCallback(callback(begun.state, begun.cookie))).status, fails ? 500 : 204); }
    finally { globalThis.setTimeout = originalSet; globalThis.clearTimeout = originalClear; }
    assert.equal(scheduled, 1); assert.equal(cleared, 1);
  }
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
  const adapterHarness = () => harness({ onIdentity: () => ({ status: 204, headers: { "SeT-CoOkIe": "session=host; Path=/; Secure; HttpOnly" } }) });
  {
    const h = adapterHarness(); const app = Fastify(); await registerOAuthRoutes(app, { bridge: h.bridge, skipAuthorize: true, identityFlow: h.flow });
    const begin = await app.inject({ method: "GET", url: "/login" }); const state = new URL(begin.headers.location as string).searchParams.get("state") as string;
    const done = await app.inject({ method: "GET", url: `/login/callback?state=${state}&code=c`, headers: { cookie: String(begin.headers["set-cookie"]).split(";", 1)[0] } });
    assert.deepEqual((done.headers["set-cookie"] as string[]).map((cookie) => cookie.split(";", 1)[0]), ["session=host", "__Host-mcp-sso-identity="]); await app.close();
  }
  {
    const h = adapterHarness(); const app = express(); app.use(createOAuthRouter({ bridge: h.bridge, skipAuthorize: true, identityFlow: h.flow }));
    const server = app.listen(0, "127.0.0.1"); await new Promise<void>((resolve) => server.once("listening", resolve));
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    try {
      const begin = await fetch(base + "/login", { redirect: "manual" }); const state = new URL(begin.headers.get("location") as string).searchParams.get("state") as string;
      const done = await fetch(base + `/login/callback?state=${state}&code=c`, { headers: { cookie: begin.headers.get("set-cookie")?.split(";", 1)[0] as string } });
      assert.deepEqual(done.headers.getSetCookie().map((cookie) => cookie.split(";", 1)[0]), ["session=host", "__Host-mcp-sso-identity="]);
    } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
  }
  {
    const h = adapterHarness(); const app = createOAuthApp({ bridge: h.bridge, skipAuthorize: true, identityFlow: h.flow, clientIp: () => IP });
    const begin = await app.request("/login"); const state = new URL(begin.headers.get("location") as string).searchParams.get("state") as string;
    const done = await app.request(`/login/callback?state=${state}&code=c`, { headers: { cookie: begin.headers.get("set-cookie")?.split(";", 1)[0] as string } });
    assert.deepEqual(done.headers.getSetCookie().map((cookie) => cookie.split(";", 1)[0]), ["session=host", "__Host-mcp-sso-identity="]);
  }
});

test("RM.17 Fastify, Express, and Hono preserve a validated redirect response", async () => {
  const adapterHarness = () => harness({ onIdentity: () => ({
    status: 303, headers: { "Content-Type": "application/x-host", "X-Host": "kept" }, redirect: "/account%20home",
  }) });
  const assertResponse = (status: number, location: string | null | undefined, contentType: string | null | undefined, hostHeader: string | null | undefined, body: string): void => {
    assert.equal(status, 303); assert.equal(location, "/account%20home"); assert.equal(contentType, "application/x-host");
    assert.equal(hostHeader, "kept"); assert.equal(body, "");
  };
  {
    const h = adapterHarness(); const app = Fastify(); await registerOAuthRoutes(app, { bridge: h.bridge, skipAuthorize: true, identityFlow: h.flow });
    const begin = await app.inject({ method: "GET", url: "/login" }); const state = new URL(begin.headers.location as string).searchParams.get("state") as string;
    const done = await app.inject({ method: "GET", url: `/login/callback?state=${state}&code=c`, headers: { cookie: String(begin.headers["set-cookie"]).split(";", 1)[0] } });
    assertResponse(done.statusCode, done.headers.location as string, done.headers["content-type"] as string, done.headers["x-host"] as string, done.body); await app.close();
  }
  {
    const h = adapterHarness(); const app = express(); app.use(createOAuthRouter({ bridge: h.bridge, skipAuthorize: true, identityFlow: h.flow }));
    const server = app.listen(0, "127.0.0.1"); await new Promise<void>((resolve) => server.once("listening", resolve));
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    try {
      const begin = await fetch(base + "/login", { redirect: "manual" }); const state = new URL(begin.headers.get("location") as string).searchParams.get("state") as string;
      const done = await fetch(base + `/login/callback?state=${state}&code=c`, { redirect: "manual", headers: { cookie: begin.headers.get("set-cookie")?.split(";", 1)[0] as string } });
      assertResponse(done.status, done.headers.get("location"), done.headers.get("content-type"), done.headers.get("x-host"), await done.text());
    } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
  }
  {
    const h = adapterHarness(); const app = createOAuthApp({ bridge: h.bridge, skipAuthorize: true, identityFlow: h.flow, clientIp: () => IP });
    const begin = await app.request("/login"); const state = new URL(begin.headers.get("location") as string).searchParams.get("state") as string;
    const done = await app.request(`/login/callback?state=${state}&code=c`, { headers: { cookie: begin.headers.get("set-cookie")?.split(";", 1)[0] as string } });
    assertResponse(done.status, done.headers.get("location"), done.headers.get("content-type"), done.headers.get("x-host"), await done.text());
  }
});

test("Fastify, Express, and Hono snapshot flow options once before route checks", async () => {
  const mount = async (adapter: "fastify" | "express" | "hono"): Promise<void> => {
    const h = harness();
    const bridgeIdentity: RedirectIdentityPort = {
      redirectUri: "https://auth.test/oauth/callback",
      buildAuthorizationUrl(args) { return `https://idp.test/authorize?state=${args.state}`; },
      async exchangeAndVerify() { return { ok: true, identity: { subject: "person-1" } }; },
    };
    const bridgeFlow = createUpstreamRedirectFlow({ bridge: h.bridge, identity: bridgeIdentity, store: h.store, clock: h.clock, audit: h.audit });
    let reads = 0;
    const options = { bridge: h.bridge, identityFlow: h.flow } as Record<string, unknown>;
    Object.defineProperty(options, "upstream", {
      enumerable: true,
      get() { reads += 1; if (reads > 1) throw new Error("flow option was read twice"); return bridgeFlow; },
    });
    if (adapter === "fastify") {
      const app = Fastify(); await registerOAuthRoutes(app, options as never); await app.close();
    } else if (adapter === "express") createOAuthRouter(options as never);
    else {
      Object.defineProperty(options, "clientIp", { enumerable: true, value: () => IP });
      createOAuthApp(options as never);
    }
    assert.equal(reads, 1, adapter);
  };
  await mount("fastify"); await mount("express"); await mount("hono");
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
  assert.throws(() => assertDistinctUpstreamFlowRoutes(h.bridge, []));
  assert.throws(() => assertDistinctUpstreamFlowRoutes(h.bridge, [bridgeFlow, h.flow, bridgeFlow]));
  assert.throws(() => assertDistinctUpstreamFlowRoutes(h.bridge, [h.flow, , bridgeFlow] as never));
  const accessor = [h.flow];
  Object.defineProperty(accessor, "0", { enumerable: true, get() { throw new Error("slot getter poison"); } });
  assert.throws(() => assertDistinctUpstreamFlowRoutes(h.bridge, accessor));

  assert.throws(() => assertDistinctUpstreamFlowRoutes(h.bridge, [flowFor(h, "bridge", "/shared"), flowFor(h, "identity", "/SHARED/")]));
  assert.throws(() => assertDistinctUpstreamFlowRoutes(h.bridge, [flowFor(h, "bridge", "/bridge-a"), flowFor(h, "bridge", "/bridge-b")]));
  assert.throws(() => assertDistinctUpstreamFlowRoutes(h.bridge, [flowFor(h, "identity", "/identity-a"), flowFor(h, "identity", "/identity-b")]));
  assert.throws(() => assertDistinctUpstreamFlowRoutes(h.bridge, new Proxy([h.flow], { ownKeys() { throw new Error("descriptor poison"); } })));
  for (const [index, callbackPath] of ["/collision", "/COLLISION", "/COLLISION/"].entries()) {
    const left = flowFor(h, "bridge", `/left-${index}`); const right = flowFor(h, "identity", `/right-${index}`);
    registerUpstreamFlowMetadata(left, h.bridge, "bridge", "/collision");
    registerUpstreamFlowMetadata(right, h.bridge, "identity", callbackPath);
    assert.throws(() => assertDistinctUpstreamFlowRoutes(h.bridge, [left, right]));
  }
  for (const [complete, callbackPath] of [["bridge", "/LOGIN/"], ["identity", "/OAUTH/AUTHORIZE/"]] as const) {
    const flow = flowFor(h, complete, `/metadata-${complete}`);
    registerUpstreamFlowMetadata(flow, h.bridge, complete, callbackPath);
    assert.throws(() => assertDistinctUpstreamFlowRoutes(h.bridge, [flow, complete === "bridge" ? h.flow : bridgeFlow]));
  }
});

test("flow factories reject effective callback and initiation route aliases", () => {
  const adapterRoutes = [
    "/oauth/authorize", "/login", "/oauth/authorize/approve", "/oauth/token",
    "/oauth/register", "/oauth/revoke", "/oauth/jwks",
    "/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp", "/.well-known/provider", "/mcp",
  ];
  for (const complete of ["bridge", "identity"] as const) {
    for (const route of adapterRoutes) {
      for (const callbackPath of new Set([route, route.toUpperCase(), route.endsWith("/") ? route : `${route}/`])) {
        const h = harness();
        assert.throws(() => flowFor(h, complete, callbackPath), Error, `${complete}:${callbackPath}`);
      }
    }
  }
  for (const [initiation, complete] of [["/login", "identity"], ["/oauth/authorize", "bridge"]] as const) {
    for (const resourcePath of [initiation, initiation.toUpperCase(), `${initiation}/`]) {
      const cfg = config(resourcePath), store = new MemoryStore(), clock = new Clock(), audit = new Audit();
      const bridge = new Bridge({ config: cfg, store, clock, audit });
      const h = { ...harness(), bridge, store, clock, audit };
      assert.throws(() => flowFor(h, complete, `/callback-${complete}`), Error, `${complete}:${resourcePath}`);
    }
  }
  const h = harness();
  assert.doesNotThrow(() => flowFor(h, "bridge", "/bridge-callback"));
  assert.doesNotThrow(() => flowFor(h, "identity", "/identity-callback"));
});

test("all adapters reject flows in the wrong completion slot before registration", async () => {
  const h = harness();
  const bridgeFlow = flowFor(h, "bridge", "/bridge-callback");
  const cases = [
    async () => { const app = Fastify(); await assert.rejects(registerOAuthRoutes(app, { bridge: h.bridge, upstream: h.flow })); assert.equal(app.hasRoute({ method: "GET", url: "/oauth/jwks" }), false); await app.close(); },
    async () => { assert.throws(() => createOAuthRouter({ bridge: h.bridge, upstream: h.flow })); },
    async () => { assert.throws(() => createOAuthApp({ bridge: h.bridge, upstream: h.flow, clientIp: () => IP })); },
    async () => { const app = Fastify(); await assert.rejects(registerOAuthRoutes(app, { bridge: h.bridge, skipAuthorize: true, identityFlow: bridgeFlow })); assert.equal(app.hasRoute({ method: "GET", url: "/oauth/jwks" }), false); await app.close(); },
    async () => { assert.throws(() => createOAuthRouter({ bridge: h.bridge, skipAuthorize: true, identityFlow: bridgeFlow })); },
    async () => { assert.throws(() => createOAuthApp({ bridge: h.bridge, skipAuthorize: true, identityFlow: bridgeFlow, clientIp: () => IP })); },
  ];
  for (const run of cases) await run();
});

test("all adapters reject wrong-bridge and sibling-route collisions before mounting", async () => {
  const owner = harness(); const other = harness();
  const collidedBridge = flowFor(owner, "bridge", "/shared-callback");
  const collidedIdentity = flowFor(owner, "identity", "/SHARED-CALLBACK");
  const options = [
    { bridge: other.bridge, skipAuthorize: true, identityFlow: owner.flow },
    { bridge: owner.bridge, upstream: collidedBridge, identityFlow: collidedIdentity },
  ];
  for (const option of options) {
    const app = Fastify(); await assert.rejects(registerOAuthRoutes(app, option));
    assert.equal(app.hasRoute({ method: "GET", url: "/oauth/jwks" }), false); await app.close();
    assert.throws(() => createOAuthRouter(option));
    assert.throws(() => createOAuthApp({ ...option, clientIp: () => IP }));
  }
});

test("identity completion rejects malformed subjects and claims before onIdentity", async () => {
  const cycle: Record<string, unknown> = {}; cycle.self = cycle;
  const accessor: Record<string, unknown> = {};
  Object.defineProperty(accessor, "value", { enumerable: true, get() { throw new Error("claim getter poison"); } });
  const inherited = Object.create({ inherited: true }) as Record<string, unknown>;
  const trapped = new Proxy({}, { ownKeys() { throw new Error("claims enumeration poison"); } });
  const identities = [
    ...INVALID_IDENTITY_SUBJECTS.map((subject) => ({ subject })),
    { subject: "person", claims: { value: Number.NaN } },
    { subject: "person", claims: { value: BigInt(1) } },
    { subject: "person", claims: { value: Symbol("x") } },
    { subject: "person", claims: { value: () => undefined } },
    { subject: "person", claims: { value: Number.POSITIVE_INFINITY } },
    { subject: "person", claims: { value: [undefined] } },
    { subject: "person", claims: { value: [, "sparse"] } },
    { subject: "person", claims: accessor }, { subject: "person", claims: trapped },
    { subject: "person", claims: inherited },
    { subject: "person", claims: cycle },
    { subject: "person", claims: { a: { b: { c: { d: { e: {} } } } } } },
    { subject: "person", claims: Object.fromEntries(Array.from({ length: 65 }, (_, index) => [`k${index}`, index])) },
    { subject: "person", claims: { ["k".repeat(129)]: true } },
    { subject: "person", claims: { value: "x".repeat(4097) } },
    { subject: "person", claims: { a: "x".repeat(4096), b: "x".repeat(4096), c: "x".repeat(4096), d: "x".repeat(4096) } },
  ];
  for (const [index, identity] of identities.entries()) {
    const h = harness({ result: { ok: true, identity } as never }); const begun = await start(h.flow);
    const response = await h.flow.handleCallback(callback(begun.state, begun.cookie));
    assert.equal(response.status, 500, `malformed identity ${index}`); assert.equal(h.completions(), 0);
    assert.deepEqual(response.setCookies?.map((cookie) => cookie.split(";", 1)[0]), ["__Host-mcp-sso-identity="]);
    assert.deepEqual(h.audit.events.map((event) => [event.event, event.status, event.reason]), [
      ["oauth.upstream.callback", "failure", "exchange_failed"],
    ]);
    assert.equal(JSON.stringify(h.audit.events).includes("poison"), false);
  }
});

test("identity subject accepts one and exactly 384 Unicode scalars", async () => {
  for (const subject of VALID_IDENTITY_SUBJECTS) {
    const h = harness({ result: { ok: true, identity: { subject } } }); const begun = await start(h.flow);
    assert.equal((await h.flow.handleCallback(callback(begun.state, begun.cookie))).status, 204);
  }
});

test("both redirect completions apply the complete subject grammar and snapshot a changing getter once", async () => {
  for (const subject of INVALID_IDENTITY_SUBJECTS) {
    const h = bridgeHarness({ ok: true, identity: { subject } }); const begun = await startBridge(h.flow);
    const response = await h.flow.handleCallback(callback(begun.state, begun.cookie));
    assert.equal(response.status, 302); assert.equal(h.audit.events.at(-1)?.reason, "exchange_failed");
  }
  for (const subject of VALID_IDENTITY_SUBJECTS) {
    const h = bridgeHarness({ ok: true, identity: { subject } }); const begun = await startBridge(h.flow);
    assert.equal((await h.flow.handleCallback(callback(begun.state, begun.cookie))).status, 200);
  }
  for (const complete of ["bridge", "identity"] as const) {
    const changing = changingIdentitySubject();
    const h = complete === "bridge"
      ? bridgeHarness({ ok: true, identity: changing.identity })
      : harness({ result: { ok: true, identity: changing.identity } });
    const begun = complete === "bridge" ? await startBridge(h.flow) : await start(h.flow);
    const response = await h.flow.handleCallback(callback(begun.state, begun.cookie));
    assert.equal(response.status, complete === "bridge" ? 200 : 204);
    assert.equal(changing.reads(), 1);
  }
});

test("identity completion rejects each host response shape at the boundary", async () => {
  const accessor = Object.create(null) as Record<string, unknown>;
  Object.defineProperty(accessor, "status", { enumerable: true, get() { throw new Error("getter poison"); } });
  Object.defineProperty(accessor, "headers", { enumerable: true, value: {} });
  const inheritedResponse = Object.assign(Object.create({ inherited: true }), { status: 204, headers: {} });
  const inheritedHeaders = Object.assign(Object.create({ inherited: true }), { "x-test": "value" });
  const symbolResponse = { status: 204, headers: {}, [Symbol("extra")]: true };
  const symbolHeaders = { "x-test": "value", [Symbol("extra")]: true };
  const nonEnumerableResponse = { status: 204, headers: {} };
  Object.defineProperty(nonEnumerableResponse, "extra", { value: true });
  const nonEnumerableHeaders = {};
  Object.defineProperty(nonEnumerableHeaders, "x-test", { value: "value" });
  const sparseCookies = ["first=x", , "third=x"];
  const accessorCookies = ["first=x"];
  Object.defineProperty(accessorCookies, "0", { enumerable: true, get() { throw new Error("cookie getter poison"); } });
  const oversizedHeaders = Object.fromEntries(Array.from({ length: 5 }, (_, index) => [`x-${index}`, "x".repeat(7000)]));
  const proxyResponse = new Proxy({ status: 204, headers: {} }, {});
  const proxyHeaders = new Proxy({}, {});
  const proxyCookies = new Proxy(["session=x"], {});
  const bad: unknown[] = [
    null, proxyResponse, inheritedResponse, symbolResponse, nonEnumerableResponse,
    { status: 204, headers: proxyHeaders },
    { status: 204, headers: inheritedHeaders }, { status: 204, headers: symbolHeaders }, { status: 204, headers: nonEnumerableHeaders },
    { status: 200, headers: {}, extra: true }, { status: 200.5, headers: {} }, { status: 199, headers: {} },
    { status: 200, headers: {}, body: undefined }, { status: 200, headers: {}, redirect: undefined },
    { status: 200, headers: {}, setCookies: undefined },
    { status: 302, headers: {}, body: "x" }, { status: 200, headers: {}, body: {} },
    { status: 200, headers: {}, body: "untyped" }, { status: 200, headers: { "content-type": "text/plain" }, body: "x".repeat(65_537) },
    { status: 204, headers: {}, body: "" }, { status: 205, headers: {}, body: "" }, { status: 300, headers: {} }, { status: 304, headers: {} },
    { status: 200, headers: {}, redirect: "/account" }, { status: 302, headers: {}, redirect: "" },
    { status: 200, headers: { connection: "close" } },
    { status: 200, headers: { "X-Test": "one", "x-test": "two" } },
    { status: 200, headers: { "bad header": "value" } }, { status: 200, headers: { "x-test": "line\nbreak" } },
    { status: 200, headers: { "x-test": " leading" } }, { status: 200, headers: { "x-test": "trailing " } },
    { status: 200, headers: { "x-test": "\tleading" } }, { status: 200, headers: { "x-test": "trailing\t" } },
    { status: 200, headers: { "content-type": "\t" }, body: "must fail before success" },
    { status: 200, headers: { "x-test": "café" } }, { status: 200, headers: { "x-test": "😀" } },
    { status: 200, headers: { ["x".repeat(257)]: "value" } },
    { status: 200, headers: { "x-test": "x".repeat(8193) } }, { status: 200, headers: oversizedHeaders },
    { status: 302, headers: {}, redirect: "https://example.test/a b" },
    { status: 302, headers: {}, redirect: "/bad%2" }, { status: 302, headers: {}, redirect: "\\bad" },
    { status: 302, headers: {}, redirect: "https://[" }, { status: 302, headers: {}, redirect: "/path[not-an-ip-literal]" },
    { status: 302, headers: {}, redirect: "https://]" }, { status: 302, headers: {}, redirect: "https://[gg]/" },
    { status: 302, headers: {}, redirect: "/path?bracket=[x]" }, { status: 302, headers: {}, redirect: "//user@@example.test/" },
    { status: 302, headers: {}, redirect: "//example.test:not-a-port/" },
    { status: 302, headers: { location: "/other" }, redirect: "/account" },
    { status: 204, headers: { "set-cookie": "" } }, { status: 204, headers: {}, setCookies: [""] },
    { status: 204, headers: { "set-cookie": "x".repeat(4097) } },
    { status: 204, headers: {}, setCookies: ["x".repeat(4097)] },
    { status: 204, headers: { "set-cookie": " session=x" } }, { status: 204, headers: {}, setCookies: ["session=x "] },
    { status: 204, headers: { "set-cookie": "session=café" } }, { status: 204, headers: {}, setCookies: ["session=😀"] },
    { status: 204, headers: { "set-cookie": "session=x\npoison" } }, { status: 204, headers: {}, setCookies: ["session=x\tpoison"] },
    { status: 204, headers: {}, setCookies: "session=x" }, { status: 204, headers: {}, setCookies: sparseCookies },
    { status: 204, headers: {}, setCookies: accessorCookies }, { status: 204, headers: {}, setCookies: proxyCookies },
    { status: 204, headers: {}, setCookies: Array.from({ length: 16 }, (_, index) => `s${index}=x`) },
    accessor,
  ];
  const stderr: string[] = []; const saved = console.error;
  console.error = (...values: unknown[]) => { stderr.push(values.join(" ")); };
  try {
    for (const value of bad) {
      const h = harness({ onIdentity: () => value as NormResponse }); const begun = await start(h.flow);
      const response = await h.flow.handleCallback(callback(begun.state, begun.cookie));
      assert.equal(response.status, 500); assert.deepEqual(response.setCookies?.map((cookie) => cookie.split(";", 1)[0]), ["__Host-mcp-sso-identity="]);
      assert.deepEqual(h.audit.events.map((event) => [event.event, event.status, event.reason]), [
        ["identity.verify", "success", undefined], ["oauth.upstream.callback", "failure", "completion_failed"],
      ]);
      assert.equal(JSON.stringify(h.audit.events).includes("poison"), false);
    }
  } finally { console.error = saved; }
  assert.equal(stderr.length, 0);
});

test("identity completion accepts the host response boundary controls", async () => {
  const cookies = Array.from({ length: 15 }, (_, index) => `s${index}=x`);
  const h = harness({ onIdentity: () => ({
    status: 303,
    headers: { "Content-Type": "text/plain", "Cache-Control": "public", Location: "/account%20home", "Set-Cookie": "primary=x" },
    setCookies: cookies,
    redirect: "/account%20home",
  }) });
  const begun = await start(h.flow); const response = await h.flow.handleCallback(callback(begun.state, begun.cookie));
  assert.equal(response.status, 303); assert.equal(response.headers["cache-control"], "no-store");
  assert.equal(response.headers.location, "/account%20home"); assert.equal(response.setCookies?.length, 16);

  for (const redirect of ["https://example.test/account", "//example.test/account", "account/next?tab=/profile?view#name", "https://[::1]/account", "scheme://[Vf.identity:part]/account"]) {
    const redirectFlow = harness({ onIdentity: () => ({ status: 303, headers: {}, redirect }) });
    const redirectStart = await start(redirectFlow.flow); const redirectResponse = await redirectFlow.flow.handleCallback(callback(redirectStart.state, redirectStart.cookie));
    assert.equal(redirectResponse.status, 303); assert.equal(redirectResponse.redirect, redirect);
  }

  const body = harness({ onIdentity: () => ({ status: 200, headers: { "Content-Type": "text/plain", "x-tab": "a\tb" }, body: "Grüezi 😀" }) });
  const bodyStart = await start(body.flow); const bodyResponse = await body.flow.handleCallback(callback(bodyStart.state, bodyStart.cookie));
  assert.equal(bodyResponse.body, "Grüezi 😀"); assert.equal(bodyResponse.status, 200);
});

test("bridge completion ignores optional attributes that identity completion rejects", async () => {
  const claims: Record<string, unknown> = {};
  Object.defineProperty(claims, "value", { enumerable: true, get() { throw new Error("ignored claim poison"); } });
  const h = bridgeHarness({ ok: true, identity: { subject: "person-1", claims } });
  const begun = await startBridge(h.flow); const response = await h.flow.handleCallback(callback(begun.state, begun.cookie));
  assert.equal(response.status, 200);
});

test("claims and completion header projections preserve inert keys on null-prototype frozen records", async () => {
  const claims = Object.create(null) as Record<string, unknown>;
  for (const key of ["__proto__", "constructor", "prototype"]) Object.defineProperty(claims, key, { value: key, enumerable: true });
  const nested: Record<string, unknown> = { kept: "value", omitted: undefined };
  for (const key of ["__proto__", "constructor", "prototype"]) Object.defineProperty(nested, key, { value: `nested-${key}`, enumerable: true });
  claims.nested = nested; claims.list = [{ value: true }];
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
  const observedNested = observed?.claims?.nested as Record<string, unknown>;
  const observedList = observed?.claims?.list as Array<Record<string, unknown>>;
  assert.equal(Object.getPrototypeOf(observedNested), null); assert.equal(Object.hasOwn(observedNested, "omitted"), false);
  assert.equal(Object.isFrozen(observedNested), true); assert.equal(Object.isFrozen(observedList), true);
  assert.equal(Object.getPrototypeOf(observedList[0]), null); assert.equal(Object.isFrozen(observedList[0]), true);
  assert.equal(Object.getPrototypeOf(response.headers), null);
  for (const key of ["__proto__", "constructor", "prototype"]) assert.equal(Object.hasOwn(response.headers, key), true);

  const ordinaryHeaders: Record<string, string> = {};
  for (const key of ["__proto__", "constructor", "prototype"]) Object.defineProperty(ordinaryHeaders, key, { value: `ordinary-${key}`, enumerable: true });
  const ordinary = harness({ onIdentity: () => ({ status: 204, headers: ordinaryHeaders }) });
  const ordinaryStart = await start(ordinary.flow); const ordinaryResponse = await ordinary.flow.handleCallback(callback(ordinaryStart.state, ordinaryStart.cookie));
  assert.equal(Object.getPrototypeOf(ordinaryResponse.headers), null);
  for (const key of ["__proto__", "constructor", "prototype"]) assert.equal(Object.hasOwn(ordinaryResponse.headers, key), true);
});

function bridgeHarness(result?: RedirectExchangeResult) {
  const cfg = config(), store = new MemoryStore(), clock = new Clock(), audit = new Audit(); let exchanges = 0;
  const identity: RedirectIdentityPort = {
    redirectUri: "https://auth.test/oauth/callback",
    buildAuthorizationUrl(args) { return `https://idp.test/authorize?state=${args.state}`; },
    async exchangeAndVerify() { exchanges += 1; return result ?? { ok: true, identity: { subject: "person-1" } }; },
  };
  const bridge = new Bridge({ config: cfg, store, clock, audit });
  const flow = createUpstreamRedirectFlow({ bridge, identity, store, clock, audit });
  return { flow, audit, store, clock, exchanges: () => exchanges };
}

async function startBridge(flow: ReturnType<typeof bridgeHarness>["flow"]): Promise<{ state: string; cookie: string }> {
  const response = await flow.handleAuthorize({
    query: { response_type: "code", client_id: "client", redirect_uri: "https://client.test/callback", code_challenge: pkceChallenge("v".repeat(43)), code_challenge_method: "S256", scope: "mcp:read", state: "client-state" },
    body: undefined, headers: {}, ip: IP,
  });
  return { state: new URL(response.redirect as string).searchParams.get("state") as string, cookie: (response.headers["set-cookie"] as string).split(";", 1)[0] as string };
}

type MatrixRow = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11;
async function runCallbackRow(complete: "bridge" | "identity", row: MatrixRow): Promise<{
  reason: string | undefined; cleared: boolean; audit: string; consumes: number; exchanges: number; response: NormResponse;
}> {
  const outcome = row === 10 ? { ok: false, kind: "exchange_failed", reason: "poison detail" } as const
    : row === 11 ? { ok: false, kind: "identity_rejected", reason: "poison detail" } as const : undefined;
  const h = complete === "bridge" ? bridgeHarness(outcome) : harness({ result: outcome });
  let consumes = 0; const consume = h.store.consumeConsentJti.bind(h.store);
  h.store.consumeConsentJti = async (...args) => { consumes += 1; return consume(...args); };
  let begun = row === 2 ? { state: "missing", cookie: "" }
    : complete === "bridge" ? await startBridge(h.flow) : await start(h.flow);
  if (row === 3) begun = { ...begun, cookie: "__Host-mcp-sso-upstream=garbage" };
  if (row === 3 && complete === "identity") begun = { ...begun, cookie: "__Host-mcp-sso-identity=garbage" };
  if (row === 4) h.clock.advance(601);
  if (row === 6) await h.flow.handleCallback(callback(begun.state, begun.cookie));
  const query: NormRequest["query"] = row === 1 ? { state: [begun.state, begun.state], code: "c" }
    : row === 5 ? { state: "wrong", code: "c" }
    : row === 7 ? { state: begun.state, error: "access_denied" }
    : row === 8 ? { state: begun.state, error: "poison query detail" }
    : row === 9 ? { state: begun.state }
    : { state: begun.state, code: "c" };
  const response = await h.flow.handleCallback({ query, body: undefined, headers: begun.cookie ? { cookie: begun.cookie } : {}, ip: IP });
  const cleared = complete === "bridge"
    ? (response.headers["set-cookie"] ?? "").includes("Max-Age=0")
    : (response.setCookies ?? []).some((cookie) => cookie.includes("Max-Age=0"));
  const events = JSON.stringify(h.audit.events);
  return { reason: h.audit.events.filter((event) => event.event === "oauth.upstream.callback").at(-1)?.reason, cleared, audit: events, consumes, exchanges: h.exchanges(), response };
}

test("all eleven shared callback rows preserve audit, mutation, and redaction parity", async () => {
  const reasons = new Map<MatrixRow, string>([[1, "duplicate_params"], [2, "flow_cookie_missing"], [3, "flow_cookie_invalid"], [4, "flow_expired"], [5, "state_mismatch"], [6, "flow_replayed"], [7, "upstream_denied"], [8, "upstream_error"], [9, "missing_code"], [10, "exchange_failed"], [11, "identity_rejected"]]);
  const expectedConsumes = new Map<MatrixRow, number>([[1, 0], [2, 0], [3, 0], [4, 0], [5, 0], [6, 2], [7, 1], [8, 1], [9, 1], [10, 1], [11, 1]]);
  const expectedExchanges = new Map<MatrixRow, number>([[1, 0], [2, 0], [3, 0], [4, 0], [5, 0], [6, 1], [7, 0], [8, 0], [9, 0], [10, 1], [11, 1]]);
  for (const row of reasons.keys()) {
    const bridge = await runCallbackRow("bridge", row); const identity = await runCallbackRow("identity", row);
    assert.equal(bridge.reason, reasons.get(row), `bridge row ${row}`); assert.equal(identity.reason, bridge.reason, `identity row ${row}`);
    assert.equal(bridge.cleared, row !== 2, `bridge clear row ${row}`); assert.equal(identity.cleared, bridge.cleared, `identity clear row ${row}`);
    assert.equal(identity.response.headers["cache-control"], row === 2 ? undefined : "no-store", `identity cache row ${row}`);
    assert.equal(bridge.consumes, expectedConsumes.get(row), `bridge mutation row ${row}`); assert.equal(identity.consumes, bridge.consumes, `identity mutation row ${row}`);
    assert.equal(bridge.exchanges, expectedExchanges.get(row), `bridge exchange row ${row}`); assert.equal(identity.exchanges, bridge.exchanges, `identity exchange row ${row}`);
    assert.equal(identity.response.redirect, undefined, `identity direct response row ${row}`);
    assert.equal(bridge.response.redirect !== undefined, [7, 8, 10, 11].includes(row), `bridge redirect response row ${row}`);
    assert.equal(bridge.audit.includes("poison"), false); assert.equal(identity.audit.includes("poison"), false);
  }
});
