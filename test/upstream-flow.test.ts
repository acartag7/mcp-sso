// §17.11 upstream redirect-leg orchestrator — unit + flow tests. Every
// failure-table row is asserted by its enum reason; the cookie profile (both
// issuer schemes), the single-use jti (no second exchange on replay), the
// never-echoed IdP error params, the allowedScopes ceiling traveling to the
// consent JWT, the no-secrets audit invariant, the boot-validation fail-closed
// rules, the Entra redirect-identity outcome mapping, and adapter mutual-
// exclusion are all covered.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { decodeJwt, generateKeyPair, SignJWT, type JWK } from "jose";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { RedirectExchangeResult, RedirectIdentityPort } from "../src/ports/identity.ts";
import type { ClientStore, ClientRegistration } from "../src/ports/client-store.ts";
import type { NormRequest, NormResponse } from "../src/adapters/http.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { createUpstreamRedirectFlow } from "../src/adapters/upstream-flow.ts";
import {
  signFlowToken, verifyFlowToken, FLOW_AUDIENCE, OAUTH_PARAM_KEYS,
} from "../src/adapters/upstream-flow-internals.ts";
import { createEntraRedirectIdentity } from "../src/identity/entra-redirect.ts";
import { entraIssuer } from "../src/identity/entra.ts";
import { createBridgeConfig, originOf, AuthConfigError, type BridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { MemoryStore } from "../src/store/memory.ts";
import Fastify from "fastify";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import express from "express";
import { createOAuthRouter } from "../src/adapters/express.ts";
import { Hono } from "hono";
import { createOAuthApp } from "../src/adapters/hono.ts";

const NOW_MS = Date.parse("2026-07-06T12:00:00.000Z");
const IP = "203.0.113.7";
const CLIENT_REDIRECT = "https://client.test/callback";
const CALLBACK_PATH = "/oauth/callback";
const ISSUER = "https://auth.test";
const RESOURCE = "https://api.test/mcp";

class FakeClock implements ClockPort { private ms: number; constructor(ms: number) { this.ms = ms; } nowMs(): number { return this.ms; } advance(s: number): void { this.ms += s * 1000; } }
class MemoryAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(e: AuthAuditEvent): Promise<void> { this.events.push(e); }
  callback(): AuthAuditEvent[] { return this.events.filter((e) => e.event === "oauth.upstream.callback"); }
  identity(): AuthAuditEvent[] { return this.events.filter((e) => e.event === "identity.verify"); }
  json(): string { return JSON.stringify(this.events); }
}
function jwk(): JWK { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK; }
function config(loopback = false): BridgeConfig {
  return createBridgeConfig({
    issuer: loopback ? "http://localhost:3000" : ISSUER,
    resource: loopback ? "http://localhost:3000/mcp" : RESOURCE,
    consentSigningSecret: "test-consent-secret-with-enough-entropy-0123456789",
    signingPrivateJwk: jwk(), signingKeyId: "k",
    redirectAllowlist: [CLIENT_REDIRECT], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: [loopback ? "http://localhost:3000" : ISSUER],
    dcr: { mode: "stateless" },
    dev: loopback ? { allowInsecureLocalhost: true } : undefined,
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}
function cookieName(c: BridgeConfig): string { return new URL(c.issuer).protocol === "https:" ? "__Host-mcp-sso-upstream" : "mcp-sso-upstream"; }
class InMemoryClientStore implements ClientStore {
  private readonly m = new Map<string, ClientRegistration>();
  async save(c: ClientRegistration): Promise<void> { this.m.set(c.clientId, c); }
  async find(clientId: string): Promise<ClientRegistration | null> { return this.m.get(clientId) ?? null; }
}
function storedConfig(store: ClientStore): BridgeConfig {
  return createBridgeConfig({
    issuer: ISSUER, resource: RESOURCE,
    consentSigningSecret: "test-consent-secret-with-enough-entropy-0123456789",
    signingPrivateJwk: jwk(), signingKeyId: "k",
    redirectAllowlist: [CLIENT_REDIRECT], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: [ISSUER], dcr: { mode: "stored", store },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

interface FakeId { identity: RedirectIdentityPort; exchangeCalls: () => number; lastArgs: () => { code: string; codeVerifier: string; nonce: string } | undefined; set: (r: RedirectExchangeResult | "throw") => void; }
function fakeIdentity(c: BridgeConfig): FakeId {
  let calls = 0; let last: { code: string; codeVerifier: string; nonce: string } | undefined;
  let result: RedirectExchangeResult | "throw" = { ok: true, identity: { subject: "user-1" } };
  const identity: RedirectIdentityPort = {
    redirectUri: `${originOf(c.issuer)}${CALLBACK_PATH}`,
    buildAuthorizationUrl(req) { return `https://idp.test/authorize?state=${req.state}&nonce=${req.nonce}&code_challenge=${req.codeChallenge}`; },
    async exchangeAndVerify(args) { calls++; last = args; if (result === "throw") throw new Error("exchange boom"); return result; },
  };
  return { identity, exchangeCalls: () => calls, lastArgs: () => last, set: (r) => { result = r; } };
}

function makeFlow(c: BridgeConfig, id: FakeId, opts: { clock?: FakeClock; audit?: MemoryAudit; callbackPath?: string; flowTtlSeconds?: number; rateLimit?: { check(key: string): Promise<boolean> } } = {}) {
  const clock = opts.clock ?? new FakeClock(NOW_MS);
  const audit = opts.audit ?? new MemoryAudit();
  const store = new MemoryStore();
  const bridge = new Bridge({ config: c, store, clock, audit });
  const flow = createUpstreamRedirectFlow({ bridge, identity: id.identity, store, clock, audit, callbackPath: opts.callbackPath ?? CALLBACK_PATH, flowTtlSeconds: opts.flowTtlSeconds, rateLimit: opts.rateLimit });
  return { flow, bridge, store, clock, audit };
}

function authorizeQuery(clientId = "client-1", state = "client-state"): Record<string, string> {
  return { response_type: "code", client_id: clientId, redirect_uri: CLIENT_REDIRECT, code_challenge: pkceChallenge("v".repeat(43)), code_challenge_method: "S256", scope: "mcp:read", state };
}
function req(query: NormRequest["query"], headers: Record<string, string> = {}, ip: string | undefined = IP): NormRequest {
  return { query, body: undefined, headers, ip };
}
// Typed header accessors (Record<string,string> + noUncheckedIndexedAccess ⇒ string | undefined).
const hLoc = (res: NormResponse): string => res.headers.location ?? "";
const hCookie = (res: NormResponse): string => res.headers["set-cookie"] ?? "";

type FlowClaims = Awaited<ReturnType<typeof verifyFlowToken>>;

/** Initiate a flow (GET /oauth/authorize) and return the response + the decoded flow cookie claims + the raw cookie header value. */
async function initiate(c: BridgeConfig, flow: ReturnType<typeof makeFlow>["flow"], query: NormRequest["query"] = authorizeQuery()): Promise<{ res: NormResponse; claims: FlowClaims; cookieValue: string }> {
  const res = await flow.handleAuthorize(req(query));
  const sc = res.headers["set-cookie"] ?? "";
  const eq = sc.indexOf("="), semi = sc.indexOf(";");
  const cookieValue = sc.slice(eq + 1, semi);
  const claims = await verifyFlowToken(cookieValue, c.consentSigningSecret, c.issuer);
  return { res, claims, cookieValue };
}

function callbackReq(c: BridgeConfig, cookieValue: string | undefined, query: NormRequest["query"]): NormRequest {
  const headers: Record<string, string> = {};
  if (cookieValue !== undefined) headers.cookie = `${cookieName(c)}=${cookieValue}`;
  return req(query, headers);
}

// ============================================================================
// Boot validation (all AuthConfigError, fail-closed — §17.11)
// ============================================================================

test("boot: callbackPath must be a plain pathname (rejects ?, #, %, \\, whitespace, control, //, ./.., encoded dot-segment, reserved)", () => {
  const c = config(); const id = fakeIdentity(c);
  const bad = ["/oauth/callback?", "/oauth/callback#x", "/oauth/cb%2f", "/oauth/cb\\x", "/oauth/cb x", "/oauth/cb\t", "/oauth//cb", "/oauth/./cb", "/oauth/../oauth/token", "/oauth/cb/..", "/.well-known/x", "/oauth/token", "/oauth/authorize", "/mcp"];
  for (const p of bad) {
    const store = new MemoryStore(); const clock = new FakeClock(NOW_MS); const audit = new MemoryAudit();
    const bridge = new Bridge({ config: c, store, clock, audit });
    assert.throws(() => createUpstreamRedirectFlow({ bridge, identity: id.identity, store, clock, audit, callbackPath: p }), AuthConfigError, `callbackPath '${p}' should be rejected`);
  }
});

test("boot: callbackPath normalized-equality rejects an encoded dot-segment that survives RAW char checks", () => {
  // RAW chars are clean (no %, no literal dot-segment), but the path normalizes
  // away after URL parse — the post-parse equality check must catch it.
  const c = config(); const id = fakeIdentity(c);
  const store = new MemoryStore(); const clock = new FakeClock(NOW_MS); const audit = new MemoryAudit();
  const bridge = new Bridge({ config: c, store, clock, audit });
  // "/a/..%2f/oauth/token" style is caught by the % RAW check; craft one with no
  // forbidden RAW char whose normalization still drifts: a trailing dot segment
  // encoded via the host-relative path that WHATWG resolves.
  assert.throws(() => createUpstreamRedirectFlow({ bridge, identity: id.identity, store, clock, audit, callbackPath: "/oauth/cb/." }), AuthConfigError);
});

test("boot: identity.redirectUri must equal issuerOrigin + callbackPath and carry no query/fragment", () => {
  const c = config();
  const store = new MemoryStore(); const clock = new FakeClock(NOW_MS); const audit = new MemoryAudit();
  const bridge = new Bridge({ config: c, store, clock, audit });
  const goodUri = `${originOf(c.issuer)}${CALLBACK_PATH}`;
  const make = (redirectUri: string) => ({ redirectUri, buildAuthorizationUrl: () => "", exchangeAndVerify: async () => ({ ok: true, identity: { subject: "x" } }) as RedirectExchangeResult });
  assert.throws(() => createUpstreamRedirectFlow({ bridge, identity: make(goodUri + "?x=1"), store, clock, audit }), AuthConfigError, "query rejected");
  assert.throws(() => createUpstreamRedirectFlow({ bridge, identity: make(goodUri + "#f"), store, clock, audit }), AuthConfigError, "fragment rejected");
  assert.throws(() => createUpstreamRedirectFlow({ bridge, identity: make("https://auth.test/wrong/callback"), store, clock, audit }), AuthConfigError, "mismatch rejected");
  // exact match succeeds.
  createUpstreamRedirectFlow({ bridge, identity: make(goodUri), store, clock, audit });
});

test("boot: flowTtlSeconds must be a positive integer <= 3600", () => {
  const c = config(); const id = fakeIdentity(c);
  for (const v of [0, -1, 1.5, 3601, NaN, Infinity]) {
    const store = new MemoryStore(); const clock = new FakeClock(NOW_MS); const audit = new MemoryAudit();
    const bridge = new Bridge({ config: c, store, clock, audit });
    assert.throws(() => createUpstreamRedirectFlow({ bridge, identity: id.identity, store, clock, audit, flowTtlSeconds: v as number }), AuthConfigError, `flowTtlSeconds ${v} rejected`);
  }
  // boundaries 600 (default) and 3600 (max) succeed.
  for (const v of [1, 600, 3600]) {
    const store = new MemoryStore(); const clock = new FakeClock(NOW_MS); const audit = new MemoryAudit();
    const bridge = new Bridge({ config: c, store, clock, audit });
    createUpstreamRedirectFlow({ bridge, identity: id.identity, store, clock, audit, flowTtlSeconds: v });
  }
});

test("boot: callbackPath default is /oauth/callback and is exposed on the flow", () => {
  const c = config(); const { flow } = makeFlow(c, fakeIdentity(c));
  assert.equal(flow.callbackPath, CALLBACK_PATH);
});

// ============================================================================
// Cookie profile (the library's first cookie — threat-model row 4)
// ============================================================================

test("cookie: https issuer sets __Host-mcp-sso-upstream with Secure, Path=/, HttpOnly, SameSite=Lax, Max-Age, NO Domain", async () => {
  const c = config(); const { flow } = makeFlow(c, fakeIdentity(c));
  const { res } = await initiate(c, flow);
  const sc = res.headers["set-cookie"] ?? "";
  assert.match(sc, /^__Host-mcp-sso-upstream=[^;]+; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=600$/, "exact https set-cookie attrs");
  assert.doesNotMatch(sc, /Domain=/i, "no Domain on __Host- cookie");
});

test("cookie: http loopback issuer drops Secure and the __Host- prefix (still no Domain, still Path=/)", async () => {
  const c = config(true); const { flow } = makeFlow(c, fakeIdentity(c));
  const { res } = await initiate(c, flow);
  const sc = res.headers["set-cookie"] ?? "";
  assert.match(sc, /^mcp-sso-upstream=[^;]+; Path=\/; HttpOnly; SameSite=Lax; Max-Age=600$/, "exact loopback set-cookie attrs (no Secure/__Host-)");
  assert.doesNotMatch(sc, /Secure/i);
  assert.doesNotMatch(sc, /Domain=/i);
});

test("cookie: clearing cookie uses identical attrs + Max-Age=0 (no Domain) — both profiles", async () => {
  // https profile
  const c = config(); const { flow } = makeFlow(c, fakeIdentity(c));
  const { claims, cookieValue } = await initiate(c, flow);
  const res = await flow.handleCallback(callbackReq(c, cookieValue, { state: "WRONG" }));
  assert.match(res.headers["set-cookie"] ?? "", /^__Host-mcp-sso-upstream=; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=0$/, "exact https clear attrs");
  assert.doesNotMatch(res.headers["set-cookie"] ?? "", /Domain=/i);
  // loopback profile (no Secure/__Host-)
  const cl = config(true); const { flow: flowL } = makeFlow(cl, fakeIdentity(cl));
  const il = await initiate(cl, flowL);
  const resL = await flowL.handleCallback(callbackReq(cl, il.cookieValue, { state: "WRONG" }));
  assert.match(resL.headers["set-cookie"] ?? "", /^mcp-sso-upstream=; Path=\/; HttpOnly; SameSite=Lax; Max-Age=0$/, "exact loopback clear attrs");
  assert.doesNotMatch(resL.headers["set-cookie"] ?? "", /Secure/i);
  assert.doesNotMatch(resL.headers["set-cookie"] ?? "", /Domain=/i);
  void claims;
});

// ============================================================================
// handleAuthorize (GET /oauth/authorize) — steps 1-4
// ============================================================================

test("authorize: rate-limit key is upstream:<ip> (false => 429, throw => fail-open)", async () => {
  const c = config();
  let seenKey = "";
  const rl = { async check(key: string): Promise<boolean> { seenKey = key; return false; } };
  const { flow } = makeFlow(c, fakeIdentity(c), { rateLimit: rl });
  const res = await flow.handleAuthorize(req(authorizeQuery()));
  assert.equal(seenKey, `upstream:${IP}`);
  assert.equal(res.status, 429);
  // fail-open: a throwing limiter allows the flow.
  let seenKey2 = "";
  const rl2 = { async check(key: string): Promise<boolean> { seenKey2 = key; throw new Error("limiter down"); } };
  const { flow: flow2 } = makeFlow(c, fakeIdentity(c), { rateLimit: rl2 });
  const res2 = await flow2.handleAuthorize(req(authorizeQuery()));
  assert.equal(seenKey2, `upstream:${IP}`);
  assert.equal(res2.status, 302, "fail-open: limiter outage does not lock out");
});

test("authorize: duplicate OAUTH_PARAM_KEYS => direct 400 invalid_request (RFC 6749 §3.1), no cookie set", async () => {
  const c = config(); const { flow } = makeFlow(c, fakeIdentity(c));
  const q = authorizeQuery(); (q as Record<string, unknown>).state = ["a", "b"];
  const res = await flow.handleAuthorize(req(q));
  assert.equal(res.status, 400);
  assert.equal((res.body as { error: string }).error, "invalid_request");
  assert.equal(res.headers["set-cookie"], undefined, "no cookie set on a direct authorize error");
  assert.equal(res.redirect, undefined);
});

test("authorize: missing client_id => direct 400; bad redirect_uri => direct 4xx invalid_redirect_uri", async () => {
  const c = config(); const { flow } = makeFlow(c, fakeIdentity(c));
  const q1 = authorizeQuery(); delete (q1 as Record<string, unknown>).client_id;
  const r1 = await flow.handleAuthorize(req(q1));
  assert.equal(r1.status, 400); assert.equal((r1.body as { error: string }).error, "invalid_request");
  const q2 = authorizeQuery(); q2.redirect_uri = "https://evil.test/cb"; // not allowlisted
  const r2 = await flow.handleAuthorize(req(q2));
  assert.equal((r2.body as { error: string }).error, "invalid_redirect_uri");
  assert.equal(r2.status, 400); assert.equal(r2.headers["set-cookie"], undefined);
});

test("authorize (stored-DCR): step 3 validates redirect_uri PER-CLIENT (§10.2) before signing the flow cookie — closes the cross-client error-redirect gap", async () => {
  // The callback's redirect-channel errors (rows 7/8/10/11) fire before
  // bridge.handleAuthorize→prepare, so the redirect_uri signed into the flow cookie
  // must already be §10.2-valid (not just globally §10.1-valid) in stored mode.
  const clients = new InMemoryClientStore();
  await clients.save({ clientId: "client-A", redirectUris: [CLIENT_REDIRECT], applicationType: "web", issuedAtEpoch: 1 });
  const c = storedConfig(clients); const { flow } = makeFlow(c, fakeIdentity(c));
  // registered client + its own redirect_uri => 302 + cookie
  const ok = await flow.handleAuthorize(req(authorizeQuery("client-A")));
  assert.equal(ok.status, 302);
  assert.ok((ok.headers["set-cookie"] ?? "").startsWith("__Host-mcp-sso-upstream="));
  // registered client + a GLOBALLY-allowlisted but NOT-per-client-registered URI
  // (https://claude.ai is a built-in default origin) => invalid_redirect_uri, no cookie
  const q = authorizeQuery("client-A"); q.redirect_uri = "https://claude.ai/cb";
  const bad = await flow.handleAuthorize(req(q));
  assert.equal((bad.body as { error: string }).error, "invalid_redirect_uri");
  assert.equal(bad.headers["set-cookie"], undefined, "no flow cookie signed for a per-client-invalid redirect");
  // unknown client_id => invalid_client (direct 401), no cookie
  const q2 = authorizeQuery("client-UNKNOWN");
  const unk = await flow.handleAuthorize(req(q2));
  assert.equal((unk.body as { error: string }).error, "invalid_client");
  assert.equal(unk.status, 401);
  assert.equal(unk.headers["set-cookie"], undefined);
});

test("authorize: success => 302 to the IdP with Set-Cookie; nothing persisted server-side", async () => {
  const c = config(); const { flow } = makeFlow(c, fakeIdentity(c));
  const { res, cookieValue, claims } = await initiate(c, flow);
  assert.equal(res.status, 302);
  assert.ok(hLoc(res).startsWith("https://idp.test/authorize?"));
  assert.ok(hCookie(res).startsWith("__Host-mcp-sso-upstream="));
  // upstream state/nonce/PKCE are in the cookie; the client's state rides in params.
  assert.equal(claims.params.state, "client-state");
  assert.equal(claims.params.client_id, "client-1");
  assert.ok(claims.jti.startsWith("upf_"));
  assert.ok(claims.state.length >= 40 && claims.nonce.length >= 40 && claims.codeVerifier.length >= 40);
  assert.ok(cookieValue.length > 0);
});

test("authorize: a request whose serialized Set-Cookie would exceed 4096 bytes => direct 400 invalid_request, no cookie set (§17.11 fast-fail)", async () => {
  const c = config(); const { flow } = makeFlow(c, fakeIdentity(c));
  // Bloat the client `state` (round-tripped in params) so the signed flow cookie's
  // SERIALIZED form (name+value+attrs) exceeds 4096 bytes — the cap is on the full
  // Set-Cookie, not the bare JWT value, so a too-large cookie is rejected at authorize
  // rather than silently dropped by the browser at the callback.
  const q = authorizeQuery(); q.state = "S".repeat(5000);
  const res = await flow.handleAuthorize(req(q));
  assert.equal(res.status, 400);
  assert.equal((res.body as { error: string }).error, "invalid_request");
  assert.equal(res.headers["set-cookie"], undefined, "no cookie set on the oversized fast-fail");
  assert.equal(res.redirect, undefined);
  // a just-under-bound request still succeeds (sanity: the cap doesn't over-fire).
  const ok = authorizeQuery(); ok.state = "S".repeat(1000);
  const okRes = await flow.handleAuthorize(req(ok));
  assert.equal(okRes.status, 302, "a sub-cap request still 302s");
  assert.ok((okRes.headers["set-cookie"] ?? "").length <= 4096, "sub-cap cookie fits");
});

// ============================================================================
// handleCallback — the 13-row failure table (asserted by enum reason)
// ============================================================================

test("callback row 1: duplicate state/code/error/error_description => direct 400 duplicate_params (fires before cookie check)", async () => {
  const c = config(); const { flow, audit } = makeFlow(c, fakeIdentity(c));
  // duplicate params AND no cookie — row 1 must win over row 2.
  const res = await flow.handleCallback(req({ state: ["a", "b"], code: "x" }, {}));
  assert.equal(res.status, 400);
  assert.equal(audit.callback()[0]?.reason, "duplicate_params");
  assert.equal(res.headers["set-cookie"], undefined, "no cookie to clear (none was read)");
  // every contracted dup key triggers row 1 on its own.
  for (const key of ["state", "code", "error", "error_description"] as const) {
    const { flow: f, audit: a } = makeFlow(c, fakeIdentity(c));
    const q: Record<string, unknown> = { state: "s", code: "c" }; q[key] = ["one", "two"];
    const r = await f.handleCallback(req(q as NormRequest["query"], {}));
    assert.equal(r.status, 400, `dup ${key} => 400`);
    assert.equal(a.callback()[0]?.reason, "duplicate_params", `dup ${key} => duplicate_params`);
  }
});

test("callback row 2: flow cookie absent => direct 400 flow_cookie_missing (no clear)", async () => {
  const c = config(); const { flow, audit } = makeFlow(c, fakeIdentity(c));
  const res = await flow.handleCallback(req({ state: "x", code: "y" }, {}));
  assert.equal(res.status, 400);
  assert.equal(audit.callback()[0]?.reason, "flow_cookie_missing");
  assert.equal(res.headers["set-cookie"], undefined);
});

test("callback row 3: flow JWT signature/iss/aud invalid => direct 400 flow_cookie_invalid", async () => {
  const c = config(); const { flow, audit } = makeFlow(c, fakeIdentity(c));
  const res = await flow.handleCallback(callbackReq(c, "not-a-valid-jwt", { state: "x", code: "y" }));
  assert.equal(res.status, 400);
  assert.equal(audit.callback()[0]?.reason, "flow_cookie_invalid");
  assert.match(res.headers["set-cookie"] ?? "", /Max-Age=0/);
});

test("callback row 4 (direct mint): an expired-but-validly-signed flow => flow_expired (not flow_cookie_invalid)", async () => {
  const c = config(); const clock = new FakeClock(NOW_MS); const id = fakeIdentity(c);
  const { flow, audit } = makeFlow(c, id, { clock });
  // Mint a cookie whose exp is already in the past.
  const expiredJwt = await signFlowToken({ secret: c.consentSigningSecret, issuer: c.issuer, clock: { nowMs: () => NOW_MS - 10_000 }, jti: "upf_" + "e".repeat(40), state: "S", nonce: "N", codeVerifier: "V".repeat(43), params: authorizeQuery(), ttlSeconds: 1 });
  const res = await flow.handleCallback(callbackReq(c, expiredJwt, { state: "S", code: "y" }));
  assert.equal(res.status, 400);
  assert.equal(audit.callback()[0]?.reason, "flow_expired");
  assert.notEqual(audit.callback()[0]?.reason, "flow_cookie_invalid");
});

test("callback row 5: state mismatch (and length mismatch) => direct 400 state_mismatch", async () => {
  const c = config(); const { flow, audit } = makeFlow(c, fakeIdentity(c));
  const { claims, cookieValue } = await initiate(c, flow);
  // wrong value
  const r1 = await flow.handleCallback(callbackReq(c, cookieValue, { state: "WRONG", code: "y" }));
  assert.equal((r1.body as { error: string }).error, "invalid_request");
  assert.equal(audit.callback().at(-1)?.reason, "state_mismatch");
  // length mismatch (timing-safe compare fails fast)
  const r2 = await flow.handleCallback(callbackReq(c, cookieValue, { state: claims.state.slice(0, 5), code: "y" }));
  assert.equal(r2.status, 400);
  assert.equal(audit.callback().at(-1)?.reason, "state_mismatch");
  // absent state param entirely (the !queryState short-circuit branch)
  const r3 = await flow.handleCallback(callbackReq(c, cookieValue, { code: "y" }));
  assert.equal(r3.status, 400);
  assert.equal(audit.callback().at(-1)?.reason, "state_mismatch", "absent state => state_mismatch");
});

test("callback row 6 + replay: single-use jti — a replayed callback is 400 flow_replayed with NO second exchange", async () => {
  const c = config(); const id = fakeIdentity(c); const { flow, audit } = makeFlow(c, id);
  const { claims, cookieValue } = await initiate(c, flow);
  const q = { state: claims.state, code: "CODE-1" };
  // First callback: success (row 13) — exchange called once.
  const r1 = await flow.handleCallback(callbackReq(c, cookieValue, q));
  assert.equal(r1.status, 200, "first callback renders the consent page");
  assert.equal(id.exchangeCalls(), 1);
  // Replay the same callback URL (same cookie + state + code): row 6 fires BEFORE the exchange.
  const r2 = await flow.handleCallback(callbackReq(c, cookieValue, q));
  assert.equal(r2.status, 400);
  assert.equal((r2.body as { error: string }).error, "invalid_request");
  assert.equal(id.exchangeCalls(), 1, "NO second exchange on replay");
  assert.equal(audit.callback().at(-1)?.reason, "flow_replayed", "the row-6 enum reason is pinned");
});

test("callback row 7: IdP error in {access_denied,...} => 302 access_denied 'upstream identity provider denied the request'", async () => {
  const c = config();
  for (const err of ["access_denied", "consent_required", "interaction_required", "login_required"]) {
    const { flow, audit } = makeFlow(c, fakeIdentity(c)); // fresh flow per iteration (jti is single-use)
    const { claims, cookieValue } = await initiate(c, flow);
    const res = await flow.handleCallback(callbackReq(c, cookieValue, { state: claims.state, error: err }));
    assert.equal(res.status, 302);
    assert.match(hLoc(res), /error=access_denied/);
    assert.match(hLoc(res), /error_description=upstream\+identity\+provider\+denied\+the\+request/);
    assert.match(hLoc(res), /state=client-state/); // the CLIENT's state, not the upstream state
    assert.equal(audit.callback().at(-1)?.reason, "upstream_denied");
  }
});

test("callback row 8: IdP error = anything else => 302 server_error 'upstream identity provider error'", async () => {
  const c = config(); const { flow, audit } = makeFlow(c, fakeIdentity(c));
  const { claims, cookieValue } = await initiate(c, flow);
  const res = await flow.handleCallback(callbackReq(c, cookieValue, { state: claims.state, error: "some_idp_failure" }));
  assert.equal(res.status, 302);
  assert.match(hLoc(res), /error=server_error/);
  assert.match(hLoc(res), /error_description=upstream\+identity\+provider\+error/);
  assert.equal(audit.callback().at(-1)?.reason, "upstream_error");
});

test("callback rows 7/8: IdP error/error_description are NEVER echoed into the redirect, audit, or stderr (poison on both fields)", async () => {
  const c = config();
  const POISON_DESC = "TOP_SECRET_IDP_DETAIL_xyz://evil";
  const POISON_ERR = "evil_custom_idp_error_value://attack";
  const chunks: string[] = [];
  const orig = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((s: string | Uint8Array): boolean => { chunks.push(typeof s === "string" ? s : Buffer.from(s).toString()); return true; }) as typeof process.stderr.write;
  try {
    // row 7: poison the error_description (error value is a recognized denied code).
    let f = makeFlow(c, fakeIdentity(c)); let i = await initiate(c, f.flow);
    let res = await f.flow.handleCallback(callbackReq(c, i.cookieValue, { state: i.claims.state, error: "access_denied", error_description: POISON_DESC }));
    assert.equal(hLoc(res).includes(encodeURIComponent(POISON_DESC)), false, "row 7: poison desc not in redirect");
    assert.equal(f.audit.json().includes(POISON_DESC), false, "row 7: poison desc not in audit");
    // row 8: poison BOTH the error value and the description (an unrecognized error code).
    f = makeFlow(c, fakeIdentity(c)); i = await initiate(c, f.flow);
    res = await f.flow.handleCallback(callbackReq(c, i.cookieValue, { state: i.claims.state, error: POISON_ERR, error_description: POISON_DESC }));
    assert.equal(hLoc(res).includes(encodeURIComponent(POISON_ERR)), false, "row 8: poison error value not in redirect");
    assert.equal(hLoc(res).includes(encodeURIComponent(POISON_DESC)), false, "row 8: poison desc not in redirect");
    assert.match(hLoc(res), /error=server_error/, "row 8: only the FIXED server_error code is emitted");
    assert.equal(f.audit.json().includes(POISON_ERR), false, "row 8: poison error value not in audit");
    assert.equal(f.audit.json().includes(POISON_DESC), false, "row 8: poison desc not in audit");
  } finally { process.stderr.write = orig; }
  assert.equal(chunks.join("").includes(POISON_DESC), false, "poison not in stderr");
  assert.equal(chunks.join("").includes(POISON_ERR), false, "poison error value not in stderr");
});

test("callback row 9: no code and no error => direct 400 missing_code", async () => {
  const c = config(); const { flow, audit } = makeFlow(c, fakeIdentity(c));
  const { claims, cookieValue } = await initiate(c, flow);
  const res = await flow.handleCallback(callbackReq(c, cookieValue, { state: claims.state }));
  assert.equal(res.status, 400);
  assert.equal(audit.callback().at(-1)?.reason, "missing_code");
});

test("callback row 10: exchange_failed (non-200/timeout/missing id_token) => 302 server_error; a THROW is also exchange_failed", async () => {
  const c = config();
  // returned exchange_failed
  const id1 = fakeIdentity(c); id1.set({ ok: false, kind: "exchange_failed", reason: "entra_exchange_failed" });
  const { flow: f1, audit: a1 } = makeFlow(c, id1);
  const i1 = await initiate(c, f1);
  const r1 = await f1.handleCallback(callbackReq(c, i1.cookieValue, { state: i1.claims.state, code: "c" }));
  assert.equal(r1.status, 302); assert.match(hLoc(r1), /error=server_error/);
  assert.match(hLoc(r1), /error_description=upstream\+identity\+provider\+error/);
  assert.equal(a1.callback().at(-1)?.reason, "exchange_failed");
  assert.equal(a1.identity().length, 0, "no identity.verify on exchange_failed");
  // thrown exchange -> also exchange_failed (the IdP endpoint returned no id_token -> exchangeCodeForToken throws)
  const id2 = fakeIdentity(c); id2.set("throw");
  const { flow: f2, audit: a2 } = makeFlow(c, id2);
  const i2 = await initiate(c, f2);
  const r2 = await f2.handleCallback(callbackReq(c, i2.cookieValue, { state: i2.claims.state, code: "c" }));
  assert.equal(r2.status, 302);
  assert.equal(a2.callback().at(-1)?.reason, "exchange_failed", "a throw is classified exchange_failed");
  assert.equal(a2.identity().length, 0, "a thrown exchange also reaches no identity decision — no identity.verify");
});

test("callback row 11: identity_rejected => 302 access_denied + identity.verify failure (with the port reason)", async () => {
  const c = config(); const id = fakeIdentity(c);
  id.set({ ok: false, kind: "identity_rejected", reason: "entra_bad_nonce" });
  const { flow, audit } = makeFlow(c, id);
  const { claims, cookieValue } = await initiate(c, flow);
  const res = await flow.handleCallback(callbackReq(c, cookieValue, { state: claims.state, code: "c" }));
  assert.equal(res.status, 302);
  assert.match(hLoc(res), /error=access_denied/);
  assert.match(hLoc(res), /error_description=upstream\+identity\+verification\+failed/);
  assert.equal(audit.callback().at(-1)?.reason, "identity_rejected");
  const idv = audit.identity().at(-1);
  assert.equal(idv?.status, "failure");
  assert.equal(idv?.reason, "entra_bad_nonce", "the port's reason lands in identity.verify");
});

test("callback rows 12/13: success => 200 consent page + identity.verify success + oauth.upstream.callback success", async () => {
  const c = config(); const { flow, audit } = makeFlow(c, fakeIdentity(c));
  const { claims, cookieValue } = await initiate(c, flow);
  const res = await flow.handleCallback(callbackReq(c, cookieValue, { state: claims.state, code: "c" }));
  assert.equal(res.status, 200);
  assert.match(String(res.body), /Authorize access/, "the consent page is the direct callback response");
  assert.match(hCookie(res), /Max-Age=0/, "cookie cleared on success too");
  assert.equal(audit.callback().at(-1)?.status, "success");
  assert.equal(audit.identity().at(-1)?.status, "success");
  assert.equal(audit.identity().at(-1)?.subject, "user-1");
});

test("callback row 12: bridge.handleAuthorize error (e.g. invalid_scope) travels on its own §9.3 channel + bridge_error audit", async () => {
  const c = config(); const id = fakeIdentity(c); const { flow, audit } = makeFlow(c, id);
  // Mint a flow whose params request an UNKNOWN scope; handleAuthorize.prepare rejects it
  // over the redirect channel (the redirect_uri was §10-validated at authorize).
  const q = authorizeQuery(); q.scope = "mcp:unknown";
  const { claims, cookieValue } = await initiate(c, flow, q);
  const res = await flow.handleCallback(callbackReq(c, cookieValue, { state: claims.state, code: "c" }));
  assert.equal(res.status, 302, "invalid_scope is a redirect-channel error");
  assert.match(hLoc(res), /error=invalid_scope/);
  assert.match(hLoc(res), /state=client-state/);
  assert.equal(audit.callback().at(-1)?.reason, "bridge_error");
});

test("callback: oauth.upstream.callback is emitted on EVERY outcome (incl. success)", async () => {
  const c = config(); const id = fakeIdentity(c); const { flow, audit } = makeFlow(c, id);
  const { claims, cookieValue } = await initiate(c, flow);
  // success
  await flow.handleCallback(callbackReq(c, cookieValue, { state: claims.state, code: "c" }));
  // missing_code (fresh flow — the jti above was consumed)
  const i2 = await initiate(c, flow);
  await flow.handleCallback(callbackReq(c, i2.cookieValue, { state: i2.claims.state }));
  assert.ok(audit.callback().length >= 2, "every callback outcome audited");
  for (const e of audit.callback()) { assert.equal(e.event, "oauth.upstream.callback"); assert.equal(typeof e.reason === "string" || e.status === "success", true); }
});

test("callback: allowedScopes ceiling from the identity NARROWS the request and travels into the consent JWT", async () => {
  const c = config(); const id = fakeIdentity(c);
  // ceiling = mcp:read only; REQUEST mcp:read+mcp:write so the narrowing is observable
  // (requesting exactly the ceiling couldn't distinguish "enforced" from "coincidence").
  id.set({ ok: true, identity: { subject: "user-1", allowedScopes: ["mcp:read"] } });
  const { flow } = makeFlow(c, id);
  const q = authorizeQuery(); q.scope = "mcp:read mcp:write";
  const { claims, cookieValue } = await initiate(c, flow, q);
  const res = await flow.handleCallback(callbackReq(c, cookieValue, { state: claims.state, code: "c" }));
  const html = String(res.body);
  const consentToken = /name="consent_token" value="([^"]+)"/.exec(html)?.[1];
  assert.ok(consentToken);
  const decoded = decodeJwt(consentToken);
  assert.equal(decoded.allowed_scopes, "mcp:read", "the §17.4 ceiling rode the verified identity into the consent JWT");
  assert.equal(decoded.scope, "mcp:read", "the granted scope was NARROWED to the ceiling (mcp:write stripped)");
});

test("callback: no-secrets — state/nonce/code/verifier/jti/cookie-value never appear in the audit", async () => {
  const c = config(); const { flow, audit } = makeFlow(c, fakeIdentity(c));
  const { claims, cookieValue } = await initiate(c, flow);
  const CODE = "SUPER_SECRET_CODE_42";
  await flow.handleCallback(callbackReq(c, cookieValue, { state: claims.state, code: CODE }));
  const json = audit.json();
  for (const secret of [claims.state, claims.nonce, claims.codeVerifier, claims.jti, CODE, cookieValue]) {
    assert.equal(json.includes(secret), false, `secret value must not appear in audit: ${secret.slice(0, 12)}…`);
  }
  // clientId IS metadata and IS present.
  assert.ok(audit.callback().some((e) => e.clientId === "client-1"));
});

test("callback: cookie cleared on every response that had a readable cookie (success + failures)", async () => {
  const c = config(); const { flow } = makeFlow(c, fakeIdentity(c));
  const { claims, cookieValue } = await initiate(c, flow);
  // state mismatch (row 5) clears.
  const r1 = await flow.handleCallback(callbackReq(c, cookieValue, { state: "WRONG", code: "c" }));
  assert.match(r1.headers["set-cookie"] ?? "", /Max-Age=0/);
  // row 3 (invalid cookie) also clears (a cookie name WAS present).
  const r2 = await flow.handleCallback(callbackReq(c, "garbage.value", { state: "x", code: "c" }));
  assert.match(r2.headers["set-cookie"] ?? "", /Max-Age=0/);
  void claims;
});

// ============================================================================
// Adapter mutual-exclusion (fastify/express/hono) — exactly one authorize mode
// ============================================================================

function adapterMutualExclusion(label: string, mount: (mode: "upstream+identity" | "upstream+skip" | "upstream-only" | "identity-only") => Promise<unknown>): void {
  test(`adapter (${label}): upstream + identity throws at registration`, async () => {
    await assert.rejects(() => mount("upstream+identity"), /mutually exclusive/);
  });
  test(`adapter (${label}): upstream + skipAuthorize throws at registration`, async () => {
    await assert.rejects(() => mount("upstream+skip"), /mutually exclusive/);
  });
  test(`adapter (${label}): upstream-only registers /oauth/authorize + callbackPath`, async () => {
    await mount("upstream-only"); // must not throw
  });
  test(`adapter (${label}): identity-only still works (unchanged)`, async () => {
    await mount("identity-only"); // must not throw
  });
}

function stubFlow(c: BridgeConfig): ReturnType<typeof makeFlow>["flow"] {
  return makeFlow(c, fakeIdentity(c)).flow;
}
function headerIdentity() { return { async verify(): Promise<{ ok: true; identity: { subject: string } }> { return { ok: true, identity: { subject: "x" } }; } }; }
function adapterBase(c: BridgeConfig): Bridge { return new Bridge({ config: c, store: new MemoryStore(), clock: new FakeClock(NOW_MS), audit: new MemoryAudit() }); }
function adapterOpts(mode: string, c: BridgeConfig): Record<string, unknown> {
  const opts: Record<string, unknown> = { bridge: adapterBase(c) };
  if (mode === "upstream+identity") { opts.upstream = stubFlow(c); opts.identity = headerIdentity() as never; }
  else if (mode === "upstream+skip") { opts.upstream = stubFlow(c); opts.skipAuthorize = true; }
  else if (mode === "upstream-only") { opts.upstream = stubFlow(c); }
  else { opts.identity = headerIdentity() as never; }
  return opts;
}

adapterMutualExclusion("fastify", async (mode) => { const c = config(); const app = Fastify(); await registerOAuthRoutes(app, adapterOpts(mode, c) as never); });
adapterMutualExclusion("express", async (mode) => { const c = config(); return createOAuthRouter(adapterOpts(mode, c) as never); });
adapterMutualExclusion("hono", async (mode) => { const c = config(); return createOAuthApp(adapterOpts(mode, c) as never); });

test("adapter wiring + cookie delivery: all three adapters mount GET /oauth/authorize -> handleAuthorize (302 + Set-Cookie) and GET callbackPath -> handleCallback", async () => {
  const c = config();
  const authorizeUrl = `/oauth/authorize?${new URLSearchParams(authorizeQuery())}`;

  // fastify (inject — also proves the same wiring buildExample relies on)
  {
    const { flow, bridge } = makeFlow(c, fakeIdentity(c));
    const app = Fastify();
    await registerOAuthRoutes(app, { bridge, upstream: flow });
    try {
      const auth = await app.inject({ method: "GET", url: authorizeUrl });
      assert.equal(auth.statusCode, 302, "fastify: /oauth/authorize -> handleAuthorize");
      assert.ok(String(auth.headers["set-cookie"] ?? "").startsWith("__Host-mcp-sso-upstream="), "fastify: Set-Cookie delivered");
      const cb = await app.inject({ method: "GET", url: "/oauth/callback" });
      assert.equal(cb.statusCode, 400, "fastify: callbackPath -> handleCallback (flow_cookie_missing)");
    } finally { await app.close(); }
  }

  // hono (app.request — no TCP server)
  {
    const { flow, bridge } = makeFlow(c, fakeIdentity(c));
    const app = createOAuthApp({ bridge, upstream: flow });
    const auth = await app.request(authorizeUrl, { method: "GET" });
    assert.equal(auth.status, 302, "hono: /oauth/authorize -> handleAuthorize");
    assert.ok((auth.headers.get("set-cookie") ?? "").startsWith("__Host-mcp-sso-upstream="), "hono: Set-Cookie delivered");
    const cb = await app.request("/oauth/callback", { method: "GET" });
    assert.equal(cb.status, 400, "hono: callbackPath -> handleCallback");
  }

  // express (real HTTP server, redirect:"manual" to capture the 302)
  {
    const { flow, bridge } = makeFlow(c, fakeIdentity(c));
    const app = express();
    app.use(express.urlencoded({ extended: false }));
    app.use("/", createOAuthRouter({ bridge, upstream: flow }));
    const server = app.listen(0, "127.0.0.1");
    await new Promise<void>((r) => server.once("listening", r));
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    try {
      const auth = await fetch(base + authorizeUrl, { redirect: "manual" });
      assert.equal(auth.status, 302, "express: /oauth/authorize -> handleAuthorize");
      assert.ok((auth.headers.get("set-cookie") ?? "").startsWith("__Host-mcp-sso-upstream="), "express: Set-Cookie delivered");
      const cb = await fetch(base + "/oauth/callback", { redirect: "manual" });
      assert.equal(cb.status, 400, "express: callbackPath -> handleCallback");
    } finally { await new Promise<void>((r) => server.close(() => r())); }
  }
});

// ============================================================================
// Entra redirect identity (createEntraRedirectIdentity) — outcome mapping
// ============================================================================

test("entra-redirect: buildAuthorizationUrl requests scope 'openid profile email' (NO offline_access) + nonce", () => {
  const tenantId = "11111111-2222-3333-4444-555555555555";
  const c: BridgeConfig = config();
  const redirectUri = `${originOf(c.issuer)}${CALLBACK_PATH}`;
  const id = createEntraRedirectIdentity({ tenantId, clientId: "cid", redirectUri });
  const url = id.buildAuthorizationUrl({ state: "S", nonce: "N", codeChallenge: "C".repeat(43), codeChallengeMethod: "S256" });
  const u = new URL(url);
  assert.equal(u.searchParams.get("scope"), "openid profile email");
  assert.equal(u.searchParams.get("nonce"), "N");
  assert.equal(u.searchParams.get("code_challenge_method"), "S256");
});

test("entra-redirect: exchange success + verify ok => {ok:true,identity}; verify failure => identity_rejected; exchange throw/non-200/missing-id_token => exchange_failed", async () => {
  const tenantId = "11111111-2222-3333-4444-555555555555";
  const clientId = "cid";
  const c: BridgeConfig = config();
  const redirectUri = `${originOf(c.issuer)}${CALLBACK_PATH}`;
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const verifyKey = publicKey; // jose jwtVerify accepts the matching public CryptoKey directly
  const now = Math.floor(NOW_MS / 1000);
  async function signIdToken(nonce: string): Promise<string> {
    return await new SignJWT({ oid: "oid-1", tid: tenantId, nonce }).setProtectedHeader({ alg: "RS256", typ: "JWT", kid: "k1" })
      .setIssuer(entraIssuer(tenantId)).setAudience(clientId).setIssuedAt(now).setExpirationTime(now + 3600).sign(privateKey);
  }
  const goodTransport = { async postForm(): Promise<{ status: number; text(): Promise<string> }> { return { status: 200, text: async () => JSON.stringify({ id_token: await signIdToken("N1") }) }; } };
  const id = createEntraRedirectIdentity({ tenantId, clientId, redirectUri }, { transport: goodTransport, verifyKey, currentDate: new Date(NOW_MS) });
  // success
  const ok = await id.exchangeAndVerify({ code: "c", codeVerifier: "v".repeat(43), nonce: "N1" });
  assert.equal(ok.ok, true);
  // nonce mismatch => identity_rejected
  const badNonceTransport = { async postForm(): Promise<{ status: number; text(): Promise<string> }> { return { status: 200, text: async () => JSON.stringify({ id_token: await signIdToken("DIFFERENT") }) }; } };
  const idBad = createEntraRedirectIdentity({ tenantId, clientId, redirectUri }, { transport: badNonceTransport, verifyKey, currentDate: new Date(NOW_MS) });
  const rej = await idBad.exchangeAndVerify({ code: "c", codeVerifier: "v".repeat(43), nonce: "N1" });
  assert.equal(rej.ok, false); if (!rej.ok) assert.equal(rej.kind, "identity_rejected");
  // non-200 => exchange_failed
  const fail200Transport = { async postForm(): Promise<{ status: number; text(): Promise<string> }> { return { status: 500, text: async () => "boom" }; } };
  const idFail = createEntraRedirectIdentity({ tenantId, clientId, redirectUri }, { transport: fail200Transport, verifyKey, currentDate: new Date(NOW_MS) });
  const ex = await idFail.exchangeAndVerify({ code: "c", codeVerifier: "v".repeat(43), nonce: "N1" });
  assert.equal(ex.ok, false); if (!ex.ok) assert.equal(ex.kind, "exchange_failed");
  // missing id_token => exchange_failed
  const noIdTokenTransport = { async postForm(): Promise<{ status: number; text(): Promise<string> }> { return { status: 200, text: async () => JSON.stringify({}) }; } };
  const idNo = createEntraRedirectIdentity({ tenantId, clientId, redirectUri }, { transport: noIdTokenTransport, verifyKey, currentDate: new Date(NOW_MS) });
  const ex2 = await idNo.exchangeAndVerify({ code: "c", codeVerifier: "v".repeat(43), nonce: "N1" });
  assert.equal(ex2.ok, false); if (!ex2.ok) assert.equal(ex2.kind, "exchange_failed");
});

test("entra-redirect: a JWKS-fetch outage (network) is exchange_failed, NOT identity_rejected (no identity decision — §17.11 deterministic throw-rule)", async () => {
  const tenantId = "11111111-2222-3333-4444-555555555555"; const clientId = "cid";
  const c: BridgeConfig = config();
  const redirectUri = `${originOf(c.issuer)}${CALLBACK_PATH}`;
  const { privateKey } = await generateKeyPair("RS256");
  const now = Math.floor(NOW_MS / 1000);
  const idToken = await new SignJWT({ oid: "entra-user-oid", tid: tenantId, nonce: "N1" }).setProtectedHeader({ alg: "RS256", typ: "JWT", kid: "k1" }).setIssuer(entraIssuer(tenantId)).setAudience(clientId).setIssuedAt(now).setExpirationTime(now + 3600).sign(privateKey);
  // Exchange succeeds (injected transport); the JWKS verify fetch fails (network).
  const transport = { async postForm(): Promise<{ status: number; text(): Promise<string> }> { return { status: 200, text: async () => JSON.stringify({ id_token: idToken }) }; } };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => { throw new TypeError("network down"); }) as typeof fetch;
  try {
    const id = createEntraRedirectIdentity({ tenantId, clientId, redirectUri }, { transport }); // JWKS path (no verifyKey)
    const r = await id.exchangeAndVerify({ code: "c", codeVerifier: "v".repeat(43), nonce: "N1" });
    assert.equal(r.ok, false, "verify did not succeed (the JWKS could not be fetched)");
    if (!r.ok) assert.equal(r.kind, "exchange_failed", "a JWKS outage is infrastructure ⇒ exchange_failed (never identity_rejected)");
  } finally { globalThis.fetch = realFetch; }
});

test("entra-redirect: re-exported from the ./identity/entra subpath source (createEntraRedirectIdentity)", async () => {
  const mod = await import("../src/identity/entra.ts");
  assert.equal(typeof mod.createEntraRedirectIdentity, "function");
});
