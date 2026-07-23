// FROZEN acceptance suite — S6b success cache + concurrency (docs/contracts.md
// §17.1.6 decision 4 + §17.1.5 rules 24/25; verification T1.S6b row S6b.8). The
// raw-client-id-keyed validated-success cache serves BOTH direct-mode prepare AND
// upstream-redirect authorize (the SAME cache); a HIT does no fetch; RFC-9111-ish
// freshness = min(valid max-age, cacheTtlCapSeconds) − Age − elapsed (seconds; ms
// via ClockPort); max-age<60 / no-store / no-cache / absent / duplicate / quoted ⇒
// NON-cacheable (never clamped up); Age cacheable only as one ^[0-9]+$ occurrence;
// negative/non-finite elapsed ⇒ non-cacheable; error/invalid docs never cached;
// bounded LRU (default 256); single-flight coalesces CONCURRENT same-raw-id; the
// global maxInFlight cap rejects a DISTINCT id as `overloaded`. Black-box through
// the public handlers + the cimdTransport/cimdResolver seams; a FakeClock drives
// freshness. FAITHFULNESS: cache behavior is observed ONLY via fetch-count / status
// / the `overloaded` audit reason — no internal cache handle is inspected.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";

const phases = JSON.parse(readFileSync(new URL("../phases.json", import.meta.url), "utf8"));

if (phases["s6b-cimd-flow"] !== true) {
  test("s6b-cimd-flow inactive — activate via test/acceptance/phases.json", { skip: true }, () => {});
} else {
  const CFG = "../../../src/config.ts";
  const { createBridgeConfig } = (await import(CFG)) as any;
  const BRIDGE = "../../../src/adapters/bridge.ts";
  const { Bridge } = (await import(BRIDGE)) as any;
  const FLOW = "../../../src/adapters/upstream-flow.ts";
  const { createUpstreamRedirectFlow } = (await import(FLOW)) as any;
  const STORE = "../../../src/store/memory.ts";
  const { MemoryStore } = (await import(STORE)) as any;
  const CRYPTO = "../../../src/crypto.ts";
  const { pkceChallenge } = (await import(CRYPTO)) as any;

  const START = Date.parse("2026-07-03T12:00:00.000Z");
  const ID = "https://cdn.example.com/client";
  const REDIRECT = "https://app.example.com/cb";
  const PUBLIC = { address: "93.184.216.34", family: 4 };
  const GENERIC = { error: "invalid_client", error_description: "client_id could not be resolved" };
  const enc = (s: string) => new TextEncoder().encode(s);
  async function* one(u8: Uint8Array) { yield u8; }
  const VERIFIER = "correct-horse-battery-staple-0123456789abcdef0123";

  class Clock { ms = START; nowMs() { return this.ms; } advance(seconds: number) { this.ms += seconds * 1000; } }
  class MemoryAudit { events: any[] = []; async writeAuthEvent(e: any) { this.events.push(e); } }
  function jwk(): any { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" }; }
  function config(opts: any = {}): any {
    return createBridgeConfig({
      issuer: "https://auth.test", resource: "https://api.test/mcp",
      consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k",
      redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
      allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" }, cimd: { enabled: true, ...opts },
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    });
  }
  const request = (clientId = ID) => ({ query: { response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", scope: "mcp:read", state: "s" }, body: undefined, headers: {}, ip: "203.0.113.3" });
  const resolver = () => ({ resolve() { return Promise.resolve([PUBLIC]); }, cancel() {} });
  const bodyFor = (id: string) => JSON.stringify({ client_id: id, client_name: "Example", redirect_uris: [REDIRECT] });
  const response = (id: string, headersDistinct: any = { "content-type": ["application/json"], "cache-control": ["max-age=3600"] }) => ({ status: 200, redirected: false, finalUrl: id, headersDistinct, encodedBody: one(enc(bodyFor(id))) });
  // Echoes the requested id back as the document client_id (distinct ids ⇒ distinct
  // valid docs) with configurable cache headers / latency.
  function echoTransport(headers: any = { "content-type": ["application/json"], "cache-control": ["max-age=3600"] }, onCall?: () => void) {
    let calls = 0;
    return { async connectAndGet(req: any) { calls++; onCall?.(); const id = `https://${req.hostHeader}${req.requestTarget}`; return response(id, headers); }, get calls() { return calls; } };
  }
  function setup(opts: { c?: any; clock?: any; t?: any } = {}) {
    const c = opts.c ?? config();
    const clock = opts.clock ?? new Clock();
    const store = new MemoryStore();
    const audit = new MemoryAudit();
    const t = opts.t ?? echoTransport();
    const bridge = new Bridge({ config: c, store, clock, audit, cimdTransport: t, cimdResolver: resolver() });
    return { c, clock, store, audit, t, bridge };
  }
  const authorize = (b: any) => b.handleAuthorize(request(), { subject: "user-1" });

  test("direct-mode prepare serves a fresh cache hit with no second fetch", async () => {
    const s = setup();
    assert.equal((await authorize(s.bridge)).status, 200);
    assert.equal((await authorize(s.bridge)).status, 200);
    assert.equal(s.t.calls, 1);
  });

  test("Cache-Control directive and header names are ASCII case-insensitive", async () => {
    const t = echoTransport({ "content-type": ["application/json"], "Cache-Control": ["MaX-aGe=120"], "AGE": ["0"] });
    const s = setup({ t });
    await authorize(s.bridge); await authorize(s.bridge);
    assert.equal(t.calls, 1);
  });

  test("freshness subtracts Age and fetch-elapsed from min(max-age, cap): min(100,80)−10−5 = 65s", async () => {
    const clock = new Clock();
    const t = echoTransport({ "content-type": ["application/json"], "cache-control": ["max-age=100"], age: ["10"] }, () => clock.advance(5));
    const s = setup({ c: config({ cacheTtlCapSeconds: 80 }), clock, t });
    assert.equal((await authorize(s.bridge)).status, 200);
    assert.equal(t.calls, 1);
    clock.advance(64); // still within t1+65s
    await authorize(s.bridge);
    assert.equal(t.calls, 1, "still fresh before t1+65s");
    clock.advance(2);
    await authorize(s.bridge);
    assert.equal(t.calls, 2, "expired after the effective lifetime");
  });

  test("max-age below 60 is non-cacheable, never clamped upward", async () => {
    const t = echoTransport({ "content-type": ["application/json"], "cache-control": ["max-age=59"] });
    const s = setup({ t });
    await authorize(s.bridge); await authorize(s.bridge);
    assert.equal(t.calls, 2);
  });

  test("no-store/no-cache/absent/duplicate/quoted Cache-Control or max-age are non-cacheable", async () => {
    const cases = [
      { "content-type": ["application/json"] }, // absent
      { "content-type": ["application/json"], "cache-control": ["no-store, max-age=3600"] },
      { "content-type": ["application/json"], "cache-control": ["no-cache, max-age=3600"] },
      { "content-type": ["application/json"], "cache-control": ["max-age=3600", "max-age=3600"] }, // duplicate occurrence
      { "content-type": ["application/json"], "cache-control": ["max-age=3600, max-age=3600"] }, // conflicting/duplicate directive
      { "content-type": ["application/json"], "cache-control": ["max-age=\"3600\""] }, // quoted
    ];
    for (const headers of cases) {
      const t = echoTransport(headers);
      const s = setup({ t });
      await authorize(s.bridge); await authorize(s.bridge);
      assert.equal(t.calls, 2, JSON.stringify(headers));
    }
  });

  test("Age is cacheable only when absent or exactly one unsigned decimal safe integer; non-positive lifetime does not cache", async () => {
    const bad: Array<string[]> = [["-1"], [" 1"], ["1, 2"], ["1", "2"], [String(Number.MAX_SAFE_INTEGER + 1)], ["120"]]; // last: Age>=max-age ⇒ ttl<=0
    for (const age of bad) {
      const headers: any = { "content-type": ["application/json"], "cache-control": ["max-age=120"], age };
      const t = echoTransport(headers);
      const s = setup({ t });
      await authorize(s.bridge); await authorize(s.bridge);
      assert.equal(t.calls, 2, `Age=${JSON.stringify(age)}`);
    }
    const noAge = echoTransport({ "content-type": ["application/json"], "cache-control": ["max-age=120"] });
    const ok = setup({ t: noAge });
    await authorize(ok.bridge); await authorize(ok.bridge);
    assert.equal(noAge.calls, 1, "absent Age means zero");
  });

  test("negative or non-finite fetch-elapsed makes an otherwise-cacheable response non-cacheable", async () => {
    for (const anomaly of ["negative", "nan"] as const) {
      let armed = false;
      const clock = { ms: START, nowMs() { if (armed) { armed = false; return anomaly === "negative" ? this.ms - 1000 : NaN; } return this.ms; } };
      const t = echoTransport(undefined, () => { armed = true; });
      const s = setup({ clock, t });
      await authorize(s.bridge); await authorize(s.bridge);
      assert.equal(t.calls, 2, anomaly);
    }
  });

  test("error and invalid-document outcomes are never cached; later valid successes are", async () => {
    let calls = 0;
    const t = { async connectAndGet() { calls++; if (calls === 1) throw new Error("first failure"); return response(ID); } };
    const s = setup({ t });
    assert.equal((await authorize(s.bridge)).status, 401, "the failure is generic");
    assert.equal((await authorize(s.bridge)).status, 200, "a later success");
    assert.equal((await authorize(s.bridge)).status, 200, "served from cache");
    assert.equal(calls, 2, "failure was not cached; the success was");

    let invalidCalls = 0;
    const invalid = { async connectAndGet() { invalidCalls++; return { ...response(ID), encodedBody: one(enc(bodyFor("https://other.example/meta"))) }; } };
    const bad = setup({ t: invalid });
    await authorize(bad.bridge); await authorize(bad.bridge);
    assert.equal(invalidCalls, 2, "invalid (client_id-mismatch) documents are never cached");
  });

  test("cache keys are RAW client_id strings, not parsed URL serializations (`:443` ≠ default)", async () => {
    const raw = ["https://cdn.example.com:443/client", "https://cdn.example.com/client"];
    let calls = 0;
    const t = { async connectAndGet() { const id = raw[calls++]!; return response(id); } };
    const s = setup({ t });
    assert.equal((await s.bridge.handleAuthorize(request(raw[0]!), { subject: "user-1" })).status, 200);
    assert.equal((await s.bridge.handleAuthorize(request(raw[1]!), { subject: "user-1" })).status, 200);
    assert.equal(calls, 2, "the two raw keys are distinct cache entries");
  });

  test("default bounded LRU evicts the least-recently-used entry at 256", async () => {
    const t = echoTransport();
    const s = setup({ t });
    for (let i = 0; i < 256; i++) assert.equal((await s.bridge.handleAuthorize(request(`https://cdn.example.com/c/${i}`), { subject: "user-1" })).status, 200);
    assert.equal(t.calls, 256);
    await s.bridge.handleAuthorize(request("https://cdn.example.com/c/0"), { subject: "user-1" }); // refresh id 0 ⇒ id 1 is now LRU
    assert.equal(t.calls, 256, "id 0 served from cache");
    await s.bridge.handleAuthorize(request("https://cdn.example.com/c/256"), { subject: "user-1" }); // inserts ⇒ evicts LRU (id 1)
    assert.equal(t.calls, 257);
    await s.bridge.handleAuthorize(request("https://cdn.example.com/c/1"), { subject: "user-1" }); // id 1 was evicted ⇒ re-fetch
    assert.equal(t.calls, 258, "least-recently-used entry (id 1) was evicted");
  });

  test("single-flight coalesces CONCURRENT same-raw-id requests; the global maxInFlight cap overloads a DISTINCT id", async () => {
    let calls = 0; let release: (() => void) | undefined;
    const t = { connectAndGet(req: any) { calls++; return new Promise<any>((resolve) => { const id = `https://${req.hostHeader}${req.requestTarget}`; release = () => resolve(response(id)); }); } };
    const s = setup({ c: config({ maxInFlight: 1 }), t });
    const a = s.bridge.handleAuthorize(request("https://cdn.example.com/a"), { subject: "user-1" });
    const b = s.bridge.handleAuthorize(request("https://cdn.example.com/a"), { subject: "user-1" });
    await new Promise<void>((r) => setImmediate(r));
    assert.equal(calls, 1, "same raw id ⇒ one in-flight fetch");
    const overloaded = await s.bridge.handleAuthorize(request("https://cdn.example.com/b"), { subject: "user-1" });
    assert.deepEqual(overloaded.body, GENERIC, "overloaded maps to the decision-2 generic");
    assert.equal(overloaded.status, 401);
    assert.ok(s.audit.events.some((e: any) => e.event === "oauth.cimd.fetch" && e.status === "failure" && e.reason === "overloaded"), "audited reason overloaded (decision 6)");
    release?.();
    assert.equal((await a).status, 200); assert.equal((await b).status, 200);
    assert.equal(calls, 1, "the follower coalesced onto the single in-flight fetch");
  });

  // ---- redirect mode uses the SAME success cache ----
  function makeFlow(t: any) {
    const store = new MemoryStore();
    const clock = new Clock();
    const audit = new MemoryAudit();
    const bridge = new Bridge({ config: config(), store, clock, audit, cimdTransport: t, cimdResolver: resolver() });
    const identity = { redirectUri: "https://auth.test/oauth/callback", buildAuthorizationUrl({ state }: any) { return `https://idp.test/a?state=${state}`; }, async exchangeAndVerify() { return { ok: true, identity: { subject: "up@test" } }; } };
    const flow = createUpstreamRedirectFlow({ bridge, identity, store, clock, audit, cimdTransport: t, cimdResolver: resolver() });
    return { flow, bridge };
  }

  test("redirect-mode: two sequential upstream authorizes for one CIMD id ⇒ one fetch (shared success cache)", async () => {
    const t = echoTransport();
    const { flow } = makeFlow(t);
    assert.equal((await flow.handleAuthorize(request())).status, 302);
    assert.equal((await flow.handleAuthorize(request())).status, 302);
    assert.equal(t.calls, 1);
  });

  // NET-NEW (VERDICT §4/§5): TRUE cross-mode shared cache on ONE Bridge instance —
  // resolve the CIMD id via the upstream-redirect authorize, then via the SAME
  // bridge's direct-mode prepare ⇒ the transport is called EXACTLY ONCE (decision
  // 4: "the SAME cache serves both modes").
  test("the SAME cache serves both modes: one Bridge — redirect authorize then direct prepare for one id ⇒ exactly ONE fetch", async () => {
    const t = echoTransport();
    const { flow, bridge } = makeFlow(t);
    const redirectRes = await flow.handleAuthorize(request()); // populates the cache (fetch #1)
    assert.equal(redirectRes.status, 302);
    assert.equal(t.calls, 1);
    const directRes = await bridge.handleAuthorize(request(), { subject: "user-1" }); // must hit the same cache
    assert.equal(directRes.status, 200, "direct prepare rendered consent from the shared cache");
    assert.equal(t.calls, 1, "the direct-mode prepare served the SAME cache entry — no second fetch");
  });

  test("the SAME cache serves both modes (reverse): one Bridge — direct prepare then redirect authorize ⇒ exactly ONE fetch", async () => {
    const t = echoTransport();
    const { flow, bridge } = makeFlow(t);
    const directRes = await bridge.handleAuthorize(request(), { subject: "user-1" }); // fetch #1
    assert.equal(directRes.status, 200);
    assert.equal(t.calls, 1);
    const redirectRes = await flow.handleAuthorize(request()); // must hit the same cache
    assert.equal(redirectRes.status, 302);
    assert.equal(t.calls, 1, "the redirect authorize served the SAME cache entry — no second fetch");
  });
}
