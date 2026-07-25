// FROZEN acceptance suite — S6b waiter cap (docs/contracts.md §17.1.6 decision 7,
// amending §17.1.5 rule 24). `maxInFlight` bounds concurrent OUTBOUND fetches; it
// does NOT bound how many inbound callers may park on ONE of them. Decision 7 adds
// `cimd.maxWaitersPerFetch` (integer [1, 4096], default 256): an over-cap FOLLOWER
// for the same raw client_id rejects with the EXISTING `overloaded` reason and the
// decision-2 generic `invalid_client`, so total concurrent waiting resolutions are
// bounded by maxInFlight × (maxWaitersPerFetch + 1) — the +1 being the leader,
// which the cap never rejects.
//
// The two properties must hold TOGETHER: rule 24's no-slot rule is unchanged (a
// follower still consumes no FETCH slot, so one popular id cannot starve distinct
// ids out of maxInFlight), and decision 7 bounds the separate waiter quantity.
//
// FAITHFULNESS: observed ONLY through the public handlers — response status/body,
// fetch counts via the cimdTransport seam, and the `oauth.cimd.fetch` audit. No
// internal registry, counter, or cache handle is inspected. Every await that
// depends on the impl's concurrency behavior is deadline-bounded so a queuing or
// hanging implementation fails FAST instead of stalling `node --test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";

const phases = JSON.parse(readFileSync(new URL("../phases.json", import.meta.url), "utf8"));

if (phases["s6b-waiter-cap"] !== true) {
  test("s6b-waiter-cap inactive — activate via test/acceptance/phases.json", { skip: true }, () => {});
} else {
  const CFG = "../../../src/config.ts";
  const { createBridgeConfig, AuthConfigError } = (await import(CFG)) as any;
  const BRIDGE = "../../../src/adapters/bridge.ts";
  const { Bridge } = (await import(BRIDGE)) as any;
  const STORE = "../../../src/store/memory.ts";
  const { MemoryStore } = (await import(STORE)) as any;
  const CRYPTO = "../../../src/crypto.ts";
  const { pkceChallenge } = (await import(CRYPTO)) as any;

  const START = Date.parse("2026-07-03T12:00:00.000Z");
  const ID = "https://cdn.example.com/client";
  const REDIRECT = "https://app.example.com/cb";
  const PUBLIC = { address: "93.184.216.34", family: 4 };
  const GENERIC = { error: "invalid_client", error_description: "client_id could not be resolved" };
  const VERIFIER = "correct-horse-battery-staple-0123456789abcdef0123";
  const enc = (s: string) => new TextEncoder().encode(s);
  async function* one(u8: Uint8Array) { yield u8; }

  class Clock { ms = START; nowMs() { return this.ms; } }
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
  const response = (id: string) => ({ status: 200, redirected: false, finalUrl: id, headersDistinct: { "content-type": ["application/json"], "cache-control": ["max-age=3600"] }, encodedBody: one(enc(bodyFor(id))) });

  // A transport that never settles until released — every caller for that id parks.
  function heldTransport() {
    let calls = 0; const releases: Array<() => void> = [];
    return {
      async connectAndGet(req: any) {
        calls++;
        const id = `https://${req.hostHeader}${req.requestTarget}`;
        return new Promise<any>((resolve) => { releases.push(() => resolve(response(id))); });
      },
      get calls() { return calls; },
      releaseAll() { for (const r of releases) r(); },
    };
  }
  function setup(opts: { c?: any; t?: any } = {}) {
    const c = opts.c ?? config();
    const clock = new Clock();
    const store = new MemoryStore();
    const audit = new MemoryAudit();
    const t = opts.t ?? heldTransport();
    const bridge = new Bridge({ config: c, store, clock, audit, cimdTransport: t, cimdResolver: resolver() });
    return { bridge, audit, t, clock };
  }
  const withDeadline = (p: any, ms = 3000): Promise<any> => {
    let tm: any;
    const d = new Promise((_, rej) => { tm = setTimeout(() => rej(new Error(`test deadline ${ms}ms exceeded — waiter cap not enforced (request parked instead of rejecting)`)), ms); });
    return Promise.race([p, d]).finally(() => clearTimeout(tm));
  };
  const settle = async (turns = 50) => { for (let i = 0; i < turns; i++) await new Promise<void>((r) => setImmediate(r)); };
  const overloadedEvents = (a: MemoryAudit) => a.events.filter((e: any) => e.event === "oauth.cimd.fetch" && e.status === "failure" && e.reason === "overloaded");

  // ---- the cap itself ----

  test("an over-cap FOLLOWER for the same raw client_id rejects `overloaded`; the leader and in-cap followers are unaffected", async () => {
    const t = heldTransport();
    const s = setup({ c: config({ maxWaitersPerFetch: 2 }), t });
    const leader = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    assert.equal(t.calls, 1, "leader started the single in-flight fetch");
    const f1 = s.bridge.handleAuthorize(request(), { subject: "u" }); // waiter 1 — in cap
    const f2 = s.bridge.handleAuthorize(request(), { subject: "u" }); // waiter 2 — in cap
    await settle();
    // Waiter 3 is over the cap: it must REJECT NOW, not park until the fetch settles.
    const over = await withDeadline(s.bridge.handleAuthorize(request(), { subject: "u" })) as any;
    assert.equal(over.status, 401, "over-cap follower rejects");
    assert.deepEqual(over.body, GENERIC, "…as the decision-2 generic — byte-identical to every other CIMD failure");
    assert.equal(t.calls, 1, "rejecting a follower starts NO new fetch");
    t.releaseAll();
    assert.equal((await withDeadline(leader)).status, 200, "the LEADER is never rejected by the cap");
    assert.equal((await withDeadline(f1)).status, 200, "in-cap follower 1 still succeeds");
    assert.equal((await withDeadline(f2)).status, 200, "in-cap follower 2 still succeeds");
    assert.equal(t.calls, 1, "all four callers coalesced onto ONE fetch");
  });

  test("the over-cap rejection is audited `oauth.cimd.fetch` failure reason `overloaded` (decision 6 reason reused — no new reason)", async () => {
    const t = heldTransport();
    const s = setup({ c: config({ maxWaitersPerFetch: 1 }), t });
    const leader = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    const inCap = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    const before = overloadedEvents(s.audit).length;
    await withDeadline(s.bridge.handleAuthorize(request(), { subject: "u" }));
    const after = overloadedEvents(s.audit);
    assert.equal(after.length, before + 1, "exactly one new overloaded failure event");
    assert.equal(after[after.length - 1].clientId, ID, "audited against the presented client_id");
    // No SUCCESS event for a rejected request — a success-then-reject trail misreports.
    t.releaseAll();
    await withDeadline(leader); await withDeadline(inCap);
  });

  test("the waiter cap does NOT consume a fetch slot: a DISTINCT id still resolves while another id is at its waiter cap (rule 24 preserved)", async () => {
    const t = heldTransport();
    // maxInFlight 2 ⇒ room for a second DISTINCT id; id A is saturated with waiters.
    const s = setup({ c: config({ maxInFlight: 2, maxWaitersPerFetch: 1 }), t });
    const a1 = s.bridge.handleAuthorize(request("https://cdn.example.com/a"), { subject: "u" });
    await settle();
    const a2 = s.bridge.handleAuthorize(request("https://cdn.example.com/a"), { subject: "u" });
    await settle();
    const aOver = await withDeadline(s.bridge.handleAuthorize(request("https://cdn.example.com/a"), { subject: "u" })) as any;
    assert.equal(aOver.status, 401, "id A is at its waiter cap");
    // A DISTINCT id must still get its own fetch — waiters never consumed A's slot,
    // so one popular client_id cannot starve other clients out of maxInFlight.
    const b1 = s.bridge.handleAuthorize(request("https://cdn.example.com/b"), { subject: "u" });
    await settle();
    assert.equal(t.calls, 2, "the distinct id started its OWN fetch — the waiter cap did not consume a fetch slot");
    t.releaseAll();
    assert.equal((await withDeadline(a1)).status, 200);
    assert.equal((await withDeadline(a2)).status, 200);
    assert.equal((await withDeadline(b1)).status, 200);
  });

  test("waiter slots are RELEASED when the fetch settles: a later burst on the same id is served again", async () => {
    const t = heldTransport();
    const s = setup({ c: config({ maxWaitersPerFetch: 1, cacheTtlCapSeconds: 60 }), t });
    const leader = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    const inCap = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    assert.equal((await withDeadline(s.bridge.handleAuthorize(request(), { subject: "u" })) as any).status, 401, "at cap");
    t.releaseAll();
    await withDeadline(leader); await withDeadline(inCap);
    // The entry settled; a fresh request must NOT inherit a stale waiter count.
    // (It is served from cache here — the point is that it is not rejected.)
    const later = await withDeadline(s.bridge.handleAuthorize(request(), { subject: "u" })) as any;
    assert.equal(later.status, 200, "waiter accounting was released on settle, not leaked");
  });

  test("a FAILING fetch also releases waiter slots (no leak on the error path)", async () => {
    let calls = 0; const releases: Array<() => void> = [];
    const t = {
      async connectAndGet() {
        calls++;
        return new Promise<any>((_res, rej) => { releases.push(() => rej(new Error("upstream down"))); });
      },
      get calls() { return calls; },
    };
    const s = setup({ c: config({ maxWaitersPerFetch: 1 }), t });
    const leader = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    const inCap = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    assert.equal((await withDeadline(s.bridge.handleAuthorize(request(), { subject: "u" })) as any).status, 401, "at cap");
    for (const r of releases) r();
    assert.equal((await withDeadline(leader) as any).status, 401, "the failed fetch maps to the generic");
    assert.equal((await withDeadline(inCap) as any).status, 401);
    // Slots must be free again even though the fetch REJECTED.
    const after = await withDeadline(s.bridge.handleAuthorize(request(), { subject: "u" })) as any;
    assert.equal(after.status, 401, "still fails (upstream down) — but as a resolution failure");
    assert.deepEqual(after.body, GENERIC);
    assert.ok(calls >= 2, "a new fetch was attempted — the entry was not left permanently saturated");
  });

  // ---- boot validation (rule 21 domain, same fail-closed treatment as the other caps) ----

  for (const bad of [0, -1, 4097, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "256", null, true]) {
    test(`cimd.maxWaitersPerFetch ${JSON.stringify(bad)} is an AuthConfigError at boot (fail closed, never coerced)`, () => {
      assert.throws(() => config({ maxWaitersPerFetch: bad as any }), (e: any) => e instanceof AuthConfigError, `${JSON.stringify(bad)} must be rejected`);
    });
  }

  for (const good of [1, 256, 4096]) {
    test(`cimd.maxWaitersPerFetch ${good} boots (domain bound [1, 4096])`, () => {
      assert.ok(config({ maxWaitersPerFetch: good }), `${good} must be accepted`);
    });
  }

  test("maxWaitersPerFetch is absent-by-default and the default admits a burst far above any single-waiter reading", async () => {
    const t = heldTransport();
    const s = setup({ t }); // no maxWaitersPerFetch ⇒ default 256
    const leader = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    // 32 concurrent followers is far below the default; NONE may be rejected.
    const followers = Array.from({ length: 32 }, () => s.bridge.handleAuthorize(request(), { subject: "u" }));
    await settle();
    assert.equal(overloadedEvents(s.audit).length, 0, "the DEFAULT cap must not reject an ordinary burst (it is a ceiling, not a throttle)");
    t.releaseAll();
    assert.equal((await withDeadline(leader)).status, 200);
    for (const f of followers) assert.equal((await withDeadline(f)).status, 200);
    assert.equal(t.calls, 1, "all 33 callers coalesced onto ONE fetch");
  });
}
