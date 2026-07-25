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
  const settle = async (turns = 60) => { for (let i = 0; i < turns; i++) await new Promise<void>((r) => setImmediate(r)); };
  const overloadedEvents = (a: MemoryAudit) => a.events.filter((e: any) => e.event === "oauth.cimd.fetch" && e.status === "failure" && e.reason === "overloaded");
  const successEvents = (a: MemoryAudit) => a.events.filter((e: any) => e.event === "oauth.cimd.fetch" && e.status === "success");
  // An ORDINARY CIMD failure (blocked address) — the byte-for-byte baseline every
  // other failure must equal, so a cap-specific header cannot become an oracle.
  async function canonicalFailure() {
    const t = { async connectAndGet() { throw new Error("unreachable"); } };
    const s = setup({ t });
    return await s.bridge.handleAuthorize(request(), { subject: "u" }) as any;
  }
  function setupFlow(opts: { c?: any; t?: any } = {}) {
    const c = opts.c ?? config();
    const clock = new Clock();
    const store = new MemoryStore();
    const audit = new MemoryAudit();
    const t = opts.t ?? heldTransport();
    const bridge = new Bridge({ config: c, store, clock, audit, cimdTransport: t, cimdResolver: resolver() });
    const identity = { redirectUri: "https://auth.test/oauth/callback", buildAuthorizationUrl({ state }: any) { return `https://idp.test/a?state=${state}`; }, async exchangeAndVerify() { return { ok: true, identity: { subject: "up@test" } }; } };
    const flow = createUpstreamRedirectFlow({ bridge, identity, store, clock, audit, cimdTransport: t, cimdResolver: resolver() });
    return { flow, bridge, audit, t };
  }

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
    const canon = await canonicalFailure();
    assert.equal(over.status, canon.status, "same STATUS as an ordinary CIMD failure");
    assert.deepEqual(over.body, canon.body, "same BODY");
    assert.deepEqual(over.headers, canon.headers, "same HEADERS — a cap-specific header would be a decision-2 oracle");
    assert.deepEqual(over.body, GENERIC, "…and that shared shape is the decision-2 generic");
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
    const okBefore = successEvents(s.audit).length;
    await withDeadline(s.bridge.handleAuthorize(request(), { subject: "u" }));
    const after = overloadedEvents(s.audit);
    assert.equal(after.length, before + 1, "exactly one new overloaded failure event");
    assert.equal(after[after.length - 1].clientId, ID, "audited against the presented client_id");
    // ASSERTED, not merely asserted-in-a-comment: a guard that emitted success
    // before returning the overloaded failure would misreport the outcome.
    assert.equal(successEvents(s.audit).length, okBefore, "the rejected follower emits NO success event");
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
    // The cap is PER in-flight entry, not resolver-global. Id /b has ZERO waiters
    // of its own, so its first follower MUST be admitted even though /a is at its
    // cap. A single global counter rejects here — that would let one client_id
    // deny service to unrelated client_ids (cross-client DoS).
    const okBefore = overloadedEvents(s.audit).length;
    const b2 = s.bridge.handleAuthorize(request("https://cdn.example.com/b"), { subject: "u" });
    await settle();
    assert.equal(overloadedEvents(s.audit).length, okBefore, "/b's FIRST follower is admitted — waiter counts are per client_id, never global");
    assert.equal(t.calls, 2, "and it coalesced onto /b's existing fetch");
    t.releaseAll();
    assert.equal((await withDeadline(a1)).status, 200);
    assert.equal((await withDeadline(a2)).status, 200);
    assert.equal((await withDeadline(b1)).status, 200);
    assert.equal((await withDeadline(b2)).status, 200, "/b's follower resolved normally");
  });

  test("waiter slots are RELEASED when the fetch settles — proven by a REFETCH, not by a cache hit", async () => {
    // NON-cacheable response: a cache hit would mask an implementation that
    // checks the cache before its single-flight registry and therefore leaves
    // the settled entry (and its stale waiter count) allocated forever.
    let calls = 0; const releases: Array<() => void> = [];
    const t = {
      async connectAndGet(req: any) {
        calls++;
        const id = `https://${req.hostHeader}${req.requestTarget}`;
        return new Promise<any>((resolve) => {
          releases.push(() => resolve({ status: 200, redirected: false, finalUrl: id, headersDistinct: { "content-type": ["application/json"], "cache-control": ["no-store"] }, encodedBody: one(enc(bodyFor(id))) }));
        });
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
    assert.equal((await withDeadline(leader)).status, 200);
    assert.equal((await withDeadline(inCap)).status, 200);
    assert.equal(calls, 1, "one fetch served the leader and the in-cap follower");
    // A later request must start a NEW fetch (nothing cached) AND be admitted —
    // proving the settled entry was removed rather than left saturated.
    const later = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    assert.equal(calls, 2, "the settled entry was REMOVED — a fresh fetch started");
    // A fresh LEADER is never rejected by the cap, so leader-only would be a
    // vacuous check. Add a FOLLOWER on this second fetch: with maxWaitersPerFetch
    // 1 it is admissible ONLY if the previous round's waiter count was actually
    // decremented. An impl that increments and never releases rejects here.
    const okBefore = overloadedEvents(s.audit).length;
    const laterFollower = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    assert.equal(overloadedEvents(s.audit).length, okBefore, "the follower is admitted — the prior round's waiter slot was RELEASED, not leaked");
    for (const r of releases) r();
    assert.equal((await withDeadline(later)).status, 200, "the retry leader resolved");
    assert.equal((await withDeadline(laterFollower)).status, 200, "and its follower resolved on the same fetch");
    assert.equal(calls, 2, "still only two fetches — the follower coalesced");
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
    // Slots must be free again even though the fetch REJECTED. Start the retry,
    // WAIT for its own transport call, release THAT promise, and only then await
    // the response — the release loop above already ran, so awaiting first would
    // hang on a promise nothing can settle (a correct impl would still time out).
    const retry = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    assert.equal(calls, 2, "a NEW fetch was attempted — the entry was not left permanently saturated");
    // …and a FOLLOWER on that retry must be admitted: an impl that clears the
    // failed promise but keeps the per-key waiter count would reject here.
    const overBefore = overloadedEvents(s.audit).length;
    const retryFollower = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    assert.equal(overloadedEvents(s.audit).length, overBefore, "the retry's follower is admitted — the failed round's waiter count was released");
    for (const r of releases) r();
    const after = await withDeadline(retry) as any;
    assert.equal((await withDeadline(retryFollower) as any).status, 401, "the follower shares the retry's failure");
    assert.equal(after.status, 401, "still fails (upstream down) — but as a resolution failure");
    assert.deepEqual(after.body, GENERIC);
  });

  test("a TIMED-OUT fetch also releases the entry (rule 24: removed on success, error, OR timeout)", async () => {
    // The transport NEVER settles — the guarded fetcher's own deadline must win.
    // An impl that cleans up on transport rejection but not on its own timeout
    // leaves this client_id saturated forever; later requests park or reject.
    let calls = 0;
    const t = { async connectAndGet() { calls++; return new Promise<any>(() => { /* never settles */ }); }, get calls() { return calls; } };
    const s = setup({ c: config({ maxWaitersPerFetch: 1, fetchTimeoutMs: 1000 }), t });
    const first = await withDeadline(s.bridge.handleAuthorize(request(), { subject: "u" }), 5000) as any;
    assert.equal(first.status, 401, "the deadline fired and mapped to the generic");
    assert.deepEqual(first.body, GENERIC);
    assert.equal(calls, 1);
    // A later request must start a NEW fetch AND admit a follower — proving the
    // timed-out entry was removed, not left holding its waiter accounting.
    const okBefore = overloadedEvents(s.audit).length;
    const retry = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    assert.equal(calls, 2, "the timed-out entry was REMOVED — a fresh fetch started");
    const follower = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    assert.equal(overloadedEvents(s.audit).length, okBefore, "and its follower is admitted — no waiter count survived the timeout");
    assert.equal((await withDeadline(retry, 5000) as any).status, 401, "the retry times out too (transport still dead) — as a resolution failure");
    assert.equal((await withDeadline(follower, 5000) as any).status, 401);
  });

  test("direct and upstream share ONE in-flight entry and ONE waiter budget for the same client_id (decision 4)", async () => {
    // The existing cross-mode rows are SEQUENTIAL (cache hit on the second call).
    // Concurrently, an impl can share the settled-success cache while keeping
    // separate in-flight registries and waiter counters: two leaders and two full
    // follower sets, blowing past maxInFlight × (maxWaitersPerFetch + 1).
    const t = heldTransport();
    const f = setupFlow({ c: config({ maxWaitersPerFetch: 1 }), t });
    const direct = f.bridge.handleAuthorize(request(), { subject: "u" }); // leader, direct mode
    await settle();
    assert.equal(t.calls, 1, "one fetch started");
    const upFollower = f.flow.handleAuthorize(request()); // follower via the OTHER boundary
    await settle();
    assert.equal(t.calls, 1, "the upstream request COALESCED onto the direct leader's fetch — one shared in-flight entry");
    assert.equal(overloadedEvents(f.audit).length, 0, "the first cross-mode follower is within the shared budget");
    // The budget is SHARED: with maxWaitersPerFetch 1 that upstream follower
    // consumed the only slot, so the next follower — from EITHER boundary — must
    // reject. Separate per-boundary counters would admit it.
    const over = await withDeadline(f.bridge.handleAuthorize(request(), { subject: "u" })) as any;
    assert.equal(over.status, 401, "the shared waiter budget is exhausted — separate counters would admit this");
    assert.deepEqual(over.body, GENERIC);
    assert.equal(overloadedEvents(f.audit).length, 1, "exactly one overload");
    assert.equal(t.calls, 1, "and still only ONE fetch across both boundaries");
    t.releaseAll();
    assert.equal((await withDeadline(direct)).status, 200, "the direct leader resolved");
    assert.equal((await withDeadline(upFollower) as any).status, 302, "the upstream follower reached the IdP on the SAME fetch");
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

  test("the ABSENT-option default is exactly 256: follower 256 is admitted, follower 257 rejects", async () => {
    const t = heldTransport();
    const s = setup({ t }); // no maxWaitersPerFetch ⇒ contract default 256
    const leader = s.bridge.handleAuthorize(request(), { subject: "u" });
    await settle();
    assert.equal(t.calls, 1, "leader owns the single in-flight fetch");
    // 256 FOLLOWERS — the last one admitted. Any default below 256 rejects here.
    const followers = Array.from({ length: 256 }, () => s.bridge.handleAuthorize(request(), { subject: "u" }));
    await settle(200);
    assert.equal(overloadedEvents(s.audit).length, 0, "256 followers are within the default — none rejected");
    // Follower 257 is over the cap. Any default ABOVE 256 admits it and fails here.
    const over = await withDeadline(s.bridge.handleAuthorize(request(), { subject: "u" })) as any;
    assert.equal(over.status, 401, "follower 257 rejects — the default is not larger than 256");
    assert.deepEqual(over.body, GENERIC);
    assert.equal(overloadedEvents(s.audit).length, 1, "exactly one overloaded event");
    t.releaseAll();
    assert.equal((await withDeadline(leader)).status, 200);
    for (const f of followers) assert.equal((await withDeadline(f)).status, 200, "every in-cap follower still succeeds");
    assert.equal(t.calls, 1, "all 257 admitted callers coalesced onto ONE fetch");
  });

  // ---- the OTHER resolution boundary (§17.1.6 decision 1a/1b) ----

  test("upstream-redirect authorize enforces the SAME cap: an over-cap follower rejects DIRECTLY, with no IdP hop", async () => {
    const t = heldTransport();
    const f = setupFlow({ c: config({ maxWaitersPerFetch: 1 }), t });
    const leader = f.flow.handleAuthorize(request());
    await settle();
    assert.equal(t.calls, 1, "leader started the fetch at the pre-identity boundary");
    const inCap = f.flow.handleAuthorize(request());
    await settle();
    const okBefore = successEvents(f.audit).length;
    const overBefore = overloadedEvents(f.audit).length;
    assert.equal(overBefore, 0, "no overload was audited for the leader or the in-cap follower");
    const over = await withDeadline(f.flow.handleAuthorize(request())) as any;
    // Same guard as the direct boundary: an impl that emits success and THEN the
    // overloaded failure for one operation misreports the outcome.
    assert.equal(successEvents(f.audit).length, okBefore, "the rejected upstream follower emits NO success event");
    // Decision 1b: resolution completes BEFORE any Set-Cookie / IdP 302, so an
    // over-cap rejection is a DIRECT error — never a redirect to the IdP and
    // never a flow cookie. An impl that caps only `prepare` fails here.
    // Byte-identical to an ORDINARY upstream CIMD failure — headers included, so
    // an upstream-only mapper cannot add e.g. `retry-after` and expose the cap.
    const canonUp = await (setupFlow({ t: { async connectAndGet() { throw new Error("unreachable"); } } })).flow.handleAuthorize(request()) as any;
    assert.equal(over.status, canonUp.status, "same STATUS as an ordinary upstream CIMD failure");
    assert.deepEqual(over.body, canonUp.body, "same BODY");
    assert.deepEqual(over.headers, canonUp.headers, "same HEADERS — no cap-specific header may leak the decision-7 condition");
    assert.equal(over.status, 401, "direct 401, not a 302");
    assert.deepEqual(over.body, GENERIC, "…and that shared shape is the decision-2 generic");
    assert.equal(over.headers?.["set-cookie"], undefined, "no flow cookie is minted for a rejected resolution");
    assert.equal(over.headers?.location, undefined, "NO IdP hop — the user is never redirected on a rejected resolution");
    assert.equal(overloadedEvents(f.audit).length, overBefore + 1, "exactly ONE new overloaded event — for the REJECTED request, not the admitted follower");
    assert.equal(t.calls, 1, "the rejection started no new fetch");
    t.releaseAll();
    assert.equal((await withDeadline(leader) as any).status, 302, "the leader still reaches the IdP");
    assert.equal((await withDeadline(inCap) as any).status, 302, "and so does the in-cap follower");
  });
}
