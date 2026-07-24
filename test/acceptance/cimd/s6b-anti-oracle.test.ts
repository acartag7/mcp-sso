// FROZEN acceptance suite — S6b anti-oracle mapping (docs/contracts.md §17.1.6
// decision 2 + 6; verification T1.S6b rows S6b.3 + S6b.9). Every CimdError (incl.
// decision-6 `overloaded` and an UNKNOWN/future reason via the mapper's
// fail-closed default) AND any unexpected throw in the CIMD resolution path
// collapse to ONE client-facing outcome: invalid_client 401, body exactly
// {"error":"invalid_client","error_description":"client_id could not be resolved"},
// never internal_error 500 (mapped inside BOTH named resolution boundaries — the
// upstream authorize resolve AND direct prepare). A non-CimdError throw audits the
// fixed allowlisted reason `fetch_failed`. The cimd:<ip> rate-limit denial sits
// OUTSIDE this map (pre-resolution 429). FAITHFULNESS: failures are pinned only on
// status(401)+body(GENERIC)+not-a-redirect; response HEADERS are NOT frozen across
// cases (only that no secret leaks); timing is NOT asserted (contract: not
// equalized); the unknown-reason default does NOT force reason==="fetch_failed".
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
  const CIMD_ERRORS = "../../../src/cimd/errors.ts";
  const { CimdError } = (await import(CIMD_ERRORS)) as any;

  const NOW = Date.parse("2026-07-03T12:00:00.000Z");
  const CIMD_ID = "https://cdn.example.com/client";
  const CIMD_REDIRECT = "https://app.example.com/cb";
  const VERIFIER = "correct-horse-battery-staple-0123456789abcdef0123";
  const PUBLIC = { address: "93.184.216.34", family: 4 };
  const GENERIC = { error: "invalid_client", error_description: "client_id could not be resolved" };
  const enc = (s: string) => new TextEncoder().encode(s);
  async function* one(u8: Uint8Array) { yield u8; }
  const cimdDoc = (over: any = {}) => ({ client_id: CIMD_ID, client_name: "Example App", redirect_uris: [CIMD_REDIRECT], ...over });
  const okResult = (o: any = {}) => ({
    status: o.status ?? 200, redirected: o.redirected ?? false, finalUrl: o.finalUrl ?? CIMD_ID,
    headersDistinct: o.headersDistinct ?? { "content-type": ["application/json"] },
    encodedBody: o.body ?? one(enc(JSON.stringify(o.doc ?? cimdDoc()))),
  });
  function transport(factory: any, opts: any = {}) { let calls = 0; return { connectAndGet() { calls++; if (opts.never) return new Promise(() => {}); if (opts.throw) return Promise.reject(new Error("TRANSPORT_BOOM_SECRET")); return Promise.resolve(typeof factory === "function" ? factory() : factory); }, get calls() { return calls; } }; }
  function resolver(answer: any = [PUBLIC]) { let calls = 0; return { resolve() { calls++; return Promise.resolve(answer); }, cancel() {}, get calls() { return calls; } }; }

  class FakeClock { ms: number; constructor(ms: number) { this.ms = ms; } nowMs() { return this.ms; } }
  class MemoryAudit { events: any[] = []; async writeAuthEvent(e: any) { this.events.push(e); } }
  function jwk(): any { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" }; }
  function cfg(cimd: any = { enabled: true }): any {
    return createBridgeConfig({
      issuer: "https://auth.test", resource: "https://api.test/mcp",
      consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k",
      redirectAllowlist: ["https://client.test/cb"], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
      allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" }, cimd,
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    });
  }
  function makeBridge(opts: any = {}) {
    const audit = new MemoryAudit();
    const store = new MemoryStore();
    const clock = new FakeClock(NOW);
    const b = new Bridge({ config: cfg(opts.cimd), store, clock, audit, cimdTransport: opts.cimdTransport, cimdResolver: opts.cimdResolver, rateLimit: opts.rateLimit });
    return { b, store, clock, audit };
  }
  function stubIdentity() {
    let hops = 0;
    return { redirectUri: "https://auth.test/oauth/callback", buildAuthorizationUrl() { hops++; return "https://idp.test/authorize"; }, async exchangeAndVerify() { return { ok: true, identity: { subject: "up@test" } }; }, get hops() { return hops; } };
  }
  const req = (query: any, ip = "203.0.113.7") => ({ query, body: undefined, headers: {}, ip });
  const authQ = (over: any = {}) => ({ response_type: "code", client_id: CIMD_ID, redirect_uri: CIMD_REDIRECT, code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", scope: "mcp:read", ...over });
  const fetchFail = (audit: any) => audit.events.filter((e: any) => e.event === "oauth.cimd.fetch" && e.status === "failure");
  const fetchOk = (audit: any) => audit.events.filter((e: any) => e.event === "oauth.cimd.fetch" && e.status === "success");
  // Decision 2: every CIMD resolution FAILURE must collapse to ONE client-visible
  // response — status + headers + code + description — or a header/status differential
  // is a residual SSRF oracle. Capture the canonical failure from the impl's OWN output
  // (not a hardcoded header map, which would freeze incidental headers) so every failure
  // must be byte-identical to it, across BOTH resolution boundaries (direct + upstream).
  const CANONICAL = await (async () => {
    const { b } = makeBridge({ cimd: { enabled: true }, cimdTransport: transport(() => okResult()), cimdResolver: resolver([{ address: "10.0.0.1", family: 4 }]) });
    const res = await b.handleAuthorize(req(authQ()), { subject: "agent@test" });
    return { status: res.status, headers: res.headers, body: res.body };
  })();
  function assertGeneric(res: any) {
    assert.equal(res.status, 401);
    assert.deepEqual(res.body, GENERIC);
    assert.equal(res.redirect, undefined);
    assert.equal(res.headers?.location, undefined);
    // byte-identical to the canonical failure (status + headers + body) — closes the header oracle
    assert.deepEqual({ status: res.status, headers: res.headers, body: res.body }, CANONICAL);
  }
  // A never-settling transport relies on the impl's fetch-timeout to abort; if that
  // regresses (the very failure the slow-endpoint rows target) the await would hang, and
  // node --test has NO per-test timeout — so bound every failure-matrix call with an
  // explicit test-side deadline (> fetchTimeoutMs) that fails fast instead of hanging CI.
  const withDeadline = (p: any, ms = 5000): Promise<any> => {
    let timer: any;
    const deadline = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error(`test deadline ${ms}ms exceeded — fetch-timeout missing/regressed`)), ms); });
    return Promise.race([p, deadline]).finally(() => clearTimeout(timer));
  };

  // Each failure MUST produce the identical client-facing outcome (401 + GENERIC,
  // never a 500 internal_error) and audit a failure to oauth.cimd.fetch.
  const cases: Array<{ name: string; t?: any; r?: any; clientId?: string; cimd?: any }> = [
    { name: "ip_blocked (resolved private addr)", r: () => resolver([{ address: "10.0.0.1", family: 4 }]) },
    { name: "multi-record rebinding (one blocked)", r: () => resolver([PUBLIC, { address: "10.0.0.1", family: 4 }]) },
    { name: "dns zero-record", r: () => resolver([]) },
    { name: "redirect refused", t: () => transport(() => okResult({ redirected: true })) },
    { name: "status !== 200", t: () => transport(() => okResult({ status: 404 })) },
    { name: "wrong content-type", t: () => transport(() => okResult({ headersDistinct: { "content-type": ["text/html"] } })) },
    { name: "present content-encoding", t: () => transport(() => okResult({ headersDistinct: { "content-type": ["application/json"], "content-encoding": ["gzip"] } })) },
    { name: "document client_id mismatch", t: () => transport(() => okResult({ doc: { client_id: "https://evil.example/x", client_name: "x", redirect_uris: [CIMD_REDIRECT] } })) },
    { name: "private-key material in jwks", t: () => transport(() => okResult({ doc: cimdDoc({ jwks: { keys: [{ kty: "oct", k: "c2VjcmV0" }] } }) })) },
    { name: "client_secret document", t: () => transport(() => okResult({ doc: cimdDoc({ client_secret: "SHHH" }) })) },
    { name: "encoded dot-segment admission", clientId: "https://cdn.example.com/a/%2e%2e/b" },
    { name: "IP-literal admission", clientId: "https://127.0.0.1/client" },
    { name: "non-CimdError transport throw", t: () => transport(null, { throw: true }) },
    { name: "over-cap body", t: () => transport(() => okResult({ body: one(enc("x".repeat(4000))) })), cimd: { enabled: true, maxDocumentBytes: 1024 } },
  ];

  for (const c of cases) {
    test(`anti-oracle: ${c.name} ⇒ identical invalid_client 401 (never 500)`, async () => {
      const t = c.t ? c.t() : transport(() => okResult());
      const r = c.r ? c.r() : resolver();
      const { b, audit } = makeBridge({ cimd: c.cimd ?? { enabled: true }, cimdTransport: t, cimdResolver: r });
      const res = await withDeadline(b.handleAuthorize(req(authQ({ client_id: c.clientId ?? CIMD_ID })), { subject: "agent@test" }));
      assertGeneric(res);
      assert.ok(fetchFail(audit).length >= 1, `${c.name}: audited to oauth.cimd.fetch (failure)`);
      assert.equal(fetchOk(audit).length, 0, `${c.name}: no success event for a failure`);
    });
  }

  // Broader SSRF/document negative table (IP-literal tricks, IPv6 ULA, mixed
  // rebinding, redirect-to-blocked, over-cap, slow, private JWK / client_secret) —
  // ALL collapse to the identical client-visible generic, and no document secret
  // leaks. (Header maps are NOT frozen — only status+body+no-redirect + no-leak.)
  test("full SSRF/document negative table collapses to the identical generic and leaks no secret", async () => {
    const POISON = "DOCUMENT_SECRET_POISON";
    const ssrf: Array<{ name: string; t?: any; r?: any; clientId?: string; cimd?: any }> = [
      { name: "encoded dot segment", clientId: "https://cdn.example.com/a/%2E%2e/meta" },
      { name: "IP-literal dword", clientId: "https://2130706433/meta" },
      { name: "IP-literal octal", clientId: "https://0177.0.0.1/meta" },
      { name: "IP-literal hex", clientId: "https://0x7f000001/meta" },
      { name: "blocked IPv4 DNS", r: () => resolver([{ address: "169.254.169.254", family: 4 }]) },
      { name: "blocked IPv6 ULA DNS", r: () => resolver([{ address: "fd00::1", family: 6 }]) },
      { name: "mixed rebinding answer", r: () => resolver([PUBLIC, { address: "127.0.0.1", family: 4 }]) },
      { name: "redirect FOLLOWED to a blocked host (redirected===true, not just a bare 302)", t: () => transport(() => okResult({ redirected: true, finalUrl: "https://127.0.0.1/private" })) },
      { name: "over-cap body", cimd: { enabled: true, maxDocumentBytes: 1024 }, t: () => transport(() => okResult({ body: one(enc("x".repeat(2048))) })) },
      { name: "slow endpoint (timeout)", cimd: { enabled: true, fetchTimeoutMs: 1000 }, t: () => transport(null, { never: true }) },
      { name: "mismatched client_id", t: () => transport(() => okResult({ doc: { client_id: "https://other.example/meta", client_name: "x", redirect_uris: [CIMD_REDIRECT] } })) },
      { name: "client_secret document", t: () => transport(() => okResult({ doc: cimdDoc({ client_secret: POISON }) })) },
      { name: "private JWK document", t: () => transport(() => okResult({ doc: cimdDoc({ jwks: { keys: [{ kty: "EC", d: POISON }] } }) })) },
    ];
    for (const c of ssrf) {
      const t = c.t ? c.t() : transport(() => okResult());
      const r = c.r ? c.r() : resolver();
      const { b, audit } = makeBridge({ cimd: c.cimd ?? { enabled: true }, cimdTransport: t, cimdResolver: r });
      const res = await withDeadline(b.handleAuthorize(req(authQ({ client_id: c.clientId ?? CIMD_ID })), { subject: "agent@test" }));
      assertGeneric(res);
      assert.equal(JSON.stringify(res).includes(POISON), false, `${c.name}: document secret must not leak`);
      assert.ok(fetchFail(audit).length >= 1, `${c.name}: failure audited`);
    }
  });

  // NET-NEW (VERDICT §4/§5, corrects C3): an UNKNOWN/future CimdError reason takes
  // the mapper's fail-closed default ⇒ the IDENTICAL generic client body. The
  // audit is a FAILURE event whose reason is NOT free-form exception text; the
  // reason string is deliberately NOT pinned (must not force `fetch_failed`).
  test("unknown/future CimdError reason ⇒ mapper fail-closed default: identical generic client body; failure audit without exception text", async () => {
    const t = transport(() => { throw new CimdError("future_reason", "UNKNOWN_REASON_MESSAGE_SECRET"); });
    const { b, audit } = makeBridge({ cimdTransport: t, cimdResolver: resolver() });
    const res = await b.handleAuthorize(req(authQ()), { subject: "agent@test" });
    assertGeneric(res); // the fail-closed CLIENT map is identical to every other CimdError
    assert.ok(fetchFail(audit).length >= 1, "a failure event is audited");
    assert.equal(fetchOk(audit).length, 0, "not a success");
    assert.equal(JSON.stringify(audit.events).includes("UNKNOWN_REASON_MESSAGE_SECRET"), false, "the CimdError message (free-form) is not audited");
  });

  // The non-CimdError throw maps to the same generic AND a FIXED allowlisted reason
  // `fetch_failed` (contract-pinned for the non-CimdError branch), never the
  // exception text.
  test("a non-CimdError throw audits the fixed reason `fetch_failed`, never the exception text", async () => {
    const { b, audit } = makeBridge({ cimdTransport: transport(null, { throw: true }), cimdResolver: resolver() });
    const res = await b.handleAuthorize(req(authQ()), { subject: "agent@test" });
    assertGeneric(res);
    assert.ok(fetchFail(audit).some((e: any) => e.reason === "fetch_failed"), "reason fetch_failed");
    assert.ok(!JSON.stringify(audit.events).includes("TRANSPORT_BOOM_SECRET"), "exception text never leaks into audit");
  });

  // Decision 2: the map covers BOTH named resolution boundaries. A CimdError at the
  // UPSTREAM authorize resolve must be mapped inside resolution and NEVER escape to
  // the upstream catch as internal_error 500, and no IdP hop occurs.
  // Decision 2 boundary (1): the FULL failure matrix must ALSO collapse at the UPSTREAM
  // authorize resolve (flow.handleAuthorize) — byte-identical to the direct CANONICAL,
  // never escaping the flow's own catch as internal_error 500, never hopping to the IdP.
  const upstreamCases: Array<{ name: string; t?: any; r?: any; cimd?: any }> = [
    { name: "ip_blocked", r: () => resolver([{ address: "10.0.0.1", family: 4 }]) },
    { name: "status !== 200", t: () => transport(() => okResult({ status: 404 })) },
    { name: "wrong content-type", t: () => transport(() => okResult({ headersDistinct: { "content-type": ["text/html"] } })) },
    { name: "document client_id mismatch", t: () => transport(() => okResult({ doc: { client_id: "https://evil.example/x", client_name: "x", redirect_uris: [CIMD_REDIRECT] } })) },
    { name: "non-CimdError throw", t: () => transport(null, { throw: true }) },
    { name: "over-cap body", cimd: { enabled: true, maxDocumentBytes: 1024 }, t: () => transport(() => okResult({ body: one(enc("x".repeat(4000))) })) },
    { name: "slow endpoint (timeout)", cimd: { enabled: true, fetchTimeoutMs: 1000 }, t: () => transport(null, { never: true }) },
  ];
  for (const c of upstreamCases) {
    test(`anti-oracle (upstream boundary): ${c.name} ⇒ identical generic 401, never 500, no IdP hop`, async () => {
      const t = c.t ? c.t() : transport(() => okResult());
      const r = c.r ? c.r() : resolver();
      const { b, store, clock, audit } = makeBridge({ cimd: c.cimd ?? { enabled: true }, cimdTransport: t, cimdResolver: r });
      const identity = stubIdentity();
      const flow = createUpstreamRedirectFlow({ bridge: b, identity, store, clock, audit, cimdTransport: t, cimdResolver: r });
      const res = await withDeadline(flow.handleAuthorize(req(authQ())));
      assertGeneric(res); // byte-identical to the direct CANONICAL — parity across BOTH named boundaries
      assert.equal(identity.hops, 0, `${c.name}: no IdP hop on a resolution failure`);
      assert.ok(fetchFail(audit).length >= 1, `${c.name}: audited to oauth.cimd.fetch (failure)`);
    });
  }

  // The cimd:<ip> RateLimitPort denial is OUTSIDE the anti-oracle map: a
  // pre-resolution DIRECT 429 temporarily_unavailable, at BOTH direct + upstream,
  // keyed cimd:<ip> (alongside the existing upstream:<ip> guard on the flow path).
  test("rate-limit: a cimd:<ip> denial is a pre-resolution 429 temporarily_unavailable (direct), no fetch", async () => {
    const t = transport(() => okResult());
    const seen: string[] = [];
    const rateLimit = { async check(key: string) { seen.push(key); return !key.startsWith("cimd:"); } };
    const { b, audit } = makeBridge({ cimdTransport: t, cimdResolver: resolver(), rateLimit });
    const res = await b.handleAuthorize(req(authQ()), { subject: "agent@test" });
    assert.equal(res.status, 429);
    assert.equal((res.body as any).error, "temporarily_unavailable");
    assert.notDeepEqual(res.body, GENERIC);
    assert.ok(seen.includes("cimd:203.0.113.7"), "rate-limit keyed cimd:<ip>");
    assert.equal(t.calls, 0, "denied before any resolution/fetch");
    assert.equal(audit.events.some((e: any) => e.event === "oauth.cimd.fetch"), false, "no fetch audit for a pre-resolution denial");
  });

  test("rate-limit (upstream): the cimd:<ip> denial is a pre-resolution 429, alongside the existing upstream:<ip> guard", async () => {
    const t = transport(() => okResult());
    const seen: string[] = [];
    const rateLimit = { async check(key: string) { seen.push(key); return !key.startsWith("cimd:"); } };
    const { b, store, clock, audit } = makeBridge({ cimdTransport: t, cimdResolver: resolver(), rateLimit });
    const identity = stubIdentity();
    const flow = createUpstreamRedirectFlow({ bridge: b, identity, store, clock, audit, rateLimit, cimdTransport: t, cimdResolver: resolver() });
    const res = await flow.handleAuthorize(req(authQ()));
    assert.equal(res.status, 429);
    assert.equal((res.body as any).error, "temporarily_unavailable");
    assert.ok(seen.includes("cimd:203.0.113.7"));
    assert.ok(seen.includes("upstream:203.0.113.7"));
    assert.equal(identity.hops, 0);
    assert.equal(t.calls, 0);
    assert.equal(audit.events.some((e: any) => e.event === "oauth.cimd.fetch"), false, "no fetch audit for a pre-resolution denial (sibling parity with the direct case)");
  });
}
