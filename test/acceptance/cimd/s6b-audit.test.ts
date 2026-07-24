// FROZEN acceptance suite — S6b CIMD audit (docs/contracts.md §17.1.6 decision 2
// "Reasons go to oauth.cimd.fetch (failure) ONLY" + decision 4 success audit;
// verification T1.S6b row S6b.4). The oauth.cimd.fetch event records the SPECIFIC
// stable reason on success and failure WITHOUT leaking the document body or
// secrets, and a non-CimdError throw audits the fixed allowlisted reason
// `fetch_failed` (never the exception text — decision 2). Black-box through
// direct-mode authorize + the cimdTransport/cimdResolver seams. FAITHFULNESS: no
// audit FIELD NAME beyond `event`/`status`/`reason` (the ones the contract pins)
// is frozen; secret-absence is asserted via unique sentinels only, never a
// blocklist of substrings.
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
  const STORE = "../../../src/store/memory.ts";
  const { MemoryStore } = (await import(STORE)) as any;
  const CRYPTO = "../../../src/crypto.ts";
  const { pkceChallenge } = (await import(CRYPTO)) as any;

  const NOW = Date.parse("2026-07-03T12:00:00.000Z");
  const CIMD_ID = "https://cdn.example.com/client";
  const CIMD_REDIRECT = "https://app.example.com/cb";
  const VERIFIER = "correct-horse-battery-staple-0123456789abcdef0123";
  const PUBLIC = { address: "93.184.216.34", family: 4 };
  const BODY_SENTINEL = "BODY_LEAK_SENTINEL_zzz";
  const enc = (s: string) => new TextEncoder().encode(s);
  async function* one(u8: Uint8Array) { yield u8; }
  const cimdDoc = (over: any = {}) => ({ client_id: CIMD_ID, client_name: "Example App", redirect_uris: [CIMD_REDIRECT], ...over });
  const okResult = (o: any = {}) => ({ status: o.status ?? 200, redirected: o.redirected ?? false, finalUrl: CIMD_ID, headersDistinct: o.headersDistinct ?? { "content-type": ["application/json"] }, encodedBody: o.body ?? one(enc(JSON.stringify(o.doc ?? cimdDoc()))) });
  function transport(factory: any, opts: any = {}) { return { connectAndGet() { if (opts.never) return new Promise(() => {}); if (opts.throw) return Promise.reject(new Error("EXC_TEXT_LEAK_SECRET")); return Promise.resolve(typeof factory === "function" ? factory() : factory); } }; }
  function resolver(answer: any = [PUBLIC]) { return { resolve() { return Promise.resolve(answer); }, cancel() {} }; }

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
  const withDeadline = (p: any, ms = 5000): Promise<any> => { let tm: any; const d = new Promise((_, rej) => { tm = setTimeout(() => rej(new Error(`deadline ${ms}ms`)), ms); }); return Promise.race([p, d]).finally(() => clearTimeout(tm)); };
  function drive(t: any, r: any) {
    const audit = new MemoryAudit();
    const b = new Bridge({ config: cfg(), store: new MemoryStore(), clock: new FakeClock(NOW), audit, cimdTransport: t, cimdResolver: r });
    const req = { query: { response_type: "code", client_id: CIMD_ID, redirect_uri: CIMD_REDIRECT, code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", scope: "mcp:read" }, body: undefined, headers: {}, ip: "1.2.3.4" };
    return { run: () => b.handleAuthorize(req, { subject: "agent@test" }), audit };
  }
  const fetchEvents = (audit: any) => audit.events.filter((e: any) => e.event === "oauth.cimd.fetch");

  test("success: a resolved CIMD document emits oauth.cimd.fetch (success) WITHOUT leaking document field values", async () => {
    const DOC_SENTINEL = "SUCCESS_DOC_FIELD_SENTINEL_zzz";
    const { run, audit } = drive(transport(() => okResult({ doc: cimdDoc({ client_name: DOC_SENTINEL }) })), resolver());
    const res = await run();
    assert.equal(res.status, 200);
    assert.ok(fetchEvents(audit).some((e: any) => e.status === "success"), "success event recorded");
    assert.equal(JSON.stringify(audit.events).includes(DOC_SENTINEL), false, "the success event must not carry fetched document field values");
  });

  // Decision 1b: the upstream authorize resolve (flow.handleAuthorize, before the IdP 302)
  // also pins an oauth.cimd.fetch SUCCESS — an impl auditing it in direct prepare but not
  // in the flow would leave Hosted-Claude/Entra CIMD successes unaudited.
  test("upstream success: flow.handleAuthorize resolves the CIMD doc and audits oauth.cimd.fetch success WITHOUT leaking document fields", async () => {
    const FLOW_MOD = "../../../src/adapters/upstream-flow.ts";
    const { createUpstreamRedirectFlow } = (await import(FLOW_MOD)) as any;
    const UP_SENTINEL = "UPSTREAM_SUCCESS_DOC_SENTINEL_zzz";
    const audit = new MemoryAudit();
    const store = new MemoryStore();
    const clock = new FakeClock(NOW);
    const b = new Bridge({ config: cfg(), store, clock, audit, cimdTransport: transport(() => okResult()), cimdResolver: resolver() });
    const identity = { redirectUri: "https://auth.test/oauth/callback", buildAuthorizationUrl({ state }: any) { return `https://idp.test/a?state=${state}`; }, async exchangeAndVerify() { return { ok: true, identity: { subject: "up@test" } }; } };
    const flow = createUpstreamRedirectFlow({ bridge: b, identity, store, clock, audit, cimdTransport: transport(() => okResult({ doc: cimdDoc({ client_name: UP_SENTINEL }) })), cimdResolver: resolver() });
    const res = await flow.handleAuthorize({ query: { response_type: "code", client_id: CIMD_ID, redirect_uri: CIMD_REDIRECT, code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", scope: "mcp:read", state: "s" }, body: undefined, headers: {}, ip: "1.2.3.4" });
    assert.equal(res.status, 302, "resolved + 302 to the IdP");
    assert.ok(fetchEvents(audit).some((e: any) => e.status === "success"), "upstream success event recorded (dec 1b)");
    assert.equal(JSON.stringify(audit.events).includes(UP_SENTINEL), false, "no document field leaks into the upstream success audit");
  });

  test("failure: a blocked resolution emits oauth.cimd.fetch failure with the SPECIFIC reason", async () => {
    const { run, audit } = drive(transport(() => okResult()), resolver([{ address: "10.0.0.1", family: 4 }]));
    await run();
    assert.ok(fetchEvents(audit).some((e: any) => e.status === "failure" && e.reason === "ip_blocked"), "reason ip_blocked");
  });

  test("failure: an invalid document emits reason document_invalid", async () => {
    const { run, audit } = drive(transport(() => okResult({ doc: { client_id: "https://evil.example/x", client_name: "x", redirect_uris: [CIMD_REDIRECT] } })), resolver());
    await run();
    assert.ok(fetchEvents(audit).some((e: any) => e.status === "failure" && e.reason === "document_invalid"));
  });

  test("no body leak: a document field value never appears in any audit event", async () => {
    const { run, audit } = drive(transport(() => okResult({ doc: cimdDoc({ client_secret: BODY_SENTINEL, client_name: BODY_SENTINEL }) })), resolver());
    await run();
    assert.ok(!JSON.stringify(audit.events).includes(BODY_SENTINEL), "no document body/secret in audit");
    assert.ok(fetchEvents(audit).some((e: any) => e.status === "failure"), "still audited as a failure");
  });

  test("no exception-text leak: a non-CimdError throw audits the fixed reason `fetch_failed`, never the thrown message", async () => {
    const { run, audit } = drive(transport(null, { throw: true }), resolver());
    await run();
    assert.ok(!JSON.stringify(audit.events).includes("EXC_TEXT_LEAK_SECRET"), "exception text never in audit");
    assert.ok(fetchEvents(audit).some((e: any) => e.status === "failure" && e.reason === "fetch_failed"), "fixed allowlisted reason fetch_failed");
  });

  // S6b.4 / decision 2: the reason is a STABLE per-failure machine code operators rely on —
  // pin EVERY CimdReason to its specific stimulus, not just "some failure event exists".
  const reasonCases: Array<{ name: string; reason: string; t?: any; r?: any; clientId?: string; cimd?: any }> = [
    { name: "admission (encoded dot-segment)", reason: "url_admission_denied", clientId: "https://cdn.example.com/a/%2e%2e/b" },
    { name: "dns zero-record", reason: "dns_failed", r: () => resolver([]) },
    { name: "ip_blocked", reason: "ip_blocked", r: () => resolver([{ address: "10.0.0.1", family: 4 }]) },
    { name: "redirect refused", reason: "redirect_refused", t: () => transport(() => okResult({ redirected: true })) },
    { name: "status !== 200", reason: "status_not_200", t: () => transport(() => okResult({ status: 404 })) },
    { name: "wrong content-type", reason: "content_type", t: () => transport(() => okResult({ headersDistinct: { "content-type": ["text/html"] } })) },
    { name: "content-encoding present", reason: "encoding", t: () => transport(() => okResult({ headersDistinct: { "content-type": ["application/json"], "content-encoding": ["gzip"] } })) },
    { name: "over-cap body", reason: "size_exceeded", cimd: { enabled: true, maxDocumentBytes: 1024 }, t: () => transport(() => okResult({ body: one(enc("x".repeat(4000))) })) },
    { name: "timeout", reason: "timeout", cimd: { enabled: true, fetchTimeoutMs: 1000 }, t: () => transport(null, { never: true }) },
    { name: "document invalid (client_id mismatch)", reason: "document_invalid", t: () => transport(() => okResult({ doc: { client_id: "https://evil.example/x", client_name: "x", redirect_uris: [CIMD_REDIRECT] } })) },
    { name: "non-CimdError throw", reason: "fetch_failed", t: () => transport(null, { throw: true }) },
  ];
  for (const rc of reasonCases) {
    test(`audit reason matrix: ${rc.name} ⇒ oauth.cimd.fetch failure reason "${rc.reason}"`, async () => {
      const audit = new MemoryAudit();
      const b = new Bridge({ config: cfg(rc.cimd ?? { enabled: true }), store: new MemoryStore(), clock: new FakeClock(NOW), audit, cimdTransport: rc.t ? rc.t() : transport(() => okResult()), cimdResolver: rc.r ? rc.r() : resolver() });
      const req = { query: { response_type: "code", client_id: rc.clientId ?? CIMD_ID, redirect_uri: CIMD_REDIRECT, code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", scope: "mcp:read" }, body: undefined, headers: {}, ip: "1.2.3.4" };
      await withDeadline(b.handleAuthorize(req, { subject: "agent@test" }));
      assert.ok(fetchEvents(audit).some((e: any) => e.status === "failure" && e.reason === rc.reason), `expected oauth.cimd.fetch failure reason "${rc.reason}"`);
    });
  }
}
