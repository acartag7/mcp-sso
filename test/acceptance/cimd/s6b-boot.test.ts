// FROZEN acceptance suite — S6b boot/config (docs/contracts.md §17.1.6 decisions
// 5 & 6, §5 cimd block, §17.1.5 rule 21; verification T1.S6b row S6b.1).
// Black-box through createBridgeConfig + the public Bridge constructor (the boot
// seam). Decision 5: there is NO deployer whole-fetcher knob and `allowLoopback`
// is NOT a cimd field — loopback effectiveness derives SOLELY from
// dev.allowInsecureLocalhost; the core constructs its own guarded fetcher and only
// the below-guard cimdTransport/cimdResolver seams inject. FAITHFULNESS: a bad
// `cimd.fetcher`/`cimd.allowLoopback`/out-of-domain cap is required to be a boot
// AuthConfigError (fail-closed) — there is no "silently ignore" accept path.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";

const phases = JSON.parse(readFileSync(new URL("../phases.json", import.meta.url), "utf8"));

if (phases["s6b-cimd-flow"] !== true) {
  test("s6b-cimd-flow inactive — activate via test/acceptance/phases.json", { skip: true }, () => {});
} else {
  const CFG = "../../../src/config.ts";
  const { createBridgeConfig, AuthConfigError } = (await import(CFG)) as any;
  const BRIDGE = "../../../src/adapters/bridge.ts";
  const { Bridge } = (await import(BRIDGE)) as any;
  const STORE = "../../../src/store/memory.ts";
  const { MemoryStore } = (await import(STORE)) as any;
  const CIMD_ERRORS = "../../../src/cimd/errors.ts";
  const { CimdError } = (await import(CIMD_ERRORS)) as any;

  const NOW = Date.parse("2026-07-03T12:00:00.000Z");
  const enc = (s: string) => new TextEncoder().encode(s);
  async function* one(u8: Uint8Array) { yield u8; }
  class FakeClock { ms: number; constructor(ms: number) { this.ms = ms; } nowMs() { return this.ms; } }
  class MemoryAudit { events: any[] = []; async writeAuthEvent(e: any) { this.events.push(e); } }
  function jwk(): any { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" }; }

  function rawConfig(over: any = {}): any {
    return {
      issuer: "https://auth.test", resource: "https://api.test/mcp",
      consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k",
      redirectAllowlist: ["https://client.test/cb"], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
      allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" },
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
      ...over,
    };
  }
  // Full boot: config validation + Bridge construction (which owns the guarded-
  // fetcher construction — decision 5). A cap/knob problem must surface as an
  // AuthConfigError from SOMEWHERE in this chain, never a raw TypeError leak.
  function boot(cimd: any): void {
    const config = createBridgeConfig(rawConfig({ cimd }));
    new Bridge({ config, store: new MemoryStore(), clock: new FakeClock(NOW), audit: new MemoryAudit() });
  }
  const isAuthConfigError = (e: any) => e instanceof AuthConfigError;

  test("cimd enabled with valid caps boots successfully (control)", () => {
    assert.doesNotThrow(() => boot({ enabled: true }));
    assert.doesNotThrow(() => boot({ enabled: true, maxDocumentBytes: 5120, fetchTimeoutMs: 5000, cacheTtlCapSeconds: 3600, maxInFlight: 8 }));
    assert.doesNotThrow(() => boot({ enabled: true, maxDocumentBytes: 1024, fetchTimeoutMs: 1000, cacheTtlCapSeconds: 60, maxInFlight: 1 }));
    assert.doesNotThrow(() => boot({ enabled: true, maxDocumentBytes: 65536, fetchTimeoutMs: 30000, cacheTtlCapSeconds: 86400, maxInFlight: 64 }));
  });

  test("cimd absent ⇒ CIMD disabled, boots fine (control)", () => {
    assert.doesNotThrow(() => { const c = createBridgeConfig(rawConfig()); new Bridge({ config: c, store: new MemoryStore(), clock: new FakeClock(NOW), audit: new MemoryAudit() }); });
  });

  // Decision 5: there is NO deployer whole-fetcher knob. A `cimd.fetcher` (or any
  // deployer-supplied GuardedFetcher-shaped value) must fail closed at boot — it
  // must NOT become a production injection point (C1: no "reject OR inert" path).
  test("a whole `cimd.fetcher` knob is rejected at boot (decision 5 — no whole-fetcher injection point)", () => {
    assert.throws(() => boot({ enabled: true, fetcher: {} }), isAuthConfigError);
    assert.throws(() => boot({ enabled: true, fetcher: { fetch() {} } }), isAuthConfigError);
    assert.throws(() => boot({ enabled: true, fetcher: { connectAndGet() {} } }), isAuthConfigError);
  });

  // Decision 5: allowLoopback is NOT a cimd field — supplying it on the cimd block
  // fails closed at boot (C2: no accept path even if "non-widening").
  test("`allowLoopback` is not a cimd config field (decision 5 — derives from dev.allowInsecureLocalhost only)", () => {
    assert.throws(() => boot({ enabled: true, allowLoopback: true }), isAuthConfigError);
    assert.throws(() => boot({ enabled: true, allowLoopback: false }), isAuthConfigError);
  });

  // Rule 21 / §5: closed integer domains; out-of-domain / wrong-type / null / NaN
  // ⇒ AuthConfigError at boot (the integerOption TypeError is reconciled to
  // AuthConfigError — never leaked as a raw TypeError).
  test("out-of-domain maxDocumentBytes ⇒ AuthConfigError [1024,65536]", () => {
    for (const v of [0, 1023, 65537, -1, 1.5, NaN, Infinity, "5120", null])
      assert.throws(() => boot({ enabled: true, maxDocumentBytes: v }), isAuthConfigError, `maxDocumentBytes=${String(v)}`);
  });
  test("out-of-domain fetchTimeoutMs ⇒ AuthConfigError [1000,30000]", () => {
    for (const v of [0, 999, 30001, -1, 1.5, NaN, Infinity, "5000", null])
      assert.throws(() => boot({ enabled: true, fetchTimeoutMs: v }), isAuthConfigError, `fetchTimeoutMs=${String(v)}`);
  });
  test("out-of-domain cacheTtlCapSeconds ⇒ AuthConfigError [60,86400]", () => {
    for (const v of [0, 59, 86401, -1, 1.5, NaN, Infinity, "3600", null])
      assert.throws(() => boot({ enabled: true, cacheTtlCapSeconds: v }), isAuthConfigError, `cacheTtlCapSeconds=${String(v)}`);
  });
  test("out-of-domain maxInFlight ⇒ AuthConfigError [1,64]", () => {
    for (const v of [0, 65, -1, 1.5, NaN, Infinity, "8", null])
      assert.throws(() => boot({ enabled: true, maxInFlight: v }), isAuthConfigError, `maxInFlight=${String(v)}`);
  });

  // Decision 5: dev.allowInsecureLocalhost is the SOLE source of loopback
  // effectiveness. With it ON, a loopback-hosted CIMD id resolves and fetches.
  test("dev.allowInsecureLocalhost is the sole loopback source (a loopback CIMD id resolves ONLY under the dev flag)", async () => {
    const LOOP_ID = "https://localhost:8443/meta";
    const REDIRECT = "http://127.0.0.1:5000/cb";
    const config = createBridgeConfig({
      issuer: "http://localhost:3000", resource: "http://localhost:3000/mcp",
      consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k",
      redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
      allowedOrigins: ["http://localhost:3000"], dcr: { mode: "stateless" },
      dev: { allowInsecureLocalhost: true }, cimd: { enabled: true },
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    });
    let calls = 0;
    const transport = { connectAndGet() { calls++; return Promise.resolve({ status: 200, redirected: false, finalUrl: LOOP_ID, headersDistinct: { "content-type": ["application/json"] }, encodedBody: one(enc(JSON.stringify({ client_id: LOOP_ID, client_name: "Local", redirect_uris: [REDIRECT] }))) }); } };
    const resolver = { resolve() { return Promise.resolve([{ address: "127.0.0.1", family: 4 }]); }, cancel() {} };
    const b = new Bridge({ config, store: new MemoryStore(), clock: new FakeClock(NOW), audit: new MemoryAudit(), cimdTransport: transport, cimdResolver: resolver });
    const res = await b.handleAuthorize({ query: { response_type: "code", client_id: LOOP_ID, redirect_uri: REDIRECT, code_challenge: "x".repeat(43), code_challenge_method: "S256", scope: "mcp:read" }, body: undefined, headers: {}, ip: "1.2.3.4" }, { subject: "agent@test" });
    assert.equal(res.status, 200, "loopback CIMD resolves under dev.allowInsecureLocalhost");
    assert.equal(calls, 1, "the below-guard transport seam was used");
  });

  // Decision 6: `overloaded` is a real, stable CimdReason value (rule-24
  // in-flight-cap rejection). Constructible at runtime.
  test("`overloaded` is a constructible stable CimdReason (decision 6)", () => {
    const e = new CimdError("overloaded");
    assert.equal(e.reason, "overloaded");
  });
}
