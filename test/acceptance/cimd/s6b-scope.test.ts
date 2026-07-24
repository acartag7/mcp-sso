// FROZEN acceptance suite — S6b scope provenance (docs/contracts.md §17.1.6
// decision 3 + §9.3; verification T1.S6b row S6b.6). CIMD accumulation is
// DEFERRED: for EVERY scheme-shaped (`https://`) id, in BOTH DCR modes,
// `priorScopes` is [] and scopes are minted from the current request only (still
// ceiling-bounded). Accumulation stays a stored-DCR opaque-client feature. The
// accumulation gate is the NEGATIVE class (accumulate iff stored && NOT
// scheme-shaped), observed only via its OUTCOME (minted token scopes +
// findGrantedScopes not consulted for a CIMD id), NEVER via UI copy. The
// approve-time scheme/claim gate is KEPT and decoupled from accumulation.
// FAITHFULNESS: the observable is the minted access-token `scope` + the
// grant-store read count; no consent-page wording (`(new)`/`already granted`) is
// frozen. `grantReads >= 1` (not a pinned minimum) for the opaque control.
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
  const { pkceChallenge, signConsentToken } = (await import(CRYPTO)) as any;
  const jose = (await import("jose")) as any;

  const NOW = Date.parse("2026-07-03T12:00:00.000Z");
  const SUBJECT = "agent@test";
  const CIMD_ID = "https://cdn.example.com/client";
  const CIMD_REDIRECT = "https://app.example.com/cb";
  const OPAQUE_ID = "opaque-stored-client";
  const FUTURE_ISO = "2026-07-03T13:00:00.000Z";
  const VERIFIER = "correct-horse-battery-staple-0123456789abcdef0123";
  const PUBLIC = { address: "93.184.216.34", family: 4 };
  const enc = (s: string) => new TextEncoder().encode(s);
  async function* one(u8: Uint8Array) { yield u8; }
  const cimdDoc = () => ({ client_id: CIMD_ID, client_name: "Example App", redirect_uris: [CIMD_REDIRECT] });
  const okResult = () => ({ status: 200, redirected: false, finalUrl: CIMD_ID, headersDistinct: { "content-type": ["application/json"] }, encodedBody: one(enc(JSON.stringify(cimdDoc()))) });
  function transport() { let calls = 0; return { connectAndGet() { calls++; return Promise.resolve(okResult()); }, get calls() { return calls; } }; }
  const resolver = () => ({ resolve() { return Promise.resolve([PUBLIC]); }, cancel() {} });

  class FakeClock { ms: number; constructor(ms: number) { this.ms = ms; } nowMs() { return this.ms; } }
  class MemoryAudit { async writeAuthEvent() {} }
  class ClientStore { m = new Map<string, any>(); async save(c: any) { this.m.set(c.clientId, c); } async find(id: string) { return this.m.get(id) ?? null; } }
  function jwk(): any { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" }; }
  function config(mode: "stateless" | "stored", clients?: any, cimd: boolean = true): any {
    return createBridgeConfig({
      issuer: "https://auth.test", resource: "https://api.test/mcp",
      consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k",
      redirectAllowlist: [CIMD_REDIRECT], scopeCatalog: ["mcp:read", "mcp:write", "mcp:admin"], defaultScopes: ["mcp:read"],
      allowedOrigins: ["https://auth.test"],
      dcr: mode === "stored" ? { mode: "stored", store: clients } : { mode: "stateless" },
      ...(cimd ? { cimd: { enabled: true } } : {}),
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    });
  }
  const reqQ = (query: any) => ({ query, body: undefined, headers: {}, ip: "1.2.3.4" });
  const reqB = (body: any, headers: any = {}) => ({ query: {}, body, headers, ip: "1.2.3.4" });
  const authQ = (clientId: string, scope = "mcp:read mcp:write") => ({ response_type: "code", client_id: clientId, redirect_uri: CIMD_REDIRECT, code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", scope, state: "s" });
  function consentOf(html: string): string { const m = /name="consent_token" value="([^"]+)"/.exec(html); assert.ok(m?.[1], "consent token not found"); return m[1]!; }
  function scopeSet(accessToken: string): string[] { const s = jose.decodeJwt(accessToken).scope; return typeof s === "string" && s ? s.split(/\s+/).filter(Boolean).sort() : []; }

  const seedGrant = (store: any, clientId: string, scopes: string[]): Promise<void> =>
    store.saveRefreshToken({ tokenHash: "a".repeat(64), familyId: "legacy-" + clientId, previousTokenHash: null, clientId, subject: SUBJECT, scopes, expiresAt: FUTURE_ISO });

  async function approveAndExchange(b: any, page: any, clientId: string): Promise<string[]> {
    const approve = await b.handleApprove(reqB({ consent_token: consentOf(String(page.body)), approved: "true" }, { origin: "https://auth.test" }));
    assert.equal(approve.status, 302, "approved");
    const code = new URL(approve.headers.location as string).searchParams.get("code");
    const token = await b.handleToken(reqB({ grant_type: "authorization_code", code, redirect_uri: CIMD_REDIRECT, client_id: clientId, code_verifier: VERIFIER }));
    assert.equal(token.status, 200, "token minted");
    return scopeSet((token.body as any).access_token);
  }

  // ---- CIMD accumulation DEFERRED (both modes): legacy broader grant never unioned ----
  for (const mode of ["stateless", "stored"] as const) {
    test(`CIMD ${mode}: a seeded broader legacy URL-keyed refresh grant is NEVER read or unioned; mints only the requested (ceiling-bounded) scope`, async () => {
      const clients = new ClientStore();
      const c = config(mode, clients);
      const store = new MemoryStore();
      await seedGrant(store, CIMD_ID, ["mcp:admin"]); // a BROADER prior grant keyed by the URL
      let grantReads = 0;
      const original = store.findGrantedScopes.bind(store);
      store.findGrantedScopes = async (...args: any[]) => { grantReads++; return original(...args); };
      const t = transport();
      const b = new Bridge({ config: c, store, clock: new FakeClock(NOW), audit: new MemoryAudit(), cimdTransport: t, cimdResolver: resolver() });
      const page = await b.handleAuthorize(reqQ(authQ(CIMD_ID)), { subject: SUBJECT, allowedScopes: ["mcp:read"] }); // ceiling = mcp:read
      assert.equal(page.status, 200);
      const scopes = await approveAndExchange(b, page, CIMD_ID);
      assert.deepEqual(scopes, ["mcp:read"], "current request intersected with ceiling; legacy mcp:admin never resurrected");
      assert.equal(grantReads, 0, "findGrantedScopes never consulted for a scheme-shaped id (negative-class gate)");
    });
  }

  test("CONTROL: an opaque stored-DCR client STILL accumulates the seeded prior grant", async () => {
    const clients = new ClientStore();
    await clients.save({ clientId: OPAQUE_ID, redirectUris: [CIMD_REDIRECT], applicationType: "web" });
    const c = config("stored", clients);
    const store = new MemoryStore();
    await seedGrant(store, OPAQUE_ID, ["mcp:admin"]);
    let grantReads = 0;
    const original = store.findGrantedScopes.bind(store);
    store.findGrantedScopes = async (...args: any[]) => { grantReads++; return original(...args); };
    const b = new Bridge({ config: c, store, clock: new FakeClock(NOW), audit: new MemoryAudit(), cimdTransport: transport(), cimdResolver: resolver() });
    const page = await b.handleAuthorize(reqQ(authQ(OPAQUE_ID, "mcp:read")), { subject: SUBJECT });
    assert.equal(page.status, 200);
    const scopes = await approveAndExchange(b, page, OPAQUE_ID);
    assert.deepEqual(scopes, ["mcp:admin", "mcp:read"], "opaque stored client accumulates the prior grant");
    assert.ok(grantReads >= 1, "findGrantedScopes IS consulted for the opaque id");
  });

  // ---- approve-time scheme/claim gate (KEPT; decoupled from accumulation) ----
  async function signedConsent(c: any, clientId: string, cimdVerified?: true): Promise<string> {
    return signConsentToken({ clientId, redirectUri: CIMD_REDIRECT, resource: c.resource, scopes: ["mcp:read"], codeChallenge: pkceChallenge(VERIFIER), codeChallengeMethod: "S256", state: "s", subject: SUBJECT, ...(cimdVerified ? { cimdVerified: true } : {}) }, c, { nowMs: () => NOW });
  }
  function trackingStore() {
    const store = new MemoryStore();
    let consumes = 0; let saves = 0;
    const c = store.consumeConsentJti.bind(store); const s = store.saveAuthCode.bind(store);
    store.consumeConsentJti = async (...a: any[]) => { consumes++; return c(...a); };
    store.saveAuthCode = async (...a: any[]) => { saves++; return s(...a); };
    return { store, get consumes() { return consumes; }, get saves() { return saves; } };
  }

  test("approve gate: a lowercase-https id + cimd enabled + cimd_verified===true is approvable (code minted)", async () => {
    const c = config("stateless");
    const tracked = trackingStore();
    const b = new Bridge({ config: c, store: tracked.store, clock: new FakeClock(NOW), audit: new MemoryAudit(), cimdTransport: transport(), cimdResolver: resolver() });
    const res = await b.handleApprove(reqB({ consent_token: await signedConsent(c, CIMD_ID, true), approved: "true" }, { origin: "https://auth.test" }));
    assert.equal(res.status, 302, "approvable ⇒ 302 with code");
    assert.ok(new URL(res.headers.location as string).searchParams.get("code"));
  });

  test("approve gate runs AFTER token verification but BEFORE Deny, jti consume, and code storage (direct invalid_consent, no state change)", async () => {
    const c = config("stateless");
    const cases: Array<{ clientId: string; verified?: true }> = [
      { clientId: CIMD_ID }, // lowercase-https WITHOUT cimd_verified
      { clientId: "HTTPS://cdn.example.com/client", verified: true }, // other scheme-shaped
      { clientId: "http://cdn.example.com/client", verified: true },
      { clientId: "ftp://cdn.example.com/client", verified: true },
      { clientId: "web+foo://cdn.example.com/client", verified: true }, // full scheme-shape, not just http/https/ftp (mirror of the dispatch classifier)
      { clientId: "x-y.z://cdn.example.com/client", verified: true },
      { clientId: OPAQUE_ID, verified: true }, // cimd_verified on a non-CIMD id
      { clientId: "https://legacy.example/client" }, // legacy URL-shaped stateless token cannot be redeemed at all
    ];
    for (const item of cases) {
      const tracked = trackingStore();
      const b = new Bridge({ config: c, store: tracked.store, clock: new FakeClock(NOW), audit: new MemoryAudit(), cimdTransport: transport(), cimdResolver: resolver() });
      // approved:"false" would normally 302-Deny to the token's redirectUri — the gate must beat that.
      const res = await b.handleApprove(reqB({ consent_token: await signedConsent(c, item.clientId, item.verified), approved: "false" }, { origin: "https://auth.test" }));
      assert.equal(res.status, 400, `${item.clientId}: direct 400`);
      assert.equal((res.body as any).error, "invalid_consent", `${item.clientId}: invalid_consent`);
      assert.equal(res.headers?.location, undefined, `${item.clientId}: gate beats the Deny redirect (no state change)`);
      assert.equal(tracked.consumes, 0, `${item.clientId}: jti not consumed`);
      assert.equal(tracked.saves, 0, `${item.clientId}: no auth code stored`);
    }
  });

  test("approve gate: a lowercase-https consent token is invalid when CIMD is DISABLED, even with cimd_verified present", async () => {
    const c = config("stateless", undefined, false); // cimd disabled
    const tracked = trackingStore();
    const b = new Bridge({ config: c, store: tracked.store, clock: new FakeClock(NOW), audit: new MemoryAudit() });
    const res = await b.handleApprove(reqB({ consent_token: await signedConsent(c, CIMD_ID, true), approved: "true" }, { origin: "https://auth.test" }));
    assert.equal(res.status, 400);
    assert.equal((res.body as any).error, "invalid_consent");
    assert.equal(tracked.consumes, 0);
    assert.equal(tracked.saves, 0);
  });

  test("approve gate (control): an opaque id with no cimd claim is approvable", async () => {
    const clients = new ClientStore();
    await clients.save({ clientId: OPAQUE_ID, redirectUris: [CIMD_REDIRECT], applicationType: "web" });
    const c = config("stored", clients);
    const b = new Bridge({ config: c, store: new MemoryStore(), clock: new FakeClock(NOW), audit: new MemoryAudit(), cimdTransport: transport(), cimdResolver: resolver() });
    const res = await b.handleApprove(reqB({ consent_token: await signedConsent(c, OPAQUE_ID), approved: "true" }, { origin: "https://auth.test" }));
    assert.equal(res.status, 302);
    assert.ok(new URL(res.headers.location as string).searchParams.get("code"));
  });
}
