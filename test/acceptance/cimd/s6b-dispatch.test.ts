// FROZEN acceptance suite — S6b three-way shape-first dispatch (docs/contracts.md
// §17.1.6 decision 1a + §17.1.5 rule 22; verification T1.S6b row S6b.10). Asserted
// at BOTH the direct-mode `prepare` (bridge.handleAuthorize) and the upstream-
// redirect `handleAuthorize`. Black-box through the public handlers + the below-
// guard cimdTransport/cimdResolver seams (decision 1e / rule 14). FAITHFULNESS:
// dispatch outcomes are asserted as OAuth code + not-a-302 + fetch-count + (for a
// CIMD id in stored mode) that the §10 store.find miss does NOT fire — never a
// specific HTTP status where the contract says only "direct invalid_client", and
// never the consent HTML shape (only that a consent token was produced).
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
  const jose = (await import("jose")) as any;

  const NOW = Date.parse("2026-07-03T12:00:00.000Z");
  const CIMD_ID = "https://cdn.example.com/client";
  const CIMD_REDIRECT = "https://app.example.com/cb";
  const OPAQUE_REDIRECT = "https://client.test/cb";
  const VERIFIER = "correct-horse-battery-staple-0123456789abcdef0123";
  const PUBLIC = { address: "93.184.216.34", family: 4 };
  const enc = (s: string) => new TextEncoder().encode(s);
  async function* one(u8: Uint8Array) { yield u8; }
  const cimdDoc = (over: any = {}) => ({ client_id: CIMD_ID, client_name: "Example App", redirect_uris: [CIMD_REDIRECT], ...over });
  const okResult = (o: any = {}) => ({
    status: o.status ?? 200, redirected: o.redirected ?? false, finalUrl: o.finalUrl ?? CIMD_ID,
    headersDistinct: o.headersDistinct ?? { "content-type": ["application/json"] },
    encodedBody: o.body ?? one(enc(JSON.stringify(o.doc ?? cimdDoc()))),
  });
  function transport(factory: any) {
    let calls = 0; let last: any = null;
    return { connectAndGet(req: any) { calls++; last = req; return Promise.resolve(typeof factory === "function" ? factory(req) : factory); }, get calls() { return calls; }, get last() { return last; } };
  }
  function resolver(answer: any = [PUBLIC]) { let calls = 0; return { resolve() { calls++; return Promise.resolve(answer); }, cancel() {}, get calls() { return calls; } }; }

  class FakeClock { ms: number; constructor(ms: number) { this.ms = ms; } nowMs() { return this.ms; } }
  class MemoryAudit { events: any[] = []; async writeAuthEvent(e: any) { this.events.push(e); } }
  // A ClientStore that COUNTS find() calls, to prove the CIMD path replaces the
  // §10 stored-DCR "Unknown client_id" lookup for a scheme-shaped id.
  class CountingClientStore { m = new Map<string, any>(); finds = 0; async save(c: any) { this.m.set(c.clientId, c); } async find(id: string) { this.finds++; return this.m.get(id) ?? null; } }
  function jwk(): any { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" }; }
  function cfg(over: any = {}): any {
    return createBridgeConfig({
      issuer: "https://auth.test", resource: "https://api.test/mcp",
      consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: jwk(), signingKeyId: "k",
      redirectAllowlist: [OPAQUE_REDIRECT], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
      allowedOrigins: ["https://auth.test"], dcr: over.dcr ?? { mode: "stateless" },
      cimd: over.cimd, accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    });
  }
  function makeBridge(opts: any = {}) {
    const store = opts.store ?? new MemoryStore();
    const config = opts.config ?? cfg({ cimd: "cimd" in opts ? opts.cimd : { enabled: true }, dcr: opts.dcr });
    const b = new Bridge({ config, store, clock: new FakeClock(NOW), audit: new MemoryAudit(), cimdTransport: opts.cimdTransport, cimdResolver: opts.cimdResolver });
    return { b, store };
  }
  function stubIdentity() {
    return {
      redirectUri: "https://auth.test/oauth/callback",
      buildAuthorizationUrl({ state }: any) { return `https://idp.test/authorize?state=${state}`; },
      async exchangeAndVerify() { return { ok: true, identity: { subject: "up@test" } }; },
    };
  }
  function makeFlow(opts: any = {}) {
    const store = opts.store ?? new MemoryStore();
    const clock = new FakeClock(NOW);
    const audit = new MemoryAudit();
    const config = cfg({ cimd: "cimd" in opts ? opts.cimd : { enabled: true }, dcr: opts.dcr });
    const b = new Bridge({ config, store, clock, audit, cimdTransport: opts.cimdTransport, cimdResolver: opts.cimdResolver });
    const flow = createUpstreamRedirectFlow({ bridge: b, identity: stubIdentity(), store, clock, audit, cimdTransport: opts.cimdTransport, cimdResolver: opts.cimdResolver });
    return { flow, b, store };
  }
  const req = (query: any, headers: any = {}, ip = "1.2.3.4") => ({ query, body: undefined, headers, ip });
  const directAuthQ = (over: any = {}) => ({ response_type: "code", client_id: CIMD_ID, redirect_uri: CIMD_REDIRECT, code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", scope: "mcp:read", ...over });
  const bodyErr = (res: any) => (res.body && typeof res.body === "object" ? res.body.error : undefined);
  const hasConsentToken = (res: any) => /name="consent_token" value="[^"]+"/.test(String(res.body));

  // ---------------- DIRECT MODE (prepare) ----------------

  test("direct (1): lowercase https id + cimd enabled ⇒ CIMD path taken (fetch + consent token minted)", async () => {
    const t = transport(() => okResult());
    const { b } = makeBridge({ cimdTransport: t, cimdResolver: resolver() });
    const res = await b.handleAuthorize(req(directAuthQ()), { subject: "agent@test" });
    assert.equal(res.status, 200, "CIMD path resolves + renders consent");
    assert.equal(t.calls, 1, "the CIMD document was fetched");
    assert.ok(hasConsentToken(res), "a consent token was produced");
  });

  test("direct (2): any other scheme-shaped id ⇒ direct invalid_client, no fetch, no fallthrough", async () => {
    for (const id of ["HTTPS://cdn.example.com/client", "http://cdn.example.com/client", "ftp://cdn.example.com/client", "HttP://cdn.example.com/client", "web+foo://cdn.example.com/client", "x-y.z://cdn.example.com/client"]) {
      const t = transport(() => okResult());
      const { b } = makeBridge({ cimdTransport: t, cimdResolver: resolver() });
      // redirect_uri is globally ALLOWLISTED: a §10 stateless fallthrough would return 200/302,
      // so a rejection here can only come from the scheme-shape gate (no false pass).
      const res = await b.handleAuthorize(req(directAuthQ({ client_id: id, redirect_uri: OPAQUE_REDIRECT })), { subject: "agent@test" });
      assert.notEqual(res.status, 302, `${id}: not a redirect/fallthrough`);
      assert.notEqual(res.status, 200, `${id}: not a success channel either`);
      assert.equal(bodyErr(res), "invalid_client", `${id}: direct invalid_client`);
      assert.equal(t.calls, 0, `${id}: never fetched`);
    }
  });

  test("direct (2b): lowercase https id while cimd DISABLED ⇒ direct invalid_client, never a stateless-DCR client", async () => {
    const t = transport(() => okResult());
    const { b } = makeBridge({ cimd: undefined, cimdTransport: t, cimdResolver: resolver() });
    // allowlisted redirect ⇒ a stateless §10 fallthrough would SUCCEED; only the gate can reject
    const res = await b.handleAuthorize(req(directAuthQ({ redirect_uri: OPAQUE_REDIRECT })), { subject: "agent@test" });
    assert.notEqual(res.status, 302);
    assert.notEqual(res.status, 200);
    assert.equal(bodyErr(res), "invalid_client");
    assert.equal(t.calls, 0);
  });

  test("direct (3): opaque non-scheme id ⇒ unchanged §10 path, never fetches", async () => {
    const t = transport(() => okResult());
    const { b } = makeBridge({ cimdTransport: t, cimdResolver: resolver() });
    const res = await b.handleAuthorize(req(directAuthQ({ client_id: "opaque-client-123", redirect_uri: OPAQUE_REDIRECT })), { subject: "agent@test" });
    assert.equal(res.status, 200, "normal opaque authorize renders consent");
    assert.equal(t.calls, 0, "opaque id never enters CIMD admission");
  });

  test("direct: a CIMD id in STORED mode does NOT fire the §10 store.find miss (CIMD REPLACES §10)", async () => {
    const t = transport(() => okResult());
    const clientStore = new CountingClientStore(); // CIMD id is NOT registered here
    const { b } = makeBridge({ dcr: { mode: "stored", store: clientStore }, cimdTransport: t, cimdResolver: resolver() });
    const res = await b.handleAuthorize(req(directAuthQ()), { subject: "agent@test" });
    assert.equal(res.status, 200, "CIMD resolves without a stored registration");
    assert.equal(t.calls, 1, "the CIMD document was fetched instead of a store lookup rejecting");
    assert.equal(clientStore.finds, 0, "the CIMD path MUST NOT call store.find (no 'Unknown client_id' miss)");
  });

  test("direct (control): an opaque id in STORED mode DOES consult store.find (§10 path unchanged)", async () => {
    const t = transport(() => okResult());
    const clientStore = new CountingClientStore();
    const { b } = makeBridge({ dcr: { mode: "stored", store: clientStore }, cimdTransport: t, cimdResolver: resolver() });
    await b.handleAuthorize(req(directAuthQ({ client_id: "opaque-unregistered", redirect_uri: OPAQUE_REDIRECT })), { subject: "agent@test" });
    assert.ok(clientStore.finds >= 1, "the §10 path consulted the client store for the opaque id");
  });

  test("direct (stored-mode): a REGISTERED scheme-shaped client_id is STILL direct invalid_client — rejected by shape BEFORE store.find", async () => {
    for (const id of ["ftp://cdn.example.com/client", "web+foo://cdn.example.com/client", "HTTPS://cdn.example.com/client", "http://cdn.example.com/client", "HttP://cdn.example.com/client", "x-y.z://cdn.example.com/client"]) {
      const t = transport(() => okResult());
      const clientStore = new CountingClientStore();
      await clientStore.save({ clientId: id, redirectUris: [OPAQUE_REDIRECT], applicationType: "web" }); // registered — but shape rejection MUST win
      const { b } = makeBridge({ dcr: { mode: "stored", store: clientStore }, cimdTransport: t, cimdResolver: resolver() });
      const res = await b.handleAuthorize(req(directAuthQ({ client_id: id, redirect_uri: OPAQUE_REDIRECT })), { subject: "agent@test" });
      assert.notEqual(res.status, 302, `${id}: no fallthrough to the registered client`);
      assert.notEqual(res.status, 200, `${id}`);
      assert.equal(bodyErr(res), "invalid_client", `${id}: direct invalid_client despite being registered`);
      assert.equal(clientStore.finds, 0, `${id}: rejected by shape BEFORE any store lookup`);
      assert.equal(t.calls, 0, `${id}: never fetched`);
    }
  });

  test("direct (stored-mode, CIMD DISABLED): a REGISTERED lowercase-https client_id is STILL direct invalid_client — no store.find, no fallthrough", async () => {
    const t = transport(() => okResult());
    const clientStore = new CountingClientStore();
    await clientStore.save({ clientId: CIMD_ID, redirectUris: [CIMD_REDIRECT], applicationType: "web" }); // a registered https client
    const { b } = makeBridge({ cimd: undefined, dcr: { mode: "stored", store: clientStore }, cimdTransport: t, cimdResolver: resolver() }); // CIMD disabled
    const res = await b.handleAuthorize(req(directAuthQ()), { subject: "agent@test" });
    assert.notEqual(res.status, 302);
    assert.notEqual(res.status, 200);
    assert.equal(bodyErr(res), "invalid_client", "lowercase-https while CIMD disabled ⇒ direct invalid_client, even if registered (1a branch 2)");
    assert.equal(clientStore.finds, 0, "rejected by shape BEFORE store.find (never a stored-DCR fallthrough)");
    assert.equal(t.calls, 0);
  });

  test("redirect (stored-mode, CIMD DISABLED): a REGISTERED lowercase-https client_id is STILL direct invalid_client — no store.find, no IdP hop", async () => {
    const clientStore = new CountingClientStore();
    await clientStore.save({ clientId: CIMD_ID, redirectUris: [CIMD_REDIRECT], applicationType: "web" });
    const t = transport(() => okResult());
    const { flow } = makeFlow({ cimd: undefined, dcr: { mode: "stored", store: clientStore }, cimdTransport: t, cimdResolver: resolver() });
    const res = await flow.handleAuthorize(req(directAuthQ()));
    assert.notEqual(res.status, 302, "no IdP hop for a disabled-CIMD https id");
    assert.equal(bodyErr(res), "invalid_client");
    assert.equal(clientStore.finds, 0, "rejected by shape BEFORE store.find");
    assert.equal(t.calls, 0);
  });

  // ---------------- UPSTREAM-REDIRECT MODE (handleAuthorize) ----------------

  test("redirect (1): CIMD id + cimd enabled ⇒ resolve-once at authorize then 302 to IdP + cookie", async () => {
    const t = transport(() => okResult());
    const { flow } = makeFlow({ cimdTransport: t, cimdResolver: resolver() });
    const res = await flow.handleAuthorize(req(directAuthQ()));
    assert.equal(res.status, 302, "302 to the upstream IdP");
    assert.ok(res.headers["set-cookie"], "flow cookie set");
    assert.equal(t.calls, 1, "resolved exactly once at authorize");
  });

  test("redirect (2): scheme-shaped variants + https-while-disabled ⇒ direct invalid_client, no 302, no fetch", async () => {
    for (const id of ["HTTPS://cdn.example.com/client", "http://cdn.example.com/client", "ftp://cdn.example.com/client", "web+foo://cdn.example.com/client", "x-y.z://cdn.example.com/client"]) {
      const t = transport(() => okResult());
      const { flow } = makeFlow({ cimdTransport: t, cimdResolver: resolver() });
      const res = await flow.handleAuthorize(req(directAuthQ({ client_id: id, redirect_uri: OPAQUE_REDIRECT })));
      assert.notEqual(res.status, 302, `${id}: no IdP hop`);
      assert.notEqual(res.status, 200, `${id}: not a success channel either`);
      assert.equal(bodyErr(res), "invalid_client", `${id}: direct invalid_client`);
      assert.ok(!res.headers["set-cookie"], `${id}: no cookie set`);
      assert.equal(t.calls, 0, `${id}: never fetched`);
    }
    const t = transport(() => okResult());
    const { flow } = makeFlow({ cimd: undefined, cimdTransport: t, cimdResolver: resolver() });
    const res = await flow.handleAuthorize(req(directAuthQ({ redirect_uri: OPAQUE_REDIRECT })));
    assert.notEqual(res.status, 302);
    assert.notEqual(res.status, 200);
    assert.equal(bodyErr(res), "invalid_client");
    assert.equal(t.calls, 0);
  });

  test("redirect (3): opaque id ⇒ unchanged §10 then 302 to IdP, never fetches", async () => {
    const t = transport(() => okResult());
    const { flow } = makeFlow({ cimdTransport: t, cimdResolver: resolver() });
    const res = await flow.handleAuthorize(req(directAuthQ({ client_id: "opaque-client-123", redirect_uri: OPAQUE_REDIRECT })));
    assert.equal(res.status, 302, "normal opaque upstream authorize");
    assert.equal(t.calls, 0);
  });

  test("redirect: a CIMD id in STORED mode does NOT fire the §10 store.find miss", async () => {
    const t = transport(() => okResult());
    const clientStore = new CountingClientStore();
    const { flow } = makeFlow({ dcr: { mode: "stored", store: clientStore }, cimdTransport: t, cimdResolver: resolver() });
    const res = await flow.handleAuthorize(req(directAuthQ()));
    assert.equal(res.status, 302, "CIMD resolves + hops to the IdP without a stored registration");
    assert.equal(clientStore.finds, 0, "CIMD path MUST NOT consult the client store");
    // Skipping store.find is NOT enough: prove the document was actually RESOLVED and the
    // validated registration carried in the cookie — else a bare IdP redirect (no resolution)
    // would pass here and leave the callback with no carried registration.
    assert.equal(t.calls, 1, "the CIMD document was fetched in stored mode");
    const jwt = (res.headers["set-cookie"] as string).slice((res.headers["set-cookie"] as string).indexOf("=") + 1, (res.headers["set-cookie"] as string).indexOf(";"));
    const claims: any = jose.decodeJwt(jwt);
    assert.equal(claims.cimd?.client_id, CIMD_ID, "the flow cookie carries the projected cimd registration");
  });

  test("redirect (stored-mode): a REGISTERED scheme-shaped client_id is STILL direct invalid_client — rejected by shape BEFORE store.find, no IdP hop", async () => {
    for (const id of ["ftp://cdn.example.com/client", "web+foo://cdn.example.com/client", "HTTPS://cdn.example.com/client", "http://cdn.example.com/client", "HttP://cdn.example.com/client", "x-y.z://cdn.example.com/client"]) {
      const clientStore = new CountingClientStore();
      await clientStore.save({ clientId: id, redirectUris: [OPAQUE_REDIRECT], applicationType: "web" });
      const t = transport(() => okResult());
      const { flow } = makeFlow({ dcr: { mode: "stored", store: clientStore }, cimdTransport: t, cimdResolver: resolver() });
      const res = await flow.handleAuthorize(req(directAuthQ({ client_id: id, redirect_uri: OPAQUE_REDIRECT })));
      assert.notEqual(res.status, 302, `${id}: no IdP hop for a scheme-shaped id`);
      assert.equal(bodyErr(res), "invalid_client", `${id}: direct invalid_client despite being registered`);
      assert.equal(clientStore.finds, 0, `${id}: rejected by shape BEFORE store.find`);
      assert.equal(t.calls, 0, `${id}: never fetched`);
    }
  });
}
