// FROZEN acceptance suite — S6b upstream-redirect CIMD (docs/contracts.md §17.1.6
// decision 1 / 1a–1e; verification T1.S6b rows S6b.10 + S6b.5). Resolve+validate
// the document ONCE at authorize, carry the validated CimdRegistration in the
// signed flow cookie (projected to EXACTLY {client_id, client_name, redirect_uris}
// — no key material), consume it at callback with NO re-fetch. Shared redirect
// matcher (https exact raw-string; loopback RFC 8252 any-port). Callback row 5a
// claim/mode/redirect matrix ⇒ direct 400 invalid_request + audit
// `flow_cookie_invalid`, AFTER state match and BEFORE jti-consume/exchange/any 302.
// Cookie-oversize residual ⇒ generic invalid_client audited as failure `oversize`.
// `prepare`'s defensive re-check ⇒ DIRECT invalid_client (never a 302).
// FAITHFULNESS: forged cookies model exactly what verifyFlowToken/handleCallback
// see; the consent-page HTML wording is never frozen (only status + that the gate
// was passed/blocked + audit reason). FLOW_AUDIENCE is imported, not hardcoded.
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
  const INTERNALS = "../../../src/adapters/upstream-flow-internals.ts";
  const { FLOW_AUDIENCE } = (await import(INTERNALS)) as any;
  const jose = (await import("jose")) as any;

  const NOW = Date.parse("2026-07-03T12:00:00.000Z");
  const CIMD_ID = "https://cdn.example.com/client";
  const CIMD_REDIRECT = "https://app.example.com/cb";
  const VERIFIER = "correct-horse-battery-staple-0123456789abcdef0123";
  const PUBLIC = { address: "93.184.216.34", family: 4 };
  const enc = (s: string) => new TextEncoder().encode(s);
  async function* one(u8: Uint8Array) { yield u8; }
  const cimdDoc = (over: any = {}) => ({ client_id: CIMD_ID, client_name: "Example App", redirect_uris: [CIMD_REDIRECT], ...over });
  const docResult = (o: any = {}) => ({
    status: o.status ?? 200, redirected: o.redirected ?? false, finalUrl: o.finalUrl ?? CIMD_ID,
    headersDistinct: o.headersDistinct ?? { "content-type": ["application/json"] },
    encodedBody: o.body ?? one(enc(JSON.stringify(o.doc ?? cimdDoc()))),
  });
  // A transport that serves the doc on the FIRST call and THROWS on any later call
  // (a callback re-fetch). Proves carry-forward, not re-fetch.
  function serveOnceThenThrow(doc?: any) { let calls = 0; return { connectAndGet() { calls++; if (calls > 1) return Promise.reject(new Error("callback re-fetch forbidden")); return Promise.resolve(docResult({ doc })); }, get calls() { return calls; } }; }
  function transport(factory: any) { let calls = 0; return { connectAndGet(r: any) { calls++; return Promise.resolve(typeof factory === "function" ? factory(r) : factory); }, get calls() { return calls; } }; }
  const throwingTransport = { connectAndGet() { return Promise.reject(new Error("must not fetch")); } };
  const throwingResolver = { resolve() { return Promise.reject(new Error("must not resolve")); }, cancel() {} };
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
  function stubIdentity() {
    let exchanges = 0;
    return {
      redirectUri: "https://auth.test/oauth/callback",
      buildAuthorizationUrl({ state }: any) { return `https://idp.test/authorize?state=${state}`; },
      async exchangeAndVerify() { exchanges++; return { ok: true, identity: { subject: "up@test" } }; },
      get exchanges() { return exchanges; },
    };
  }
  // A store whose consumeConsentJti is spied, to prove row-5a runs BEFORE jti
  // consumption (a 5a rejection never consumes the flow jti).
  function trackingStore() {
    const store = new MemoryStore();
    let consumes = 0;
    const original = store.consumeConsentJti.bind(store);
    store.consumeConsentJti = async (...args: any[]) => { consumes++; return original(...args); };
    return { store, get consumes() { return consumes; } };
  }
  function makeFlow(opts: any = {}) {
    const store = opts.store ?? new MemoryStore();
    const clock = new FakeClock(NOW);
    const audit = new MemoryAudit();
    const config = cfg("cimd" in opts ? opts.cimd : { enabled: true }); // explicit undefined ⇒ disabled (never re-enabled)
    // The bridge-side seams default to THROWING so a callback re-fetch is caught.
    const b = new Bridge({ config, store, clock, audit, cimdTransport: opts.bridgeTransport ?? throwingTransport, cimdResolver: opts.bridgeResolver ?? throwingResolver });
    const identity = opts.identity ?? stubIdentity();
    const flow = createUpstreamRedirectFlow({ bridge: b, identity, store, clock, audit, cimdTransport: opts.cimdTransport ?? transport(() => docResult()), cimdResolver: opts.cimdResolver ?? resolver() });
    return { flow, b, store, clock, audit, config, identity };
  }
  const req = (query: any, headers: any = {}, ip = "1.2.3.4") => ({ query, body: undefined, headers, ip });
  const authQ = (over: any = {}) => ({ response_type: "code", client_id: CIMD_ID, redirect_uri: CIMD_REDIRECT, code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", scope: "mcp:read", state: "client-state", ...over });
  const COOKIE = "__Host-mcp-sso-upstream";
  const cookieJwtOf = (setCookie: string) => setCookie.slice(setCookie.indexOf("=") + 1, setCookie.indexOf(";"));
  const bodyErr = (res: any) => (res.body && typeof res.body === "object" ? res.body.error : undefined);
  const GENERIC = { error: "invalid_client", error_description: "client_id could not be resolved" };
  const cimdFetchEvents = (audit: any) => audit.events.filter((e: any) => e.event === "oauth.cimd.fetch");
  const callbackFail = (audit: any) => audit.events.filter((e: any) => e.event === "oauth.upstream.callback" && e.status === "failure");
  // Mint a validly-signed flow cookie (same structure as signFlowToken) with an
  // optional top-level `cimd` claim — models exactly what verifyFlowToken sees.
  async function forge(config: any, o: any) {
    const now = Math.floor(NOW / 1000);
    const payload: any = { jti: o.jti ?? "upf_forged", state: o.state, nonce: o.nonce ?? "n", code_verifier: o.codeVerifier ?? "cv-0123456789012345678901234567890123456789012", params: o.params };
    if (o.cimd !== undefined) payload.cimd = o.cimd;
    return await new jose.SignJWT(payload).setProtectedHeader({ alg: "HS256", typ: "JWT" }).setIssuer(config.issuer).setAudience(FLOW_AUDIENCE).setIssuedAt(now).setExpirationTime(now + 600).sign(enc(config.consentSigningSecret));
  }

  // ---- 1d carry-forward: resolve ONCE at authorize; callback does NOT re-fetch ----
  test("carry-forward: doc resolved ONCE at authorize; callback completes even though BOTH bridge CIMD seams throw (dual-seam proof)", async () => {
    const authTransport = serveOnceThenThrow();
    // bridge seams throw (default): if the callback tried to re-fetch/resolve it would blow up.
    const { flow } = makeFlow({ cimdTransport: authTransport, cimdResolver: resolver() });
    const auth = await flow.handleAuthorize(req(authQ()));
    assert.equal(auth.status, 302);
    assert.equal(authTransport.calls, 1, "resolved exactly once at authorize");
    const jwt = cookieJwtOf(auth.headers["set-cookie"] as string);
    const state = jose.decodeJwt(jwt).state as string;
    const cb = await flow.handleCallback(req({ code: "THE_CODE", state }, { cookie: `${COOKIE}=${jwt}` }));
    assert.equal(cb.status, 200, "callback completes from the carried registration (no re-fetch)");
    assert.equal(authTransport.calls, 1, "the authorize transport was NOT called again at callback");
  });

  // ---- 1c: the carried cimd claim projects EXACTLY the three named fields ----
  test("1c projection: the flow-cookie `cimd` claim carries EXACTLY {client_id, client_name, redirect_uris} — no key material / no attacker members", async () => {
    const doc = cimdDoc({ jwks: { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }] }, logo_uri: "https://logo.test/x.png", unknown_extension: "ATTACKER_MEMBER_SECRET" });
    const { flow } = makeFlow({ cimdTransport: transport(() => docResult({ doc })), cimdResolver: resolver() });
    const auth = await flow.handleAuthorize(req(authQ()));
    assert.equal(auth.status, 302);
    const jwt = cookieJwtOf(auth.headers["set-cookie"] as string);
    const claims = jose.decodeJwt(jwt);
    assert.deepEqual(Object.keys(claims.cimd).sort(), ["client_id", "client_name", "redirect_uris"]);
    assert.equal(JSON.stringify(claims.cimd).includes("ATTACKER_MEMBER_SECRET"), false, "no attacker-controlled member rides the cookie");
  });

  // ---- shared redirect matcher (rule 20): https exact raw-string; loopback any-port ----
  test("matcher: an https redirect exact raw-string matching a doc entry succeeds", async () => {
    const { flow } = makeFlow({ cimdTransport: transport(() => docResult()), cimdResolver: resolver() });
    const res = await flow.handleAuthorize(req(authQ({ redirect_uri: CIMD_REDIRECT })));
    assert.equal(res.status, 302);
  });
  test("matcher: https is EXACT raw-string — :443, a query difference, and a trailing slash all fail closed (generic)", async () => {
    for (const presented of ["https://app.example.com:443/cb", "https://app.example.com/cb?x=1", "https://app.example.com/cb/"]) {
      const { flow, audit } = makeFlow({ cimdTransport: transport(() => docResult()), cimdResolver: resolver() });
      const res = await flow.handleAuthorize(req(authQ({ redirect_uri: presented })));
      assert.notEqual(res.status, 302, `${presented}: not a 302`);
      assert.equal(bodyErr(res), "invalid_client", `${presented}: generic invalid_client`);
      assert.deepEqual(res.body, GENERIC, `${presented}: identical generic body`);
      assert.ok(cimdFetchEvents(audit).some((e: any) => e.status === "failure"), `${presented}: audited failure`);
    }
  });
  test("matcher: an explicit non-default https port matches when raw-equal", async () => {
    const doc = cimdDoc({ redirect_uris: ["https://app.example.com:8443/cb"] });
    const { flow } = makeFlow({ cimdTransport: transport(() => docResult({ doc })), cimdResolver: resolver() });
    const res = await flow.handleAuthorize(req(authQ({ redirect_uri: "https://app.example.com:8443/cb" })));
    assert.equal(res.status, 302);
  });
  test("matcher: a loopback http entry matches ANY port (RFC 8252) but not a host/path/localhost difference", async () => {
    const doc = cimdDoc({ redirect_uris: ["http://127.0.0.1:5000/cb"] });
    const mk = () => makeFlow({ cimdTransport: transport(() => docResult({ doc })), cimdResolver: resolver() });
    assert.equal((await mk().flow.handleAuthorize(req(authQ({ redirect_uri: "http://127.0.0.1:7000/cb" })))).status, 302, "any loopback port");
    assert.equal((await mk().flow.handleAuthorize(req(authQ({ redirect_uri: "http://127.0.0.1:5000/cb" })))).status, 302, "exact loopback port");
    assert.notEqual((await mk().flow.handleAuthorize(req(authQ({ redirect_uri: "http://127.0.0.1:5000/cb/extra" })))).status, 302, "path difference rejects");
    assert.notEqual((await mk().flow.handleAuthorize(req(authQ({ redirect_uri: "http://127.0.0.2:5000/cb" })))).status, 302, "host difference rejects");
    assert.notEqual((await mk().flow.handleAuthorize(req(authQ({ redirect_uri: "http://localhost:5000/cb" })))).status, 302, "localhost != 127.0.0.1 under the matcher");
  });
  test("matcher: a presented redirect absent from the doc fails closed (generic invalid_client)", async () => {
    const { flow } = makeFlow({ cimdTransport: transport(() => docResult()), cimdResolver: resolver() });
    const res = await flow.handleAuthorize(req(authQ({ redirect_uri: "https://evil.example/cb" })));
    assert.notEqual(res.status, 302);
    assert.deepEqual(res.body, GENERIC);
  });

  // ---- 1b cookie-oversize residual ----
  test("cookie-oversize: a document-VALID registration whose projected flow cookie exceeds 4096 bytes ⇒ generic invalid_client, audit failure `oversize`, no success/302/cookie", async () => {
    const many = Array.from({ length: 16 }, (_, i) => `https://app.example.com/callback/${String(i)}/${"p".repeat(210)}`);
    const doc = cimdDoc({ redirect_uris: many });
    const { flow, audit, identity } = makeFlow({ cimd: { enabled: true, maxDocumentBytes: 65536 }, cimdTransport: transport(() => docResult({ doc })), cimdResolver: resolver() });
    const res = await flow.handleAuthorize(req(authQ({ redirect_uri: many[0] })));
    assert.notEqual(res.status, 302, "not a 302 to the IdP");
    assert.ok(!res.headers["set-cookie"], "no oversized cookie set");
    assert.deepEqual(res.body, GENERIC, "generic invalid_client (not invalid_request)");
    assert.equal(identity.exchanges, 0);
    const fetches = cimdFetchEvents(audit);
    assert.ok(fetches.some((e: any) => e.status === "failure" && e.reason === "oversize"), "audited as failure reason oversize");
    assert.equal(fetches.some((e: any) => e.status === "success"), false, "never a success event before the reject");
  });

  // ---- callback row 3 (malformed claim) + row 5a matrix ----
  const baseParams = (over: any = {}) => ({ response_type: "code", client_id: CIMD_ID, redirect_uri: CIMD_REDIRECT, code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", scope: "mcp:read", state: "st-1", ...over });
  const validClaim = (over: any = {}) => ({ client_id: CIMD_ID, client_name: "Example App", redirect_uris: [CIMD_REDIRECT], ...over });

  async function callbackWith(opts: { cimdEnabled?: boolean; cimd: any; params: any; jti?: string; cbState?: string; cbQuery?: any }) {
    const tracked = trackingStore();
    const { flow, audit, identity } = makeFlow({ cimd: { enabled: opts.cimdEnabled ?? true }, store: tracked.store });
    const state = opts.params.state;
    const jwt = await forge(cfg(), { state, params: opts.params, cimd: opts.cimd, jti: opts.jti });
    const cbQuery = opts.cbQuery ?? { code: "C", state: opts.cbState ?? state };
    const res = await flow.handleCallback(req(cbQuery, { cookie: `${COOKIE}=${jwt}` }));
    return { res, audit, identity, consumes: tracked.consumes };
  }

  test("callback row 5a matrix: each claim/mode/redirect inconsistency ⇒ direct 400 invalid_request + flow_cookie_invalid, no location, no jti consume, no exchange", async () => {
    const matrix: Array<{ label: string; cimdEnabled?: boolean; cimd: any; params: any }> = [
      { label: "CIMD id without a cimd claim", cimd: undefined, params: baseParams() },
      { label: "CIMD id with cimd DISABLED", cimdEnabled: false, cimd: validClaim(), params: baseParams() },
      // redirect_uris MATCH the opaque params so the SOLE 5a trigger is "a non-CIMD id carries a cimd claim" (not a redirect mismatch).
      { label: "non-CIMD (opaque) id carrying a cimd claim", cimd: validClaim({ client_id: "opaque-abc", redirect_uris: ["https://client.test/cb"] }), params: baseParams({ client_id: "opaque-abc", redirect_uri: "https://client.test/cb" }) },
      { label: "params.redirect_uri not in the claim's redirect_uris", cimd: validClaim(), params: baseParams({ redirect_uri: "https://client.test/cb" }) },
    ];
    for (const m of matrix) {
      const { res, audit, identity, consumes } = await callbackWith({ cimdEnabled: m.cimdEnabled, cimd: m.cimd, params: m.params });
      assert.equal(res.status, 400, `${m.label}: direct 400`);
      assert.equal(bodyErr(res), "invalid_request", `${m.label}: invalid_request`);
      assert.equal(res.headers?.location, undefined, `${m.label}: no redirect-channel response`);
      assert.ok(callbackFail(audit).some((e: any) => e.reason === "flow_cookie_invalid"), `${m.label}: audit reason flow_cookie_invalid`);
      assert.equal(consumes, 0, `${m.label}: jti NOT consumed (5a precedes jti consume)`);
      assert.equal(identity.exchanges, 0, `${m.label}: no upstream exchange`);
    }
  });

  test("callback row 5a (control OK): a valid cimd claim + matching redirect + state match ⇒ passes the gate (200)", async () => {
    const { res } = await callbackWith({ cimd: validClaim(), params: baseParams() });
    assert.equal(res.status, 200, "passed row 5a → consent page");
  });

  test("callback ordering: row 5 (state) precedes row 5a — a state mismatch audits `state_mismatch`, not `flow_cookie_invalid`", async () => {
    const { res, audit } = await callbackWith({ cimd: undefined, params: baseParams(), cbQuery: { code: "C", state: "DIFFERENT" } });
    assert.equal(res.status, 400);
    assert.ok(callbackFail(audit).some((e: any) => e.reason === "state_mismatch"), "state row precedes the CIMD policy row");
  });

  test("callback row 5a does NOT consume the flow jti: a 5a-rejected cookie's jti still works on a later valid cookie", async () => {
    const tracked = trackingStore();
    const { flow } = makeFlow({ cimd: { enabled: true }, store: tracked.store });
    const jwtA = await forge(cfg(), { state: "st-1", params: baseParams(), cimd: undefined, jti: "upf_shared" }); // 5a violation
    const rej = await flow.handleCallback(req({ code: "C", state: "st-1" }, { cookie: `${COOKIE}=${jwtA}` }));
    assert.equal(bodyErr(rej), "invalid_request", "A rejected at 5a");
    const jwtB = await forge(cfg(), { state: "st-1", params: baseParams(), cimd: validClaim(), jti: "upf_shared" });
    const ok = await flow.handleCallback(req({ code: "C2", state: "st-1" }, { cookie: `${COOKIE}=${jwtB}` }));
    assert.equal(ok.status, 200, "B succeeds on the same jti ⇒ 5a did not consume it");
  });

  test("callback row 3: a present-but-malformed cimd claim fails cookie verification ⇒ 400 invalid_request / flow_cookie_invalid (widest shape matrix)", async () => {
    const malformed: any[] = [
      null, [], "not-an-object",
      { client_id: 7, client_name: "Example App", redirect_uris: [CIMD_REDIRECT] },
      { client_id: CIMD_ID, client_name: 7, redirect_uris: [CIMD_REDIRECT] },
      { client_id: CIMD_ID, client_name: "", redirect_uris: [CIMD_REDIRECT] },
      { client_id: CIMD_ID, client_name: "x".repeat(257), redirect_uris: [CIMD_REDIRECT] },
      { client_id: "https://other.example/client", client_name: "Example App", redirect_uris: [CIMD_REDIRECT] },
      { client_id: CIMD_ID, client_name: "Example App", redirect_uris: "not-an-array" },
      { client_id: CIMD_ID, client_name: "Example App", redirect_uris: [] },
      { client_id: CIMD_ID, client_name: "Example App", redirect_uris: Array(17).fill(CIMD_REDIRECT) },
      { client_id: CIMD_ID, client_name: "Example App", redirect_uris: [7] },
    ];
    for (const claim of malformed) {
      const { res, audit, consumes } = await callbackWith({ cimd: claim, params: baseParams() });
      assert.equal(res.status, 400, `${JSON.stringify(claim)}: 400`);
      assert.equal(bodyErr(res), "invalid_request");
      assert.equal(res.headers?.location, undefined);
      assert.ok(callbackFail(audit).some((e: any) => e.reason === "flow_cookie_invalid"));
      assert.equal(consumes, 0);
    }
  });

  test("flow-token parse ignores unknown members of a valid cimd claim (projects fresh named fields only)", async () => {
    const { res } = await callbackWith({ cimd: validClaim({ unknown: "SIGNED_UNKNOWN_MEMBER_SECRET" }), params: baseParams() });
    assert.equal(res.status, 200, "unknown members are ignored; the flow proceeds");
    assert.equal(String(res.body).includes("SIGNED_UNKNOWN_MEMBER_SECRET"), false, "the unknown member never surfaces");
  });

  // ---- prepare's defensive redirect re-check (direct, via the registration option) ----
  test("prepare defensive re-check: a supplied registration whose redirect_uris omit params.redirect_uri ⇒ DIRECT invalid_client (never a 302)", async () => {
    const config = cfg({ enabled: true });
    const b = new Bridge({ config, store: new MemoryStore(), clock: new FakeClock(NOW), audit: new MemoryAudit(), cimdTransport: throwingTransport, cimdResolver: throwingResolver });
    const res = await b.handleAuthorize(req(authQ({ redirect_uri: "https://other.example/cb" })), { subject: "up@test", registration: { client_id: CIMD_ID, client_name: "Example App", redirect_uris: [CIMD_REDIRECT] } });
    assert.notEqual(res.status, 302, "never a 302");
    assert.equal(bodyErr(res), "invalid_client");
    assert.equal(res.headers?.location, undefined);
  });

  test("prepare with a supplied registration does NOT re-fetch (registration-presence, not mode, suppresses the fetch)", async () => {
    const config = cfg({ enabled: true });
    const b = new Bridge({ config, store: new MemoryStore(), clock: new FakeClock(NOW), audit: new MemoryAudit(), cimdTransport: throwingTransport, cimdResolver: throwingResolver });
    const res = await b.handleAuthorize(req(authQ({ redirect_uri: CIMD_REDIRECT })), { subject: "up@test", registration: { client_id: CIMD_ID, client_name: "Example App", redirect_uris: [CIMD_REDIRECT] } });
    assert.equal(res.status, 200, "consent rendered from the supplied registration with no fetch");
  });
}
