// FROZEN acceptance suite — CIMD D00-4.5.2 loopback-port compatibility.
// A registered loopback http entry gets the narrow any-port exception whether
// application_type is native, web, or absent. Scheme, host, path, and query stay
// exact; unknown or malformed declarations still fail closed.
import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const phases = JSON.parse(readFileSync(new URL("../phases.json", import.meta.url), "utf8"));

if (phases["cimd-native-loopback-policy"] !== true) {
  test("cimd-native-loopback-policy inactive — activate via test/acceptance/phases.json", { skip: true }, () => {});
} else {
  const { createBridgeConfig } = (await import("../../../src/config.ts")) as any;
  const { Bridge } = (await import("../../../src/adapters/bridge.ts")) as any;
  const { createUpstreamRedirectFlow } = (await import("../../../src/adapters/upstream-flow.ts")) as any;
  const { MemoryStore } = (await import("../../../src/store/memory.ts")) as any;
  const { pkceChallenge } = (await import("../../../src/crypto.ts")) as any;
  const jose = (await import("jose")) as any;

  const NOW = Date.parse("2026-08-14T12:00:00.000Z");
  const CLIENT_ID = "https://cdn.example.com/client";
  const LOOPBACKS = [
    { registered: "http://127.0.0.1/cb", differentPort: "http://127.0.0.1:7000/cb" },
    { registered: "http://localhost/cb", differentPort: "http://localhost:7000/cb" },
    { registered: "http://[::1]/cb", differentPort: "http://[::1]:7000/cb" },
  ] as const;
  const REGISTERED = LOOPBACKS[0].registered;
  const DIFFERENT_PORT = LOOPBACKS[0].differentPort;
  const VERIFIER = "correct-horse-battery-staple-0123456789abcdef0123";
  const OMIT = Symbol("omit");
  const enc = (value: string) => new TextEncoder().encode(value);
  async function* body(value: Uint8Array) { yield value; }
  const CLAUDE_CODE_DOCUMENT = {
    client_id: "https://claude.ai/oauth/claude-code-client-metadata",
    client_name: "Claude Code",
    redirect_uris: ["http://localhost/callback", "http://127.0.0.1/callback"],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  };

  class Clock { nowMs() { return NOW; } }
  class Audit { events: any[] = []; async writeAuthEvent(event: any) { this.events.push(event); } }

  function document(applicationType: unknown | typeof OMIT, redirect: string = REGISTERED): Record<string, unknown> {
    const value: Record<string, unknown> = {
      client_id: CLIENT_ID, client_name: "Native policy client", redirect_uris: [redirect],
    };
    if (applicationType !== OMIT) value.application_type = applicationType;
    return value;
  }

  function context(doc: Readonly<Record<string, unknown>>, suppliedStore?: any) {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const config = createBridgeConfig({
      issuer: "https://auth.test", resource: "https://api.test/mcp",
      consentSigningSecret: "n".repeat(40),
      signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" },
      signingKeyId: "k", redirectAllowlist: ["https://client.test/cb"],
      scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
      allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" }, cimd: { enabled: true },
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600,
      consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    });
    const store = suppliedStore ?? new MemoryStore();
    const clock = new Clock();
    const audit = new Audit();
    let fetches = 0;
    const transport = {
      connectAndGet() {
        fetches += 1;
        return Promise.resolve({
          status: 200, redirected: false,
          finalUrl: typeof doc.client_id === "string" ? doc.client_id : CLIENT_ID,
          headersDistinct: {
            "content-type": ["application/json"],
            "cache-control": ["public, max-age=600"],
          },
          encodedBody: body(enc(JSON.stringify(doc))),
        });
      },
    };
    const resolver = { resolve() { return Promise.resolve([{ address: "93.184.216.34", family: 4 }]); }, cancel() {} };
    const bridge = new Bridge({ config, store, clock, audit, cimdTransport: transport, cimdResolver: resolver });
    let exchanges = 0;
    const identity = {
      redirectUri: "https://auth.test/oauth/callback",
      buildAuthorizationUrl({ state }: any) { return `https://idp.test/authorize?state=${state}`; },
      async exchangeAndVerify() { exchanges += 1; return { ok: true, identity: { subject: "user-1" } }; },
    };
    const flow = createUpstreamRedirectFlow({ bridge, identity, store, clock, audit, cimdTransport: transport, cimdResolver: resolver });
    return { bridge, flow, config, store, audit, get fetches() { return fetches; }, get exchanges() { return exchanges; } };
  }

  const request = (query: any, headers: any = {}) => ({ query, headers, body: undefined, ip: "1.2.3.4" });
  const params = (redirectUri: string) => ({
    response_type: "code", client_id: CLIENT_ID, redirect_uri: redirectUri,
    code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
    scope: "mcp:read", state: "client-state",
  });
  const cookieValue = (header: string) => header.slice(header.indexOf("=") + 1, header.indexOf(";"));
  const errorCode = (response: any) => response.body && typeof response.body === "object" ? response.body.error : undefined;

  test("Claude Code's published document resolves an ephemeral loopback port", async () => {
    const ctx = context(CLAUDE_CODE_DOCUMENT);
    const response = await ctx.bridge.handleAuthorize(request({
      ...params("http://localhost:3118/callback"), client_id: CLAUDE_CODE_DOCUMENT.client_id,
    }), { subject: "user-1" });
    assert.equal(response.status, 200);
    assert.equal(ctx.fetches, 1);
  });

  test("document path: registered loopback http is any-port for native, web, and absent types", async () => {
    for (const loopback of LOOPBACKS) {
      for (const [applicationType, redirect] of [
        ["native", loopback.differentPort], ["web", loopback.differentPort],
        [OMIT, loopback.differentPort], ["web", loopback.registered],
        [OMIT, loopback.registered],
      ] as const) {
        const ctx = context(document(applicationType, loopback.registered));
        for (const pass of ["miss", "hit"] as const) {
          const response = await ctx.bridge.handleAuthorize(request(params(redirect)), { subject: "user-1" });
          assert.equal(response.status, 200, `${String(applicationType)} ${pass} at ${redirect}`);
        }
        assert.equal(ctx.fetches, 1, "the second type decision uses the cached named projection");
      }
    }

    for (const malformed of ["mobile", "", null, 1, true, [], {}]) {
      const ctx = context(document(malformed));
      const response = await ctx.bridge.handleAuthorize(request(params(REGISTERED)), { subject: "user-1" });
      assert.equal(response.status, 401, `malformed ${JSON.stringify(malformed)}`);
      assert.equal(errorCode(response), "invalid_client");
    }
  });

  test("loopback elasticity changes only the port", async () => {
    for (const [registered, presented] of [
      ["https://client.example/cb", "https://client.example:7000/cb"],
      ["http://localhost/cb", "https://localhost:7000/cb"],
      ["http://localhost/cb", "http://127.0.0.1:7000/cb"],
      ["http://localhost/cb", "http://localhost:7000/other"],
      ["http://localhost/cb", "http://localhost:7000/cb?extra=1"],
      ["http://localhost/cb", "http://localhost:7000/cb#fragment"],
      ["http://localhost/cb", "http://localhost:80/cb"],
      ["http://localhost/cb", "http://localhost:080/cb"],
      ["http://localhost/cb", "http://localhost:07000/cb"],
    ] as const) {
      const ctx = context(document(OMIT, registered));
      const response = await ctx.bridge.handleAuthorize(request(params(presented)), { subject: "user-1" });
      assert.equal(response.status, 401, `${registered} must not match ${presented}`);
      assert.equal(errorCode(response), "invalid_client");
    }
  });

  test("real upstream flow carries native through projection, cookie, callback, and prepare", async () => {
    const ctx = context(document("native"));
    const authorization = await ctx.flow.handleAuthorize(request(params(DIFFERENT_PORT)));
    assert.equal(authorization.status, 302);
    const token = cookieValue(authorization.headers["set-cookie"]);
    const state = jose.decodeJwt(token).state;
    assert.equal(jose.decodeJwt(token).cimd.application_type, "native");
    const callback = await ctx.flow.handleCallback(request(
      { code: "upstream-code", state }, { cookie: `__Host-mcp-sso-upstream=${token}` },
    ));
    assert.equal(callback.status, 200);
    assert.equal(ctx.fetches, 1, "callback and prepare use the signed carried registration");
    assert.equal(ctx.exchanges, 1);
  });

  test("prepare re-check accepts declared or absent types for a registered loopback port", async () => {
    for (const loopback of LOOPBACKS) {
      for (const [applicationType, expected] of [["native", 200], ["web", 200], [OMIT, 200]] as const) {
        const ctx = context(document(OMIT));
        const registration: Record<string, unknown> = {
          client_id: CLIENT_ID, client_name: "Carried", redirect_uris: [loopback.registered],
        };
        if (applicationType !== OMIT) registration.application_type = applicationType;
        const response = await ctx.bridge.handleAuthorize(
          request(params(loopback.differentPort)), { subject: "user-1", registration },
        );
        assert.equal(response.status, expected, `${String(applicationType)} at ${loopback.differentPort}`);
        assert.equal(ctx.fetches, 0, "supplied registration never re-fetches");
      }
    }
    for (const applicationType of ["mobile", null, 1]) {
      const ctx = context(document(OMIT));
      const registration: Record<string, unknown> = {
        client_id: CLIENT_ID, client_name: "Carried", redirect_uris: [REGISTERED], application_type: applicationType,
      };
      const response = await ctx.bridge.handleAuthorize(
        request(params(DIFFERENT_PORT)), { subject: "user-1", registration },
      );
      assert.equal(response.status, 401, String(applicationType));
      assert.equal(ctx.fetches, 0, "supplied registration never re-fetches");
    }
  });

  test("signed callback claims accept native, web, and absent types but reject malformed types before consumption", async () => {
    const store = new MemoryStore();
    let consumes = 0;
    const originalConsume = store.consumeConsentJti.bind(store);
    store.consumeConsentJti = async (...args: any[]) => { consumes += 1; return originalConsume(...args); };
    const ctx = context(document(OMIT), store);
    const seed = await ctx.flow.handleAuthorize(request(params(REGISTERED)));
    const audience = jose.decodeJwt(cookieValue(seed.headers["set-cookie"])).aud;

    async function forge(applicationType: unknown | typeof OMIT, registered: string, redirect: string) {
      const cimd: Record<string, unknown> = {
        client_id: CLIENT_ID, client_name: "Carried", redirect_uris: [registered],
      };
      if (applicationType !== OMIT) cimd.application_type = applicationType;
      const now = Math.floor(NOW / 1000);
      return await new jose.SignJWT({
        jti: `upf_${randomBytes(32).toString("base64url")}`, state: "flow-state", nonce: "nonce",
        code_verifier: VERIFIER, params: { ...params(redirect), state: "flow-state" }, cimd,
      }).setProtectedHeader({ alg: "HS256", typ: "JWT" }).setIssuer(ctx.config.issuer)
        .setAudience(audience).setIssuedAt(now).setExpirationTime(now + 600)
        .sign(enc(ctx.config.consentSigningSecret));
    }

    const cases: Array<readonly [unknown | typeof OMIT, string, string, number, number]> = [];
    for (const loopback of LOOPBACKS) {
      cases.push(
        ["native", loopback.registered, loopback.differentPort, 200, 1],
        ["web", loopback.registered, loopback.differentPort, 200, 1],
        [OMIT, loopback.registered, loopback.differentPort, 200, 1],
      );
    }
    cases.push(["web", REGISTERED, REGISTERED, 200, 1], [OMIT, REGISTERED, REGISTERED, 200, 1]);
    for (const malformed of ["mobile", "", null, 1, true, [], {}]) {
      cases.push([malformed, REGISTERED, REGISTERED, 400, 0]);
    }

    for (const [applicationType, registered, redirect, expected, consumed] of cases) {
      const before = consumes;
      const token = await forge(applicationType, registered, redirect);
      const response = await ctx.flow.handleCallback(request(
        { code: "upstream-code", state: "flow-state" },
        { cookie: `__Host-mcp-sso-upstream=${token}` },
      ));
      assert.equal(response.status, expected, `${String(applicationType)} at ${redirect}`);
      assert.equal(consumes - before, consumed, "rejected claims precede JTI consumption");
    }
  });
}
