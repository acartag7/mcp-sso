// Integration test of the §17.11 upstream redirect-flow through the STANDALONE
// ENTRY (examples/fastify-sqlite's buildExample, Entra-redirect branch) over real
// in-process HTTP, with a stubbed globalThis.fetch serving the Entra JWKS + a
// synthetic RS256 id_token (the CF integration-test pattern, zero real network).
// Full register → authorize (302 + cookie) → callback → consent → approve →
// token → protected /mcp round trip, plus the replayed-callback negative (no
// second exchange) and a no-secrets-on-disk assertion against the audit file.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { decodeJwt, exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { pkceChallenge } from "../src/crypto.ts";
import { entraIssuer, entraJwksUrl, entraTokenEndpoint } from "../src/identity/entra.ts";
import type { GoogleConfig } from "../src/identity/google.ts";
import type { GenericOidcConfig } from "../src/identity/generic-oidc.ts";
import type { RedirectIdentityPort } from "../src/ports/identity.ts";
import { buildExample, defaultListenHost, type OidcIdentityFactories } from "../examples/fastify-sqlite/app.ts";
import { buildGatewayExample } from "../examples/api-key-gateway/app.ts";
import { buildBackend } from "../examples/api-key-gateway/backend.ts";

function jwk(): JWK { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }) } as JWK; }
function json<T>(res: { body: unknown }): T { assert.equal(typeof res.body, "string", "inject body is a string"); return JSON.parse(res.body as string) as T; }
function extractValue(html: string, name: string): string { const m = new RegExp(`name="${name}" value="([^"]+)"`).exec(html); assert.ok(m?.[1], `hidden field ${name} not found`); return m[1]!; }

function sdkFetchShim(app: { inject(args: unknown): Promise<unknown> }): typeof fetch {
  return (async (url: URL | string, init?: { method?: string; headers?: unknown; body?: unknown }): Promise<Response> => {
    const u = url instanceof URL ? url : new URL(String(url));
    const headers: Record<string, string> = {};
    const src = init?.headers;
    if (src instanceof Headers) src.forEach((v, k) => { headers[k] = v; });
    else if (src && typeof src === "object") for (const [k, v] of Object.entries(src as Record<string, string>)) headers[k] = v;
    const method = (init?.method ?? "POST") as "POST";
    const payload = init?.body === undefined || init?.body === null ? undefined : typeof init.body === "string" ? init.body : JSON.stringify(init.body);
    const r = await app.inject(payload === undefined ? { method, url: u.pathname + u.search, headers } : { method, url: u.pathname + u.search, headers, payload }) as unknown as { statusCode: number; headers: Record<string, string>; body: string };
    return new Response(r.body, { status: r.statusCode, headers: r.headers });
  }) as typeof fetch;
}
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => { const t = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms); p.then((v) => { clearTimeout(t); resolve(v); }, (e) => { clearTimeout(t); reject(e); }); });
}
async function callProtectedMcp(
  app: { inject(args: unknown): Promise<unknown> }, resource: string, accessToken: string,
  toolName: string, expectedText: string | RegExp,
): Promise<void> {
  const transport = new StreamableHTTPClientTransport(new URL(resource), { fetch: sdkFetchShim(app) as never, requestInit: { headers: { authorization: `Bearer ${accessToken}` } } });
  const client = new Client({ name: "int-upstream-flow", version: "0.0.1" }, { capabilities: {} });
  try {
    await withTimeout(client.connect(transport), 10_000, "MCP client connect");
    const result = await withTimeout(client.callTool({ name: toolName, arguments: {} }), 10_000, "MCP client callTool");
    const text = (result.content as Array<{ type: string; text?: string }>).find((c) => c.type === "text")?.text;
    if (typeof expectedText === "string") assert.equal(text, expectedText, "the upstream-resolved subject reached /mcp");
    else assert.match(text ?? "", expectedText, "the protected MCP round trip reached the expected backend");
  } finally { await client.close(); await transport.close(); }
}

const FLOW_REDIRECT = "http://localhost:4321/callback";
const ISSUER = "http://localhost:3000";
const TENANT = "11111111-2222-3333-4444-555555555555";
const CLIENT_ID = "entra-test-client-id";
const OID = "entra-user-oid-123";

test("integration — Entra-redirect branch: buildExample full flow (stubbed JWKS + synthetic RS256 id_token) → token → /mcp; replayed callback rejected with no second exchange; no secrets on disk", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-upstream-"));
  const dir = join(base, "state");
  // RSA keypair: public half served as the Entra JWKS, private half signs the id_token.
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = { ...(await exportJWK(publicKey)), kid: "entra-test-key", alg: "RS256", use: "sig" };
  // The flow's nonce is generated at authorize (inside the cookie). The token-endpoint
  // stub must return an id_token whose nonce matches it, so capture it after decoding
  // the authorize cookie into a mutable cell the closure reads.
  let capturedNonce = "UNSET";
  let tokenEndpointHits = 0;
  let signedIdToken = "";
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: URL | Request | string): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === entraJwksUrl(TENANT)) return new Response(JSON.stringify({ keys: [publicJwk] }), { status: 200, headers: { "content-type": "application/json" } });
    if (url === entraTokenEndpoint(TENANT)) {
      tokenEndpointHits++;
      const now = Math.floor(Date.now() / 1000);
      signedIdToken = await new SignJWT({ oid: OID, tid: TENANT, nonce: capturedNonce })
        .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: "entra-test-key" })
        .setIssuer(entraIssuer(TENANT)).setAudience(CLIENT_ID).setIssuedAt(now).setExpirationTime(now + 3600).sign(privateKey);
      return new Response(JSON.stringify({ id_token: signedIdToken, access_token: "UPSTREAM_ACCESS_SECRET", refresh_token: "UPSTREAM_REFRESH_SECRET" }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  try {
    const { app, store, config } = await buildExample({
      MCP_SSO_DIR: dir,
      ENTRA_TENANT_ID: TENANT,
      ENTRA_CLIENT_ID: CLIENT_ID,
      ENTRA_REDIRECT_URI: `${ISSUER}/oauth/callback`,
      OAUTH_ISSUER: ISSUER,
      OAUTH_RESOURCE: `${ISSUER}/mcp`,
      OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
      OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(jwk()),
      OAUTH_REDIRECT_ALLOWLIST: FLOW_REDIRECT,
      OAUTH_ALLOW_INSECURE_LOCALHOST: "true",
    });
    assert.equal(config.issuer, ISSUER);
    assert.ok(existsSync(dir), "the Entra branch created the state dir (parity with CF/pairing)");
    try {
      // register a client
      const reg = await app.inject({ method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" }, payload: JSON.stringify({ redirect_uris: [FLOW_REDIRECT] }) });
      assert.equal(reg.statusCode, 201);
      const clientId = json<{ client_id: string }>(reg).client_id;
      const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
      const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: FLOW_REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: "client-st" });

      // authorize → 302 to Entra + Set-Cookie (loopback variant: mcp-sso-upstream, no Secure/__Host-)
      const auth = await app.inject({ method: "GET", url: `/oauth/authorize?${q}` });
      assert.equal(auth.statusCode, 302);
      assert.match(auth.headers.location, /^https:\/\/login\.microsoftonline\.com\//, "302 to the Entra authorize endpoint");
      const sc = auth.headers["set-cookie"] as string;
      assert.match(sc, /^mcp-sso-upstream=[^;]+; Path=\/; HttpOnly; SameSite=Lax; Max-Age=600$/, "loopback cookie profile (no Secure/__Host-)");
      const cookieJwt = sc.slice("mcp-sso-upstream=".length, sc.indexOf(";"));
      const claims = decodeJwt(cookieJwt);
      assert.equal(claims.aud, "mcp-sso/upstream-flow", "distinct pinned audience");
      assert.ok((claims.jti as string).startsWith("upf_"));
      capturedNonce = claims.nonce as string; // the token-endpoint stub will bind the id_token to this

      // callback → validates (state/nonce/single-use jti), exchanges (stubbed), verifies, renders consent
      const cb = await app.inject({ method: "GET", url: `/oauth/callback?code=THE_CODE&state=${claims.state as string}`, headers: { cookie: `mcp-sso-upstream=${cookieJwt}` } });
      assert.equal(cb.statusCode, 200, "consent page is the DIRECT callback response");
      assert.match(cb.body, /Authorize access/);
      assert.match(cb.headers["set-cookie"] as string, /Max-Age=0/, "cookie cleared on the success callback");
      assert.equal(tokenEndpointHits, 1, "the upstream exchange happened exactly once");
      const consentToken = extractValue(cb.body, "consent_token");

      // approve → 302 with an auth code
      const approve = await app.inject({ method: "POST", url: "/oauth/authorize/approve", headers: { "content-type": "application/x-www-form-urlencoded", origin: ISSUER }, payload: new URLSearchParams({ consent_token: consentToken, approved: "true" }).toString() });
      assert.equal(approve.statusCode, 302);
      const authCode = new URL(approve.headers.location as string).searchParams.get("code");
      assert.ok(authCode);

      // token exchange
      const tokenResp = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "authorization_code", code: authCode as string, redirect_uri: FLOW_REDIRECT, client_id: clientId, code_verifier: verifier }).toString() });
      assert.equal(tokenResp.statusCode, 200);
      const { access_token: accessToken } = json<{ access_token: string }>(tokenResp);

      // protected /mcp via the official SDK client — the Entra oid reached /mcp
      await callProtectedMcp(app, config.resource, accessToken, "ping", `pong: ${OID}`);

      // REPLAY the same callback URL (the test held the original cookie + state + code):
      // the single-use jti is consumed, so the replay is 400 flow_replayed and the
      // upstream token endpoint is NOT hit a second time (row 6 precedes the exchange).
      const replay = await app.inject({ method: "GET", url: `/oauth/callback?code=THE_CODE&state=${claims.state as string}`, headers: { cookie: `mcp-sso-upstream=${cookieJwt}` } });
      assert.equal(replay.statusCode, 400, "replayed callback rejected");
      assert.equal(tokenEndpointHits, 1, "NO second exchange on replay");

      // no-secrets-on-disk: the audit file carries enum reasons + metadata only —
      // never the id_token, the upstream access/refresh tokens, the code, the nonce,
      // the upstream state, or the flow cookie value.
      const audit = readFileSync(join(dir, "audit.jsonl"), "utf8");
      for (const poison of ["UPSTREAM_ACCESS_SECRET", "UPSTREAM_REFRESH_SECRET", "THE_CODE", capturedNonce, claims.state as string, cookieJwt, signedIdToken]) {
        assert.equal(audit.includes(poison), false, `secret must not appear in the audit file: ${poison}`);
      }
      // the replayed callback was audited with its contracted enum reason (row 6).
      assert.ok(audit.includes("\"reason\":\"flow_replayed\""), "the replayed callback is audited as flow_replayed");
      assert.ok(audit.includes("\"event\":\"oauth.upstream.callback\""), "the upstream callback event is present");
    } finally {
      await app.close();
      await store.close();
    }
    void decodeJwt;
  } finally {
    globalThis.fetch = realFetch;
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — listen host: the Entra-redirect branch binds 0.0.0.0 (network deployment; the IdP is the gate)", () => {
  assert.equal(defaultListenHost({ ENTRA_TENANT_ID: "x" }), "0.0.0.0", "Entra branch → all interfaces");
  assert.equal(defaultListenHost({}), "127.0.0.1", "pairing mode → loopback (unchanged)");
});

interface FactoryCapture {
  google?: GoogleConfig;
  genericOidc?: GenericOidcConfig;
  exchangeCalls: number;
}

function stubIdentity(redirectUri: string, subject: string, provider: string, capture: FactoryCapture): RedirectIdentityPort {
  return {
    redirectUri,
    buildAuthorizationUrl({ state, nonce, codeChallenge }) {
      const query = new URLSearchParams({ state, nonce, code_challenge: codeChallenge, code_challenge_method: "S256" });
      return `https://${provider}.idp.test/authorize?${query}`;
    },
    async exchangeAndVerify() {
      capture.exchangeCalls++;
      return { ok: true, identity: { subject } };
    },
  };
}

function factories(subject: string): { identityFactories: OidcIdentityFactories; capture: FactoryCapture } {
  const capture: FactoryCapture = { exchangeCalls: 0 };
  return {
    capture,
    identityFactories: {
      async google(config) {
        capture.google = config;
        return stubIdentity(config.redirectUri, subject, "google", capture);
      },
      async genericOidc(config) {
        capture.genericOidc = config;
        return stubIdentity(config.redirectUri, subject, "generic", capture);
      },
    },
  };
}

test("integration — branch precedence remains Entra → Cloudflare → Google → generic OIDC → pairing", async () => {
  const allProvidersBase = mkdtempSync(join(tmpdir(), "mcp-sso-int-precedence-entra-"));
  const cfBase = mkdtempSync(join(tmpdir(), "mcp-sso-int-precedence-cf-"));
  const allStub = factories("unused");
  try {
    const { app, store } = await buildExample({
      ...bridgeEnv(join(allProvidersBase, "state")),
      ENTRA_TENANT_ID: TENANT, ENTRA_CLIENT_ID: CLIENT_ID, ENTRA_REDIRECT_URI: `${TEST_ORIGIN}/entra/callback`,
      CF_ACCESS_AUDIENCE: "cf-aud", CF_ACCESS_CERTS_URL: "https://cf.test/certs", CF_ACCESS_ISSUER: "https://cf.test",
      GOOGLE_CLIENT_ID: "google-client", GOOGLE_CLIENT_SECRET: "google-secret", GOOGLE_REDIRECT_URI: `${TEST_ORIGIN}/google/callback`,
      OIDC_ISSUER: "https://issuer.test", OIDC_CLIENT_ID: "oidc-client", OIDC_REDIRECT_URI: `${TEST_ORIGIN}/oidc/callback`,
    }, allStub.identityFactories);
    try {
      const reg = await app.inject({ method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" }, payload: JSON.stringify({ redirect_uris: [FLOW_REDIRECT] }) });
      const clientId = json<{ client_id: string }>(reg).client_id;
      const query = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: FLOW_REDIRECT, code_challenge: "x".repeat(43), code_challenge_method: "S256", scope: "mcp:read" });
      const authorize = await app.inject({ method: "GET", url: `/oauth/authorize?${query}` });
      assert.equal(authorize.statusCode, 302);
      assert.match(authorize.headers.location, /^https:\/\/login\.microsoftonline\.com\//, "Entra remains the highest-precedence branch");
      assert.equal(allStub.capture.google, undefined);
      assert.equal(allStub.capture.genericOidc, undefined);
    } finally { await app.close(); await store.close(); }

    const cfStub = factories("unused");
    const built = await buildExample({
      ...bridgeEnv(join(cfBase, "state")),
      CF_ACCESS_AUDIENCE: "cf-aud", CF_ACCESS_CERTS_URL: "https://cf.test/certs", CF_ACCESS_ISSUER: "https://cf.test",
      GOOGLE_CLIENT_ID: "google-client", GOOGLE_CLIENT_SECRET: "google-secret", GOOGLE_REDIRECT_URI: `${TEST_ORIGIN}/google/callback`,
      OIDC_ISSUER: "https://issuer.test", OIDC_CLIENT_ID: "oidc-client", OIDC_REDIRECT_URI: `${TEST_ORIGIN}/oidc/callback`,
    }, cfStub.identityFactories);
    try {
      const response = await built.app.inject({ method: "GET", url: "/oauth/authorize?client_id=c&redirect_uri=http://localhost:4321/callback" });
      assert.equal(response.statusCode, 401, "Cloudflare remains ahead of Google/generic OIDC (missing assertion rejects)");
      assert.equal(cfStub.capture.google, undefined);
      assert.equal(cfStub.capture.genericOidc, undefined);
    } finally { await built.app.close(); await built.store.close(); }
  } finally {
    rmSync(allProvidersBase, { recursive: true, force: true });
    rmSync(cfBase, { recursive: true, force: true });
  }
});

const TEST_ORIGIN = "http://localhost:3000";
const INIT_BODY = JSON.stringify({ jsonrpc: "2.0", method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "0" } }, id: 1 });

function bridgeEnv(dir: string): Record<string, string> {
  return {
    MCP_SSO_DIR: dir,
    OAUTH_ISSUER: TEST_ORIGIN,
    OAUTH_RESOURCE: `${TEST_ORIGIN}/mcp`,
    OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
    OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(jwk()),
    OAUTH_REDIRECT_ALLOWLIST: FLOW_REDIRECT,
    OAUTH_ALLOW_INSECURE_LOCALHOST: "true",
  };
}

async function driveStubbedUpstreamFlow(args: {
  app: { inject(input: unknown): Promise<unknown> };
  resource: string;
  callbackPath: string;
  provider: string;
  capture: FactoryCapture;
  subject: string;
  toolName: string;
  expectedText: string | RegExp;
}): Promise<void> {
  const { app } = args;
  const reg = await app.inject({ method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" }, payload: JSON.stringify({ redirect_uris: [FLOW_REDIRECT] }) }) as { statusCode: number; body: string };
  assert.equal(reg.statusCode, 201);
  const clientId = JSON.parse(reg.body).client_id as string;
  const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
  const query = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: FLOW_REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: "client-state" });

  const authorize = await app.inject({ method: "GET", url: `/oauth/authorize?${query}` }) as { statusCode: number; headers: Record<string, string> };
  assert.equal(authorize.statusCode, 302, `${args.provider}: upstream branch selected`);
  assert.match(authorize.headers.location ?? "", new RegExp(`^https://${args.provider}\\.idp\\.test/authorize\\?`));
  const setCookie = authorize.headers["set-cookie"];
  assert.ok(setCookie, `${args.provider}: flow cookie set`);
  const cookieJwt = setCookie.slice("mcp-sso-upstream=".length, setCookie.indexOf(";"));
  const claims = decodeJwt(cookieJwt);

  const callbackUrl = `${args.callbackPath}?code=stub-code&state=${claims.state as string}`;
  const callbackHeaders = { cookie: `mcp-sso-upstream=${cookieJwt}` };
  const callback = await app.inject({ method: "GET", url: callbackUrl, headers: callbackHeaders }) as { statusCode: number; body: string };
  assert.equal(callback.statusCode, 200, `${args.provider}: callback route mounted and consent rendered`);
  const consentToken = extractValue(callback.body, "consent_token");
  assert.equal(args.capture.exchangeCalls, 1, `${args.provider}: callback exchanged once`);

  const replay = await app.inject({ method: "GET", url: callbackUrl, headers: callbackHeaders }) as { statusCode: number };
  assert.equal(replay.statusCode, 400, `${args.provider}: replayed callback rejected`);
  assert.equal(args.capture.exchangeCalls, 1, `${args.provider}: replay did not exchange again`);

  const approve = await app.inject({ method: "POST", url: "/oauth/authorize/approve", headers: { "content-type": "application/x-www-form-urlencoded", origin: TEST_ORIGIN }, payload: new URLSearchParams({ consent_token: consentToken, approved: "true" }).toString() }) as { statusCode: number; headers: Record<string, string> };
  assert.equal(approve.statusCode, 302);
  const approveLocation = approve.headers.location;
  assert.ok(approveLocation);
  const code = new URL(approveLocation).searchParams.get("code");
  assert.ok(code);
  const token = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: FLOW_REDIRECT, client_id: clientId, code_verifier: verifier }).toString() }) as { statusCode: number; body: string };
  assert.equal(token.statusCode, 200);
  const accessToken = JSON.parse(token.body).access_token as string;

  const tokenless = await app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json" }, payload: INIT_BODY }) as { statusCode: number; headers: Record<string, string> };
  assert.equal(tokenless.statusCode, 401, `${args.provider}: tokenless /mcp rejected`);
  assert.match(tokenless.headers["www-authenticate"] ?? "", /^Bearer resource_metadata=/, `${args.provider}: PRM challenge returned`);
  const foreignOrigin = await app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json", origin: "https://evil.test" }, payload: INIT_BODY }) as { statusCode: number };
  assert.equal(foreignOrigin.statusCode, 403, `${args.provider}: foreign Origin rejected`);

  await callProtectedMcp(app, args.resource, accessToken, args.toolName, args.expectedText);
}

for (const provider of ["google", "generic"] as const) {
  test(`integration — ${provider}: buildExample selects branch and completes authorize→callback→consent→token→/mcp with negatives`, async () => {
    const base = mkdtempSync(join(tmpdir(), `mcp-sso-int-${provider}-example-`));
    const dir = join(base, "state");
    const subject = provider === "google" ? "123456789012345678901" : "https://issuer.test|generic-user";
    const callbackPath = provider === "google" ? "/google/callback" : "/oidc/callback";
    const env = {
      ...bridgeEnv(dir),
      ...(provider === "google" ? {
        GOOGLE_CLIENT_ID: "google-client", GOOGLE_CLIENT_SECRET: "google-secret",
        GOOGLE_REDIRECT_URI: `${TEST_ORIGIN}${callbackPath}`, GOOGLE_HOSTED_DOMAIN: "example.com",
        GOOGLE_SUBJECT_ALLOWLIST: `${subject},second-subject`, GOOGLE_ALLOW_EMAIL_ALLOWLIST: "true",
      } : {
        OIDC_ISSUER: "https://issuer.test", OIDC_CLIENT_ID: "oidc-client", OIDC_CLIENT_SECRET: "oidc-secret",
        OIDC_REDIRECT_URI: `${TEST_ORIGIN}${callbackPath}`, OIDC_SCOPES: "openid profile groups",
        OIDC_SUBJECT_ALLOWLIST: "generic-user,second-subject",
      }),
    };
    const stub = factories(subject);
    try {
      const { app, store, config } = await buildExample(env, stub.identityFactories);
      try {
        if (provider === "google") {
          assert.deepEqual(stub.capture.google, {
            clientId: "google-client", clientSecret: "google-secret", redirectUri: `${TEST_ORIGIN}${callbackPath}`,
            hostedDomain: "example.com", subjectAllowlist: [subject, "second-subject"], allowEmailAllowlist: true,
          });
          assert.equal(stub.capture.genericOidc, undefined, "Google wins its branch without constructing generic OIDC");
        } else {
          assert.deepEqual(stub.capture.genericOidc, {
            issuer: "https://issuer.test", clientId: "oidc-client", clientSecret: "oidc-secret",
            redirectUri: `${TEST_ORIGIN}${callbackPath}`, endpoints: "discover", scopes: "openid profile groups",
            subjectAllowlist: ["generic-user", "second-subject"],
          });
          assert.equal(stub.capture.google, undefined);
        }
        await driveStubbedUpstreamFlow({ app, resource: config.resource, callbackPath, provider, capture: stub.capture, subject, toolName: "ping", expectedText: `pong: ${subject}` });
      } finally { await app.close(); await store.close(); }
    } finally { rmSync(base, { recursive: true, force: true }); }
  });

  test(`integration — ${provider}: buildGatewayExample selects the same branch and proxies the protected /mcp round trip`, async () => {
    const base = mkdtempSync(join(tmpdir(), `mcp-sso-int-${provider}-gateway-`));
    const dir = join(base, "state");
    const subject = provider === "google" ? "987654321098765432109" : "https://issuer.test|gateway-user";
    const callbackPath = provider === "google" ? "/google/callback" : "/oidc/callback";
    const backendKey = `backend-${provider}-secret`;
    const backend = await buildBackend({ apiKey: backendKey });
    await backend.app.listen({ port: 0, host: "127.0.0.1" });
    const address = backend.app.server.address() as AddressInfo;
    const stub = factories(subject);
    const env = {
      ...bridgeEnv(dir),
      ...(provider === "google" ? {
        GOOGLE_CLIENT_ID: "google-gateway-client", GOOGLE_CLIENT_SECRET: "google-gateway-secret",
        GOOGLE_REDIRECT_URI: `${TEST_ORIGIN}${callbackPath}`,
      } : {
        OIDC_ISSUER: "https://issuer.test", OIDC_CLIENT_ID: "oidc-gateway-client",
        OIDC_REDIRECT_URI: `${TEST_ORIGIN}${callbackPath}`,
      }),
    };
    try {
      const { app, store, config } = await buildGatewayExample(env, {
        backendUrl: `http://127.0.0.1:${address.port}/mcp`,
        getBackendCredential: () => backendKey,
        identityFactories: stub.identityFactories,
      });
      try {
        if (provider === "google") assert.equal(stub.capture.google?.clientId, "google-gateway-client");
        else {
          assert.equal(stub.capture.genericOidc?.clientId, "oidc-gateway-client");
          assert.equal(stub.capture.genericOidc?.clientSecret, undefined, "generic OIDC public-client mode preserved when the optional secret is absent");
        }
        await driveStubbedUpstreamFlow({ app, resource: config.resource, callbackPath, provider, capture: stub.capture, subject, toolName: "status", expectedText: /"backend":"stub-backend-v1"/ });
      } finally { await app.close(); await store.close(); }
    } finally {
      await backend.close();
      rmSync(base, { recursive: true, force: true });
    }
  });
}
