// Integration tests of the STANDALONE ENTRY wiring (examples/fastify-sqlite's
// buildExample — what index.ts calls). The earlier e2e tests drove buildApp()
// directly, so index.ts's branch selection / state-dir creation / sqlite+audit
// path derivation were never exercised — which is why the "CF branch doesn't
// create the dir" crash, the "routes CF startup to pairing" misrouting, and the
// "drops sqliteFile" regressions all shipped past 179 green unit tests. These
// tests cover exactly that wiring, both branches.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { pkceChallenge } from "../src/crypto.ts";
import { AuthConfigError } from "../src/config.ts";
import { buildExample, defaultListenHost } from "../examples/fastify-sqlite/app.ts";

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }) } as JWK;
}

const AUTHORIZE_QUERY = "/oauth/authorize?response_type=code&client_id=c&redirect_uri=http://localhost/cb&code_challenge=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx&code_challenge_method=S256&scope=mcp:read";

test("integration — zero-setup branch: buildExample creates a fresh state dir, runs quickstart, selects pairing", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-zs-"));
  const dir = join(base, "nested-state"); // does NOT exist — buildExample must create it
  try {
    const { app, store } = await buildExample({ MCP_SSO_DIR: dir });
    // quickstart created the signing material + .gitignore + the dir.
    assert.ok(existsSync(dir), "state dir created");
    assert.ok(existsSync(join(dir, "secrets.json")), "quickstart wrote secrets.json");
    assert.ok(existsSync(join(dir, ".gitignore")), "quickstart wrote .gitignore");
    // Pairing mode (NOT header-based): GET /oauth/authorize renders the pairing page.
    const page = await app.inject({ method: "GET", url: AUTHORIZE_QUERY });
    assert.equal(page.statusCode, 200);
    assert.match(page.body, /Pair this device/);
    await app.close();
    await store.close();
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — Cloudflare Access branch: buildExample creates the state dir, opens auth.db, selects CF identity (NOT pairing)", async () => {
  // This is the regression class that shipped untested: the CF branch derives
  // auth.db/audit.jsonl under MCP_SSO_DIR but must also CREATE that dir, or
  // openSqliteStore crashes ("unable to open database file") and audit appends
  // fail. It also must not route to pairing.
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-cf-"));
  const dir = join(base, "nested-state"); // does NOT exist
  try {
    const key = jwk();
    const { app, store, config } = await buildExample({
      MCP_SSO_DIR: dir,
      CF_ACCESS_AUDIENCE: "https://cf.test/aud",
      CF_ACCESS_CERTS_URL: "https://cf.test/certs",
      CF_ACCESS_ISSUER: "https://cf.test",
      OAUTH_ISSUER: "http://localhost",
      OAUTH_RESOURCE: "http://localhost/mcp",
      OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
      OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(key),
      OAUTH_ALLOW_INSECURE_LOCALHOST: "true",
    });
    assert.equal(config.issuer, "http://localhost");
    assert.ok(existsSync(dir), "CF branch created the state dir (the regression)");
    assert.ok(existsSync(join(dir, "auth.db")), "sqlite opened auth.db in the state dir");
    assert.ok(existsSync(join(dir, ".gitignore")), "CF branch protected the state dir from git (managed .gitignore)");
    // CF header-based identity (NOT pairing): no Cf-Access-Jwt-Assertion → 401,
    // not the 200 pairing page.
    const page = await app.inject({ method: "GET", url: AUTHORIZE_QUERY });
    assert.equal(page.statusCode, 401);
    await app.close();
    await store.close();
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — Cloudflare Access branch rejects a group/other-accessible pre-existing state dir", async () => {
  // A world-writable MCP_SSO_DIR lets another local user replace auth.db with
  // OAuth state they control. The CF branch must mirror quickstart's assertRealDir.
  if (process.platform === "win32") return;
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-cf-unsafe-"));
  const dir = join(base, "state");
  mkdirSync(dir, { recursive: true, mode: 0o777 });
  chmodSync(dir, 0o777);
  writeFileSync(join(dir, ".gitignore"), "*\n", { mode: 0o600 }); // valid ignore → only the dir mode is at fault
  try {
    await assert.rejects(
      buildExample({ MCP_SSO_DIR: dir, CF_ACCESS_AUDIENCE: "https://cf.test/aud" }),
      AuthConfigError,
    );
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — listen host: pairing binds loopback; Cloudflare binds 0.0.0.0 (HOST overrides)", () => {
  // Pairing's trust envelope is single-operator/private-console: the authorize
  // surface + the printed-code attempt budget must not be exposed to the network
  // by default. CF/proxy is externally bound (fronted by CF / a reverse proxy).
  assert.equal(defaultListenHost({}), "127.0.0.1", "pairing mode → loopback");
  assert.equal(defaultListenHost({ CF_ACCESS_AUDIENCE: "x" }), "0.0.0.0", "CF mode → all interfaces");
});

test("integration — OAUTH_SQLITE_FILE overrides the default auth.db location (both branches)", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-sql-"));
  const dir = join(base, "state");
  const customDb = join(base, "custom.db");
  try {
    await buildExample({ MCP_SSO_DIR: dir, OAUTH_SQLITE_FILE: customDb });
    assert.ok(existsSync(customDb), "OAUTH_SQLITE_FILE honored (custom db created)");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Flow-level entry wiring (the boot-level tests above stop at GET /authorize).
// These drive register → authorize → (pairing or CF header) → consent → approve
// → token → protected /mcp → refresh through buildExample — the actual index.ts
// path. Both catch the S1b wiring-bug class (branch routing, sqliteFile, dir
// creation) at the flow level, not just boot.
// ---------------------------------------------------------------------------

const FLOW_REDIRECT = "http://localhost:4321/callback";

function extractValue(html: string, name: string): string {
  const m = new RegExp(`name="${name}" value="([^"]+)"`).exec(html);
  assert.ok(m?.[1], `hidden field ${name} not found`);
  return m[1] as string;
}

/** Parse a fastify inject response body. (buildExample's app is typed as
 *  ReturnType<typeof Fastify>, whose inject reply's .json() is untyped — so parse
 *  the body explicitly.) */
function json<T>(res: { body: unknown }): T {
  assert.equal(typeof res.body, "string", "inject response body is a string");
  return JSON.parse(res.body as string) as T;
}

function extractPairingCode(text: string): string {
  const m = /code: ([BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4})/.exec(text);
  assert.ok(m?.[1], "pairing code not printed");
  return m[1]!.replace(/-/g, "");
}

/** Route the official MCP SDK client through the in-process Fastify app (so a test
 *  can call protected /mcp without a TCP socket). Mirrors e2e-pairing's shim. */
function sdkFetchShim(app: { inject(args: unknown): Promise<unknown> }): typeof fetch {
  return (async (url: URL | string, init?: { method?: string; headers?: unknown; body?: unknown }): Promise<Response> => {
    const u = url instanceof URL ? url : new URL(String(url));
    const headers: Record<string, string> = {};
    const src = init?.headers;
    if (src instanceof Headers) src.forEach((v, k) => { headers[k] = v; });
    else if (src && typeof src === "object") for (const [k, v] of Object.entries(src as Record<string, string>)) headers[k] = v;
    const method = (init?.method ?? "POST") as "POST";
    const payload = init?.body === undefined || init?.body === null
      ? undefined
      : typeof init.body === "string" ? init.body : JSON.stringify(init.body);
    const r = await app.inject(payload === undefined ? { method, url: u.pathname + u.search, headers } : { method, url: u.pathname + u.search, headers, payload }) as unknown as { statusCode: number; headers: Record<string, string>; body: string };
    return new Response(r.body, { status: r.statusCode, headers: r.headers });
  }) as typeof fetch;
}

/** Race a promise against a hard deadline (reject after `ms` with `label`). The MCP
 *  SDK transport overrides requestInit.signal with its own AbortController.signal, so
 *  the abort lever is transport.close() (in the caller's finally), not a bounded
 *  requestInit.signal. (Sweep of the Codex P2 on the full-flow driver.) */
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
  });
}

async function callProtectedMcp(app: { inject(args: unknown): Promise<unknown> }, resource: string, accessToken: string, expectedSubject: string, extraHeaders: Record<string, string> = {}): Promise<void> {
  const transport = new StreamableHTTPClientTransport(new URL(resource), { fetch: sdkFetchShim(app) as never, requestInit: { headers: { authorization: `Bearer ${accessToken}`, ...extraHeaders } } });
  const client = new Client({ name: "int-entry-flow", version: "0.0.1" }, { capabilities: {} });
  try {
    await withTimeout(client.connect(transport), 10_000, "MCP client connect");
    const result = await withTimeout(client.callTool({ name: "ping", arguments: {} }), 10_000, "MCP client callTool");
    const text = (result.content as Array<{ type: string; text?: string }>).find((c) => c.type === "text")?.text;
    assert.equal(text, `pong: ${expectedSubject}`, "the entry-resolved subject reached /mcp");
  } finally {
    await client.close();
    await transport.close();
  }
}

test("integration — zero-setup branch: full flow through the entry (pairing code from stderr → token → /mcp → refresh)", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-zsflow-"));
  const dir = join(base, "state"); // does NOT exist — buildExample must create it
  const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
  const ORIGIN = "http://localhost:3000";
  try {
    const { app, store, config } = await buildExample({
      MCP_SSO_DIR: dir,
      OAUTH_ISSUER: ORIGIN,
      OAUTH_RESOURCE: `${ORIGIN}/mcp`,
      OAUTH_REDIRECT_ALLOWLIST: FLOW_REDIRECT,
    });
    try {
      const reg = await app.inject({ method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" }, payload: JSON.stringify({ redirect_uris: [FLOW_REDIRECT] }) });
      assert.equal(reg.statusCode, 201);
      const clientId = json<{ client_id: string }>(reg).client_id;
      const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: FLOW_REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: "s1" });

      // GET /authorize renders the pairing page; the code is printed to process.stderr
      // (buildExample passes pairing:{}, so ConsolePairingOptions.output defaults to
      // process.stderr — no env seam). Capture by wrapping process.stderr.write and
      // restore in finally so a failure can't corrupt the run's stderr. node --test
      // runs each file in its own process, so this never touches another file's stderr.
      let code: string;
      let pairingNonce: string;
      const originalWrite = process.stderr.write.bind(process.stderr);
      const chunks: string[] = [];
      process.stderr.write = ((s: string | Uint8Array): boolean => {
        chunks.push(typeof s === "string" ? s : Buffer.from(s).toString());
        return true;
      }) as typeof process.stderr.write;
      try {
        const pairingPage = await app.inject({ method: "GET", url: `/oauth/authorize?${q}` });
        assert.equal(pairingPage.statusCode, 200);
        assert.match(pairingPage.body, /Pair this device/);
        pairingNonce = extractValue(pairingPage.body, "pairing_nonce");
        code = extractPairingCode(chunks.join(""));
      } finally {
        process.stderr.write = originalWrite;
      }

      // POST the pasted code + nonce → consent page.
      const consentPage = await app.inject({ method: "POST", url: "/oauth/authorize", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ ...Object.fromEntries(q), pairing_code: code, pairing_nonce: pairingNonce }).toString() });
      assert.equal(consentPage.statusCode, 200);
      assert.match(consentPage.body, /Authorize access/);
      const consentToken = extractValue(consentPage.body, "consent_token");

      // Approve → 302 with an auth code.
      const approve = await app.inject({ method: "POST", url: "/oauth/authorize/approve", headers: { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN }, payload: new URLSearchParams({ consent_token: consentToken, approved: "true" }).toString() });
      assert.equal(approve.statusCode, 302);
      const authCode = new URL(approve.headers.location as string).searchParams.get("code");
      assert.ok(authCode);

      // Exchange → tokens.
      const tokenResp = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "authorization_code", code: authCode as string, redirect_uri: FLOW_REDIRECT, client_id: clientId, code_verifier: verifier }).toString() });
      assert.equal(tokenResp.statusCode, 200);
      const { access_token: accessToken, refresh_token: refreshToken } = json<{ access_token: string; refresh_token: string }>(tokenResp);

      // Protected /mcp via the OFFICIAL MCP SDK client — the pairing-resolved
      // subject ("console-operator") reaches /mcp through the entry wiring.
      await callProtectedMcp(app, config.resource, accessToken, "console-operator");
      // A PRESENT, allowlisted Origin on /mcp is admitted by the Origin gate: the
      // full SDK round-trip still succeeds (the MCP client sends no Origin by
      // default; this injects the allowlisted one to exercise the gate's admit
      // path, not only the absent-Origin path every other call proves).
      await callProtectedMcp(app, config.resource, accessToken, "console-operator", { origin: ORIGIN });

      // Refresh rotates.
      const refreshed = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId }).toString() });
      assert.equal(refreshed.statusCode, 200);
      assert.notEqual(json<{ refresh_token: string }>(refreshed).refresh_token, refreshToken);
    } finally {
      await app.close();
      await store.close();
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — Cloudflare Access branch: full header flow through the entry (in-test JWKS + signed RS256 Access JWT, zero real network) → token → /mcp → refresh", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-cfflow-"));
  const dir = join(base, "state");
  const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
  const ORIGIN = "http://localhost";
  const CERTS_URL = "https://cf.test/certs";
  const CF_ISSUER = "https://cf.test";
  const CF_AUDIENCE = "https://cf.test/aud";

  // RSA keypair for the CF Access JWT: the public half is served as JWKS at the
  // https certsUrl (stubbed globalThis.fetch), the private half signs the assertion.
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = { ...(await exportJWK(publicKey)), kid: "cf-test-key", alg: "RS256", use: "sig" };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: URL | Request | string): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === CERTS_URL) return new Response(JSON.stringify({ keys: [publicJwk] }), { status: 200, headers: { "content-type": "application/json" } });
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  try {
    const signingKey = jwk(); // the bridge's own ES256 access-token key (from env)
    const { app, store, config } = await buildExample({
      MCP_SSO_DIR: dir,
      CF_ACCESS_AUDIENCE: CF_AUDIENCE,
      CF_ACCESS_CERTS_URL: CERTS_URL,
      CF_ACCESS_ISSUER: CF_ISSUER,
      OAUTH_ISSUER: ORIGIN,
      OAUTH_RESOURCE: `${ORIGIN}/mcp`,
      OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
      OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(signingKey),
      OAUTH_REDIRECT_ALLOWLIST: FLOW_REDIRECT,
      OAUTH_ALLOW_INSECURE_LOCALHOST: "true",
    });
    assert.equal(config.issuer, ORIGIN);
    try {
      const reg = await app.inject({ method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" }, payload: JSON.stringify({ redirect_uris: [FLOW_REDIRECT] }) });
      assert.equal(reg.statusCode, 201);
      const clientId = json<{ client_id: string }>(reg).client_id;

      // A valid CF Access JWT (RS256, matching the served JWKS; aud/iss/exp per the
      // port's checks). Sent in the cf-access-jwt-assertion header → resolveIdentity.
      const now = Math.floor(Date.now() / 1000);
      const cfJwt = await new SignJWT({ email: "operator@cf.test", sub: "cf-operator" })
        .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: "cf-test-key" })
        .setIssuer(CF_ISSUER).setAudience(CF_AUDIENCE).setIssuedAt(now).setExpirationTime(now + 3600)
        .sign(privateKey);

      const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: FLOW_REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: "s1" });
      const authPage = await app.inject({ method: "GET", url: `/oauth/authorize?${q}`, headers: { "cf-access-jwt-assertion": cfJwt } });
      assert.equal(authPage.statusCode, 200, "CF identity accepted → consent page (NOT 401, NOT the pairing page)");
      assert.match(authPage.body, /Authorize access/);
      const consentToken = extractValue(authPage.body, "consent_token");

      const approve = await app.inject({ method: "POST", url: "/oauth/authorize/approve", headers: { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN }, payload: new URLSearchParams({ consent_token: consentToken, approved: "true" }).toString() });
      assert.equal(approve.statusCode, 302);
      const authCode = new URL(approve.headers.location as string).searchParams.get("code");
      assert.ok(authCode);

      const tokenResp = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "authorization_code", code: authCode as string, redirect_uri: FLOW_REDIRECT, client_id: clientId, code_verifier: verifier }).toString() });
      assert.equal(tokenResp.statusCode, 200);
      const { access_token: accessToken, refresh_token: refreshToken } = json<{ access_token: string; refresh_token: string }>(tokenResp);

      // The CF-resolved subject (sub) reaches /mcp through the entry wiring.
      await callProtectedMcp(app, config.resource, accessToken, "cf-operator");

      const refreshed = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId }).toString() });
      assert.equal(refreshed.statusCode, 200);
      assert.notEqual(json<{ refresh_token: string }>(refreshed).refresh_token, refreshToken);

      // A WRONG-audience CF JWT is rejected (the CF port's own gate, through the entry).
      const badAud = await new SignJWT({ email: "operator@cf.test", sub: "cf-operator" }).setProtectedHeader({ alg: "RS256", typ: "JWT", kid: "cf-test-key" }).setIssuer(CF_ISSUER).setAudience("https://evil.test").setIssuedAt(now).setExpirationTime(now + 3600).sign(privateKey);
      const rejected = await app.inject({ method: "GET", url: `/oauth/authorize?${q}`, headers: { "cf-access-jwt-assertion": badAud } });
      assert.equal(rejected.statusCode, 401, "CF JWT with the wrong audience is rejected (fail-closed)");
    } finally {
      await app.close();
      await store.close();
    }
  } finally {
    globalThis.fetch = realFetch;
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — /mcp Origin gate (MCP Streamable HTTP DNS-rebinding MUST): foreign Origin ⇒ 403 before parsing/auth on ALL methods; absent/allowlisted ⇒ proceed", async () => {
  // The MCP Streamable HTTP transport says servers MUST validate `Origin` on every
  // connection. The example enforces it in an onRequest hook scoped to /mcp — BEFORE
  // body parsing and for EVERY method (POST/GET/DELETE) — so a foreign Origin is
  // 403'd before authorize() AND before Fastify's body parser (a malformed/oversized
  // body with a foreign Origin still gets 403, not 400/413), while an absent Origin
  // (MCP clients are not browsers) or an allowlisted Origin proceeds to 401 (no token).
  const ORIGIN = "http://localhost:3000";
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-origin-"));
  const dir = join(base, "state");
  const init = JSON.stringify({ jsonrpc: "2.0", method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "0" } }, id: 1 });
  try {
    const { app, store } = await buildExample({ MCP_SSO_DIR: dir, OAUTH_ISSUER: ORIGIN, OAUTH_RESOURCE: `${ORIGIN}/mcp` });
    try {
      // Foreign Origin ⇒ 403, and the resource-server challenge is NOT emitted
      // (authorize() never ran).
      const evil = await app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json", origin: "https://evil.test" }, payload: init });
      assert.equal(evil.statusCode, 403, "foreign Origin rejected before authorization");
      assert.doesNotMatch(evil.headers["www-authenticate"] ?? "", /resource_metadata=/, "Origin gate fires before the authorize leg — no challenge");

      // Foreign Origin on GET and DELETE ⇒ 403 too — the hook is method-agnostic, not
      // a POST-handler-only check.
      const evilGet = await app.inject({ method: "GET", url: "/mcp", headers: { origin: "https://evil.test" } });
      assert.equal(evilGet.statusCode, 403, "foreign Origin rejected on GET (method coverage)");
      const evilDelete = await app.inject({ method: "DELETE", url: "/mcp", headers: { origin: "https://evil.test" } });
      assert.equal(evilDelete.statusCode, 403, "foreign Origin rejected on DELETE (method coverage)");

      // Foreign Origin beats body parsing: malformed JSON with a foreign Origin gets
      // 403, not Fastify's 400 body-parse error.
      const evilBadBody = await app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json", origin: "https://evil.test" }, payload: "{not valid json" });
      assert.equal(evilBadBody.statusCode, 403, "foreign Origin rejected before body parsing (malformed JSON ⇒ 403, not 400)");

      // Allowlisted Origin ⇒ proceeds to the bearer check ⇒ 401 + challenge.
      const allowlisted = await app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json", origin: ORIGIN }, payload: init });
      assert.equal(allowlisted.statusCode, 401, "allowlisted Origin proceeds to the bearer check");
      assert.match(allowlisted.headers["www-authenticate"] ?? "", /^Bearer resource_metadata=/, "reached the resource-server leg");

      // Absent Origin (non-browser client — the normal MCP case) ⇒ proceeds ⇒ 401.
      const absent = await app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json" }, payload: init });
      assert.equal(absent.statusCode, 401, "absent Origin proceeds to the bearer check");
      assert.match(absent.headers["www-authenticate"] ?? "", /^Bearer resource_metadata=/, "reached the resource-server leg");
    } finally {
      await app.close();
      await store.close();
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — /mcp Origin gate admits the issuer origin even when allowedOrigins carries the raw (un-normalized) issuer (trailing slash)", async () => {
  // Regression for the normalization gap: allowedOrigins defaults to the RAW
  // OAUTH_ISSUER string, but a browser serializes Origin to scheme://host[:port]
  // (no trailing slash/path). An issuer set with a trailing slash would make the
  // gate 403 a same-origin browser request on a string mismatch — while the
  // consent approve flow (src/authorize.ts assertOrigin) admits it via
  // originOf(issuer). The gate mirrors assertOrigin: originOf(issuer) is admitted.
  const ISSUER = "http://localhost:3000/"; // trailing slash — a common misconfig
  const BROWSER_ORIGIN = "http://localhost:3000"; // what a browser sends (== originOf(issuer))
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-origin-norm-"));
  const dir = join(base, "state");
  const init = JSON.stringify({ jsonrpc: "2.0", method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "0" } }, id: 1 });
  try {
    // allowedOrigins defaults to [ISSUER] = ["http://localhost:3000/"] (raw, slash).
    const { app, store, config } = await buildExample({ MCP_SSO_DIR: dir, OAUTH_ISSUER: ISSUER, OAUTH_RESOURCE: "http://localhost:3000/mcp" });
    assert.deepEqual(config.allowedOrigins, [ISSUER], "allowedOrigins is the raw, trailing-slash issuer (not normalized)");
    try {
      // Browser sends the normalized origin. Without originOf(issuer) admission this
      // is 403 (string mismatch); with it, the gate admits it → proceeds to the
      // bearer check → 401 (no token).
      const res = await app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json", origin: BROWSER_ORIGIN }, payload: init });
      assert.equal(res.statusCode, 401, "issuer origin admitted despite the raw allowedOrigins mismatch (originOf normalization) → reached the bearer check");
      assert.match(res.headers["www-authenticate"] ?? "", /^Bearer resource_metadata=/, "reached the resource-server leg, not the 403 Origin gate");
    } finally {
      await app.close();
      await store.close();
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
