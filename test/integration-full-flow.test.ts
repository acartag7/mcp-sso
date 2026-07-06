// Cross-adapter full /mcp round-trip + store×flow integration (closes the S1b
// coverage gap: the entry wiring, the cross-adapter full flow, store×flow, and
// the real process — exactly what let S1b's wiring bugs ship past 187 green unit
// tests). TEST-ONLY: drives the SHIPPED adapters/stores/examples; no src seams.
//
// Self-contained mount + driver helpers. Deliberately does NOT import
// test/lib/adapter-flow.ts — S2a changes the identity signature there, and this
// suite must not merge-conflict with it. The full /mcp round-trip already exists
// for fastify (test/e2e-mcp-sdk.test.ts); this file adds it for express + hono,
// then reuses the same driver for the sqlite-FILE and mysql stores.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { request as httpRequest, createServer, type Server } from "node:http";
import { createPool } from "mysql2/promise";
import type { IncomingMessage, ServerResponse } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import express from "express";
import { Hono } from "hono";
import type { JWK } from "jose";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig, originOf, type BridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import { buildUnauthorizedChallenge } from "../src/challenge.ts";
import { RequestAuthorizer } from "../src/verifier.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { noopAudit } from "../src/ports/audit.ts";
import type { IdentityPort } from "../src/ports/identity.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { openSqliteStore } from "../src/store/sqlite.ts";
import { MysqlStore, createMysqlStore } from "../src/store/mysql.ts";
import { createOAuthRouter } from "../src/adapters/express.ts";
import { createOAuthApp } from "../src/adapters/hono.ts";

const REDIRECT = "http://127.0.0.1:9/callback"; // any loopback callback; allowlisted below
const SUBJECT = "agent@test";
const STUB_TOKEN = "stub-good";
const IDENTITY_HEADER = "cf-access-jwt-assertion";

const stubIdentity: IdentityPort = {
  async verify(input: unknown) {
    return input === STUB_TOKEN ? { ok: true, identity: { subject: SUBJECT } } : { ok: false, reason: "bad_token" };
  },
};

function ecJwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK;
}

/** Build a loopback config. `issuer` may be port-less (stable across restart);
 *  `resource` is the real per-port /mcp URL. Both must be loopback for the dev flag. */
function makeConfig(opts: { resource: string; issuer: string; signingPrivateJwk?: JWK; consentSigningSecret?: string }): BridgeConfig {
  return createBridgeConfig({
    issuer: opts.issuer,
    resource: opts.resource,
    consentSigningSecret: opts.consentSigningSecret ?? "c".repeat(40),
    signingPrivateJwk: opts.signingPrivateJwk ?? ecJwk(),
    signingKeyId: "k",
    redirectAllowlist: [REDIRECT],
    scopeCatalog: ["mcp:read", "mcp:write"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: [originOf(opts.issuer)],
    dcr: { mode: "stateless" },
    dev: { allowInsecureLocalhost: true },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.unref();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const addr = s.address();
      if (addr && typeof addr === "object") {
        const port = addr.port;
        s.close(() => resolve(port));
      } else {
        s.close();
        reject(new Error("could not bind a free port"));
      }
    });
  });
}

interface Resp { status: number; headers: Record<string, string>; body: string; location: string | undefined }

/** Race a promise against a hard deadline (reject after `ms` with `label`). For the
 *  MCP SDK client ops: its transport overrides requestInit.signal with its own
 *  AbortController.signal, so the abort lever is transport.close() (in the caller's
 *  finally), not a bounded requestInit.signal. */
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
  });
}

function httpCall(base: string, method: string, path: string, headers: Record<string, string>, body?: string): Promise<Resp> {
  return new Promise((resolve, reject) => {
    const url = new URL(base + path);
    const req = httpRequest({ hostname: url.hostname, port: url.port, path: url.pathname + url.search, method, headers, timeout: 10_000 }, (res) => {
      let buf = "";
      res.setEncoding("utf8");
      res.on("data", (c: string) => { buf += c; });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers as Record<string, string>, body: buf, location: res.headers.location as string | undefined }));
    });
    // Hang-guard: a server that accepts the socket but never responds (e.g. a
    // server-side throw that leaves the reply open) must fail the test, not hang it
    // to the CI job timeout. node --test has no per-test timeout.
    req.on("timeout", () => req.destroy(new Error(`http ${method} ${path} timed out after 10s`)));
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

const http = {
  get: (base: string, path: string, headers: Record<string, string> = {}) => httpCall(base, "GET", path, headers),
  postForm: (base: string, path: string, body: Record<string, string>, headers: Record<string, string> = {}) =>
    httpCall(base, "POST", path, { "content-type": "application/x-www-form-urlencoded", ...headers }, new URLSearchParams(body).toString()),
  postJson: (base: string, path: string, body: unknown, headers: Record<string, string> = {}) =>
    httpCall(base, "POST", path, { "content-type": "application/json", ...headers }, JSON.stringify(body)),
};

/** The protected /mcp surface, mirroring examples/fastify-sqlite/app.ts: verify the
 *  bridge-minted access token (RequestAuthorizer), emit the RFC 9728 challenge on
 *  failure, else delegate to an MCP server via the SDK transport. `parsedBody`
 *  undefined ⇒ the SDK reads the raw stream (hono native path); a parsed body ⇒
 *  the SDK uses it directly (express.json path, no double-read). */
async function serveMcp(req: IncomingMessage, res: ServerResponse, parsedBody: unknown, authorizer: RequestAuthorizer, config: BridgeConfig): Promise<void> {
  let auth: { subject: string };
  try {
    auth = await authorizer.authorize({ authorization: req.headers.authorization });
  } catch (error) {
    const oe = error instanceof OAuthError ? error : new OAuthError("invalid_token", "Bearer token is invalid", 401);
    res.writeHead(oe.status, {
      "content-type": "application/json",
      "www-authenticate": buildUnauthorizedChallenge(config, { scope: config.scopeCatalog, error: oe.code, errorDescription: oe.message }),
    });
    res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: `${oe.code}: ${oe.message}` }, id: null }));
    return;
  }
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  const mcp = new McpServer({ name: "mcp-sso-int-flow", version: "0.0.1" });
  mcp.tool("ping", "echo the authenticated subject", async () => ({ content: [{ type: "text" as const, text: `pong: ${auth.subject}` }] }));
  try {
    await mcp.connect(transport);
    await transport.handleRequest(req, res, parsedBody);
  } catch {
    // Callers fire-and-forget serveMcp (`void`), so an unhandled rejection here
    // would leave res open and hang httpCall to its 10s backstop. End the socket
    // best-effort: a 500 if headers aren't sent yet, else just end.
    try {
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null }));
      } else {
        res.end();
      }
    } catch { /* socket already torn down */ }
  } finally {
    try { await mcp.close(); } catch { /* cleanup best-effort */ }
  }
}

interface Mount { base: string; close(): Promise<void> }

/** express: real app.listen socket. express req/res ARE Node req/res, so the SDK
 *  transport handles them directly with the express.json()-parsed body. */
async function mountExpress(bridge: Bridge, authorizer: RequestAuthorizer, config: BridgeConfig, port: number): Promise<Mount> {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use("/", createOAuthRouter({ bridge, identity: stubIdentity }));
  app.post("/mcp", (req, res) => { void serveMcp(req as unknown as IncomingMessage, res as unknown as ServerResponse, req.body, authorizer, config); });
  const server = app.listen(port, "127.0.0.1");
  await new Promise<void>((resolve, reject) => { server.on("listening", resolve); server.on("error", reject); });
  return { base: `http://127.0.0.1:${port}`, close: () => new Promise<void>((r) => server.close(() => r())) };
}

/** hono: ONE node:http server. /mcp is handled natively on raw req/res (no body
 *  pre-parse ⇒ SDK reads the stream); every other path is bridged
 *  IncomingMessage → web Request → app.fetch → write the Response back. Deliberately
 *  no @hono/node-server dependency. */
async function mountHono(bridge: Bridge, authorizer: RequestAuthorizer, config: BridgeConfig, port: number): Promise<Mount> {
  const honoApp = createOAuthApp({ bridge, identity: stubIdentity });
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);
    if (url.pathname === "/mcp") {
      void serveMcp(req, res, undefined, authorizer, config);
      return;
    }
    void (async () => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) if (v !== undefined) headers.set(k, Array.isArray(v) ? v.join(",") : v);
      const host = req.headers.host ?? "127.0.0.1";
      const init: RequestInit = { method: req.method ?? "GET", headers };
      if (req.method !== "GET" && req.method !== "HEAD") init.body = Buffer.concat(chunks);
      let webRes: Response;
      try {
        webRes = await honoApp.fetch(new Request(`http://${host}${req.url ?? "/"}`, init));
      } catch {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "internal_error", error_description: "OAuth request failed" }));
        return;
      }
      const out: Record<string, string> = {};
      webRes.headers.forEach((v, k) => { out[k] = v; });
      res.writeHead(webRes.status, out);
      res.end(Buffer.from(await webRes.arrayBuffer()));
    })();
  });
  await new Promise<void>((resolve, reject) => { server.on("error", reject); server.listen(port, "127.0.0.1", () => resolve()); });
  return { base: `http://127.0.0.1:${port}`, close: () => new Promise<void>((r) => server.close(() => r())) };
}

interface FlowArtifacts { clientId: string; verifier: string; accessToken: string; refreshToken: string; newRefreshToken: string; consentToken: string }

/** Drive the full /mcp round-trip against a real socket. `full` false stops after
 *  the first refresh (used by the sqlite-FILE reopen test, which needs a LIVE
 *  successor + a consumed-but-not-revoked predecessor to prove persistence). */
async function driveRoundTrip(base: string, issuer: string, origin: string, opts: { full: boolean }): Promise<FlowArtifacts> {
  const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
  const meta = await http.get(base, "/.well-known/oauth-authorization-server");
  assert.equal(meta.status, 200, "AS metadata served");
  assert.equal(JSON.parse(meta.body).issuer, issuer);

  const reg = await http.postJson(base, "/oauth/register", { redirect_uris: [REDIRECT] });
  assert.equal(reg.status, 201);
  const clientId = JSON.parse(reg.body).client_id as string;

  const authPage = await http.get(base, `/oauth/authorize?${new URLSearchParams({
    response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
    code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: "s1",
  })}`, { [IDENTITY_HEADER]: STUB_TOKEN });
  assert.equal(authPage.status, 200);
  const consentToken = /name="consent_token" value="([^"]+)"/.exec(authPage.body)?.[1];
  assert.ok(consentToken, "consent token rendered");

  const approve = await http.postForm(base, "/oauth/authorize/approve", { consent_token: consentToken as string, approved: "true" }, { origin });
  assert.equal(approve.status, 302);
  const code = new URL(approve.location ?? "").searchParams.get("code");
  assert.ok(code, "auth code in redirect");

  const token = await http.postForm(base, "/oauth/token", { grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier });
  assert.equal(token.status, 200);
  // threat-model row 1: token responses are non-cacheable (no-store + no-cache).
  assert.ok((token.headers["cache-control"] ?? "").includes("no-store"), "cache-control: no-store on token response");
  assert.equal(token.headers["pragma"], "no-cache", "pragma: no-cache on token response");
  const { access_token: accessToken, refresh_token: refreshToken } = JSON.parse(token.body) as { access_token: string; refresh_token: string };

  // Protected /mcp via the OFFICIAL MCP SDK client against the real socket (no fetch shim).
  // Hang-guard: the SDK transport builds its OWN AbortController.signal into each fetch
  // init, which (per createFetchWithInit's {...baseInit, ...init} merge) OVERRIDES
  // requestInit.signal — so a bounded requestInit.signal would NOT abort the fetch.
  // Instead, race the SDK ops against a deadline and close() the transport in finally
  // (close() aborts the controller → aborts the in-flight fetch → frees the socket).
  // Without this, a /mcp handler that accepts and never completes hangs CI (node --test
  // has no per-test timeout). (Codex P2.)
  const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${accessToken}` } } });
  const client = new Client({ name: "int-full-flow", version: "0.0.1" }, { capabilities: {} });
  try {
    await withTimeout(client.connect(transport), 10_000, "MCP client connect");
    const result = await withTimeout(client.callTool({ name: "ping", arguments: {} }), 10_000, "MCP client callTool");
    const text = (result.content as Array<{ type: string; text?: string }>).find((c) => c.type === "text")?.text;
    assert.equal(text, `pong: ${SUBJECT}`, "bridge-minted token carried the verified subject to /mcp");
  } finally {
    await client.close();
    await transport.close();
  }

  // Refresh rotates the token.
  const refreshed = await http.postForm(base, "/oauth/token", { grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId });
  assert.equal(refreshed.status, 200);
  const newRefreshToken = (JSON.parse(refreshed.body) as { refresh_token: string }).refresh_token;
  assert.notEqual(newRefreshToken, refreshToken, "refresh rotated");

  if (opts.full) {
    // Replay of the consumed token ⇒ family revoked (RFC 6749 §5.2 invalid_grant).
    const replay = await http.postForm(base, "/oauth/token", { grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId });
    assert.equal(replay.status, 400);
    assert.equal((JSON.parse(replay.body) as { error: string }).error, "invalid_grant");
    // The rotated successor is dead too (family revocation observed).
    const afterReplay = await http.postForm(base, "/oauth/token", { grant_type: "refresh_token", refresh_token: newRefreshToken, client_id: clientId });
    assert.equal(afterReplay.status, 400, "rotated successor died with the family");
    // RFC 7009: revoke is always 200.
    const revoke = await http.postForm(base, "/oauth/revoke", { token: newRefreshToken });
    assert.equal(revoke.status, 200);
  }

  return { clientId, verifier, accessToken, refreshToken, newRefreshToken, consentToken: consentToken as string };
}

function deps(config: BridgeConfig, store: { close(): Promise<void> }) {
  const clock = new SystemClock();
  const bridge = new Bridge({ config, store: store as never, clock, audit: noopAudit });
  const authorizer = new RequestAuthorizer({ config, clock, audit: noopAudit });
  return { bridge, authorizer };
}

// ---------------------------------------------------------------------------
// Item 1: cross-adapter full /mcp round-trip (fastify already covered in e2e-mcp-sdk)
// ---------------------------------------------------------------------------

test("integration — express full /mcp round-trip: register → authorize → token → /mcp (SDK) → refresh → replay-family-revoke → revoke", async () => {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const config = makeConfig({ resource: `${base}/mcp`, issuer: base });
  const store = new MemoryStore();
  const { bridge, authorizer } = deps(config, store);
  const mount = await mountExpress(bridge, authorizer, config, port);
  try {
    await driveRoundTrip(mount.base, base, base, { full: true });
  } finally {
    await mount.close();
    await store.close();
  }
});

test("integration — hono full /mcp round-trip (node:http↔fetch bridge, no @hono/node-server)", async () => {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const config = makeConfig({ resource: `${base}/mcp`, issuer: base });
  const store = new MemoryStore();
  const { bridge, authorizer } = deps(config, store);
  const mount = await mountHono(bridge, authorizer, config, port);
  try {
    await driveRoundTrip(mount.base, base, base, { full: true });
  } finally {
    await mount.close();
    await store.close();
  }
});

test("integration — /mcp without a token: 401 + RFC 9728 resource_metadata challenge (express + hono)", async () => {
  for (const mountFn of [mountExpress, mountHono]) {
    const port = await freePort();
    const base = `http://127.0.0.1:${port}`;
    const config = makeConfig({ resource: `${base}/mcp`, issuer: base });
    const store = new MemoryStore();
    const { bridge, authorizer } = deps(config, store);
    const mount = await mountFn(bridge, authorizer, config, port);
    try {
      const res = await httpCall(base, "POST", "/mcp", { "content-type": "application/json" }, JSON.stringify({ jsonrpc: "2.0", method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "0" } }, id: 1 }));
      assert.equal(res.status, 401);
      assert.match(res.headers["www-authenticate"] ?? "", /^Bearer resource_metadata=/);
    } finally {
      await mount.close();
      await store.close();
    }
  }
});

// ---------------------------------------------------------------------------
// Item 3: sqlite FILE store — the e2e suite only ever uses :memory:. Prove the
// quickstart's persistence-across-restart promise: a live refresh token still
// refreshes, a pre-restart-consumed token is still dead, and a pre-restart
// consent-JTI replay is still rejected (all persisted in the file).
// ---------------------------------------------------------------------------

test("integration — sqlite FILE store: full round-trip survives restart (live refresh, consumed-dead, consent-JTI replay rejected)", async () => {
  if (process.platform === "win32") return; // node:sqlite file-lock/perm parity is POSIX-only
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-int-sqlite-file-"));
  const sqliteFile = join(dir, "auth.db");
  // STABLE signing material + port-less loopback issuer across restart: the issuer
  // must be stable so the pre-restart consent token still verifies on reopen.
  const signingPrivateJwk = ecJwk();
  const consentSigningSecret = "s".repeat(40);
  const STABLE_ISSUER = "http://127.0.0.1";
  try {
    // --- run 1: drive the flow through the first refresh, then close ---
    const port1 = await freePort();
    const base1 = `http://127.0.0.1:${port1}`;
    const config1 = makeConfig({ resource: `${base1}/mcp`, issuer: STABLE_ISSUER, signingPrivateJwk, consentSigningSecret });
    const store1 = openSqliteStore(sqliteFile);
    const { bridge: bridge1, authorizer: authorizer1 } = deps(config1, store1);
    const mount1 = await mountExpress(bridge1, authorizer1, config1, port1);
    let artifacts: FlowArtifacts;
    try {
      artifacts = await driveRoundTrip(mount1.base, STABLE_ISSUER, STABLE_ISSUER, { full: false });
    } finally {
      await mount1.close();
      await store1.close();
    }

    // --- reopen run 2: SAME file + signing material + issuer (mirrors a restart) ---
    const port2 = await freePort();
    const base2 = `http://127.0.0.1:${port2}`;
    const config2 = makeConfig({ resource: `${base2}/mcp`, issuer: STABLE_ISSUER, signingPrivateJwk, consentSigningSecret });
    const store2 = openSqliteStore(sqliteFile);
    const { bridge: bridge2, authorizer: authorizer2 } = deps(config2, store2);
    const mount2 = await mountExpress(bridge2, authorizer2, config2, port2);
    try {
      // 1. The LIVE refresh token minted before restart (the rotated successor)
      //    still refreshes — refresh-token state survived the file reopen.
      const refresh = await http.postForm(mount2.base, "/oauth/token", { grant_type: "refresh_token", refresh_token: artifacts.newRefreshToken, client_id: artifacts.clientId });
      assert.equal(refresh.status, 200, "live refresh token survived restart");

      // 2. The pre-restart consent token (its JTI already consumed at the first
      //    approve) is STILL rejected on reopen — the consent-JTI ledger persisted.
      const consentReplay = await http.postForm(mount2.base, "/oauth/authorize/approve", { consent_token: artifacts.consentToken, approved: "true" }, { origin: STABLE_ISSUER });
      assert.equal(consentReplay.status, 400, "replayed consent JTI rejected after restart");
      assert.equal((JSON.parse(consentReplay.body) as { error: string }).error, "invalid_grant");

      // 3. The pre-restart CONSUMED refresh token (the original) is still dead.
      //    Done last: replaying a consumed token revokes the whole family.
      const r1Replay = await http.postForm(mount2.base, "/oauth/token", { grant_type: "refresh_token", refresh_token: artifacts.refreshToken, client_id: artifacts.clientId });
      assert.equal(r1Replay.status, 400, "pre-restart consumed refresh token still dead");
      assert.equal((JSON.parse(r1Replay.body) as { error: string }).error, "invalid_grant");
    } finally {
      await mount2.close();
      await store2.close();
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Item 3: mysql store full round-trip. node --test runs files CONCURRENTLY in
// separate processes against the SAME CI database, and store-mysql.conformance
// does a beforeEach DELETE-all — so this test takes a named advisory lock that
// the conformance file also takes, serializing the two (CI is sacred; no flakes).
// Gated EXACTLY like store-mysql.conformance: skip when RUN_INTEGRATION unset,
// hard-fail when RUN_INTEGRATION=true and MYSQL_URL missing — keyed on
// RUN_INTEGRATION, never the ambient CI var (publish.yml runs `pnpm test` too).
// ---------------------------------------------------------------------------

const RUN_INTEGRATION = process.env.RUN_INTEGRATION === "true";
const MYSQL_URL = process.env.MYSQL_URL;

if (RUN_INTEGRATION && !MYSQL_URL) {
  throw new Error("MYSQL_URL is required when RUN_INTEGRATION is set — the MysqlStore full-flow round-trip must be exercised.");
}

if (MYSQL_URL) {
  // 120s must exceed the conformance file's whole-suite runtime (it holds the same
  // lock for its lifetime; this file waits the difference). Headroom over 60s so a
  // growing conformance suite doesn't turn the waiter's ok===1 assert into a flake.
  const LOCK_NAME = "mcp_sso_oauth_lock";

  test("integration — mysql store full /mcp round-trip (isolated from the conformance file via advisory lock)", async () => {
    // Acquire the named lock on a DEDICATED connection (GET_LOCK is per-connection;
    // the conformance file holds the same lock for its lifetime, so this blocks
    // until that file finishes — no concurrent DELETE can wipe this flow's rows).
    // The pool is closed in an OUTER finally so a failure at ANY step — getConnection,
    // GET_LOCK, or the ok===1 assert (lock not granted / held past 120s by the sibling)
    // — still ends the pool; otherwise mysql2's open socket keeps the event loop alive
    // and node --test hangs after reporting the failure. (Codex P2.)
    const lockPool = createPool(MYSQL_URL as string);
    try {
      const conn = await lockPool.getConnection();
      try {
        const [lockRows] = await conn.query("SELECT GET_LOCK(?, 120) AS ok", [LOCK_NAME]);
        assert.equal((lockRows as Array<{ ok: number }>)[0]?.ok, 1, `acquired ${LOCK_NAME}`);

        // Migrate (+ boot-time strict-mode/collation asserts) on the shared DB.
        const migrator = await createMysqlStore(MYSQL_URL as string);
        await migrator.close();

        const port = await freePort();
        const base = `http://127.0.0.1:${port}`;
        const config = makeConfig({ resource: `${base}/mcp`, issuer: base });
        const pool = createPool(MYSQL_URL as string);
        const store = new MysqlStore(pool, true); // ownsPool: close() ends it
        const { bridge, authorizer } = deps(config, store);
        const mount = await mountExpress(bridge, authorizer, config, port);
        try {
          await driveRoundTrip(mount.base, base, base, { full: true });
        } finally {
          await mount.close();
          await store.close();
        }
      } finally {
        // Error-tolerant release: if the dedicated connection died mid-test,
        // RELEASE_LOCK throws — swallow it so the pool close below always runs.
        try { await conn.query("SELECT RELEASE_LOCK(?)", [LOCK_NAME]); } catch { /* pool ending below anyway */ }
        try { conn.release(); } catch { /* already released */ }
      }
    } finally {
      await lockPool.end();
    }
  });
}
