// S1b end-to-end: the example boots in pairing mode and an operator completes
// the OAuth flow by pasting a console-printed code. Drives buildApp() with a
// JsonlFileAudit wired in (the verify target: "JSONL audit file has events and
// no secrets"), captures the code from the pairing identity's output, and runs
// the full GET pairing page → POST code → consent → approve → token → protected
// /mcp (official SDK client) path.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { JWK } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { JsonlFileAudit } from "../src/audit/jsonl-file.ts";
import { createConsolePairingIdentity, formatPairingCode } from "../src/identity/console-pairing.ts";
import type { AuthAuditEvent } from "../src/ports/audit.ts";
import { buildApp } from "../examples/fastify-sqlite/app.ts";

const ISSUER = "http://localhost";
const RESOURCE = "http://localhost/mcp";
const REDIRECT = "http://localhost:4321/callback";
const SUBJECT = "console-operator";
const ORIGIN = "http://localhost";

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK;
}

function extractValue(html: string, name: string): string {
  const m = new RegExp(`name="${name}" value="([^"]+)"`).exec(html);
  assert.ok(m?.[1], `hidden field ${name} not found`);
  return m[1]!;
}

function extractCode(text: string): string {
  const m = /code: ([BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4})/.exec(text);
  assert.ok(m?.[1], "pairing code not printed");
  return m[1]!.replace(/-/g, "");
}

test("S1b.8: zero-config pairing flow — code → consent → token → /mcp; JSONL audit has events and no secrets", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-e2e-pairing-"));
  try {
    const config = createBridgeConfig({
      issuer: ISSUER, resource: RESOURCE,
      consentSigningSecret: "x".repeat(40), signingPrivateJwk: jwk(), signingKeyId: "k",
      redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
      allowedOrigins: [ISSUER], dcr: { mode: "stateless" }, dev: { allowInsecureLocalhost: true },
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    });

    // Captured pairing output (where the code is printed) + a real JSONL audit sink.
    const outputChunks: string[] = [];
    const auditPath = join(dir, "audit.jsonl");
    const audit = new JsonlFileAudit(auditPath);
    const pairing = createConsolePairingIdentity({
      audit,
      output: { write(s: string): boolean { outputChunks.push(s); return true; } },
    });

    const { app, store } = await buildApp({ config, pairing, audit });

    const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
    const reg = await app.inject({
      method: "POST", url: "/oauth/register",
      headers: { "content-type": "application/json" },
      payload: JSON.stringify({ redirect_uris: [REDIRECT] }),
    });
    assert.equal(reg.statusCode, 201);
    const clientId = reg.json<{ client_id: string }>().client_id;

    const oauthQuery = new URLSearchParams({
      response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
      code_challenge: pkceChallenge(verifier), code_challenge_method: "S256",
      resource: RESOURCE, scope: "mcp:read", state: "s1",
    });

    // 1. GET /oauth/authorize → pairing page (code printed to output).
    const pairingPage = await app.inject({ method: "GET", url: `/oauth/authorize?${oauthQuery}` });
    assert.equal(pairingPage.statusCode, 200);
    assert.match(pairingPage.body, /Pair this device/);
    const pairingNonce = extractValue(pairingPage.body, "pairing_nonce");
    const code = extractCode(outputChunks.join(""));

    // 2. POST /oauth/authorize with the pasted code → consent page.
    const consentPage = await app.inject({
      method: "POST", url: "/oauth/authorize",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        ...Object.fromEntries(oauthQuery), pairing_code: code, pairing_nonce: pairingNonce,
      }).toString(),
    });
    assert.equal(consentPage.statusCode, 200);
    assert.match(consentPage.body, /Authorize access/);
    const consentToken = extractValue(consentPage.body, "consent_token");

    // 3. Approve → 302 with an auth code.
    const approve = await app.inject({
      method: "POST", url: "/oauth/authorize/approve",
      headers: { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN },
      payload: new URLSearchParams({ consent_token: consentToken, approved: "true" }).toString(),
    });
    assert.equal(approve.statusCode, 302);
    const authCode = new URL(approve.headers.location as string).searchParams.get("code");
    assert.ok(authCode);

    // 4. Exchange → tokens.
    const tokenResp = await app.inject({
      method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        grant_type: "authorization_code", code: authCode as string, redirect_uri: REDIRECT,
        client_id: clientId, code_verifier: verifier,
      }).toString(),
    });
    assert.equal(tokenResp.statusCode, 200);
    const { access_token: accessToken } = tokenResp.json<{ access_token: string }>();

    // 5. Protected /mcp via the OFFICIAL MCP SDK client.
    const fetchShim = async (url: URL | string, init?: { method?: string; headers?: unknown; body?: unknown }): Promise<Response> => {
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
    };
    const transport = new StreamableHTTPClientTransport(new URL(RESOURCE), { fetch: fetchShim as never, requestInit: { headers: { authorization: `Bearer ${accessToken}` } } });
    const client = new Client({ name: "verify-gate-pairing", version: "0.0.1" }, { capabilities: {} });
    await client.connect(transport);
    const result = await client.callTool({ name: "ping", arguments: {} });
    const text = (result.content as Array<{ type: string; text?: string }>).find((c) => c.type === "text")?.text;
    assert.equal(text, `pong: ${SUBJECT}`); // the pairing-resolved subject reaches /mcp
    await client.close();
    await transport.close();

    // 6. JSONL audit: has the pairing event + the v0.1 flow events; no raw secrets/code.
    const raw = await readFile(auditPath, "utf8");
    const events = raw.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l) as AuthAuditEvent);
    const names = events.map((e) => e.event);
    assert.ok(names.includes("oauth.pairing.attempt"), "pairing audit event present");
    assert.ok(names.includes("oauth.authorize.prepare"));
    assert.ok(names.includes("oauth.token.authorization_code"));
    assert.ok(events.some((e) => e.event === "oauth.pairing.attempt" && e.status === "success"));
    // No raw code (canonical AND displayed dashed form), auth code, or access token in the audit output.
    assert.equal(raw.includes(code), false, "canonical pairing code leaked into audit");
    assert.equal(raw.includes(formatPairingCode(code)), false, "displayed (dashed) pairing code leaked into audit");
    assert.equal(raw.includes(authCode as string), false, "auth code leaked into audit");
    assert.equal(raw.includes(accessToken), false, "access token leaked into audit");

    await app.close();
    await store.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("S1b: a wrong pairing code re-renders the pairing page (not a 401, not the consent page)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-pairing-wrong-"));
  try {
    const config = createBridgeConfig({
      issuer: ISSUER, resource: RESOURCE, consentSigningSecret: "x".repeat(40), signingPrivateJwk: jwk(), signingKeyId: "k",
      redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"], allowedOrigins: [ISSUER],
      dcr: { mode: "stateless" }, dev: { allowInsecureLocalhost: true },
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    });
    const outputChunks: string[] = [];
    const pairing = createConsolePairingIdentity({ output: { write(s: string): boolean { outputChunks.push(s); return true; } } });
    const { app, store } = await buildApp({ config, pairing });

    const reg = await app.inject({ method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" }, payload: JSON.stringify({ redirect_uris: [REDIRECT] }) });
    const clientId = reg.json<{ client_id: string }>().client_id;
    const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: pkceChallenge("v"), code_challenge_method: "S256", scope: "mcp:read" });
    const page = await app.inject({ method: "GET", url: `/oauth/authorize?${q}` });
    const nonce = extractValue(page.body, "pairing_nonce");

    const wrong = await app.inject({
      method: "POST", url: "/oauth/authorize",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ ...Object.fromEntries(q), pairing_code: "BBBBBBBBBBBB", pairing_nonce: nonce }).toString(),
    });
    assert.equal(wrong.statusCode, 200);
    assert.match(wrong.body, /Pair this device/); // re-rendered the pairing page, not consent
    assert.match(wrong.body, /Invalid or expired pairing code/);

    await app.close();
    await store.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
