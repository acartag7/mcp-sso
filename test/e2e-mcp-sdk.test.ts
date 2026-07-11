// Phase 4 end-to-end verify gate. Drives the OAuth flow against the runnable
// example (mounted in-process) and then uses the OFFICIAL MCP SDK client to call
// the protected /mcp with a bridge-minted token, then refresh -> replay-revocation
// -> revoke. This is the "verify before done" gate (green units alone != done).

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import type { IdentityPort } from "../src/ports/identity.ts";
import { buildApp } from "../examples/fastify-sqlite/app.ts";

const ISSUER = "http://localhost";
const RESOURCE = "http://localhost/mcp";
const REDIRECT = "http://localhost:4321/callback";
const SUBJECT = "agent@test";
const STUB_TOKEN = "stub-good";
const IDENTITY_HEADER = "cf-access-jwt-assertion";

function jwk(): JWK { const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK; }
const stubIdentity: IdentityPort = {
  async verify(input: unknown) { return input === STUB_TOKEN ? { ok: true, identity: { subject: SUBJECT } } : { ok: false, reason: "bad" }; },
};

function extractConsentToken(html: string): string { const m = /name="consent_token" value="([^"]+)"/.exec(html); assert.ok(m?.[1]); return m[1]; }

/** Real fetch captured at module load — before any test stubs globalThis.fetch.
 *  The SDK /mcp call must hit the real loopback server, not a per-test fetch stub. */
const networkFetch = globalThis.fetch.bind(globalThis) as typeof fetch;

/** Race a promise against a hard deadline. The MCP SDK transport overrides
 *  requestInit.signal with its own AbortController.signal, so the abort lever is
 *  transport.close() in the caller's finally, not a bounded requestInit.signal. */
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
  });
}

test("e2e: register -> authorize -> token -> /mcp (official SDK client) -> refresh -> replay-revoke -> revoke", async () => {
  const config = createBridgeConfig({
    issuer: ISSUER, resource: RESOURCE,
    consentSigningSecret: "x".repeat(40), signingPrivateJwk: jwk(), signingKeyId: "k",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: [ISSUER], dcr: { mode: "stateless" }, dev: { allowInsecureLocalhost: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const { app, store } = await buildApp({ config, identity: stubIdentity });
  // The SDK call below opens a real listening server (app.listen). Wrap the whole
  // flow so app.close()/store.close() run in finally — a timeout or assertion
  // failure must not leak the listening handle (node --test has no per-test
  // timeout; a leaked server hangs the subprocess).
  try {
    // --- OAuth flow (driven directly against the adapter) ---
    const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
    const reg = await app.inject({ method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" }, payload: JSON.stringify({ redirect_uris: [REDIRECT] }) });
    assert.equal(reg.statusCode, 201);
    const clientId = reg.json<{ client_id: string }>().client_id;

    const authPage = await app.inject({ method: "GET", url: `/oauth/authorize?${new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: "s1" })}`, headers: { [IDENTITY_HEADER]: STUB_TOKEN } });
    assert.equal(authPage.statusCode, 200);
    const consentToken = extractConsentToken(authPage.body);

    const approve = await app.inject({ method: "POST", url: "/oauth/authorize/approve", headers: { "content-type": "application/x-www-form-urlencoded", origin: ISSUER }, payload: new URLSearchParams({ consent_token: consentToken, approved: "true" }).toString() });
    assert.equal(approve.statusCode, 302);
    const code = new URL(approve.headers.location as string).searchParams.get("code");
    assert.ok(code);

    const tokenResp = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier }).toString() });
    assert.equal(tokenResp.statusCode, 200);
    const { access_token: accessToken, refresh_token: refreshToken } = tokenResp.json<{ access_token: string; refresh_token: string }>();

    // --- /mcp call via the OFFICIAL MCP SDK client over a REAL loopback socket,
    //     presenting the bridge-minted token. (The inject-mock socket lacks
    //     destroySoon(); the SDK server transport's forceClose timer throws on it
    //     ~500 ms later — issue #66. A real listen() socket has destroySoon().) ---
    const base = await app.listen({ port: 0, host: "127.0.0.1" });
    const transport = new StreamableHTTPClientTransport(new URL(new URL(RESOURCE).pathname, base), { fetch: networkFetch, requestInit: { headers: { authorization: `Bearer ${accessToken}` } } });
    const client = new Client({ name: "verify-gate", version: "0.0.1" }, { capabilities: {} });
    try {
      await withTimeout(client.connect(transport), 10_000, "MCP client connect");
      const result = await withTimeout(client.callTool({ name: "ping", arguments: {} }), 10_000, "MCP client callTool");
      assert.equal(result.isError ?? false, false); // success (isError omitted/undefined on success)
      const text = (result.content as Array<{ type: string; text?: string }>).find((c) => c.type === "text")?.text;
      assert.equal(text, `pong: ${SUBJECT}`); // the bridge-minted token carried the verified subject
    } finally {
      await client.close();
      await transport.close();
    }

    // --- refresh rotates; replay revokes the family; revoke is always 200 ---
    const refreshed = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId }).toString() });
    assert.equal(refreshed.statusCode, 200);
    const newRefresh = refreshed.json<{ refresh_token: string }>().refresh_token;
    assert.notEqual(newRefresh, refreshToken);

    const replay = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId }).toString() });
    assert.equal(replay.statusCode, 400); // replay of the consumed token -> family revoked
    assert.equal(replay.json<{ error: string }>().error, "invalid_grant"); // RFC 6749 §5.2 top-level string

    const afterReplay = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: newRefresh, client_id: clientId }).toString() });
    assert.equal(afterReplay.statusCode, 400); // the rotated successor is dead too (family revoked)

    const revoke = await app.inject({ method: "POST", url: "/oauth/revoke", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ token: newRefresh }).toString() });
    assert.equal(revoke.statusCode, 200); // RFC 7009: always 200
  } finally {
    await app.close();
    await store.close();
  }
});

test("e2e: /mcp without a token returns 401 with the resource_metadata challenge (fix #1)", async () => {
  const config = createBridgeConfig({
    issuer: ISSUER, resource: RESOURCE, consentSigningSecret: "x".repeat(40), signingPrivateJwk: jwk(), signingKeyId: "k",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"], allowedOrigins: [ISSUER], dcr: { mode: "stateless" }, dev: { allowInsecureLocalhost: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const { app, store } = await buildApp({ config, identity: stubIdentity });
  const res = await app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json" }, payload: JSON.stringify({ jsonrpc: "2.0", method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "0" } }, id: 1 }) });
  assert.equal(res.statusCode, 401);
  assert.match(res.headers["www-authenticate"] as string, /^Bearer resource_metadata="http:\/\/localhost\/\.well-known\/oauth-protected-resource"/);
  await app.close();
  await store.close();
});
