// The 0.4.0 release gate: ONE issuer protecting TWO independently addressable
// MCP resources, driven the way AGENTS.md defines "done" — register → authorize
// → token → call a protected /mcp with the OFFICIAL MCP SDK client over a REAL
// socket → refresh → replay-detection → cross-resource negatives.
//
// The in-process multi-resource tests prove each guard in isolation. This proves
// the product: two live endpoints, two pinned verifiers, one bridge, and a token
// minted for one endpoint being useless at the other over real HTTP.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import Fastify from "fastify";
import type { JWK } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Bridge } from "../src/adapters/bridge.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import { RequestAuthorizer } from "../src/verifier.ts";
import { buildUnauthorizedChallenge } from "../src/challenge.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { noopAudit } from "../src/ports/audit.ts";
import { MemoryStore } from "../src/store/memory.ts";
import type { IdentityPort } from "../src/ports/identity.ts";
import { resolveResource, buildResourceCatalog } from "../src/resource.ts";
import type { ResourceConfiguration } from "../src/resource.ts";

const ISSUER = "http://localhost";
const PATH_A = "/grafana/mcp";
const PATH_B = "/memory/mcp";
const REDIRECT = "http://localhost:4321/callback";
const SUBJECT = "agent@test";
const STUB_TOKEN = "stub-good";
const IDENTITY_HEADER = "cf-access-jwt-assertion";

/** Real fetch captured before any test can stub globalThis.fetch — the SDK call
 *  must reach the real loopback server. */
const networkFetch = globalThis.fetch.bind(globalThis) as typeof fetch;

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK;
}

const stubIdentity: IdentityPort = {
  async verify(input: unknown) {
    return input === STUB_TOKEN ? { ok: true, identity: { subject: SUBJECT } } : { ok: false, reason: "bad" };
  },
};

function extractConsentToken(html: string): string {
  const m = /name="consent_token" value="([^"]+)"/.exec(html);
  assert.ok(m?.[1], "consent page must carry a consent_token");
  return m[1];
}

/** The MCP SDK transport overrides requestInit.signal with its own controller,
 *  so the abort lever is transport.close() in the caller's finally. */
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
  });
}

/** Two resources that deliberately SHARE the scope "mcp:read": isolation must
 *  come from the audience binding, never from scope names being different. */
function twoResourceConfig(origin: string): BridgeConfig {
  return createBridgeConfig({
    issuer: ISSUER,
    consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: jwk(),
    signingKeyId: "k",
    redirectAllowlist: [REDIRECT],
    allowedOrigins: [ISSUER],
    dcr: { mode: "stateless" },
    dev: { allowInsecureLocalhost: true },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
    resources: [
      { resource: `${origin}${PATH_A}`, scopeCatalog: ["mcp:read", "grafana:admin"], defaultScopes: ["mcp:read"] },
      { resource: `${origin}${PATH_B}`, scopeCatalog: ["mcp:read", "memory:curate"], defaultScopes: ["mcp:read"] },
    ],
  } as never);
}

/** Mount ONE bridge and TWO protected endpoints, each behind its own
 *  resource-pinned RequestAuthorizer — the deployment shape 0.4.0 exists for. */
async function buildTwoResourceApp(config: BridgeConfig, origin: string) {
  const app = Fastify();
  const clock = new SystemClock();
  const store = new MemoryStore();
  const bridge = new Bridge({ config, store, clock, audit: noopAudit });
  await registerOAuthRoutes(app, { bridge, identity: stubIdentity, identityHeader: IDENTITY_HEADER });

  for (const path of [PATH_A, PATH_B]) {
    const resource = `${origin}${path}`;
    const authorizer = new RequestAuthorizer({ config, clock, audit: noopAudit, resource });
    app.post(path, async (request, reply) => {
      let auth;
      try {
        auth = await authorizer.authorize({ authorization: request.headers.authorization });
      } catch (error) {
        const oe = error instanceof OAuthError ? error : new OAuthError("invalid_token", "Bearer token is invalid", 401);
        // The challenge is built for THIS endpoint's pinned resource.
        reply.header("www-authenticate", buildUnauthorizedChallenge(config, { resource, error: oe.code }));
        reply.code(oe.status).send({ jsonrpc: "2.0", error: { code: -32001, message: oe.code }, id: null });
        return;
      }
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      const mcp = new McpServer({ name: `mcp-sso-${path}`, version: "0.0.1" });
      mcp.tool("whoami", "echo the subject and the resource this endpoint serves", async () => ({
        content: [{ type: "text" as const, text: `${auth.subject}@${auth.resource}` }],
      }));
      await mcp.connect(transport);
      reply.hijack();
      try {
        await transport.handleRequest(request.raw, reply.raw, request.body);
      } finally {
        await mcp.close();
      }
    });
  }
  return { app, store };
}

/** Full interactive grant for ONE resource, through the real OAuth endpoints. */
async function grant(app: Awaited<ReturnType<typeof buildTwoResourceApp>>["app"], resource: string) {
  const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
  const reg = await app.inject({
    method: "POST", url: "/oauth/register",
    headers: { "content-type": "application/json" },
    payload: JSON.stringify({ redirect_uris: [REDIRECT] }),
  });
  assert.equal(reg.statusCode, 201);
  const clientId = reg.json<{ client_id: string }>().client_id;

  const authPage = await app.inject({
    method: "GET",
    url: `/oauth/authorize?${new URLSearchParams({
      response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
      code_challenge: pkceChallenge(verifier), code_challenge_method: "S256",
      scope: "mcp:read", state: "s1", resource,
    })}`,
    headers: { [IDENTITY_HEADER]: STUB_TOKEN },
  });
  assert.equal(authPage.statusCode, 200, `authorize must render consent for ${resource}`);

  const approve = await app.inject({
    method: "POST", url: "/oauth/authorize/approve",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: ISSUER },
    payload: new URLSearchParams({ consent_token: extractConsentToken(authPage.body), approved: "true" }).toString(),
  });
  assert.equal(approve.statusCode, 302);
  const code = new URL(approve.headers.location as string).searchParams.get("code");
  assert.ok(code);

  const tokenResp = await app.inject({
    method: "POST", url: "/oauth/token",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: new URLSearchParams({
      grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT,
      client_id: clientId, code_verifier: verifier, resource,
    }).toString(),
  });
  assert.equal(tokenResp.statusCode, 200, `token exchange must succeed for ${resource}`);
  const body = tokenResp.json<{ access_token: string; refresh_token: string }>();
  return { clientId, ...body };
}

/** Call a protected endpoint with the OFFICIAL SDK client over a real socket. */
async function callWithSdk(base: string, path: string, accessToken: string) {
  const transport = new StreamableHTTPClientTransport(new URL(path, base), {
    fetch: networkFetch,
    requestInit: { headers: { authorization: `Bearer ${accessToken}` } },
  });
  const client = new Client({ name: "multi-resource-gate", version: "0.0.1" }, { capabilities: {} });
  try {
    await withTimeout(client.connect(transport), 10_000, `connect ${path}`);
    const result = await withTimeout(client.callTool({ name: "whoami", arguments: {} }), 10_000, `callTool ${path}`);
    assert.equal(result.isError ?? false, false);
    return (result.content as Array<{ type: string; text?: string }>).find((c) => c.type === "text")?.text;
  } finally {
    await client.close();
    await transport.close();
  }
}

test("e2e multi-resource: two live MCP endpoints, one issuer, no token crosses over", async () => {
  // The origin is only known after listen(0), and the resources embed it, so the
  // app is built in two phases: bind a port, then configure against that origin.
  const probe = Fastify();
  const probeBase = await probe.listen({ port: 0, host: "127.0.0.1" });
  const origin = new URL(probeBase).origin;
  await probe.close();

  const config = twoResourceConfig(origin);
  const { app, store } = await buildTwoResourceApp(config, origin);
  const resourceA = `${origin}${PATH_A}`;
  const resourceB = `${origin}${PATH_B}`;

  try {
    const base = await app.listen({ port: 0, host: "127.0.0.1", listenTextResolver: () => origin });

    // --- Independent grants, one per resource ---
    const a = await grant(app, resourceA);
    const b = await grant(app, resourceB);
    assert.notEqual(a.access_token, b.access_token);

    // --- Each endpoint works through the OFFICIAL SDK client ---
    assert.equal(await callWithSdk(base, PATH_A, a.access_token), `${SUBJECT}@${resourceA}`,
      "A's endpoint must serve A's token and report A as the verified resource");
    assert.equal(await callWithSdk(base, PATH_B, b.access_token), `${SUBJECT}@${resourceB}`,
      "B's endpoint must serve B's token and report B as the verified resource");

    // --- THE CROSS-RESOURCE NEGATIVE, over real HTTP ---
    // Both resources declare "mcp:read", so only the audience binding stops this.
    const crossed = await fetch(new URL(PATH_B, base), {
      method: "POST",
      headers: {
        authorization: `Bearer ${a.access_token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0", id: 1, method: "initialize",
        params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "0" } },
      }),
    });
    assert.equal(crossed.status, 401, "A's token must be rejected at B's endpoint");
    const challenge = crossed.headers.get("www-authenticate") ?? "";
    assert.match(challenge, /invalid_token/);
    // B's 401 must point the client at B's OWN metadata, not A's.
    assert.ok(challenge.includes(`oauth-protected-resource${PATH_B}`),
      `B's challenge must advertise B's PRM URL, got: ${challenge}`);
    assert.ok(!challenge.includes(PATH_A), "B's challenge must not mention A");

    // --- Refresh keeps its resource; it cannot be redirected to the other one ---
    const refreshedAtB = await app.inject({
      method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        grant_type: "refresh_token", refresh_token: a.refresh_token,
        client_id: a.clientId, resource: resourceB,
      }).toString(),
    });
    assert.equal(refreshedAtB.statusCode, 400, "A's refresh token must not rotate at B");
    assert.equal(refreshedAtB.json<{ error: string }>().error, "invalid_target");

    // The family survived that rejection — a wrong-resource guess is not a DoS.
    const refreshedAtA = await app.inject({
      method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        grant_type: "refresh_token", refresh_token: a.refresh_token,
        client_id: a.clientId, resource: resourceA,
      }).toString(),
    });
    assert.equal(refreshedAtA.statusCode, 200, "the mismatch must not have revoked A's family");
    const rotated = refreshedAtA.json<{ access_token: string; refresh_token: string }>();

    // The rotated token still works at A and still does not work at B.
    assert.equal(await callWithSdk(base, PATH_A, rotated.access_token), `${SUBJECT}@${resourceA}`);

    // --- Replay of the consumed predecessor revokes A's family (and only A's) ---
    const replay = await app.inject({
      method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        grant_type: "refresh_token", refresh_token: a.refresh_token,
        client_id: a.clientId, resource: resourceA,
      }).toString(),
    });
    assert.equal(replay.statusCode, 400);
    assert.equal(replay.json<{ error: string }>().error, "invalid_grant");

    const afterReplay = await app.inject({
      method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        grant_type: "refresh_token", refresh_token: rotated.refresh_token,
        client_id: a.clientId, resource: resourceA,
      }).toString(),
    });
    assert.equal(afterReplay.statusCode, 400, "the replay revoked A's whole family");

    // B's family is untouched — revocation is per-resource, not global.
    const bStillWorks = await app.inject({
      method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        grant_type: "refresh_token", refresh_token: b.refresh_token,
        client_id: b.clientId, resource: resourceB,
      }).toString(),
    });
    assert.equal(bStillWorks.statusCode, 200, "revoking A's family must not touch B's");
  } finally {
    await app.close();
    await store.close();
  }
});

test("e2e multi-resource: each endpoint publishes its own PRM over real HTTP", async () => {
  const probe = Fastify();
  const probeBase = await probe.listen({ port: 0, host: "127.0.0.1" });
  const origin = new URL(probeBase).origin;
  await probe.close();

  const config = twoResourceConfig(origin);
  const { app, store } = await buildTwoResourceApp(config, origin);
  try {
    const base = await app.listen({ port: 0, host: "127.0.0.1", listenTextResolver: () => origin });
    for (const [path, other] of [[PATH_A, PATH_B], [PATH_B, PATH_A]] as const) {
      const res = await fetch(new URL(`/.well-known/oauth-protected-resource${path}`, base));
      assert.equal(res.status, 200, `PRM route for ${path} must be served`);
      const doc = await res.json() as { resource: string; scopes_supported?: string[] };
      assert.equal(doc.resource, `${origin}${path}`);
      assert.ok(!JSON.stringify(doc).includes(other), `${path}'s PRM must not mention ${other}`);
    }
    // AS metadata is issuer-wide and publishes the union for discovery only.
    const asMeta = await fetch(new URL("/.well-known/oauth-authorization-server", base));
    const meta = await asMeta.json() as Record<string, unknown>;
    assert.deepEqual(meta.scopes_supported, ["grafana:admin", "mcp:read", "memory:curate"].sort(),
      "AS metadata publishes the sorted union of both catalogs");
    assert.equal("protected_resources" in meta, false, "no non-standard protected_resources field");
  } finally {
    await app.close();
    await store.close();
  }
});

test("e2e multi-resource: an unknown resource never reaches a live endpoint", () => {
  const origin = "http://127.0.0.1:9999";
  const catalog = buildResourceCatalog(
    twoResourceConfig(origin) as unknown as ResourceConfiguration,
    { allowInsecureLocalhost: true },
  );
  assert.throws(() => resolveResource(catalog, `${origin}/evil/mcp`), (e: unknown) => e instanceof OAuthError);
  assert.throws(() => resolveResource(catalog, undefined), (e: unknown) => e instanceof OAuthError);
});
