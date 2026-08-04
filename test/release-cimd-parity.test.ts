import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { request } from "node:http";
import { test } from "node:test";
import express from "express";
import Fastify from "fastify";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createOAuthRouter } from "../src/adapters/express.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import { createOAuthApp } from "../src/adapters/hono.ts";
import type { CimdTransport, DnsResolver } from "../src/cimd/transport.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import type { IdentityPort } from "../src/ports/identity.ts";
import { MemoryStore } from "../src/store/memory.ts";

const CIMD_ID = "https://client-metadata.test/cimd.json";
const REDIRECT = "https://client.test/callback";
const VERIFIER = "release-cimd-verifier-0123456789abcdef012345678901234";
const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;
const identity: IdentityPort = { async verify() { return { ok: true, identity: { subject: "release-user" } }; } };

class CountingClientStore implements ClientStore {
  readonly clients = new Map<string, ClientRegistration>();
  saves = 0;
  async save(client: ClientRegistration): Promise<void> { this.saves++; this.clients.set(client.clientId, client); }
  async find(clientId: string): Promise<ClientRegistration | null> { return this.clients.get(clientId) ?? null; }
}

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "release" } as JWK;
}

function runtime(): { bridge: Bridge; clients: CountingClientStore; calls: { dns: number; transport: number } } {
  const clients = new CountingClientStore();
  const calls = { dns: 0, transport: 0 };
  const resolver: DnsResolver = { async resolve() { calls.dns++; return [{ address: "93.184.216.34", family: 4 }]; } };
  const config = createBridgeConfig({
    issuer: "https://auth.test", resource: "https://resource.test/mcp",
    consentSigningSecret: "r".repeat(40), signingPrivateJwk: jwk(), signingKeyId: "release",
    redirectAllowlist: ["https://opaque.test/callback"], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stored", store: clients }, cimd: { enabled: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const transport: CimdTransport = { async connectAndGet() {
    calls.transport++;
    async function* body(): AsyncGenerator<Uint8Array> {
      yield new TextEncoder().encode(JSON.stringify({ client_id: CIMD_ID, client_name: "Release client", redirect_uris: [REDIRECT] }));
    }
    return { status: 200, redirected: false, finalUrl: CIMD_ID,
      headersDistinct: { "content-type": ["application/json"] }, encodedBody: body() };
  } };
  const bridge = new Bridge({ config, store: new MemoryStore(), clock: { nowMs: () => Date.parse("2026-08-03T12:00:00Z") },
    audit: { async writeAuthEvent() {} }, cimdTransport: transport, cimdResolver: resolver });
  return { bridge, clients, calls };
}

function authorizePath(): string {
  return `/oauth/authorize?${new URLSearchParams({ response_type: "code", client_id: CIMD_ID, redirect_uri: REDIRECT,
    code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", scope: "mcp:read", state: "release" })}`;
}

async function fastifyAuthorize(bridge: Bridge): Promise<{ status: number; body: string }> {
  const app = Fastify();
  await registerOAuthRoutes(app, { bridge, identity, identityHeader: "x-release-identity" });
  try { const response = await app.inject({ method: "GET", url: authorizePath(), headers: { "x-release-identity": "ok" } });
    return { status: response.statusCode, body: response.body }; } finally { await app.close(); }
}

async function expressAuthorize(bridge: Bridge): Promise<{ status: number; body: string }> {
  const app = express();
  app.use("/", createOAuthRouter({ bridge, identity, identityHeader: "x-release-identity" }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const port = (server.address() as { port: number }).port;
  try {
    return await new Promise((resolve, reject) => {
      const req = request({ host: "127.0.0.1", port, path: authorizePath(), headers: { "x-release-identity": "ok" } }, (res) => {
        let body = ""; res.setEncoding("utf8"); res.on("data", (chunk: string) => { body += chunk; });
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      });
      req.on("error", reject); req.end();
    });
  } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
}

async function honoAuthorize(bridge: Bridge): Promise<{ status: number; body: string; app: ReturnType<typeof createOAuthApp> }> {
  const app = createOAuthApp({ bridge, identity, identityHeader: "x-release-identity" });
  const response = await app.fetch(new Request(`https://auth.test${authorizePath()}`, { headers: { "x-release-identity": "ok" } }));
  return { status: response.status, body: await response.text(), app };
}

releaseTest("RM.6 HTTPS CIMD authorization reaches the resolver through Fastify, Express, and Hono without DCR state", async () => {
  for (const authorize of [fastifyAuthorize, expressAuthorize, async (bridge: Bridge) => honoAuthorize(bridge)]) {
    const current = runtime();
    const response = await authorize(current.bridge);
    assert.equal(response.status, 200);
    assert.match(response.body, /Authorize access/);
    assert.deepEqual(current.calls, { dns: 1, transport: 1 }, "DNS resolution and guarded transport each ran exactly once");
    assert.equal(current.clients.saves, 0, "CIMD did not create a DCR record");
  }
});
