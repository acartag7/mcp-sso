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
import { createUpstreamRedirectFlow, type UpstreamRedirectFlow } from "../src/adapters/upstream-flow.ts";
import type { CimdTransport, DnsResolver } from "../src/cimd/transport.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { noopAudit } from "../src/ports/audit.ts";
import type { IdentityPort, RedirectIdentityPort } from "../src/ports/identity.ts";
import { MemoryStore } from "../src/store/memory.ts";

const NOW = Date.parse("2026-08-14T12:00:00.000Z");
const CIMD_ID = "https://client-metadata.example.test/client.json";
const REDIRECT = "https://client.example.test/callback";
const VERIFIER = "adapter-cimd-verifier-0123456789abcdef012345678901234";
const IDENTITY_HEADER = "x-test-identity";
const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const SIGNING_JWK = {
  ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "adapter-test",
} as JWK;

type AdapterName = "fastify" | "express" | "hono";
interface HttpResponse { status: number; headers: Record<string, string>; body: string }
interface HttpClient {
  get(path: string, headers?: Record<string, string>): Promise<HttpResponse>;
  close(): Promise<void>;
}
type AuthorizeMode = { identity: IdentityPort } | { upstream: UpstreamRedirectFlow };

function normalizedHeaders(headers: Record<string, unknown>): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value !== undefined) normalized[name] = Array.isArray(value) ? value.join(", ") : String(value);
  }
  return normalized;
}

async function mount(name: AdapterName, bridge: Bridge, mode: AuthorizeMode): Promise<HttpClient> {
  if (name === "fastify") {
    const app = Fastify();
    await registerOAuthRoutes(app, { bridge, ...mode });
    return {
      async get(path, headers) {
        const response = await app.inject({ method: "GET", url: path, headers: headers ?? {} });
        return { status: response.statusCode, headers: normalizedHeaders(response.headers), body: response.body };
      },
      async close() { await app.close(); },
    };
  }
  if (name === "express") {
    const app = express();
    app.use("/", createOAuthRouter({ bridge, ...mode }));
    const server = app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const port = (server.address() as { port: number }).port;
    return {
      get(path, headers = {}) {
        return new Promise((resolve, reject) => {
          const outbound = request({ host: "127.0.0.1", port, path, headers }, (response) => {
            let body = "";
            response.setEncoding("utf8");
            response.on("data", (chunk: string) => { body += chunk; });
            response.on("end", () => resolve({
              status: response.statusCode ?? 0,
              headers: normalizedHeaders(response.headers),
              body,
            }));
          });
          outbound.on("error", reject);
          outbound.end();
        });
      },
      async close() { await new Promise<void>((resolve) => server.close(() => resolve())); },
    };
  }
  const app = createOAuthApp({ bridge, ...mode });
  return {
    async get(path, headers) {
      const response = await app.request(path, { method: "GET", headers: headers ?? {} });
      return { status: response.status, headers: Object.fromEntries(response.headers), body: await response.text() };
    },
    async close() {},
  };
}

function runtime() {
  const calls = { dns: 0, transport: 0, idp: 0, exchange: 0 };
  const resolver: DnsResolver = {
    async resolve() {
      calls.dns += 1;
      return [{ address: "93.184.216.34", family: 4 }];
    },
  };
  const transport: CimdTransport = {
    async connectAndGet() {
      calls.transport += 1;
      async function* body(): AsyncGenerator<Uint8Array> {
        yield new TextEncoder().encode(JSON.stringify({
          client_id: CIMD_ID,
          client_name: "Adapter evidence client",
          redirect_uris: [REDIRECT],
        }));
      }
      return {
        status: 200,
        redirected: false,
        finalUrl: CIMD_ID,
        headersDistinct: { "content-type": ["application/json"] },
        encodedBody: body(),
      };
    },
  };
  const config = createBridgeConfig({
    issuer: "https://auth.example.test",
    resource: "https://resource.example.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: SIGNING_JWK,
    signingKeyId: "adapter-test",
    redirectAllowlist: ["https://opaque.example.test/callback"],
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.example.test"],
    dcr: { mode: "stateless" },
    cimd: { enabled: true },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
  const store = new MemoryStore();
  const clock = { nowMs: () => NOW };
  const bridge = new Bridge({
    config, store, clock, audit: noopAudit,
    cimdTransport: transport, cimdResolver: resolver,
  });
  const identity: IdentityPort = {
    async verify() { return { ok: true, identity: { subject: "direct-user@example.test" } }; },
  };
  const redirectIdentity: RedirectIdentityPort = {
    redirectUri: "https://auth.example.test/oauth/callback",
    buildAuthorizationUrl({ state }) {
      calls.idp += 1;
      return `https://idp.example.test/authorize?state=${encodeURIComponent(state)}`;
    },
    async exchangeAndVerify() {
      calls.exchange += 1;
      return { ok: true, identity: { subject: "upstream-user@example.test" } };
    },
  };
  const upstream = createUpstreamRedirectFlow({
    bridge, identity: redirectIdentity, store, clock, audit: noopAudit,
    cimdTransport: transport, cimdResolver: resolver,
  });
  return { bridge, identity, upstream, calls };
}

function authorizePath(): string {
  return `/oauth/authorize?${new URLSearchParams({
    response_type: "code",
    client_id: CIMD_ID,
    redirect_uri: REDIRECT,
    code_challenge: pkceChallenge(VERIFIER),
    code_challenge_method: "S256",
    scope: "mcp:read",
    state: "client-state",
  })}`;
}

function flowCookie(setCookie: string): string {
  return setCookie.split(";", 1)[0] ?? "";
}

for (const adapter of ["fastify", "express", "hono"] as const) {
  test(`${adapter}: direct CIMD authorization and served support metadata use shipped routes`, async () => {
    const subject = runtime();
    const client = await mount(adapter, subject.bridge, { identity: subject.identity });
    try {
      const metadata = await client.get("/.well-known/oauth-authorization-server");
      assert.equal(metadata.status, 200);
      assert.equal(JSON.parse(metadata.body).client_id_metadata_document_supported, true);
      const response = await client.get(authorizePath(), { [IDENTITY_HEADER]: "ok" });
      assert.equal(response.status, 200);
      assert.match(response.body, /Authorize access/);
      assert.deepEqual(subject.calls, { dns: 1, transport: 1, idp: 0, exchange: 0 });
    } finally {
      await client.close();
    }
  });

  test(`${adapter}: upstream CIMD route completes callback to consent`, async () => {
    const subject = runtime();
    const client = await mount(adapter, subject.bridge, { upstream: subject.upstream });
    try {
      const started = await client.get(authorizePath());
      assert.equal(started.status, 302);
      const upstreamState = new URL(started.headers.location ?? "").searchParams.get("state");
      assert.ok(upstreamState);
      const cookie = flowCookie(started.headers["set-cookie"] ?? "");
      assert.ok(cookie);
      const callback = await client.get(
        `/oauth/callback?${new URLSearchParams({ state: upstreamState, code: "upstream-code" })}`,
        { cookie },
      );
      assert.equal(callback.status, 200);
      assert.match(callback.body, /Authorize access/);
      assert.deepEqual(subject.calls, { dns: 1, transport: 1, idp: 1, exchange: 1 });
    } finally {
      await client.close();
    }
  });
}
