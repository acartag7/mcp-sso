// Contracts §9.6 transport boundary, sibling sweep across fastify/express/hono.
//
// The §9.6 guarantee is that below-cap media the adapters do not interpret stay
// out of OAuth field selection. The default parser chain is not the whole story:
// an application may mount its own parser for an unsupported media type on the
// same OAuth paths (`express.json({ type: "text/plain" })`, a Fastify
// `text/plain` parser returning an object), and that parser fills the framework's
// body slot BEFORE the adapter's own parsers run. These cases pin that the
// adapters key on the request's Content-Type rather than on whoever produced the
// body, so a caller-owned parser cannot promote unsupported bytes into
// `redirect_uris` (RFC 7591 DCR) or `token` (RFC 7009 revocation).

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { createServer, request } from "node:http";
import { test } from "node:test";
import express from "express";
import Fastify from "fastify";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createOAuthRouter } from "../src/adapters/express.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import { createOAuthApp } from "../src/adapters/hono.ts";
import { createBridgeConfig } from "../src/config.ts";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { IdentityPort } from "../src/ports/identity.ts";
import { MemoryStore } from "../src/store/memory.ts";

const NOW_MS = Date.parse("2026-07-03T12:00:00.000Z");
const REDIRECT = "https://client.test/callback";
const UNSUPPORTED = "text/plain";

class FakeClock { nowMs(): number { return NOW_MS; } }
class MemoryAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(event); }
}

const stubIdentity: IdentityPort = { async verify() { return { ok: false, reason: "bad_token" }; } };

/** A store that counts every refresh-token lookup revocation would perform. */
function countingStore(): { store: MemoryStore; lookups: () => number } {
  const store = new MemoryStore();
  const find = store.findRefreshToken.bind(store);
  let lookups = 0;
  store.findRefreshToken = async (tokenHash) => { lookups += 1; return find(tokenHash); };
  return { store, lookups: () => lookups };
}

function makeBridge(store: MemoryStore): Bridge {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const signingPrivateJwk = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK;
  const config = createBridgeConfig({
    issuer: "https://auth.test", resource: "https://api.test/mcp",
    consentSigningSecret: "x".repeat(40), signingPrivateJwk, signingKeyId: "k",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  return new Bridge({ config, store, clock: new FakeClock(), audit: new MemoryAudit() });
}

interface Resp { status: number; body: string }

function post(port: number, path: string, headers: Record<string, string>, body: string): Promise<Resp> {
  return new Promise((resolve, reject) => {
    const req = request(
      { hostname: "127.0.0.1", port, path, method: "POST", headers },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => { buf += chunk; });
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

const call = (port: number, path: string, contentType: string, body: string): Promise<Resp> =>
  post(port, path, { "content-type": contentType }, body);

interface Mounted { port: number; lookups: () => number; close: () => Promise<void> }

async function mountExpress(preParser: express.RequestHandler): Promise<Mounted> {
  const { store, lookups } = countingStore();
  const app = express();
  app.set("query parser", (source: string) => Object.fromEntries(new URLSearchParams(source)));
  app.use(preParser); // application-owned parser, mounted before the OAuth router
  app.use("/", createOAuthRouter({ bridge: makeBridge(store), identity: stubIdentity }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    port: (server.address() as { port: number }).port,
    lookups,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function mountFastify(): Promise<Mounted> {
  const { store, lookups } = countingStore();
  const app = Fastify();
  // Application-owned parser: this deployment decided text/plain carries JSON.
  app.addContentTypeParser(UNSUPPORTED, { parseAs: "string" }, (_req, body, done) => {
    try { done(null, JSON.parse(String(body)) as unknown); }
    catch { done(null, Object.fromEntries(new URLSearchParams(String(body)))); }
  });
  await registerOAuthRoutes(app, { bridge: makeBridge(store), identity: stubIdentity });
  await app.listen({ port: 0, host: "127.0.0.1" });
  return {
    port: (app.server.address() as { port: number }).port,
    lookups,
    close: () => app.close(),
  };
}

async function mountHono(): Promise<Mounted> {
  const { store, lookups } = countingStore();
  const app = createOAuthApp({ bridge: makeBridge(store), identity: stubIdentity });
  const server = createServer(async (incoming, outgoing) => {
    const chunks: Buffer[] = [];
    for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
    const headers = new Headers();
    for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
      headers.append(incoming.rawHeaders[index]!, incoming.rawHeaders[index + 1]!);
    }
    const response = await app.fetch(new Request(`http://localhost${incoming.url ?? "/"}`, {
      method: incoming.method, headers, body: Buffer.concat(chunks),
    }));
    outgoing.statusCode = response.status;
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  });
  server.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    port: (server.address() as { port: number }).port,
    lookups,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const JSON_DCR = JSON.stringify({ redirect_uris: [REDIRECT], client_name: "unsupported-media" });
// querystring.parse (express.urlencoded extended:false) turns repeated keys into
// an array, so this is the URL-encoded shape that satisfies `redirect_uris`.
const FORM_DCR = `redirect_uris=${encodeURIComponent(REDIRECT)}&redirect_uris=${encodeURIComponent(REDIRECT)}`;
const JSON_REVOKE = JSON.stringify({ token: "rt_must_not_be_selected" });
const FORM_REVOKE = "token=rt_must_not_be_selected";

/** Each adapter with the body shape ITS parser would actually turn into OAuth
 *  fields — otherwise the case would pass for the wrong reason. */
const MOUNTS: ReadonlyArray<{ name: string; mount: () => Promise<Mounted>; dcr: string; revoke: string }> = [
  {
    name: "express + application json parser typed text/plain",
    mount: () => mountExpress(express.json({ type: UNSUPPORTED })),
    dcr: JSON_DCR, revoke: JSON_REVOKE,
  },
  {
    name: "express + application urlencoded parser typed text/plain",
    mount: () => mountExpress(express.urlencoded({ extended: false, type: UNSUPPORTED })),
    dcr: FORM_DCR, revoke: FORM_REVOKE,
  },
  { name: "fastify + application text/plain parser", mount: mountFastify, dcr: JSON_DCR, revoke: JSON_REVOKE },
  { name: "hono", mount: mountHono, dcr: JSON_DCR, revoke: JSON_REVOKE },
];

for (const { name, mount, dcr, revoke } of MOUNTS) {
  test(`${name}: an unsupported media type never registers a DCR client`, async () => {
    const app = await mount();
    try {
      const response = await call(app.port, "/oauth/register", UNSUPPORTED, dcr);
      assert.notEqual(response.status, 201, "unsupported media must not create a client");
      assert.equal(response.status, 400);
      assert.match(response.body, /"error":"invalid_request"/);
      assert.doesNotMatch(response.body, /client_id/, "no client_id may be issued from unsupported bytes");
    } finally {
      await app.close();
    }
  });

  test(`${name}: an unsupported media type never selects a revocation token`, async () => {
    const app = await mount();
    try {
      // RFC 7009 §2.2: an unrecognized/absent token is still HTTP 200. The point
      // here is that no token field was selected, so no lookup was performed.
      const response = await call(app.port, "/oauth/revoke", UNSUPPORTED, revoke);
      assert.equal(app.lookups(), 0, "unsupported bytes must not become the token field");
      assert.equal(response.status, 200);

      // The adjacent supported media type still works — this gate is about the
      // media type, not about disabling revocation.
      const form = await call(app.port, "/oauth/revoke", "application/x-www-form-urlencoded", FORM_REVOKE);
      assert.equal(form.status, 200);
      assert.equal(app.lookups(), 1, "URL-encoded revocation still selects its token field");
    } finally {
      await app.close();
    }
  });
}

// The gate keys on an essence being present AND supported, so a request with no
// Content-Type at all fails closed the same way an unsupported one does. Only a
// parser that consumes everything (`type: () => true`) can produce a body here,
// which is exactly the shape the default chain's bounded raw fallback cannot.
test("express: a body parsed with no Content-Type never becomes OAuth fields", async () => {
  const app = await mountExpress(express.json({ type: () => true }));
  try {
    const registered = await post(app.port, "/oauth/register", {}, JSON_DCR);
    assert.equal(registered.status, 400);
    assert.doesNotMatch(registered.body, /client_id/, "a Content-Type-less body must not register a client");

    const revoked = await post(app.port, "/oauth/revoke", {}, JSON_REVOKE);
    assert.equal(revoked.status, 200);
    assert.equal(app.lookups(), 0, "a Content-Type-less body must not become the token field");
  } finally {
    await app.close();
  }
});
