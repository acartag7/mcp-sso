import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import express from "express";
import Fastify, { type FastifyInstance } from "fastify";
import type { JWK } from "jose";
import { createOAuthRouter } from "../src/adapters/express.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import { createOAuthApp } from "../src/adapters/hono.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import { buildUnauthorizedChallenge, protectedResourceMetadataUrl } from "../src/challenge.ts";
import {
  AuthConfigError, KNOWN_CONFIG_KEYS, createBridgeConfig, type MultiResourceBridgeConfig,
} from "../src/config.ts";
import { authorizationServerMetadata } from "../src/metadata.ts";
import { noopAudit } from "../src/ports/audit.ts";
import { MemoryStore } from "../src/store/memory.ts";

const A = "https://api.test/alpha";
const B = "https://api.test/beta";
const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const signingPrivateJwk = {
  ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "activation-key",
} as JWK;

function common() {
  return {
    issuer: "https://auth.test",
    consentSigningSecret: "activation-test-consent-secret-with-enough-entropy",
    signingPrivateJwk,
    signingKeyId: "activation-key",
    redirectAllowlist: [],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" as const },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 600,
    consentTokenTtlSeconds: 600,
    authorizationCodeTtlSeconds: 600,
  };
}

function resources(a = A, b = B) {
  return [
    { resource: a, scopeCatalog: ["zeta", "shared"], defaultScopes: ["shared"] },
    { resource: b, scopeCatalog: ["alpha", "shared"], defaultScopes: ["alpha"] },
  ];
}

function multi(a = A, b = B): MultiResourceBridgeConfig {
  return createBridgeConfig({ ...common(), resources: resources(a, b) });
}

function bridge(config = multi()): Bridge<MultiResourceBridgeConfig> {
  return new Bridge({
    config, store: new MemoryStore(), clock: { nowMs: () => Date.parse("2026-07-30T12:00:00Z") }, audit: noopAudit,
  });
}

async function json(response: Response): Promise<Record<string, unknown>> {
  return await response.json() as Record<string, unknown>;
}

test("two-resource config activates while the singleton input/output stays unchanged", () => {
  const activated = multi();
  assert.deepEqual(activated.resources.map((entry) => entry.resource), [A, B]);
  assert.equal(Object.hasOwn(activated, "resource"), false);
  assert.equal(Object.isFrozen(activated.resources), true);
  assert.equal(KNOWN_CONFIG_KEYS.has("resources"), true);
  assert.equal(KNOWN_CONFIG_KEYS.has("legacySingletonResource"), true);

  const singleton = createBridgeConfig({
    ...common(), resource: A, scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
  });
  assert.equal(singleton.resource, A);
  assert.deepEqual(singleton.scopeCatalog, ["mcp:read"]);
  assert.equal(Object.hasOwn(singleton, "resources"), false);
});

test("AS metadata publishes the sorted scope union and no non-standard resource list", () => {
  const metadata = authorizationServerMetadata(multi());
  assert.deepEqual(metadata.scopes_supported, ["alpha", "shared", "zeta"]);
  assert.equal(Object.hasOwn(metadata, "protected_resources"), false);
});

test("challenge and URL helpers pin the path-inserted PRM and resource-owned scopes", () => {
  const config = multi();
  assert.equal(
    protectedResourceMetadataUrl(config, A),
    "https://api.test/.well-known/oauth-protected-resource/alpha",
  );
  assert.equal(
    buildUnauthorizedChallenge(config, { resource: B, scope: ["alpha", "shared", "zeta"] }),
    "Bearer resource_metadata=\"https://api.test/.well-known/oauth-protected-resource/beta\", scope=\"alpha shared\"",
  );
  const oneEntry = createBridgeConfig({ ...common(), resources: [resources()[0]!] });
  assert.equal(
    protectedResourceMetadataUrl(oneEntry),
    "https://api.test/.well-known/oauth-protected-resource",
  );
});

test("Fastify, Express, and Hono path-inserted routes return their own PRM", async () => {
  const fastify = Fastify();
  await registerOAuthRoutes(fastify, { bridge: bridge(), skipAuthorize: true });
  for (const [path, resource, scopes] of [
    ["/.well-known/oauth-protected-resource/alpha", A, ["zeta", "shared"]],
    ["/.well-known/oauth-protected-resource/beta", B, ["alpha", "shared"]],
  ] as const) {
    const response = await fastify.inject({ method: "GET", url: path });
    assert.deepEqual(response.json(), { resource, authorization_servers: ["https://auth.test"], scopes_supported: scopes });
  }
  assert.equal((await fastify.inject({ method: "GET", url: "/.well-known/oauth-protected-resource" })).statusCode, 404);
  await fastify.close();

  const expressApp = express();
  expressApp.use(createOAuthRouter({ bridge: bridge(), skipAuthorize: true }));
  const server = expressApp.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const port = (server.address() as { port: number }).port;
  try {
    const alpha = await fetch(`http://127.0.0.1:${port}/.well-known/oauth-protected-resource/alpha`);
    const beta = await fetch(`http://127.0.0.1:${port}/.well-known/oauth-protected-resource/beta`);
    assert.equal((await json(alpha)).resource, A);
    assert.equal((await json(beta)).resource, B);
  } finally { await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }

  const hono = createOAuthApp({ bridge: bridge(), skipAuthorize: true });
  assert.equal((await json(await hono.request("http://local/.well-known/oauth-protected-resource/alpha"))).resource, A);
  assert.equal((await json(await hono.request("http://local/.well-known/oauth-protected-resource/beta"))).resource, B);
});

test("duplicate decoded or case-folded PRM route pathnames fail before Fastify is touched", async () => {
  for (const [left, right] of [
    ["https://one.test/a", "https://two.test/%61"],
    ["https://one.test/Case", "https://two.test/case"],
    ["https://one.test/same", "https://two.test/same"],
  ]) {
    const configured = bridge(multi(left!, right!));
    let frameworkReads = 0;
    const untouched = new Proxy({}, { get() { frameworkReads += 1; throw new Error("framework touched"); } });
    await assert.rejects(
      registerOAuthRoutes(untouched as FastifyInstance, { bridge: configured, skipAuthorize: true }),
      (error: unknown) => error instanceof AuthConfigError && error.message.includes(left!) && error.message.includes(right!),
    );
    assert.equal(frameworkReads, 0);
    assert.throws(() => createOAuthRouter({ bridge: configured, skipAuthorize: true }), AuthConfigError);
    assert.throws(() => createOAuthApp({ bridge: configured, skipAuthorize: true }), AuthConfigError);
  }
});

test("Fastify rejects relaxed routerOptions before registering any route", async () => {
  for (const routerOptions of [
    { caseSensitive: false },
    { ignoreTrailingSlash: true },
  ]) {
    const app = Fastify({ routerOptions });
    await assert.rejects(
      registerOAuthRoutes(app, { bridge: bridge(), skipAuthorize: true }),
      AuthConfigError,
    );
    assert.equal(app.printRoutes(), "(empty tree)");
    await app.close();
  }
});

test("root fallback exists only for a one-resource mount or an exact root resource", async () => {
  const allPaths = createOAuthApp({ bridge: bridge(), skipAuthorize: true });
  assert.equal((await allPaths.request("http://local/.well-known/oauth-protected-resource")).status, 404);

  const oneMount = createOAuthApp({ bridge: bridge(), skipAuthorize: true, protectedResources: [B] });
  assert.equal((await json(await oneMount.request("http://local/.well-known/oauth-protected-resource"))).resource, B);
  assert.equal((await oneMount.request("http://local/.well-known/oauth-protected-resource/alpha")).status, 404);

  const root = "https://api.test";
  const rootConfig = multi(root, A);
  const rootMount = createOAuthApp({ bridge: bridge(rootConfig), skipAuthorize: true });
  assert.equal((await json(await rootMount.request("http://local/.well-known/oauth-protected-resource"))).resource, root);
  assert.equal((await json(await rootMount.request("http://local/.well-known/oauth-protected-resource/alpha"))).resource, A);
});
