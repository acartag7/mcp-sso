import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { test } from "node:test";
import type { FastifyRateLimitOptions, FastifyRateLimitStore } from "@fastify/rate-limit";
import type { JWK } from "jose";
import { buildApp } from "../examples/fastify-sqlite/app.ts";
import {
  createDcrRegistrationRateLimitPort, EXAMPLE_UPSTREAM_BUCKET_CAP,
  FASTIFY_DCR_REGISTER_RATE_LIMIT,
} from "../examples/fastify-sqlite/registration-rate-limit.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import type { AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";

function signingJwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }) } as JWK;
}

function registrationPayload(redirectUri: string): Record<string, unknown> {
  return {
    client_name: "CLI regression fixture",
    application_type: redirectUri.startsWith("http://") ? "native" : "web",
    redirect_uris: [redirectUri],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  };
}

function configFor(
  mode: "stateless" | "stored",
  clientStore: ClientStore,
): { config: BridgeConfig; redirectUri: string } {
  const redirectUri = mode === "stored"
    ? "http://localhost:1455/auth/callback"
    : "https://app.test/callback";
  return {
    config: createBridgeConfig({
      issuer: "https://bridge.test",
      resource: "https://bridge.test/mcp",
      consentSigningSecret: randomBytes(32).toString("base64url"),
      signingPrivateJwk: signingJwk(),
      redirectAllowlist: mode === "stored" ? ["http://localhost"] : [redirectUri],
      scopeCatalog: ["mcp:read"],
      defaultScopes: ["mcp:read"],
      allowedOrigins: ["https://bridge.test"],
      dcr: mode === "stored" ? { mode, store: clientStore } : { mode },
      accessTokenTtlSeconds: 600,
      refreshTokenTtlSeconds: 2_592_000,
      consentTokenTtlSeconds: 300,
      authorizationCodeTtlSeconds: 300,
    }),
    redirectUri,
  };
}

test("runnable-example core limiter bounds upstream key cardinality", async () => {
  const limiter = createDcrRegistrationRateLimitPort();
  for (let index = 0; index < EXAMPLE_UPSTREAM_BUCKET_CAP; index++) {
    assert.equal(await limiter.check(`upstream:198.51.${Math.floor(index / 256)}.${index % 256}`), true);
  }
  assert.equal(await limiter.check("upstream:203.0.113.1"), false);
  assert.equal(await limiter.check("token:203.0.113.1"), true, "unowned key classes retain their library policy");
});

test("Fastify/SQLite registration limiter bounds both DCR modes before parsing and registration effects", async () => {
  for (const mode of ["stateless", "stored"] as const) {
    const saved: ClientRegistration[] = [];
    const events: AuthAuditEvent[] = [];
    const clientStore: ClientStore = {
      async save(client) { saved.push(client); },
      async find(clientId) { return saved.find((client) => client.clientId === clientId) ?? null; },
    };
    const { config, redirectUri } = configFor(mode, clientStore);
    const built = await buildApp({
      config,
      identity: { async verify() { return { ok: false, reason: "unused" }; } },
      audit: { async writeAuthEvent(event) { events.push(event); } },
      protectedResourceRateLimit: { max: 1, timeWindowMs: 60_000 },
    });
    try {
      for (let index = 0; index < FASTIFY_DCR_REGISTER_RATE_LIMIT.max; index++) {
        const admitted = await built.app.inject({
          method: "POST",
          url: "/oauth/register",
          headers: { "content-type": "application/json" },
          payload: registrationPayload(redirectUri),
        });
        assert.equal(admitted.statusCode, 201, `${mode} registration ${index + 1}: ${admitted.body}`);
      }
      const denied = await built.app.inject({
        method: "POST",
        url: "http://bridge.test/oauth/register",
        headers: { "content-type": "application/json" },
        payload: "{malformed",
      });
      assert.equal(denied.statusCode, 429, `${mode}: absolute-form budget denial runs before JSON parsing`);
      assert.equal(saved.length, mode === "stored" ? FASTIFY_DCR_REGISTER_RATE_LIMIT.max : 0);
      assert.equal(
        events.filter((event) => event.event === "oauth.register" && event.status === "success").length,
        FASTIFY_DCR_REGISTER_RATE_LIMIT.max,
        `${mode}: the denied request has no success audit effect`,
      );
    } finally {
      await built.app.close();
      await built.close();
    }
  }
});

test("Fastify/SQLite stored DCR keeps an aggregate core budget behind the route hook", async () => {
  const saved: ClientRegistration[] = [];
  const clientStore: ClientStore = {
    async save(client) { saved.push(client); },
    async find(clientId) {
      return saved.find((client) => client.clientId === clientId) ?? null;
    },
  };
  const { config, redirectUri } = configFor("stored", clientStore);
  const built = await buildApp({
    config,
    identity: { async verify() { return { ok: false, reason: "unused" }; } },
  });
  try {
    const statuses: number[] = [];
    for (let index = 0; index <= FASTIFY_DCR_REGISTER_RATE_LIMIT.max; index++) {
      const response = await built.bridge.handleRegister({
        query: {}, headers: {}, ip: `198.51.100.${index + 1}`,
        body: registrationPayload(redirectUri),
      });
      statuses.push(response.status);
    }
    assert.deepEqual(
      statuses.slice(0, FASTIFY_DCR_REGISTER_RATE_LIMIT.max),
      Array(FASTIFY_DCR_REGISTER_RATE_LIMIT.max).fill(201),
    );
    assert.equal(statuses.at(-1), 429);
    assert.equal(saved.length, FASTIFY_DCR_REGISTER_RATE_LIMIT.max);
  } finally {
    await built.app.close();
    await built.close();
  }
});

test("Fastify/SQLite registration limiter store failure is a fixed 503 before durable effects", async () => {
  const privateDetail = "registration limiter backend detail";
  class FailingStore implements FastifyRateLimitStore {
    constructor(_options: FastifyRateLimitOptions) {}
    incr(
      _key: string,
      callback: (error: Error | null, result?: { current: number; ttl: number }) => void,
    ): void { callback(new Error(privateDetail)); }
    child(): FastifyRateLimitStore { return this; }
  }
  const saved: ClientRegistration[] = [];
  const events: AuthAuditEvent[] = [];
  const clientStore: ClientStore = {
    async save(client) { saved.push(client); },
    async find() { return null; },
  };
  const { config } = configFor("stored", clientStore);
  const built = await buildApp({
    config,
    identity: { async verify() { return { ok: false, reason: "unused" }; } },
    audit: { async writeAuthEvent(event) { events.push(event); } },
    protectedResourceRateLimit: { store: FailingStore },
  });
  try {
    const response = await built.app.inject({
      method: "POST",
      url: "/oauth/register",
      headers: { "content-type": "application/json" },
      payload: "{malformed",
    });
    assert.equal(response.statusCode, 503);
    assert.match(response.body, /Protected resource rate limiter unavailable/);
    assert.doesNotMatch(response.body, new RegExp(privateDetail));
    assert.equal(saved.length, 0, "limiter outage occurs before ClientStore.save");
    assert.equal(events.length, 0, "limiter outage occurs before Bridge registration audit");
  } finally {
    await built.app.close();
    await built.close();
  }
});
