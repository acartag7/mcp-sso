import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import type { JWK } from "jose";
import {
  AuthConfigError, Bridge, createBridgeConfig, noopRateLimit,
  type AuditPort, type BridgeConfig, type RateLimitPort,
} from "../src/index.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { boundedTestRateLimit } from "./support/bounded-rate-limit.ts";

const clock = { nowMs: () => Date.parse("2026-08-17T12:00:00Z") };
const audit: AuditPort = { async writeAuthEvent() {} };

function config(
  mode: "stateless" | "stored",
  clients: ClientStore,
  redirectAllowlist: string[] = [],
): BridgeConfig {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return createBridgeConfig({
    issuer: "https://auth.test",
    resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: privateKey.export({ format: "jwk" }) as JWK,
    redirectAllowlist,
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: mode === "stored" ? { mode, store: clients } : { mode },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
}

function boot(cfg: BridgeConfig, rateLimit?: RateLimitPort): Bridge {
  return new Bridge({ config: cfg, store: new MemoryStore(), clock, audit, rateLimit });
}

test("DCR boot matrix requires a limiter for public stateless and every stored deployment", () => {
  const clients: ClientStore = { async save() {}, async find() { return null; } };
  const bounded: RateLimitPort = boundedTestRateLimit();

  assert.throws(() => boot(config("stateless", clients)), AuthConfigError);
  assert.doesNotThrow(() => boot(config("stateless", clients), bounded));
  assert.throws(
    () => boot(config("stored", clients)),
    /stored DCR requires a bounded RateLimitPort/,
  );
  assert.doesNotThrow(() => boot(config("stored", clients), bounded));
});

test("stored DCR rejects noopRateLimit and does not inherit stateless carve-outs", () => {
  const clients: ClientStore = { async save() {}, async find() { return null; } };
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const localStored = createBridgeConfig({
    issuer: "http://localhost:3000",
    resource: "http://localhost:3000/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: privateKey.export({ format: "jwk" }) as JWK,
    redirectAllowlist: ["http://localhost"],
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: ["http://localhost:3000"],
    dcr: { mode: "stored", store: clients },
    dev: { allowInsecureLocalhost: true },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });

  assert.throws(() => boot(localStored, noopRateLimit), /bounded RateLimitPort/);
  assert.throws(() => new Bridge({
    config: localStored,
    store: new MemoryStore(),
    clock,
    audit,
    acknowledgeUnsafeStatelessDefaults: true,
  }), /bounded RateLimitPort/);
});

test("stored DCR refuses unbounded boot and emits 429 before bulk writes with a limiter", async () => {
  const saved: ClientRegistration[] = [];
  const clients: ClientStore = {
    async save(client) { saved.push(client); },
    async find(clientId) {
      return saved.find((client) => client.clientId === clientId) ?? null;
    },
  };
  const stored = config("stored", clients, ["https://client.test/callback"]);
  assert.throws(() => boot(stored), /stored DCR requires a bounded RateLimitPort/);

  let registrations = 0;
  const bridge = boot(stored, {
    async check(key) {
      if (!key.startsWith("register:")) return true;
      registrations += 1;
      return registrations <= 3;
    },
  });
  const statuses: number[] = [];
  for (let index = 0; index < 200; index++) {
    const response = await bridge.handleRegister({
      query: {},
      headers: {},
      ip: `198.51.100.${index + 1}`,
      body: {
        client_name: `bulk-${index}`,
        application_type: "web",
        redirect_uris: ["https://client.test/callback"],
      },
    });
    statuses.push(response.status);
  }

  assert.deepEqual(statuses.slice(0, 3), [201, 201, 201]);
  assert.deepEqual(statuses.slice(3), Array(197).fill(429));
  assert.equal(saved.length, 3, "denied registrations never reach durable storage");
  assert.ok(statuses.includes(429));
});
