import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import type { JWK } from "jose";
import {
  AuthConfigError, Bridge, createBridgeConfig,
  noopRateLimit, type AuditPort, type BridgeConfig,
} from "../src/index.ts";
import { MemoryStore } from "../src/store/memory.ts";

const clock = { nowMs: () => Date.parse("2026-08-13T12:00:00Z") };
const audit: AuditPort = { async writeAuthEvent() {} };

function config(overrides: Partial<BridgeConfig> = {}): BridgeConfig {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return createBridgeConfig({
    issuer: "https://auth.test",
    resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: privateKey.export({ format: "jwk" }) as JWK,
    redirectAllowlist: [],
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
    ...overrides,
  });
}

function construct(cfg: BridgeConfig, rateLimit = undefined as typeof noopRateLimit | undefined): Bridge {
  return new Bridge({
    config: cfg,
    store: new MemoryStore(),
    clock,
    audit,
    ...(rateLimit === undefined ? {} : { rateLimit }),
  });
}

test("the explicit starter acknowledgement warns and permits boot", () => {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => { warnings.push(args.map(String).join(" ")); };
  try {
    assert.doesNotThrow(() => new Bridge({
      config: config(), store: new MemoryStore(), clock, audit,
      acknowledgeUnsafeStatelessDefaults: true,
    }));
  } finally {
    console.warn = original;
  }
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /acknowledgeUnsafeStatelessDefaults.*unsafe for internet-facing use/);
});

test("Bridge boot rejects stateless DCR plus starter-only redirect trust plus no limiter", () => {
  for (const redirectAllowlist of [
    [],
    ["https://claude.ai", "https://chatgpt.com"],
    ["http://localhost", "http://127.0.0.1", "http://[::1]"],
  ]) {
    assert.throws(
      () => construct(config({ redirectAllowlist })),
      (error: unknown) => error instanceof AuthConfigError
        && /stateless DCR.*application-specific HTTPS redirect.*RateLimitPort/.test(error.message),
    );
  }
  assert.throws(() => construct(config(), noopRateLimit), AuthConfigError);
});

test("Bridge boot accepts each adjacent composition when one unsafe-default condition changes", () => {
  assert.doesNotThrow(() => construct(config(), { async check() { return true; } }));
  assert.doesNotThrow(() => construct(config({ redirectAllowlist: ["https://client.test/callback"] })));
  const clients = { async save() {}, async find() { return null; } };
  assert.doesNotThrow(() => construct(config({ dcr: { mode: "stored", store: clients } })));
});
