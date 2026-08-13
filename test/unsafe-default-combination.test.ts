import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { JWK } from "jose";
import {
  AuthConfigError, Bridge, createBridgeConfig,
  noopRateLimit, type AuditPort, type BridgeConfig,
} from "../src/index.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { buildApp } from "../examples/fastify-sqlite/app.ts";
import { buildGateway } from "../examples/api-key-gateway/app.ts";

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
      config: config({
        issuer: "http://localhost:3000",
        resource: "http://localhost:3000/mcp",
        dev: { allowInsecureLocalhost: true },
      }), store: new MemoryStore(), clock, audit,
      acknowledgeUnsafeStatelessDefaults: true,
    }));
  } finally {
    console.warn = original;
  }
  const acknowledgementWarnings = warnings.filter((warning) => warning.includes("acknowledgeUnsafeStatelessDefaults"));
  assert.equal(acknowledgementWarnings.length, 1);
  assert.match(acknowledgementWarnings[0]!, /unsafe for internet-facing use/);
});

test("the starter acknowledgement is restricted to loopback issuer and resource", () => {
  for (const overrides of [
    {},
    { issuer: "https://localhost" },
    { resource: "https://localhost/mcp" },
  ]) {
    assert.throws(() => new Bridge({
      config: config(overrides), store: new MemoryStore(), clock, audit,
      acknowledgeUnsafeStatelessDefaults: true,
    }), /restricted to loopback issuer and resource/);
  }
});

test("Bridge boot rejects stateless DCR plus starter-only redirect trust plus no limiter", () => {
  for (const redirectAllowlist of [
    [],
    ["https://claude.ai", "https://chatgpt.com"],
    ["http://localhost", "http://127.0.0.1", "http://[::1]"],
    ["http://localhost:4321/callback"],
    ["https://localhost", "https://127.0.0.1", "https://[::1]"],
  ]) {
    assert.throws(
      () => construct(config({ redirectAllowlist })),
      (error: unknown) => error instanceof AuthConfigError
        && /stateless DCR.*application-specific HTTPS redirect.*RateLimitPort/.test(error.message),
    );
  }
  assert.throws(() => construct(config(), noopRateLimit), AuthConfigError);
  for (const rateLimit of [{}, { check: 1 }]) {
    assert.throws(() => construct(config(), rateLimit as never), /rateLimit must implement/);
  }
});

test("Bridge boot accepts each adjacent composition when one unsafe-default condition changes", () => {
  assert.doesNotThrow(() => construct(config(), { async check() { return true; } }));
  assert.doesNotThrow(() => construct(config({ redirectAllowlist: ["https://client.test/callback"] })));
  assert.doesNotThrow(() => construct(config({ redirectAllowlist: ["https://localhost/callback"] })));
  const clients = { async save() {}, async find() { return null; } };
  assert.doesNotThrow(() => construct(config({ dcr: { mode: "stored", store: clients } })));
});

test("example factories reject before opening SQLite and do not coerce malformed acknowledgements", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-unsafe-composition-"));
  try {
    const cases = [
      { file: join(dir, "app.db"), run: () => buildApp({
        config: config(), sqliteFile: join(dir, "app.db"),
        acknowledgeUnsafeStatelessDefaults: "false" as never,
      }) },
      { file: join(dir, "gateway.db"), run: () => buildGateway({
        config: config(), sqliteFile: join(dir, "gateway.db"),
        backendUrl: "http://127.0.0.1:8788/mcp", getBackendCredential: () => "test",
        acknowledgeUnsafeStatelessDefaults: "false" as never,
      }) },
    ];
    for (const entry of cases) {
      await assert.rejects(entry.run, /stateless DCR/);
      assert.equal(existsSync(entry.file), false, "rejected composition created a SQLite file");
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
