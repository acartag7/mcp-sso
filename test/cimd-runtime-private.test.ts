import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

test("compiled root API keeps CIMD network capabilities runtime-private", async () => {
  const root = resolve(import.meta.dirname, "..");
  const api = await import(pathToFileURL(resolve(root, "dist/index.js")).href);
  const { MemoryStore } = await import(pathToFileURL(resolve(root, "dist/store/memory.js")).href);
  const privateJwk = { ...generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" };
  const config = api.createBridgeConfig({
    issuer: "https://auth.test", resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy", signingPrivateJwk: privateJwk,
    redirectAllowlist: ["https://client.test/cb"], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" }, cimd: { enabled: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const bridge = new api.Bridge({
    config, store: new MemoryStore(), clock: { nowMs: () => Date.now() },
    audit: { async writeAuthEvent() {} },
  });
  const resolver = bridge.cimd;
  const forbidden = [
    "config", "clock", "audit", "rateLimit", "cache", "inFlight", "maxInFlight",
    "maxWaitersPerFetch", "waiters", "cacheTtlCapSeconds", "defaultFetcher", "seams",
    "allowLoopback", "maxDocumentBytes", "fetchTimeoutMs", "fetcher", "fetcherFor", "createFetcher",
    "rateGuard", "registrationFor", "fetchAndCache", "emit",
  ];
  const own = Object.getOwnPropertyNames(resolver);
  const prototype = Object.getOwnPropertyNames(Object.getPrototypeOf(resolver));
  for (const name of forbidden) {
    assert.ok(!own.includes(name), `${name} must not be an own runtime property`);
    assert.ok(!prototype.includes(name), `${name} must not be a prototype runtime method`);
    assert.equal(resolver[name], undefined, `${name} must not be reachable`);
    Object.defineProperty(resolver, name, { value: "attacker", configurable: true });
    assert.equal(resolver[name], "attacker", `${name} shadow is inert user-owned state`);
  }
  assert.deepEqual(
    prototype.filter((name) => name !== "constructor").sort(),
    ["assertCapProfile", "rejectAfterResolve", "resolve"],
  );
});
