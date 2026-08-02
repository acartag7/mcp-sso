import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import {
  AuthConfigError, createBridgeConfig, type BridgeConfig,
} from "../src/config.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";

class WorkingClientStore implements ClientStore {
  readonly clients = new Map<string, ClientRegistration>();
  async save(client: ClientRegistration): Promise<void> {
    this.clients.set(client.clientId, client);
  }
  async find(clientId: string): Promise<ClientRegistration | null> {
    return this.clients.get(clientId) ?? null;
  }
}

function privateJwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "key-1" } as JWK;
}

function baseInput(): BridgeConfig {
  return {
    issuer: "https://auth.test",
    resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: privateJwk(),
    signingKeyId: "key-1",
    redirectAllowlist: ["https://client.test/callback"],
    scopeCatalog: ["mcp:read", "mcp:write"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  };
}

test("config publication snapshots and freezes every remaining mutable sibling", async () => {
  const store = new WorkingClientStore();
  const replacement = new WorkingClientStore();
  const dcr: BridgeConfig["dcr"] = { mode: "stored", store };
  const clientCredentials = { enabled: false };
  const scopeCatalog = ["mcp:read", "mcp:write"];
  const defaultScopes = ["mcp:read"];
  const allowedOrigins = ["https://auth.test"];
  const keyOps = ["sign"];
  const signingPrivateJwk = { ...privateJwk(), key_ops: keyOps };
  const config = createBridgeConfig({
    ...baseInput(), dcr, clientCredentials, scopeCatalog, defaultScopes,
    allowedOrigins, signingPrivateJwk,
  });

  for (const [published, caller, label] of [
    [config.dcr, dcr, "dcr"],
    [config.clientCredentials, clientCredentials, "clientCredentials"],
    [config.scopeCatalog, scopeCatalog, "scopeCatalog"],
    [config.defaultScopes, defaultScopes, "defaultScopes"],
    [config.allowedOrigins, allowedOrigins, "allowedOrigins"],
    [config.signingPrivateJwk, signingPrivateJwk, "signingPrivateJwk"],
  ] as const) {
    assert.notEqual(published, caller, `${label} must not be caller-owned`);
    assert.equal(Object.isFrozen(published), true, `${label} must be frozen`);
  }

  (dcr as { mode: string; store: ClientStore }).mode = "stateless";
  (dcr as { mode: string; store: ClientStore }).store = replacement;
  clientCredentials.enabled = true;
  scopeCatalog.push("mcp:admin");
  defaultScopes.push("mcp:write");
  allowedOrigins.push("https://evil.test");
  signingPrivateJwk.kid = "swapped";
  signingPrivateJwk.d = "tampered";
  keyOps.push("verify");

  assert.equal(config.dcr.mode, "stored");
  assert.equal(config.dcr.mode === "stored" && config.dcr.store, store);
  assert.equal(config.clientCredentials?.enabled, false);
  assert.deepEqual(config.scopeCatalog, ["mcp:read", "mcp:write"]);
  assert.deepEqual(config.defaultScopes, ["mcp:read"]);
  assert.deepEqual(config.allowedOrigins, ["https://auth.test"]);
  assert.equal(config.signingPrivateJwk.kid, "key-1");
  assert.notEqual(config.signingPrivateJwk.d, "tampered");
  assert.deepEqual(config.signingPrivateJwk.key_ops, ["sign"]);
  assert.notEqual(config.signingPrivateJwk.key_ops, keyOps);
  assert.equal(Object.isFrozen(config.signingPrivateJwk.key_ops), true);

  const registration: ClientRegistration = {
    clientId: "client-1", redirectUris: ["https://client.test/callback"],
    applicationType: "web", issuedAtEpoch: 1,
  };
  if (config.dcr.mode !== "stored") assert.fail("stored DCR snapshot expected");
  await config.dcr.store.save(registration);
  assert.equal(await config.dcr.store.find("client-1"), registration);
});

test("config publication reads caller-owned nested values once", () => {
  const store = new WorkingClientStore();
  const scopeCatalog = ["mcp:read"];
  let scopeRead = 0;
  Object.defineProperty(scopeCatalog, 0, {
    configurable: true, enumerable: true,
    get() { scopeRead += 1; return scopeRead === 1 ? "mcp:read" : "mcp:admin"; },
  });
  let modeReads = 0;
  let storeReads = 0;
  const dcr = {
    get mode() { modeReads += 1; return "stored" as const; },
    get store() { storeReads += 1; return store; },
  };
  let enabledReads = 0;
  const clientCredentials = {
    get enabled() { enabledReads += 1; return false; },
  };
  const rawJwk = privateJwk();
  let scalarReads = 0;
  Object.defineProperty(rawJwk, "d", {
    configurable: true, enumerable: true,
    get() { scalarReads += 1; return scalarReads === 1 ? "approved" : "tampered"; },
  });

  const config = createBridgeConfig({
    ...baseInput(), scopeCatalog, defaultScopes: ["mcp:read"], dcr,
    clientCredentials, signingPrivateJwk: rawJwk,
  });
  assert.deepEqual(
    { scopeRead, modeReads, storeReads, enabledReads, scalarReads },
    { scopeRead: 1, modeReads: 1, storeReads: 1, enabledReads: 1, scalarReads: 1 },
  );
  assert.deepEqual(config.scopeCatalog, ["mcp:read"]);
  assert.equal(config.signingPrivateJwk.d, "approved");
});

test("malformed JS and cast-TypeScript config containers fail with AuthConfigError", () => {
  const base = baseInput();
  const malformed: Array<() => unknown> = [
    () => createBridgeConfig(null as unknown as BridgeConfig),
    () => createBridgeConfig({ ...base, dcr: null } as unknown as BridgeConfig),
    () => createBridgeConfig({ ...base, dcr: { mode: "stored", store: {} } } as BridgeConfig),
    () => createBridgeConfig({ ...base, dev: { allowInsecureLocalhost: "true" } } as unknown as BridgeConfig),
    () => createBridgeConfig({ ...base, clientCredentials: { enabled: "false" } } as unknown as BridgeConfig),
    () => createBridgeConfig({ ...base, scopeCatalog: "mcp:read" } as unknown as BridgeConfig),
    () => createBridgeConfig({ ...base, defaultScopes: [7] } as unknown as BridgeConfig),
    () => createBridgeConfig({ ...base, allowedOrigins: null } as unknown as BridgeConfig),
    () => createBridgeConfig({ ...base, signingPrivateJwk: null } as unknown as BridgeConfig),
    () => createBridgeConfig({
      ...base, signingPrivateJwk: { ...privateJwk(), key_ops: [() => undefined] },
    } as unknown as BridgeConfig),
  ];
  for (const construct of malformed) {
    assert.throws(construct, (error: unknown) => error instanceof AuthConfigError);
  }
});

test("throwing accessors and proxy traps are translated to AuthConfigError", () => {
  const base = baseInput();
  const issuer = { ...base };
  Object.defineProperty(issuer, "issuer", {
    enumerable: true,
    get() { throw new TypeError("hostile issuer getter"); },
  });
  const redirectAllowlist = new Proxy(["https://client.test/callback"], {
    get(target, property, receiver) {
      if (property === "length") throw new TypeError("hostile length getter");
      return Reflect.get(target, property, receiver);
    },
  });
  const cimd = {
    enabled: true as const,
    get maxInFlight(): number { throw new TypeError("hostile cap getter"); },
  };
  const ownKeys = new Proxy({ ...base }, {
    ownKeys() { throw new TypeError("hostile ownKeys trap"); },
  });

  for (const construct of [
    () => createBridgeConfig(issuer),
    () => createBridgeConfig({ ...base, redirectAllowlist }),
    () => createBridgeConfig({ ...base, cimd }),
    () => createBridgeConfig(ownKeys),
  ]) {
    assert.throws(construct, (error: unknown) => error instanceof AuthConfigError);
  }
});

test("revoked top-level and nested proxies are translated to AuthConfigError", () => {
  const base = baseInput();
  const top = Proxy.revocable({ ...base }, {});
  const redirect = Proxy.revocable(["https://client.test/callback"], {});
  const jwk = Proxy.revocable(privateJwk(), {});
  top.revoke();
  redirect.revoke();
  jwk.revoke();

  for (const construct of [
    () => createBridgeConfig(top.proxy),
    () => createBridgeConfig({ ...base, redirectAllowlist: redirect.proxy }),
    () => createBridgeConfig({ ...base, signingPrivateJwk: jwk.proxy }),
  ]) {
    assert.throws(construct, (error: unknown) => error instanceof AuthConfigError);
  }
});

test("hostile and oversized configuration array lengths fail before iteration", () => {
  const base = baseInput();
  let entryReads = 0;
  const hostile = new Proxy(["mcp:read"], {
    get(target, property, receiver) {
      if (property === "length") return 1_000_000_000;
      if (property === "0") entryReads += 1;
      return Reflect.get(target, property, receiver);
    },
  });

  assert.throws(
    () => createBridgeConfig({ ...base, scopeCatalog: hostile }),
    (error: unknown) => error instanceof AuthConfigError,
  );
  assert.equal(entryReads, 0, "the cap must reject before reading any entry");
  assert.throws(
    () => createBridgeConfig({ ...base, allowedOrigins: Array(4097).fill("https://auth.test") }),
    (error: unknown) => error instanceof AuthConfigError,
  );
  assert.throws(
    () => createBridgeConfig({
      ...base, signingPrivateJwk: { ...privateJwk(), key_ops: Array(4097).fill("sign") },
    }),
    (error: unknown) => error instanceof AuthConfigError,
  );
});
