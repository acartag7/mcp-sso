import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig } from "../src/config.ts";
import { MemoryStore } from "../src/store/memory.ts";

const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const signingKey = { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK;

function bridge(): Bridge {
  const config = createBridgeConfig({
    issuer: "https://auth.test",
    resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy-0123456789",
    signingPrivateJwk: signingKey,
    signingKeyId: "k",
    redirectAllowlist: ["https://a.test/"],
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
  return new Bridge({
    config,
    store: new MemoryStore(),
    clock: { nowMs: () => Date.parse("2026-07-26T12:00:00.000Z") },
    audit: { writeAuthEvent: async () => {} },
  });
}

function request(grantTypes: unknown) {
  return {
    body: { redirect_uris: ["https://a.test/cb"], grant_types: grantTypes },
    query: {},
    headers: {},
    ip: "203.0.113.9",
  };
}

test("DCR accepts grant_types beyond the redirect_uris cardinality cap", async () => {
  const response = await bridge().handleRegister(request(Array(17).fill("authorization_code")));
  assert.equal(response.status, 201);
});

test("DCR still rejects client_credentials beyond 16 grant_types entries", async () => {
  const grantTypes = Array(17).fill("authorization_code");
  grantTypes[16] = "client_credentials";
  const response = await bridge().handleRegister(request(grantTypes));
  assert.equal(response.status, 400);
  assert.equal((response.body as { error: string }).error, "invalid_client_metadata");
  assert.match((response.body as { error_description: string }).error_description, /client_credentials/);
});

test("DCR still rejects malformed grant_types containers and members", async () => {
  for (const malformed of ["authorization_code", ["authorization_code", 7]]) {
    const response = await bridge().handleRegister(request(malformed));
    assert.equal(response.status, 400);
    assert.equal((response.body as { error: string }).error, "invalid_client_metadata");
  }
});

test("DCR rejects non-integer and negative grant_types lengths", async () => {
  for (const length of [Number.NaN, 1.5, Number.POSITIVE_INFINITY, -1]) {
    const grantTypes = new Proxy(["authorization_code"], {
      get(target, key, receiver) {
        if (key === "length") return length;
        return Reflect.get(target, key, receiver);
      },
    });
    const response = await bridge().handleRegister(request(grantTypes));
    assert.equal(response.status, 400, `length=${String(length)}`);
    assert.equal((response.body as { error: string }).error, "invalid_client_metadata");
  }
});

test("DCR snapshots grant_types length once and reads each selected index once", async () => {
  let lengthReads = 0;
  let indexReads = 0;
  const grantTypes = new Proxy(Array(17).fill("authorization_code"), {
    get(target, key, receiver) {
      if (key === "length") {
        lengthReads++;
        return lengthReads === 1 ? 17 : 100_000;
      }
      if (typeof key === "string" && /^\d+$/.test(key)) indexReads++;
      return Reflect.get(target, key, receiver);
    },
  });
  const response = await bridge().handleRegister(request(grantTypes));
  assert.equal(response.status, 201);
  assert.equal(lengthReads, 1);
  assert.equal(indexReads, 17);
});
