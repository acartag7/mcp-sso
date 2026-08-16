import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { OAuthAuthorizationUseCase } from "../src/authorize.ts";
import { createBridgeConfig, type BridgeConfig, AuthConfigError } from "../src/config.ts";
import { MAX_CONSENT_TOKEN_BYTES, signConsentToken } from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import { validateAllowedScopes } from "../src/machine-client-secret.ts";
import {
  assertAllowedScopesCeiling, normalizeScopes, resolveClientCredentialsScope, storedScopes,
} from "../src/scopes.ts";
import { MemoryStore } from "../src/store/memory.ts";

function scope(index: number, bytes = 256): string {
  return `s${index.toString(36).padStart(3, "0")}${"a".repeat(bytes - 4)}`;
}

function config(overrides: Partial<BridgeConfig> = {}): BridgeConfig {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    issuer: "https://auth.test", resource: "https://api.test/mcp", consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK,
    signingKeyId: "k", redirectAllowlist: ["https://client.test/callback"],
    scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"], allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stateless" }, accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300, ...overrides,
  };
}

function isOAuth(code: string): (error: unknown) => boolean {
  return (error) => error instanceof OAuthError && error.code === code;
}

class CorruptPriorStore extends MemoryStore {
  consumeCalls = 0;
  codeWrites = 0;
  override async consumeConsentJti(...args: Parameters<MemoryStore["consumeConsentJti"]>): Promise<boolean> {
    this.consumeCalls += 1;
    return await super.consumeConsentJti(...args);
  }
  override async saveAuthCode(...args: Parameters<MemoryStore["saveAuthCode"]>): Promise<void> {
    this.codeWrites += 1;
    await super.saveAuthCode(...args);
  }
  override async findGrantedScopes(): Promise<string[]> {
    return Array(129).fill("mcp:read");
  }
}

test("scope bounds: boot rejects overlong tokens and lists over 128 entries", () => {
  const scopes = Array.from({ length: 129 }, (_, index) => scope(index));
  assert.throws(() => createBridgeConfig(config({ scopeCatalog: scopes, defaultScopes: scopes })), AuthConfigError);
  assert.throws(() => createBridgeConfig(config({ scopeCatalog: ["a".repeat(257)], defaultScopes: [] })), AuthConfigError);
});

test("scope bounds: request, identity, stored, and machine-client scope carriers fail closed", () => {
  const scopes = Array.from({ length: 129 }, (_, index) => scope(index));
  assert.throws(() => normalizeScopes(scopes, scopes, []), isOAuth("invalid_scope"));
  assert.throws(() => assertAllowedScopesCeiling(scopes), isOAuth("access_denied"));
  assert.throws(() => storedScopes(scopes, scopes), isOAuth("invalid_grant"));
  assert.throws(() => resolveClientCredentialsScope(undefined, scopes, scopes), isOAuth("invalid_scope"));
  assert.throws(() => validateAllowedScopes(scopes, scopes), isOAuth("invalid_scope"));
});

test("scope bounds: identity ceilings snapshot their bounded entries without iterating twice", () => {
  let lengthReads = 0;
  let indexReads = 0;
  let iteratorReads = 0;
  const ceiling = new Proxy(["mcp:read"], {
    get(target, key, receiver) {
      if (key === "length") {
        lengthReads += 1;
        return lengthReads === 1 ? 1 : 129;
      }
      if (key === "0") indexReads += 1;
      if (key === Symbol.iterator) {
        iteratorReads += 1;
        return function* () {
          yield* iteratorReads === 1 ? target : Array(129).fill("mcp:read");
        };
      }
      return Reflect.get(target, key, receiver);
    },
  });
  assert.deepEqual(assertAllowedScopesCeiling(ceiling), ["mcp:read"]);
  assert.deepEqual({ lengthReads, indexReads, iteratorReads }, { lengthReads: 1, indexReads: 1, iteratorReads: 0 });
});

test("scope bounds: signer refuses a consent token that cannot fit the approval route", async () => {
  const checked = createBridgeConfig(config());
  await assert.rejects(
    signConsentToken({
      clientId: "client-1", redirectUri: "https://client.test/callback", resource: checked.resource,
      scopes: ["mcp:read"], codeChallenge: "a".repeat(43), codeChallengeMethod: "S256",
      state: "a".repeat(MAX_CONSENT_TOKEN_BYTES), subject: "user-1",
    }, checked, { nowMs: () => Date.parse("2026-08-03T12:00:00.000Z") }),
    isOAuth("invalid_request"),
  );
});

test("scope bounds: corrupt stored scopes fail before consuming consent", async () => {
  const store = new CorruptPriorStore();
  const checked = createBridgeConfig(config({
    dcr: {
      mode: "stored",
      store: {
        async save() {},
        async find(clientId) {
          return clientId === "client-1"
            ? { clientId, redirectUris: ["https://client.test/callback"], applicationType: "web", issuedAtEpoch: 1 }
            : null;
        },
      },
    },
  }));
  const auth = new OAuthAuthorizationUseCase({
    config: checked, store, clock: { nowMs: () => Date.parse("2026-08-03T12:00:00.000Z") },
    audit: { async writeAuthEvent() {} },
  });
  const consentToken = await signConsentToken({
    clientId: "client-1", redirectUri: "https://client.test/callback", resource: checked.resource,
    scopes: ["mcp:read"], codeChallenge: "a".repeat(43), codeChallengeMethod: "S256", subject: "user-1",
  }, checked, { nowMs: () => Date.parse("2026-08-03T12:00:00.000Z") });
  await assert.rejects(auth.approve({ consentToken, approved: true, origin: "https://auth.test" }), isOAuth("invalid_grant"));
  assert.deepEqual({ consumeCalls: store.consumeCalls, codeWrites: store.codeWrites }, { consumeCalls: 0, codeWrites: 0 });
});
