import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { createBridgeConfig, type BridgeConfig, AuthConfigError } from "../src/config.ts";
import { MAX_CONSENT_TOKEN_BYTES, signConsentToken } from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import { validateAllowedScopes } from "../src/machine-client-secret.ts";
import {
  assertAllowedScopesCeiling, normalizeScopes, resolveClientCredentialsScope, storedScopes,
} from "../src/scopes.ts";

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
