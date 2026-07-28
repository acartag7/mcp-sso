import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { JWK } from "jose";
import { createBridgeConfig, AuthConfigError } from "../src/config.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import { STORED_DCR_GRANT_GENERATION } from "../src/ports/store.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { noopAudit } from "../src/ports/audit.ts";
import {
  generateRefreshToken, parseRefreshFamilyId, pkceChallenge, sha256Hex,
} from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { openSqliteStore } from "../src/store/sqlite.ts";
import { OAuthTokenUseCase } from "../src/token.ts";

const REDIRECT = "https://client.test/callback";
const VERIFIER = "grant-generation-verifier-012345678901234567890";

class TestClientStore implements ClientStore {
  private readonly records = new Map<string, ClientRegistration>();
  async save(record: ClientRegistration): Promise<void> { this.records.set(record.clientId, record); }
  async find(clientId: string): Promise<ClientRegistration | null> { return this.records.get(clientId) ?? null; }
}

test("stored-DCR rollback grants fail for unknown and existing client IDs", async () => {
  const clients = new TestClientStore();
  await clients.save({
    clientId: "existing-client", redirectUris: [REDIRECT],
    applicationType: "web", issuedAtEpoch: 1,
  });
  const config = storedConfig(clients);
  const store = new MemoryStore();
  const token = new OAuthTokenUseCase({ config, store, clock: new SystemClock(), audit: noopAudit });

  for (const clientId of ["unknown-client", "existing-client"]) {
    const rawCode = `legacy-code-${clientId}`;
    await store.saveAuthCode({
      codeHash: sha256Hex(rawCode), clientId, subject: "subject",
      redirectUri: REDIRECT, resource: config.resource, scopes: ["mcp:read"],
      codeChallenge: pkceChallenge(VERIFIER), codeChallengeMethod: "S256",
      expiresAt: futureIso(), grantGeneration: null,
    });
    await assert.rejects(
      token.exchangeAuthorizationCode({
        grantType: "authorization_code", code: rawCode, redirectUri: REDIRECT,
        clientId, codeVerifier: VERIFIER,
      }),
      invalidGrant,
      `${clientId}: legacy authorization code`,
    );

    const rawRefresh = generateRefreshToken();
    const familyId = parseRefreshFamilyId(rawRefresh);
    assert.ok(familyId);
    await store.saveRefreshToken({
      tokenHash: sha256Hex(rawRefresh), familyId, previousTokenHash: null,
      clientId, subject: "subject", scopes: ["mcp:read"],
      expiresAt: futureIso(), grantGeneration: null,
    });
    await assert.rejects(
      token.refresh({ grantType: "refresh_token", refreshToken: rawRefresh, clientId }),
      invalidGrant,
      `${clientId}: legacy refresh family`,
    );
  }
  assert.deepEqual(
    await store.findGrantedScopes("subject", "existing-client", new Date().toISOString(), STORED_DCR_GRANT_GENERATION),
    [],
    "legacy family cannot contribute scopes to a new current grant",
  );
  await store.close();
});

test("stored-DCR use-cases reject a store without the generation capability", () => {
  const clients = new TestClientStore();
  const store = new MemoryStore();
  Object.defineProperty(store, "storedDcrGrantGeneration", { value: undefined });
  assert.throws(
    () => new OAuthTokenUseCase({
      config: storedConfig(clients), store, clock: new SystemClock(), audit: noopAudit,
    }),
    (error: unknown) => error instanceof AuthConfigError && /storedDcrGrantGeneration 1/.test(error.message),
  );
});

test("a current stored-DCR interactive session survives SQLite restarts", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-current-session-"));
  const file = join(dir, "oauth.sqlite");
  const clients = new TestClientStore();
  await clients.save({
    clientId: "existing-client", redirectUris: [REDIRECT],
    applicationType: "web", issuedAtEpoch: 1,
  });
  const config = storedConfig(clients);
  const rawCode = "current-generation-code";
  try {
    const beforeCodeExchange = openSqliteStore(file);
    await beforeCodeExchange.saveAuthCode({
      codeHash: sha256Hex(rawCode), clientId: "existing-client", subject: "subject",
      redirectUri: REDIRECT, resource: config.resource, scopes: ["mcp:read"],
      codeChallenge: pkceChallenge(VERIFIER), codeChallengeMethod: "S256",
      expiresAt: futureIso(), grantGeneration: STORED_DCR_GRANT_GENERATION,
    });
    await beforeCodeExchange.close();

    const codeExchangeStore = openSqliteStore(file);
    const codeExchange = new OAuthTokenUseCase({
      config, store: codeExchangeStore, clock: new SystemClock(), audit: noopAudit,
    });
    const first = await codeExchange.exchangeAuthorizationCode({
      grantType: "authorization_code", code: rawCode, redirectUri: REDIRECT,
      clientId: "existing-client", codeVerifier: VERIFIER,
    });
    await codeExchangeStore.close();

    const refreshStore = openSqliteStore(file);
    const refresh = new OAuthTokenUseCase({
      config, store: refreshStore, clock: new SystemClock(), audit: noopAudit,
    });
    const second = await refresh.refresh({
      grantType: "refresh_token", refreshToken: first.refresh_token,
      clientId: "existing-client",
    });
    assert.notEqual(second.refresh_token, first.refresh_token);
    await refreshStore.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function storedConfig(store: ClientStore) {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return createBridgeConfig({
    issuer: "https://auth.test", resource: "https://api.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: privateKey.export({ format: "jwk" }) as JWK,
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"], allowedOrigins: ["https://auth.test"],
    dcr: { mode: "stored", store }, accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 3600, consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
}

function futureIso(): string {
  return new Date(Date.now() + 60_000).toISOString();
}

function invalidGrant(error: unknown): boolean {
  return error instanceof OAuthError && error.code === "invalid_grant";
}
