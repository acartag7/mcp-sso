import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import {
  chmodSync, copyFileSync, mkdtempSync, readFileSync, rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import type { JWK } from "jose";
import { createBridgeConfig } from "../src/config.ts";
import { generateRefreshToken, sha256Hex } from "../src/crypto.ts";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { openSqliteStore } from "../src/store/sqlite.ts";
import { OAuthTokenUseCase, type UserTokenResponse } from "../src/token.ts";

const FAMILY_ID = "chosenfamily123456";
const RAW_REFRESH = generateRefreshToken(FAMILY_ID);
const CLIENT_ID = "chosen-client";
const RESOURCE = "https://api.test/mcp";

class RecordingAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(event); }
}

test("an unsafe-directory preseed cannot reach real refresh issuance or mutate hostile state", {
  skip: process.platform === "win32"
    ? "Node exposes no Windows ACL admission primitive; the documented contract requires a deployer-private ACL directory"
    : false,
}, async () => {
  const trustedDir = privateDir("mcp-sso-trusted-preseed-");
  const unsafeDir = privateDir("mcp-sso-hostile-preseed-");
  const trustedFile = join(trustedDir, "state.sqlite");
  const hostileFile = join(unsafeDir, "state.sqlite");
  const config = bridgeConfig();
  try {
    const seedStore = openSqliteStore(trustedFile);
    await seedStore.saveRefreshToken({
      tokenHash: sha256Hex(RAW_REFRESH), familyId: FAMILY_ID, previousTokenHash: null,
      clientId: CLIENT_ID, subject: "chosen-subject", resource: RESOURCE,
      scopes: ["mcp:read"], expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      grantGeneration: null,
    });
    await seedStore.close();
    copyFileSync(trustedFile, hostileFile);
    chmodSync(hostileFile, 0o600);
    chmodSync(unsafeDir, 0o777);

    const bytesBefore = readFileSync(hostileFile);
    const stateBefore = databaseState(hostileFile);
    const audit = new RecordingAudit();
    let response: UserTokenResponse | undefined;
    let bootError: unknown;
    let hostileStore: ReturnType<typeof openSqliteStore> | undefined;
    try {
      hostileStore = openSqliteStore(hostileFile);
      const tokens = new OAuthTokenUseCase({
        config, store: hostileStore, clock: new SystemClock(), audit,
      });
      response = await tokens.refresh({
        grantType: "refresh_token", refreshToken: RAW_REFRESH, clientId: CLIENT_ID,
      });
    } catch (error) {
      bootError = error;
    } finally {
      await hostileStore?.close();
    }

    assert.match(String((bootError as Error | undefined)?.message), /sqlite: unsafe persistent state:/);
    assert.equal(response, undefined, "no bridge-signed access or refresh token was returned");
    assert.equal(audit.events.some((event) => event.status === "success"), false, "no success audit was emitted");
    assert.deepEqual(readFileSync(hostileFile), bytesBefore, "rejection did not alter hostile database bytes");
    assert.deepEqual(databaseState(hostileFile), stateBefore, "rejection did not migrate or rotate hostile rows");
    assert.equal(stateBefore.tokens.length, 1, "the fixture contains only the chosen predecessor");
    assert.equal(stateBefore.tokens[0]?.consumed_at, null, "the chosen predecessor starts unconsumed");

    const trustedAudit = new RecordingAudit();
    const trustedStore = openSqliteStore(trustedFile);
    try {
      const trustedTokens = new OAuthTokenUseCase({
        config, store: trustedStore, clock: new SystemClock(), audit: trustedAudit,
      });
      const trustedResponse = await trustedTokens.refresh({
        grantType: "refresh_token", refreshToken: RAW_REFRESH, clientId: CLIENT_ID,
      });
      assert.ok(trustedResponse.access_token, "operator-owned state can mint an access token");
      assert.notEqual(trustedResponse.refresh_token, RAW_REFRESH, "operator-owned state rotates the family");
      assert.equal(trustedAudit.events.some((event) => event.status === "success"), true);
    } finally {
      await trustedStore.close();
    }
  } finally {
    rmSync(trustedDir, { recursive: true, force: true });
    rmSync(unsafeDir, { recursive: true, force: true });
  }
});

interface DatabaseState {
  schema: unknown[];
  families: unknown[];
  tokens: { token_hash: unknown; previous_token_hash: unknown; consumed_at: unknown }[];
}

function databaseState(file: string): DatabaseState {
  const db = new DatabaseSync(file, { readOnly: true });
  try {
    return {
      schema: db.prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name").all(),
      families: db.prepare("SELECT * FROM oauth_refresh_token_families ORDER BY family_id").all(),
      tokens: db.prepare(`SELECT token_hash, previous_token_hash, consumed_at
        FROM oauth_refresh_tokens ORDER BY token_hash`).all() as DatabaseState["tokens"],
    };
  } finally {
    db.close();
  }
}

function bridgeConfig() {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return createBridgeConfig({
    issuer: "https://auth.test", resource: RESOURCE,
    consentSigningSecret: randomBytes(32).toString("base64url"),
    signingPrivateJwk: privateKey.export({ format: "jwk" }) as JWK,
    signingKeyId: "preseed-test-key", redirectAllowlist: ["https://client.test/callback"],
    scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

function privateDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  if (process.platform !== "win32") chmodSync(dir, 0o700);
  return dir;
}
