// Runs the shared store-conformance suite against BOTH reference adapters
// (contracts §12): MemoryStore and SqliteStore (:memory:). A downstream SQL
// adapter must pass the same suite by importing runStoreConformance.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { STORED_DCR_GRANT_GENERATION } from "../src/ports/store.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { openSqliteStore } from "../src/store/sqlite.ts";
import { runStoreConformance } from "./lib/store-conformance.ts";

runStoreConformance("MemoryStore", () => new MemoryStore());
runStoreConformance("SqliteStore", () => openSqliteStore(":memory:"));

test("SqliteStore (file): persists no raw secrets and only OAuth tables", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-idp-store-"));
  const file = join(dir, "oauth.sqlite");
  const rawCode = "raw-secret-code-on-disk";
  const rawRefresh = "rt.famx.rawsecrettoken-on-disk-aaa";
  const expiresAt = "2026-07-03T13:00:00.000Z";
  const store = openSqliteStore(file);
  await store.saveAuthCode({
    codeHash: sha256Hex(rawCode), clientId: "c", subject: "s",
    redirectUri: "https://client.test/callback", resource: "https://api.test/mcp",
    scopes: ["mcp:read"], codeChallenge: "x", codeChallengeMethod: "S256", expiresAt,
  });
  await store.saveRefreshToken({
    tokenHash: sha256Hex(rawRefresh), familyId: "famx", previousTokenHash: null,
    clientId: "c", subject: "s", resource: "https://api.test/mcp", scopes: ["mcp:read"], expiresAt,
  });
  await store.close();
  if (process.platform !== "win32") {
    assert.equal(statSync(file).mode & 0o777, 0o600, "sqlite file is locked to 0600 (OAuth state: subjects + token hashes)");
  }
  const bytes = readFileSync(file);
  assert.equal(bytes.includes(Buffer.from(rawCode)), false, "raw auth code persisted");
  assert.equal(bytes.includes(Buffer.from(rawRefresh)), false, "raw refresh token persisted");
  const db = new DatabaseSync(file);
  const tables = db.prepare(`SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name`).all()
    .map((r) => String((r as { name: unknown }).name));
  db.close();
  assert.deepEqual(tables, ["oauth_auth_codes", "oauth_consent_jtis", "oauth_refresh_token_families", "oauth_refresh_tokens"]);
  assert.equal(tables.some((n) => /content|body|cache|page/i.test(n)), false);
  rmSync(dir, { recursive: true, force: true });
});

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

test("SqliteStore: a file: URI filename is not chmod'd (URI string not passed to chmod)", async () => {
  // chmod'ing the literal "file:..." URI string would throw ENOENT after the DB
  // opened; URI names are detected and skipped so valid SQLite URIs work.
  const store = openSqliteStore("file:mcp-sso-uri-test?mode=memory");
  await store.close();
});

test("SqliteStore: generation survives reopen and old-column inserts remain legacy", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-generation-"));
  const file = join(dir, "oauth.sqlite");
  try {
    const first = openSqliteStore(file);
    await first.saveAuthCode({
      codeHash: sha256Hex("current-code"), clientId: "existing-client", subject: "s",
      redirectUri: "https://client.test/callback", resource: "https://api.test/mcp",
      scopes: ["mcp:read"], codeChallenge: "x", codeChallengeMethod: "S256",
      expiresAt: "2026-07-03T13:00:00.000Z", grantGeneration: STORED_DCR_GRANT_GENERATION,
    });
    await first.saveRefreshToken({
      tokenHash: sha256Hex("current-refresh"), familyId: "current-family",
      previousTokenHash: null, clientId: "existing-client", subject: "s", resource: "https://api.test/mcp",
      scopes: ["mcp:read"], expiresAt: "2026-07-03T13:00:00.000Z",
      grantGeneration: STORED_DCR_GRANT_GENERATION,
    });
    await first.close();

    const oldBinary = new DatabaseSync(file);
    oldBinary.prepare(`INSERT INTO oauth_auth_codes (
      code_hash, client_id, subject, redirect_uri, resource, scopes_json,
      code_challenge, code_challenge_method, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      sha256Hex("legacy-code"), "existing-client", "s", "https://client.test/callback",
      "https://api.test/mcp", '["mcp:read"]', "x", "S256", "2026-07-03T13:00:00.000Z",
    );
    oldBinary.prepare(
      `INSERT INTO oauth_refresh_token_families (family_id, resource, revoked_at) VALUES (?, ?, NULL)`,
    ).run("legacy-family", "https://api.test/mcp");
    oldBinary.prepare(`INSERT INTO oauth_refresh_tokens (
      token_hash, family_id, previous_token_hash, client_id, subject, resource,
      scopes_json, expires_at, consumed_at
    ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, NULL)`).run(
      sha256Hex("legacy-refresh"), "legacy-family", "existing-client",
      "s", "https://api.test/mcp", '["mcp:write"]', "2026-07-03T13:00:00.000Z",
    );
    oldBinary.prepare(`INSERT INTO oauth_refresh_tokens (
      token_hash, family_id, previous_token_hash, client_id, subject, resource,
      scopes_json, expires_at, consumed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`).run(
      sha256Hex("legacy-in-current-family"), "current-family",
      sha256Hex("current-refresh"), "existing-client", "s",
      "https://api.test/mcp", '["mcp:write"]', "2026-07-03T13:00:00.000Z",
    );
    oldBinary.close();

    const reopened = openSqliteStore(file);
    assert.equal(
      (await reopened.consumeAuthCode(
        sha256Hex("current-code"), "2026-07-03T12:00:00.000Z",
        STORED_DCR_GRANT_GENERATION,
      ))?.grantGeneration,
      STORED_DCR_GRANT_GENERATION,
      "a genuine current code survives restart",
    );
    assert.equal(
      await reopened.consumeAuthCode(
        sha256Hex("legacy-code"), "2026-07-03T12:00:00.000Z",
        STORED_DCR_GRANT_GENERATION,
      ),
      null,
      "old explicit-column insert receives SQL NULL and is rejected",
    );
    assert.ok(await reopened.rotateRefreshToken(
      sha256Hex("current-refresh"),
      {
        tokenHash: sha256Hex("current-successor"), familyId: "current-family",
        previousTokenHash: sha256Hex("current-refresh"), clientId: "ignored",
        subject: "ignored", resource: "https://api.test/mcp", scopes: [], expiresAt: "2026-07-03T13:00:00.000Z",
        grantGeneration: 2,
      },
      "2026-07-03T12:00:00.000Z",
      STORED_DCR_GRANT_GENERATION,
    ), "a genuine current family survives restart");
    assert.equal(await reopened.rotateRefreshToken(
      sha256Hex("legacy-refresh"),
      {
        tokenHash: sha256Hex("legacy-successor"), familyId: "legacy-family",
        previousTokenHash: sha256Hex("legacy-refresh"), clientId: "existing-client",
        subject: "s", resource: "https://api.test/mcp", scopes: [], expiresAt: "2026-07-03T13:00:00.000Z",
        grantGeneration: STORED_DCR_GRANT_GENERATION,
      },
      "2026-07-03T12:00:00.000Z",
      STORED_DCR_GRANT_GENERATION,
    ), null);
    assert.equal(await reopened.findRefreshToken(sha256Hex("legacy-successor")), null);
    assert.equal(await reopened.rotateRefreshToken(
      sha256Hex("legacy-in-current-family"),
      {
        tokenHash: sha256Hex("legacy-current-successor"), familyId: "current-family",
        previousTokenHash: sha256Hex("legacy-in-current-family"), clientId: "existing-client",
        subject: "s", resource: "https://api.test/mcp", scopes: [], expiresAt: "2026-07-03T13:00:00.000Z",
        grantGeneration: STORED_DCR_GRANT_GENERATION,
      },
      "2026-07-03T12:00:00.000Z",
      STORED_DCR_GRANT_GENERATION,
    ), null, "old successor in a current family is still legacy");
    assert.deepEqual(
      await reopened.findGrantedScopes(
        "s", "existing-client", "2026-07-03T12:00:00.000Z",
        STORED_DCR_GRANT_GENERATION,
      ),
      ["mcp:read"],
      "old successor in a current family cannot contribute scopes",
    );
    await reopened.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("SqliteStore: resource migration leaves legacy refresh rows unusable without rebinding", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-resource-migration-"));
  const file = join(dir, "oauth.sqlite");
  const resource = "https://api-a.test/mcp";
  try {
    // Simulate the deployed pre-resource schema. The migration must add nullable
    // columns and preserve these rows as legacy rather than guessing the current
    // bridge resource from this test's later store open.
    const old = new DatabaseSync(file);
    old.exec(`
      PRAGMA foreign_keys = ON;
      CREATE TABLE oauth_refresh_token_families (
        family_id TEXT PRIMARY KEY NOT NULL,
        revoked_at TEXT,
        grant_generation INTEGER
      ) STRICT;
      CREATE TABLE oauth_refresh_tokens (
        token_hash TEXT PRIMARY KEY NOT NULL,
        family_id TEXT NOT NULL,
        previous_token_hash TEXT,
        client_id TEXT NOT NULL,
        subject TEXT NOT NULL,
        scopes_json TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        consumed_at TEXT,
        grant_generation INTEGER,
        FOREIGN KEY (family_id) REFERENCES oauth_refresh_token_families (family_id) ON DELETE CASCADE
      ) STRICT;
    `);
    old.prepare(`INSERT INTO oauth_refresh_token_families (family_id, revoked_at, grant_generation) VALUES (?, NULL, ?)`)
      .run("legacy-resource-family", STORED_DCR_GRANT_GENERATION);
    old.prepare(`INSERT INTO oauth_refresh_tokens (
      token_hash, family_id, previous_token_hash, client_id, subject, scopes_json,
      expires_at, consumed_at, grant_generation
    ) VALUES (?, ?, NULL, ?, ?, ?, ?, NULL, ?)`)
      .run(
        sha256Hex("legacy-resource-token"), "legacy-resource-family", "client-1", "subject-1",
        '["mcp:read"]', "2026-07-03T13:00:00.000Z", STORED_DCR_GRANT_GENERATION,
      );
    old.close();

    const store = openSqliteStore(file);
    assert.equal((await store.findRefreshToken(sha256Hex("legacy-resource-token")))?.resource, null);
    assert.deepEqual(
      await store.findGrantedScopes(
        "subject-1", "client-1", "2026-07-03T12:00:00.000Z",
        STORED_DCR_GRANT_GENERATION, resource,
      ),
      [],
      "a pre-resource row cannot contribute scopes after migration",
    );
    const rotated = await store.rotateRefreshToken(
      sha256Hex("legacy-resource-token"),
      {
        tokenHash: sha256Hex("legacy-resource-successor"), familyId: "legacy-resource-family",
        previousTokenHash: sha256Hex("legacy-resource-token"), clientId: "client-1", subject: "subject-1",
        resource, scopes: ["mcp:read"], expiresAt: "2026-07-03T13:00:00.000Z",
        grantGeneration: STORED_DCR_GRANT_GENERATION,
      },
      "2026-07-03T12:00:00.000Z",
      STORED_DCR_GRANT_GENERATION,
      resource,
    );
    assert.equal(rotated, null, "legacy row fails closed instead of rebinding to resource A");
    assert.ok(await store.findRefreshToken(sha256Hex("legacy-resource-token")), "legacy predecessor remains untouched");
    assert.equal(await store.findRefreshToken(sha256Hex("legacy-resource-successor")), null, "no successor was persisted");
    await store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
