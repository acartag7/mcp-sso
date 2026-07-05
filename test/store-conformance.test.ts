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
    clientId: "c", subject: "s", scopes: ["mcp:read"], expiresAt,
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
