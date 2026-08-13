// SqliteStore schema migration (contracts §12.3). Idempotent; STRICT tables.
// State is OAuth-only — no content/body/cache tables (asserted by the conformance
// suite). All secrets are SHA-256 digests; there is NO grant table (findGrantedScopes
// queries the refresh-token tables directly).

import { randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { assertStoreInstanceId } from "../ports/store.ts";

const CLIENT_TABLE_SQL = `CREATE TABLE oauth_clients (
    client_id TEXT PRIMARY KEY NOT NULL,
    redirect_uris_json TEXT NOT NULL,
    application_type TEXT NOT NULL CHECK (application_type IN ('native', 'web')),
    issued_at_epoch INTEGER NOT NULL CHECK (issued_at_epoch >= 0)
  ) STRICT`;

const METADATA_TABLE_SQL = `CREATE TABLE oauth_store_metadata (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    instance_id TEXT UNIQUE NOT NULL
  ) STRICT`;

const MIGRATIONS = [
  `PRAGMA foreign_keys = ON`,
  `CREATE TABLE IF NOT EXISTS oauth_auth_codes (
    code_hash TEXT PRIMARY KEY NOT NULL,
    client_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    resource TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL CHECK (code_challenge_method = 'S256'),
    expires_at TEXT NOT NULL,
    grant_generation INTEGER
  ) STRICT`,
  `CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_expires_at ON oauth_auth_codes (expires_at)`,
  `CREATE TABLE IF NOT EXISTS oauth_refresh_token_families (
    family_id TEXT PRIMARY KEY NOT NULL,
    resource TEXT NOT NULL,
    revoked_at TEXT,
    grant_generation INTEGER
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY NOT NULL,
    family_id TEXT NOT NULL,
    previous_token_hash TEXT,
    client_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    resource TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    grant_generation INTEGER,
    FOREIGN KEY (family_id) REFERENCES oauth_refresh_token_families (family_id) ON DELETE CASCADE
  ) STRICT`,
  `CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_family_id ON oauth_refresh_tokens (family_id)`,
  `CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_expires_at ON oauth_refresh_tokens (expires_at)`,
  `CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_subject_client ON oauth_refresh_tokens (subject, client_id)`,
  `CREATE TABLE IF NOT EXISTS oauth_consent_jtis (
    jti TEXT PRIMARY KEY NOT NULL,
    expires_at TEXT NOT NULL
  ) STRICT`,
  `CREATE INDEX IF NOT EXISTS idx_oauth_consent_jtis_expires_at ON oauth_consent_jtis (expires_at)`,
  CLIENT_TABLE_SQL.replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS"),
  METADATA_TABLE_SQL.replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS"),
];

export function migrateSqliteStore(db: DatabaseSync): void {
  const existingClientObject = clientSchemaObject(db);
  if (existingClientObject && existingClientObject.type !== "table") {
    throw new Error("oauth_clients schema is incompatible");
  }
  if (existingClientObject) assertClientTable(db);
  const metadataObject = db.prepare(
    "SELECT type FROM sqlite_schema WHERE name = 'oauth_store_metadata'",
  ).get();
  if (metadataObject) {
    assertMetadataSchema(db);
    assertMetadataValue(db, false);
  }
  for (const migration of MIGRATIONS) {
    db.exec(migration);
  }
  db.prepare(`INSERT OR IGNORE INTO oauth_store_metadata (singleton, instance_id) VALUES (1, ?)`).run(
    randomBytes(18).toString("base64url"),
  );
  assertMetadataSchema(db);
  assertMetadataValue(db, true);
  ensureColumn(db, "oauth_auth_codes", "grant_generation", "INTEGER");
  ensureColumn(db, "oauth_refresh_token_families", "grant_generation", "INTEGER");
  ensureColumn(db, "oauth_refresh_tokens", "grant_generation", "INTEGER");
  ensureColumn(db, "oauth_refresh_token_families", "resource", "TEXT");
  ensureColumn(db, "oauth_refresh_tokens", "resource", "TEXT");
  assertClientTable(db);
}

function clientSchemaObject(db: DatabaseSync): { type: unknown } | undefined {
  return db.prepare("SELECT type FROM sqlite_schema WHERE name = 'oauth_clients' COLLATE NOCASE").get() as
    { type: unknown } | undefined;
}

function assertMetadataSchema(db: DatabaseSync): void {
  const schema = db.prepare(
    "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'oauth_store_metadata'",
  ).get() as { sql?: unknown } | undefined;
  if (schema?.sql !== METADATA_TABLE_SQL) {
    throw new Error("oauth_store_metadata schema is incompatible");
  }
  const attached = db.prepare(`SELECT name FROM sqlite_schema
    WHERE tbl_name = 'oauth_store_metadata' AND name != 'oauth_store_metadata'
      AND sql IS NOT NULL AND name != 'sqlite_autoindex_oauth_store_metadata_1'`).get();
  if (attached) throw new Error("oauth_store_metadata schema is incompatible");
}

function assertMetadataValue(db: DatabaseSync, required: boolean): void {
  const metadata = db.prepare(
    "SELECT instance_id FROM oauth_store_metadata WHERE singleton = 1",
  ).get() as { instance_id?: unknown } | undefined;
  if (!metadata && !required) return;
  assertStoreInstanceId(metadata?.instance_id);
}

function ensureColumn(db: DatabaseSync, table: string, column: string, definition: string): void {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
  if (!rows.some((row) => row.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

function assertClientTable(db: DatabaseSync): void {
  const row = db.prepare(
    "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'oauth_clients' COLLATE NOCASE",
  ).get() as { sql: unknown } | undefined;
  if (row?.sql !== CLIENT_TABLE_SQL) throw new Error("oauth_clients schema is incompatible");
  const attached = db.prepare(`SELECT name FROM sqlite_schema
    WHERE tbl_name = 'oauth_clients' COLLATE NOCASE
      AND name != 'oauth_clients' COLLATE NOCASE AND sql IS NOT NULL`).get();
  if (attached) throw new Error("oauth_clients schema is incompatible");
}
