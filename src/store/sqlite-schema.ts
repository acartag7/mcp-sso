// SqliteStore schema migration (contracts §12.3). Idempotent; STRICT tables.
// State is OAuth-only — no content/body/cache tables (asserted by the conformance
// suite). All secrets are SHA-256 digests; there is NO grant table (findGrantedScopes
// queries the refresh-token tables directly).

import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

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
  `CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY NOT NULL,
    redirect_uris_json TEXT NOT NULL,
    application_type TEXT NOT NULL CHECK (application_type IN ('native', 'web')),
    issued_at_epoch INTEGER NOT NULL CHECK (issued_at_epoch >= 0)
  ) STRICT`,
];

export function migrateSqliteStore(db: DatabaseSync): void {
  const existingClientObject = clientSchemaObject(db);
  if (existingClientObject && existingClientObject.type !== "table") {
    throw new Error("oauth_clients schema is incompatible");
  }
  if (existingClientObject) assertClientTable(db);
  for (const migration of MIGRATIONS) {
    db.exec(migration);
  }
  ensureColumn(db, "oauth_auth_codes", "grant_generation", "INTEGER");
  ensureColumn(db, "oauth_refresh_token_families", "grant_generation", "INTEGER");
  ensureColumn(db, "oauth_refresh_tokens", "grant_generation", "INTEGER");
  ensureColumn(db, "oauth_refresh_token_families", "resource", "TEXT");
  ensureColumn(db, "oauth_refresh_tokens", "resource", "TEXT");
  assertClientTable(db);
}

function clientSchemaObject(db: DatabaseSync): { type: unknown } | undefined {
  return db.prepare("SELECT type FROM sqlite_schema WHERE name = 'oauth_clients'").get() as
    { type: unknown } | undefined;
}

function ensureColumn(db: DatabaseSync, table: string, column: string, definition: string): void {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
  if (!rows.some((row) => row.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

function assertClientTable(db: DatabaseSync): void {
  const columns = db.prepare("PRAGMA table_info(oauth_clients)").all() as Array<{
    name: unknown; type: unknown; notnull: unknown; pk: unknown;
  }>;
  const expected = [
    ["client_id", "TEXT", 1, 1],
    ["redirect_uris_json", "TEXT", 1, 0],
    ["application_type", "TEXT", 1, 0],
    ["issued_at_epoch", "INTEGER", 1, 0],
  ] as const;
  if (columns.length !== expected.length || columns.some((column, index) => {
    const wanted = expected[index];
    return !wanted || column.name !== wanted[0] || column.type !== wanted[1]
      || column.notnull !== wanted[2] || column.pk !== wanted[3];
  })) throw new Error("oauth_clients schema is incompatible");
  const table = db.prepare(
    "SELECT strict FROM pragma_table_list WHERE schema = 'main' AND name = 'oauth_clients'",
  ).get() as { strict: unknown } | undefined;
  if (table?.strict !== 1) throw new Error("oauth_clients schema is incompatible");
  assertClientConstraints(db);
}

function assertClientConstraints(db: DatabaseSync): void {
  const prefix = `__mcp_sso_schema_probe_${randomUUID()}`;
  const insert = db.prepare(`INSERT INTO oauth_clients (
    client_id, redirect_uris_json, application_type, issued_at_epoch
  ) VALUES (?, '["https://client.example/callback"]', ?, ?)`);
  db.exec("SAVEPOINT mcp_sso_client_schema_probe");
  try {
    insert.run(`${prefix}_native`, "native", 0);
    insert.run(`${prefix}_web`, "web", 0);
    if (!insertRejected(insert, `${prefix}_kind`, "machine", 0)
      || !insertRejected(insert, `${prefix}_epoch`, "native", -1)) {
      throw new Error("oauth_clients schema is incompatible");
    }
  } catch {
    throw new Error("oauth_clients schema is incompatible");
  } finally {
    db.exec("ROLLBACK TO mcp_sso_client_schema_probe; RELEASE mcp_sso_client_schema_probe");
  }
}

function insertRejected(
  insert: ReturnType<DatabaseSync["prepare"]>, clientId: string, applicationType: string, issuedAt: number,
): boolean {
  try { insert.run(clientId, applicationType, issuedAt); return false; } catch { return true; }
}
