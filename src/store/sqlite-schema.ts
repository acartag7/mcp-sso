// SqliteStore schema migration (contracts §12.3). Idempotent; STRICT tables.
// State is OAuth-only — no content/body/cache tables (asserted by the conformance
// suite). All secrets are SHA-256 digests; there is NO grant table (findGrantedScopes
// queries the refresh-token tables directly).

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
    expires_at TEXT NOT NULL
  ) STRICT`,
  `CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_expires_at ON oauth_auth_codes (expires_at)`,
  `CREATE TABLE IF NOT EXISTS oauth_refresh_token_families (
    family_id TEXT PRIMARY KEY NOT NULL,
    revoked_at TEXT
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY NOT NULL,
    family_id TEXT NOT NULL,
    previous_token_hash TEXT,
    client_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
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
];

export function migrateSqliteStore(db: DatabaseSync): void {
  for (const migration of MIGRATIONS) {
    db.exec(migration);
  }
}
