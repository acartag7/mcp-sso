// MysqlStore schema + boot-time config assertions (contracts §12.3). Idempotent.
// State is OAuth-only — no content/body/cache tables (asserted in the conformance
// suite). All secrets are SHA-256 digests; there is NO grant table (findGrantedScopes
// queries the refresh-token tables directly).
//
// Every oauth_* table is DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin: MySQL 8.x
// otherwise defaults to case-insensitive utf8mb4_0900_ai_ci, which would conflate
// distinct hashes/identifiers on the PRIMARY KEY and match subject/client_id
// case-insensitively — diverging from the sqlite TEXT reference (review B2).
// Timestamps are VARCHAR(24), NOT DATETIME: the canonical 3-ms UTC ISO format
// compares chronologically correct as a byte string, preserving the §12.1
// lexicographic-ordering invariant sqlite gets from TEXT (a DATETIME would change
// comparison/timezone semantics). Boot-time assertions fail closed unless sql_mode
// contains STRICT_TRANS_TABLES (silent truncation would collide distinct values on
// the PK — review H2) and the tables actually resolved to utf8mb4_bin.

import type { PoolConnection, RowDataPacket } from "mysql2/promise";
import { StoreInputError } from "../ports/store.ts";

export const MYSQL_OAUTH_TABLES = [
  "oauth_auth_codes", "oauth_refresh_token_families", "oauth_refresh_tokens", "oauth_consent_jtis",
] as const;

const MIGRATIONS = [
  `CREATE TABLE IF NOT EXISTS oauth_auth_codes (
    code_hash VARCHAR(64) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    redirect_uri VARCHAR(2048) NOT NULL,
    resource VARCHAR(2048) NOT NULL,
    scopes_json TEXT NOT NULL,
    code_challenge VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(16) NOT NULL CHECK (code_challenge_method = 'S256'),
    expires_at VARCHAR(24) NOT NULL,
    PRIMARY KEY (code_hash),
    INDEX idx_oauth_auth_codes_expires_at (expires_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`,
  `CREATE TABLE IF NOT EXISTS oauth_refresh_token_families (
    family_id VARCHAR(64) NOT NULL,
    revoked_at VARCHAR(24),
    PRIMARY KEY (family_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`,
  `CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token_hash VARCHAR(64) NOT NULL,
    family_id VARCHAR(64) NOT NULL,
    previous_token_hash VARCHAR(64),
    client_id VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    scopes_json TEXT NOT NULL,
    expires_at VARCHAR(24) NOT NULL,
    consumed_at VARCHAR(24),
    PRIMARY KEY (token_hash),
    INDEX idx_oauth_refresh_tokens_family_id (family_id),
    INDEX idx_oauth_refresh_tokens_expires_at (expires_at),
    INDEX idx_oauth_refresh_tokens_subject_client (subject, client_id),
    CONSTRAINT fk_oauth_refresh_tokens_family FOREIGN KEY (family_id)
      REFERENCES oauth_refresh_token_families (family_id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`,
  `CREATE TABLE IF NOT EXISTS oauth_consent_jtis (
    jti VARCHAR(255) NOT NULL,
    expires_at VARCHAR(24) NOT NULL,
    PRIMARY KEY (jti),
    INDEX idx_oauth_consent_jtis_expires_at (expires_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`,
];

/** Run idempotent migrations + boot-time config assertions on a connection.
 *  Call once before first use (createMysqlStore does this). */
export async function migrateMysqlStore(conn: PoolConnection): Promise<void> {
  await assertStrictMode(conn);
  for (const ddl of MIGRATIONS) await conn.query(ddl);
  await assertTableCollations(conn);
}

async function assertStrictMode(conn: PoolConnection): Promise<void> {
  const [rows] = await conn.query<RowDataPacket[]>("SELECT @@session.sql_mode AS sql_mode");
  const mode = String((rows[0] as { sql_mode?: string } | undefined)?.sql_mode ?? "");
  if (!mode.split(",").includes("STRICT_TRANS_TABLES")) {
    throw new StoreInputError(
      `MySQL sql_mode must include STRICT_TRANS_TABLES (got "${mode}"); without it, silent truncation can collide distinct values on the primary key. Set sql_mode=STRICT_TRANS_TABLES on the server.`,
    );
  }
}

async function assertTableCollations(conn: PoolConnection): Promise<void> {
  const [rows] = await conn.query<RowDataPacket[]>(
    "SELECT TABLE_NAME, TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (?)",
    [[...MYSQL_OAUTH_TABLES]],
  );
  const byTable = new Map((rows as { TABLE_NAME: string; TABLE_COLLATION: string }[]).map((r) => [r.TABLE_NAME, r.TABLE_COLLATION]));
  for (const table of MYSQL_OAUTH_TABLES) {
    const collation = byTable.get(table);
    if (collation !== "utf8mb4_bin") {
      throw new StoreInputError(
        `oauth table ${table} must use utf8mb4_bin collation (got "${collation}"); a case-insensitive collation would conflate distinct hashes/identifiers.`,
      );
    }
  }
}
