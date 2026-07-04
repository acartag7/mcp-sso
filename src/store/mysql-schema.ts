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
import type { AuthCodeRecord, RefreshTokenRecord, SaveAuthCodeInput, SaveRefreshTokenInput } from "../ports/store.ts";
import { StoreInputError, assertSha256Hex, assertUtcIsoTimestamp } from "../ports/store.ts";

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
  await assertColumnCollations(conn);
}

async function assertStrictMode(conn: PoolConnection): Promise<void> {
  const [rows] = await conn.query<RowDataPacket[]>("SELECT @@session.sql_mode AS sql_mode");
  const modes = String((rows[0] as { sql_mode?: string } | undefined)?.sql_mode ?? "").split(",");
  // Either strict flag suffices for InnoDB (transactional) tables — they differ only for
  // non-transactional engines. Accepting both avoids false-failing a STRICT_ALL_TABLES config.
  if (!modes.includes("STRICT_TRANS_TABLES") && !modes.includes("STRICT_ALL_TABLES")) {
    throw new StoreInputError(
      `MySQL sql_mode must include STRICT_TRANS_TABLES or STRICT_ALL_TABLES (got "${modes.join(",")}"); without strict mode, silent truncation can collide distinct values on the primary key.`,
    );
  }
}

async function assertColumnCollations(conn: PoolConnection): Promise<void> {
  // Check every character COLUMN's collation, not just the table default: MySQL compares
  // by column collation, and a drifted table can have TABLE_COLLATION=utf8mb4_bin while
  // columns remain utf8mb4_0900_ai_ci (e.g. after a default-collation change). The table-
  // level check would pass while comparisons are still case-insensitive (Codex P2).
  const [rows] = await conn.query<RowDataPacket[]>(
    "SELECT TABLE_NAME, COLUMN_NAME, COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (?) AND COLLATION_NAME IS NOT NULL AND COLLATION_NAME != 'utf8mb4_bin'",
    [[...MYSQL_OAUTH_TABLES]],
  );
  const drifted = rows as { TABLE_NAME: string; COLUMN_NAME: string; COLLATION_NAME: string }[];
  if (drifted.length > 0) {
    const sample = drifted.slice(0, 3).map((r) => `${r.TABLE_NAME}.${r.COLUMN_NAME}=${r.COLLATION_NAME}`).join(", ");
    throw new StoreInputError(
      `oauth columns must use utf8mb4_bin collation (found non-binary: ${sample}${drifted.length > 3 ? ", ..." : ""}); a case-insensitive collation would conflate distinct hashes/identifiers.`,
    );
  }
}

// ---- Row interfaces + DML/validation helpers (shared with mysql.ts) ----

export interface AuthCodeRow { code_hash: string; client_id: string; subject: string; redirect_uri: string; resource: string; scopes_json: string; code_challenge: string; code_challenge_method: "S256"; expires_at: string }
export interface RefreshTokenRow { token_hash: string; family_id: string; previous_token_hash: string | null; client_id: string; subject: string; scopes_json: string; expires_at: string; consumed_at: string | null; f_revoked_at: string | null }

export async function insertRefreshToken(conn: PoolConnection, input: SaveRefreshTokenInput): Promise<void> {
  await conn.query(
    `INSERT INTO oauth_refresh_tokens (token_hash, family_id, previous_token_hash, client_id, subject, scopes_json, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
    [input.tokenHash, input.familyId, input.previousTokenHash, input.clientId, input.subject, JSON.stringify(input.scopes), input.expiresAt],
  );
}

export async function revokeFamily(conn: PoolConnection, familyId: string, revokedAtIso: string): Promise<void> {
  // MySQL 8.0.20+ row-alias ODKU (NOT sqlite's `excluded`); revoked_at set once (review H1).
  await conn.query(
    `INSERT INTO oauth_refresh_token_families (family_id, revoked_at) VALUES (?, ?) AS new ON DUPLICATE KEY UPDATE revoked_at = COALESCE(oauth_refresh_token_families.revoked_at, new.revoked_at)`,
    [familyId, revokedAtIso],
  );
}

export function isDuplicateEntry(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { code?: string }).code === "ER_DUP_ENTRY";
}

export function nextFromRow(input: SaveRefreshTokenInput, row: RefreshTokenRow): SaveRefreshTokenInput {
  return { ...input, clientId: row.client_id, subject: row.subject, scopes: parseScopes(row.scopes_json) };
}

export function authCodeFromRow(row: AuthCodeRow): AuthCodeRecord {
  return { codeHash: row.code_hash, clientId: row.client_id, subject: row.subject, redirectUri: row.redirect_uri, resource: row.resource, scopes: parseScopes(row.scopes_json), codeChallenge: row.code_challenge, codeChallengeMethod: row.code_challenge_method, expiresAt: row.expires_at };
}

export function refreshTokenFromRow(row: RefreshTokenRow): RefreshTokenRecord {
  return { tokenHash: row.token_hash, familyId: row.family_id, previousTokenHash: row.previous_token_hash, clientId: row.client_id, subject: row.subject, scopes: parseScopes(row.scopes_json), expiresAt: row.expires_at };
}

export function validateAuthCode(input: SaveAuthCodeInput): void {
  assertSha256Hex(input.codeHash, "codeHash");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
  if (input.codeChallengeMethod !== "S256") throw new StoreInputError("codeChallengeMethod must be S256");
}

export function validateRefreshToken(input: SaveRefreshTokenInput): void {
  assertSha256Hex(input.tokenHash, "tokenHash");
  if (input.previousTokenHash !== null) assertSha256Hex(input.previousTokenHash, "previousTokenHash");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
}

export function validateRotation(tokenHash: string, next: SaveRefreshTokenInput, nowIso: string): void {
  assertSha256Hex(tokenHash, "tokenHash");
  validateRefreshToken(next);
  assertUtcIsoTimestamp(nowIso, "nowIso");
  if (next.previousTokenHash !== tokenHash) throw new StoreInputError("next.previousTokenHash must match tokenHash");
}

export function parseScopes(value: string): string[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some((scope) => typeof scope !== "string")) throw new Error("Stored scopes are invalid");
  return parsed;
}
