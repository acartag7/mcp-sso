// MysqlStore — pooled persistent StorePort on mysql2 (contracts §12.3). See §12.3
// for the binding async/pooled pattern: begun-guard + release-in-finally (addendum 13),
// SELECT ... FOR UPDATE on rotate/consume, READ COMMITTED isolation, the two-step
// sweep, INSERT IGNORE for consent JTIs, and the row-alias family upsert.

import { createPool, type Pool, type PoolConnection, type PoolOptions, type ResultSetHeader, type RowDataPacket } from "mysql2/promise";
import type { AuthCodeRecord, RefreshTokenRecord, SaveAuthCodeInput, SaveRefreshTokenInput, StorePort } from "../ports/store.ts";
import { StoreInputError, assertSha256Hex, assertUtcIsoTimestamp } from "../ports/store.ts";
import { migrateMysqlStore } from "./mysql-schema.ts";

interface AuthCodeRow { code_hash: string; client_id: string; subject: string; redirect_uri: string; resource: string; scopes_json: string; code_challenge: string; code_challenge_method: "S256"; expires_at: string }
interface RefreshTokenRow { token_hash: string; family_id: string; previous_token_hash: string | null; client_id: string; subject: string; scopes_json: string; expires_at: string; consumed_at: string | null; f_revoked_at: string | null }

export class MysqlStore implements StorePort {
  private closed = false;
  private readonly pool: Pool;
  constructor(pool: Pool) {
    this.pool = pool;
  }

  async saveAuthCode(input: SaveAuthCodeInput): Promise<void> {
    this.ensureOpen();
    validateAuthCode(input);
    await this.pool.query(
      `INSERT INTO oauth_auth_codes (code_hash, client_id, subject, redirect_uri, resource, scopes_json, code_challenge, code_challenge_method, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [input.codeHash, input.clientId, input.subject, input.redirectUri, input.resource, JSON.stringify(input.scopes), input.codeChallenge, input.codeChallengeMethod, input.expiresAt],
    );
  }

  async consumeAuthCode(codeHash: string, nowIso: string): Promise<AuthCodeRecord | null> {
    this.ensureOpen();
    assertSha256Hex(codeHash, "codeHash");
    assertUtcIsoTimestamp(nowIso, "nowIso");
    return this.transaction(async (conn) => {
      const [rows] = await conn.query<RowDataPacket[]>(`SELECT * FROM oauth_auth_codes WHERE code_hash = ? FOR UPDATE`, [codeHash]);
      const row = rows[0] as AuthCodeRow | undefined;
      if (!row) return null;
      await conn.query(`DELETE FROM oauth_auth_codes WHERE code_hash = ?`, [codeHash]);
      return row.expires_at > nowIso ? authCodeFromRow(row) : null;
    });
  }

  async consumeConsentJti(jti: string, expiresAtIso: string): Promise<boolean> {
    this.ensureOpen();
    assertUtcIsoTimestamp(expiresAtIso, "expiresAtIso");
    // INSERT IGNORE: affectedRows is 1 on first INSERT, 0 on every replay, independent
    // of the supplied timestamp (addendum 10). ODKU expires_at=expires_at reports 1 even
    // on a no-op replay under MySQL 8.4, so it cannot distinguish first-use.
    const [result] = await this.pool.query<ResultSetHeader>(
      `INSERT IGNORE INTO oauth_consent_jtis (jti, expires_at) VALUES (?, ?)`,
      [jti, expiresAtIso],
    );
    return result.affectedRows === 1;
  }

  async saveRefreshToken(input: SaveRefreshTokenInput): Promise<void> {
    this.ensureOpen();
    validateRefreshToken(input);
    await this.transaction(async (conn) => {
      await conn.query(
        `INSERT INTO oauth_refresh_token_families (family_id, revoked_at) VALUES (?, NULL) AS new ON DUPLICATE KEY UPDATE revoked_at = oauth_refresh_token_families.revoked_at`,
        [input.familyId],
      );
      await insertRefreshToken(conn, input);
    });
  }

  async rotateRefreshToken(tokenHash: string, next: SaveRefreshTokenInput, nowIso: string): Promise<RefreshTokenRecord | null> {
    this.ensureOpen();
    validateRotation(tokenHash, next, nowIso);
    return this.transaction(async (conn) => {
      const [rows] = await conn.query<RowDataPacket[]>(
        `SELECT t.*, f.revoked_at AS f_revoked_at FROM oauth_refresh_tokens t JOIN oauth_refresh_token_families f ON f.family_id = t.family_id WHERE t.token_hash = ? FOR UPDATE`,
        [tokenHash],
      );
      const row = rows[0] as RefreshTokenRow | undefined;
      if (!row || row.f_revoked_at !== null) return null;
      if (row.consumed_at !== null) { await revokeFamily(conn, row.family_id, nowIso); return null; } // SAME conn — review B1
      if (row.expires_at <= nowIso || next.familyId !== row.family_id) return null;
      await conn.query(`UPDATE oauth_refresh_tokens SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL`, [nowIso, tokenHash]);
      try {
        await insertRefreshToken(conn, nextFromRow(next, row)); // Fix #3 backfill from the consumed row
      } catch (error) {
        if (isDuplicateEntry(error)) return null; // colliding successor hash -> null (review M2)
        throw error;
      }
      return refreshTokenFromRow(row);
    });
  }

  async revokeRefreshTokenFamily(familyId: string, revokedAtIso: string): Promise<void> {
    this.ensureOpen();
    assertUtcIsoTimestamp(revokedAtIso, "revokedAtIso");
    await this.transaction(async (conn) => { await revokeFamily(conn, familyId, revokedAtIso); });
  }

  async findRefreshToken(tokenHash: string): Promise<RefreshTokenRecord | null> {
    this.ensureOpen();
    const [rows] = await this.pool.query<RowDataPacket[]>(
      `SELECT t.*, f.revoked_at AS f_revoked_at FROM oauth_refresh_tokens t JOIN oauth_refresh_token_families f ON f.family_id = t.family_id WHERE t.token_hash = ?`,
      [tokenHash],
    );
    const row = rows[0] as RefreshTokenRow | undefined;
    return row ? refreshTokenFromRow(row) : null;
  }

  async findGrantedScopes(subject: string, clientId: string, nowIso: string): Promise<string[]> {
    this.ensureOpen();
    assertUtcIsoTimestamp(nowIso, "nowIso");
    const [rows] = await this.pool.query<RowDataPacket[]>(
      `SELECT t.scopes_json FROM oauth_refresh_tokens t JOIN oauth_refresh_token_families f ON f.family_id = t.family_id
       WHERE t.subject = ? AND t.client_id = ? AND t.consumed_at IS NULL AND f.revoked_at IS NULL AND t.expires_at > ?`,
      [subject, clientId, nowIso],
    );
    const out: string[] = [];
    for (const row of rows as { scopes_json: string }[]) for (const s of parseScopes(row.scopes_json)) if (!out.includes(s)) out.push(s);
    return out;
  }

  async sweepExpired(nowIso: string): Promise<void> {
    this.ensureOpen();
    assertUtcIsoTimestamp(nowIso, "nowIso");
    await this.transaction(async (conn) => {
      await conn.query(`DELETE FROM oauth_auth_codes WHERE expires_at < ?`, [nowIso]);
      await conn.query(`DELETE FROM oauth_consent_jtis WHERE expires_at < ?`, [nowIso]);
      // Family-validity retention (addendum 8): delete a refresh token ONLY when its
      // family has no still-valid member. Two-step (review H1): SELECT the exact dead
      // rows by PK, then DELETE those rows — a successor committed after the SELECT is
      // not in the hash list, so a still-valid rotated successor cannot be swept under
      // READ COMMITTED. The derived table + GROUP BY avoids ER_UPDATE_TABLE_USED.
      const [dead] = await conn.query<RowDataPacket[]>(
        `SELECT token_hash FROM oauth_refresh_tokens WHERE family_id IN (
           SELECT family_id FROM (SELECT family_id FROM oauth_refresh_tokens GROUP BY family_id HAVING MAX(expires_at) < ?) AS dead_families
         )`,
        [nowIso],
      );
      const deadHashes = (dead as { token_hash: string }[]).map((r) => r.token_hash);
      if (deadHashes.length > 0) await conn.query(`DELETE FROM oauth_refresh_tokens WHERE token_hash IN (?)`, [deadHashes]);
      await conn.query(`DELETE FROM oauth_refresh_token_families WHERE family_id NOT IN (SELECT DISTINCT family_id FROM oauth_refresh_tokens)`);
    });
  }

  /** Run idempotent migrations + boot-time config assertions (strict mode, binary
   *  collation). MUST be called once before first use; createMysqlStore does this. */
  async migrate(): Promise<void> {
    this.ensureOpen();
    const conn = await this.pool.getConnection();
    try { await migrateMysqlStore(conn); }
    finally { try { conn.release(); } catch { /* swallow cleanup */ } }
  }

  async close(): Promise<void> {
    if (!this.closed) { this.closed = true; await this.pool.end(); }
  }

  /** §12.3 addendum 13: acquire OUTSIDE the try; begin inside the try behind a
   *  begun-guard; release in finally on EVERY path; swallow cleanup so the original
   *  error propagates. READ COMMITTED drops InnoDB gap locks (no sweep/rotate deadlock). */
  private async transaction<T>(fn: (conn: PoolConnection) => Promise<T>): Promise<T> {
    const conn = await this.pool.getConnection();
    let begun = false;
    try {
      await conn.query("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");
      await conn.beginTransaction();
      begun = true;
      const result = await fn(conn);
      await conn.commit();
      return result;
    } catch (error) {
      if (begun) { try { await conn.rollback(); } catch { /* swallow */ } }
      throw error;
    } finally {
      try { conn.release(); } catch { /* swallow */ }
    }
  }

  private ensureOpen(): void {
    if (this.closed) throw new Error("Store is closed");
  }
}

export async function createMysqlStore(config: string | PoolOptions): Promise<MysqlStore> {
  const pool = typeof config === "string" ? createPool(config) : createPool(config);
  const store = new MysqlStore(pool);
  try {
    await store.migrate();
  } catch (error) {
    // Do not leak the pool if boot-time config assertions (strict mode, collation) fail.
    try { await pool.end(); } catch { /* swallow cleanup */ }
    throw error;
  }
  return store;
}

async function insertRefreshToken(conn: PoolConnection, input: SaveRefreshTokenInput): Promise<void> {
  await conn.query(
    `INSERT INTO oauth_refresh_tokens (token_hash, family_id, previous_token_hash, client_id, subject, scopes_json, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
    [input.tokenHash, input.familyId, input.previousTokenHash, input.clientId, input.subject, JSON.stringify(input.scopes), input.expiresAt],
  );
}

async function revokeFamily(conn: PoolConnection, familyId: string, revokedAtIso: string): Promise<void> {
  // MySQL 8.0.20+ row-alias ODKU (NOT sqlite's `excluded`); revoked_at set once (review H1).
  await conn.query(
    `INSERT INTO oauth_refresh_token_families (family_id, revoked_at) VALUES (?, ?) AS new ON DUPLICATE KEY UPDATE revoked_at = COALESCE(oauth_refresh_token_families.revoked_at, new.revoked_at)`,
    [familyId, revokedAtIso],
  );
}

function isDuplicateEntry(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { code?: string }).code === "ER_DUP_ENTRY";
}

function nextFromRow(input: SaveRefreshTokenInput, row: RefreshTokenRow): SaveRefreshTokenInput {
  return { ...input, clientId: row.client_id, subject: row.subject, scopes: parseScopes(row.scopes_json) };
}

function authCodeFromRow(row: AuthCodeRow): AuthCodeRecord {
  return { codeHash: row.code_hash, clientId: row.client_id, subject: row.subject, redirectUri: row.redirect_uri, resource: row.resource, scopes: parseScopes(row.scopes_json), codeChallenge: row.code_challenge, codeChallengeMethod: row.code_challenge_method, expiresAt: row.expires_at };
}

function refreshTokenFromRow(row: RefreshTokenRow): RefreshTokenRecord {
  return { tokenHash: row.token_hash, familyId: row.family_id, previousTokenHash: row.previous_token_hash, clientId: row.client_id, subject: row.subject, scopes: parseScopes(row.scopes_json), expiresAt: row.expires_at };
}

function validateAuthCode(input: SaveAuthCodeInput): void {
  assertSha256Hex(input.codeHash, "codeHash");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
  if (input.codeChallengeMethod !== "S256") throw new StoreInputError("codeChallengeMethod must be S256");
}

function validateRefreshToken(input: SaveRefreshTokenInput): void {
  assertSha256Hex(input.tokenHash, "tokenHash");
  if (input.previousTokenHash !== null) assertSha256Hex(input.previousTokenHash, "previousTokenHash");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
}

function validateRotation(tokenHash: string, next: SaveRefreshTokenInput, nowIso: string): void {
  assertSha256Hex(tokenHash, "tokenHash");
  validateRefreshToken(next);
  assertUtcIsoTimestamp(nowIso, "nowIso");
  if (next.previousTokenHash !== tokenHash) throw new StoreInputError("next.previousTokenHash must match tokenHash");
}

function parseScopes(value: string): string[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some((scope) => typeof scope !== "string")) throw new Error("Stored scopes are invalid");
  return parsed;
}
