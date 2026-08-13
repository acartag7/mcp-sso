// MysqlStore — pooled persistent StorePort on mysql2. See contracts §12.3.

import { createPool, type Pool, type PoolConnection, type PoolOptions, type ResultSetHeader, type RowDataPacket } from "mysql2/promise";
import type { AuthCodeRecord, RefreshTokenRecord, SaveAuthCodeInput, SaveRefreshTokenInput, StorePort } from "../ports/store.ts";
import {
  STORED_DCR_GRANT_GENERATION, STORED_DCR_RESOURCE_BINDING, StoreInputError, assertSha256Hex, assertUtcIsoTimestamp,
  grantGenerationForWrite, grantGenerationFromStored, normalizeRefreshTokenWrite,
  refreshResourceFromStored, UNBOUND_REFRESH_RESOURCE,
} from "../ports/store.ts";
import { readMysqlStoreInstanceId, rotateMysqlStoreInstanceId } from "./mysql-instance.ts";
import {
  migrateMysqlStore, insertRefreshToken, revokeFamily, isDuplicateEntry, nextFromRow,
  authCodeFromRow, refreshTokenFromRow, validateAuthCode, validateRefreshToken, validateRotation, parseScopes,
  type AuthCodeRow, type RefreshTokenRow,
} from "./mysql-schema.ts";

export class MysqlStore implements StorePort {
  readonly storedDcrGrantGeneration = STORED_DCR_GRANT_GENERATION;
  readonly storedDcrResourceBinding = STORED_DCR_RESOURCE_BINDING;
  private closed = false;
  private readonly pool: Pool;
  private readonly ownsPool: boolean;
  /** `ownsPool` makes `close()` end the pool; caller-supplied pools stay open. */
  constructor(pool: Pool, ownsPool = false) {
    this.pool = pool;
    this.ownsPool = ownsPool;
  }

  async getStoreInstanceId(): Promise<string> {
    this.ensureOpen();
    return readMysqlStoreInstanceId(this.pool);
  }

  async rotateStoreInstanceId(): Promise<string> {
    this.ensureOpen();
    return rotateMysqlStoreInstanceId(this.pool);
  }

  async saveAuthCode(input: SaveAuthCodeInput): Promise<void> {
    this.ensureOpen();
    validateAuthCode(input);
    await this.pool.query(
      `INSERT INTO oauth_auth_codes (code_hash, client_id, subject, redirect_uri, resource, scopes_json, code_challenge, code_challenge_method, expires_at, grant_generation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [input.codeHash, input.clientId, input.subject, input.redirectUri, input.resource, JSON.stringify(input.scopes), input.codeChallenge, input.codeChallengeMethod, input.expiresAt, grantGenerationForWrite(input.grantGeneration)],
    );
  }

  async consumeAuthCode(codeHash: string, nowIso: string, expectedGrantGeneration?: number, expectedResource?: string): Promise<AuthCodeRecord | null> {
    this.ensureOpen();
    assertSha256Hex(codeHash, "codeHash");
    assertUtcIsoTimestamp(nowIso, "nowIso");
    return this.transaction(async (conn) => {
      const [rows] = await conn.query<RowDataPacket[]>(`SELECT * FROM oauth_auth_codes WHERE code_hash = ? FOR UPDATE`, [codeHash]);
      const row = rows[0] as AuthCodeRow | undefined;
      if (!row) return null;
      if (expectedResource !== undefined && row.resource !== expectedResource) return null;
      await conn.query(`DELETE FROM oauth_auth_codes WHERE code_hash = ?`, [codeHash]);
      const record = authCodeFromRow(row);
      return row.expires_at > nowIso
        && (expectedGrantGeneration === undefined || record.grantGeneration === expectedGrantGeneration) ? record : null;
    });
  }

  async consumeConsentJti(jti: string, expiresAtIso: string): Promise<boolean> {
    this.ensureOpen();
    assertUtcIsoTimestamp(expiresAtIso, "expiresAtIso");
    try {
      await this.pool.query<ResultSetHeader>(
        `INSERT INTO oauth_consent_jtis (jti, expires_at) VALUES (?, ?)`,
        [jti, expiresAtIso],
      );
      return true;
    } catch (error) {
      if (isDuplicateEntry(error)) return false;
      throw error;
    }
  }

  async saveRefreshToken(input: SaveRefreshTokenInput): Promise<void> {
    this.ensureOpen();
    input = normalizeRefreshTokenWrite(input);
    validateRefreshToken(input);
    await this.transaction(async (conn) => {
      const generation = grantGenerationForWrite(input.grantGeneration);
      await conn.query(
        `INSERT INTO oauth_refresh_token_families (family_id, resource, revoked_at, grant_generation) VALUES (?, ?, NULL, ?) ON DUPLICATE KEY UPDATE revoked_at = oauth_refresh_token_families.revoked_at`,
        [input.familyId, input.resource, generation],
      );
      const [families] = await conn.query<RowDataPacket[]>(
        `SELECT resource, grant_generation FROM oauth_refresh_token_families WHERE family_id = ? FOR UPDATE`,
        [input.familyId],
      );
      const family = families[0] as { resource?: unknown; grant_generation?: unknown } | undefined;
      if (refreshResourceFromStored(family?.resource) !== input.resource
        || grantGenerationFromStored(family?.grant_generation) !== generation) {
        throw new StoreInputError("family grantGeneration or resource mismatch");
      }
      await insertRefreshToken(conn, input);
    });
  }

  async rotateRefreshToken(tokenHash: string, next: SaveRefreshTokenInput, nowIso: string, expectedGrantGeneration?: number, expectedResource?: string): Promise<RefreshTokenRecord | null> {
    this.ensureOpen();
    next = normalizeRefreshTokenWrite(next);
    validateRotation(tokenHash, next, nowIso);
    return this.transaction(async (conn) => {
      const [rows] = await conn.query<RowDataPacket[]>(
        `SELECT t.*, f.revoked_at AS f_revoked_at, f.resource AS f_resource, f.grant_generation AS f_grant_generation FROM oauth_refresh_tokens t JOIN oauth_refresh_token_families f ON f.family_id = t.family_id WHERE t.token_hash = ? FOR UPDATE`,
        [tokenHash],
      );
      const row = rows[0] as RefreshTokenRow | undefined;
      if (!row || row.f_revoked_at !== null) return null;
      if (expectedGrantGeneration !== undefined
        && (grantGenerationFromStored(row.f_grant_generation) !== expectedGrantGeneration
          || grantGenerationFromStored(row.grant_generation) !== expectedGrantGeneration)) return null;
      const resource = refreshResourceFromStored(row.resource);
      if (resource === null || resource === UNBOUND_REFRESH_RESOURCE || resource !== refreshResourceFromStored(row.f_resource)
        || (expectedResource !== undefined && resource !== expectedResource)) return null;
      if (row.consumed_at !== null) { await revokeFamily(conn, row.family_id, nowIso); return null; } // SAME conn — review B1
      if (row.expires_at <= nowIso || next.familyId !== row.family_id) return null;
      // Insert successor BEFORE marking the predecessor consumed: a colliding successor
      // hash returns null WITHOUT consuming the predecessor (sqlite parity; Codex P2).
      try {
        await insertRefreshToken(conn, nextFromRow(next, row)); // backfill from the consumed row
      } catch (error) {
        if (isDuplicateEntry(error)) return null;
        throw error;
      }
      await conn.query(`UPDATE oauth_refresh_tokens SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL`, [nowIso, tokenHash]);
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
      `SELECT t.*, f.revoked_at AS f_revoked_at, f.grant_generation AS f_grant_generation FROM oauth_refresh_tokens t JOIN oauth_refresh_token_families f ON f.family_id = t.family_id WHERE t.token_hash = ?`,
      [tokenHash],
    );
    const row = rows[0] as RefreshTokenRow | undefined;
    return row ? refreshTokenFromRow(row) : null;
  }

  async findGrantedScopes(subject: string, clientId: string, nowIso: string, expectedGrantGeneration?: number, expectedResource?: string): Promise<string[]> {
    this.ensureOpen();
    assertUtcIsoTimestamp(nowIso, "nowIso");
    const generationClause = expectedGrantGeneration === undefined
      ? "" : " AND f.grant_generation = ? AND t.grant_generation = ?";
    const resourceClause = expectedResource === undefined
      ? "" : " AND f.resource = ? AND t.resource = ?";
    const params: (string | number)[] = [subject, clientId, nowIso];
    if (expectedGrantGeneration !== undefined) params.push(expectedGrantGeneration, expectedGrantGeneration);
    if (expectedResource !== undefined) params.push(expectedResource, expectedResource);
    const [rows] = await this.pool.query<RowDataPacket[]>(
      `SELECT t.scopes_json FROM oauth_refresh_tokens t JOIN oauth_refresh_token_families f ON f.family_id = t.family_id
       WHERE t.subject = ? AND t.client_id = ? AND t.consumed_at IS NULL
       AND f.revoked_at IS NULL AND t.expires_at > ?${generationClause}${resourceClause}`,
      params,
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
      // Two-step (review H1): SELECT exact dead rows by PK, then DELETE by hash — a
      // successor committed after the SELECT is not in the list, so a still-valid rotated
      // successor can't be swept. GROUP BY avoids ER_UPDATE_TABLE_USED.
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

  /** Run idempotent migrations + boot-time config assertions (strict mode, binary collation).
   *  MUST be called once before first use; createMysqlStore does this. */
  async migrate(): Promise<void> {
    this.ensureOpen();
    const conn = await this.pool.getConnection();
    try { await migrateMysqlStore(conn); }
    finally { try { conn.release(); } catch { /* swallow cleanup */ } }
  }

  async close(): Promise<void> {
    if (!this.closed) {
      this.closed = true;
      // Only end a pool this store created; never a caller-supplied shared pool.
      if (this.ownsPool) await this.pool.end();
    }
  }

  /** §12.3 addendum 13: acquire OUTSIDE the try; begin inside behind a begun-guard;
   *  release in finally on EVERY path; swallow cleanup so the original error propagates.
   *  READ COMMITTED drops InnoDB gap locks (no sweep/rotate deadlock). */
  private async transaction<T>(fn: (conn: PoolConnection) => Promise<T>): Promise<T> {
    const conn = await this.pool.getConnection();
    let begun = false;
    try {
      // Next-tx form (not SET SESSION): scopes READ COMMITTED to THIS transaction so a
      // shared pool (new MysqlStore(appPool)) doesn't inherit it after release (Codex P2).
      await conn.query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED");
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
  // typeof narrows the union so each call matches a createPool overload (else TS2769).
  const pool = typeof config === "string" ? createPool(config) : createPool(config);
  const store = new MysqlStore(pool, true); // store owns the pool it created -> close() ends it
  try {
    await store.migrate();
  } catch (error) {
    // Do not leak the pool if boot-time config assertions (strict mode, collation, engine) fail.
    try { await pool.end(); } catch { /* swallow cleanup */ }
    throw error;
  }
  return store;
}
