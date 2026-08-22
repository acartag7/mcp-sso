// SqliteStore — persistent StorePort + user ClientStore (contracts §6.4, §12.3).
import { DatabaseSync } from "node:sqlite";
import type { ClockPort } from "../ports/clock.ts";
import type {
  AuthCodeRecord, ConsentApprovalCommitResult, RefreshTokenRecord, SaveAuthCodeInput, SaveRefreshTokenInput, StorePort,
} from "../ports/store.ts";
import { STORED_DCR_GRANT_GENERATION, STORED_DCR_RESOURCE_BINDING, StoreInputError, assertSha256Hex, assertStoreInstanceId, assertUtcIsoTimestamp,
  assertRefreshResource, assertStoreSubject, grantGenerationForWrite, grantGenerationFromStored, normalizeRefreshTokenWrite,
  refreshResourceFromStored, UNBOUND_REFRESH_RESOURCE,
} from "../ports/store.ts";
import { migrateSqliteStore } from "./sqlite-schema.ts";
import { readSqliteStoreInstanceId, rotateSqliteStoreInstanceId } from "./sqlite-instance.ts";
import {
  advanceSqliteSweepWatermark, commitSqliteConsentApproval,
  consumeSqliteConsentJti, insertSqliteAuthCode,
} from "./sqlite-consent.ts";
import {
  admitSqliteFile, closeSqliteAdmission, sqlitePath, SqliteStateError,
  verifySqlitePathIdentity,
} from "./sqlite-open.ts";
import {
  authCodeFromRow, insertRefreshToken, nextFromRow, parseScopes,
  refreshTokenFromRow, revokeFamily, validateAuthCode, validateRefreshToken,
  validateRotation, type AuthCodeRow, type RefreshTokenRow,
} from "./sqlite-records.ts";
import { SqliteClientStoreBase } from "./sqlite-clients.ts";
import { StoreExpiryLifecycle } from "./expiry-lifecycle.ts";

export class SqliteStore extends SqliteClientStoreBase implements StorePort {
  readonly storedDcrGrantGeneration = STORED_DCR_GRANT_GENERATION;
  readonly storedDcrResourceBinding = STORED_DCR_RESOURCE_BINDING;
  private readonly expiry = new StoreExpiryLifecycle(this);
  constructor(db: DatabaseSync, options: { schemaReady?: true } = {}) {
    super(db); if (options.schemaReady === true) this.expiry.markReady();
  }
  async getStoreInstanceId(): Promise<string> {
    this.ensureOpen();
    return readSqliteStoreInstanceId(this.db);
  }
  async rotateStoreInstanceId(): Promise<string> {
    this.ensureOpen();
    return this.transaction(() => rotateSqliteStoreInstanceId(this.db));
  }
  async commitConsentApproval(
    expectedStoreInstanceId: string, jti: string, expiresAtIso: string, authCode: SaveAuthCodeInput,
  ): Promise<ConsentApprovalCommitResult> {
    this.ensureOpen();
    assertStoreInstanceId(expectedStoreInstanceId);
    assertUtcIsoTimestamp(expiresAtIso, "expiresAtIso");
    validateAuthCode(authCode);
    return this.transaction(() => commitSqliteConsentApproval(
      this.db, expectedStoreInstanceId, jti, expiresAtIso, authCode));
  }
  async saveAuthCode(input: SaveAuthCodeInput): Promise<void> {
    this.ensureOpen();
    validateAuthCode(input);
    insertSqliteAuthCode(this.db, input);
  }

  async consumeAuthCode(codeHash: string, nowIso: string, expectedGrantGeneration?: number, expectedResource?: string): Promise<AuthCodeRecord | null> {
    this.ensureOpen();
    assertSha256Hex(codeHash, "codeHash");
    assertUtcIsoTimestamp(nowIso, "nowIso");
    return this.transaction(() => {
      const row = this.db.prepare(`SELECT * FROM oauth_auth_codes WHERE code_hash = ?`).get(codeHash) as AuthCodeRow | undefined;
      if (!row) return null;
      if (expectedResource !== undefined && row.resource !== expectedResource) return null;
      assertStoreSubject(row.subject, "stored subject");
      this.db.prepare(`DELETE FROM oauth_auth_codes WHERE code_hash = ?`).run(codeHash);
      const record = authCodeFromRow(row);
      return row.expires_at > nowIso
        && (expectedGrantGeneration === undefined || record.grantGeneration === expectedGrantGeneration) ? record : null;
    });
  }

  async consumeConsentJti(jti: string, expiresAtIso: string): Promise<boolean> {
    this.ensureOpen();
    assertUtcIsoTimestamp(expiresAtIso, "expiresAtIso"); // addendum 10: source left this unvalidated
    return this.transaction(() => consumeSqliteConsentJti(this.db, jti, expiresAtIso));
  }

  async saveRefreshToken(input: SaveRefreshTokenInput): Promise<void> {
    this.ensureOpen();
    input = normalizeRefreshTokenWrite(input);
    validateRefreshToken(input);
    this.transaction(() => {
      const generation = grantGenerationForWrite(input.grantGeneration);
      this.db.prepare(`INSERT INTO oauth_refresh_token_families (
        family_id, resource, revoked_at, grant_generation
      ) VALUES (?, ?, NULL, ?) ON CONFLICT(family_id) DO NOTHING`).run(input.familyId, input.resource, generation);
      const family = this.db.prepare(
        `SELECT resource, grant_generation FROM oauth_refresh_token_families WHERE family_id = ?`,
      ).get(input.familyId) as { resource: unknown; grant_generation: unknown };
      if (refreshResourceFromStored(family.resource) !== input.resource
        || grantGenerationFromStored(family.grant_generation) !== generation) {
        throw new StoreInputError("family grantGeneration or resource mismatch");
      }
      insertRefreshToken(this.db, input);
    });
  }

  async rotateRefreshToken(tokenHash: string, next: SaveRefreshTokenInput, nowIso: string, expectedGrantGeneration?: number, expectedResource?: string): Promise<RefreshTokenRecord | null> {
    this.ensureOpen();
    next = normalizeRefreshTokenWrite(next);
    validateRotation(tokenHash, next, nowIso);
    return this.transaction(() => {
      const row = this.db.prepare(
        `SELECT t.*, f.revoked_at, f.resource AS f_resource, f.grant_generation AS f_grant_generation FROM oauth_refresh_tokens t
         JOIN oauth_refresh_token_families f ON f.family_id = t.family_id WHERE t.token_hash = ?`,
      ).get(tokenHash) as RefreshTokenRow | undefined;
      if (!row) return null;
      assertStoreSubject(row.subject, "stored subject");
      if (row.revoked_at !== null) return null;
      if (expectedGrantGeneration !== undefined
        && (grantGenerationFromStored(row.f_grant_generation) !== expectedGrantGeneration
          || grantGenerationFromStored(row.grant_generation) !== expectedGrantGeneration)) return null;
      const resource = refreshResourceFromStored(row.resource);
      if (resource === null || resource === UNBOUND_REFRESH_RESOURCE || resource !== refreshResourceFromStored(row.f_resource)
        || (expectedResource !== undefined && resource !== expectedResource)) return null;
      if (row.consumed_at !== null) {
        revokeFamily(this.db, row.family_id, nowIso);
        return null;
      }
      if (row.expires_at <= nowIso || next.familyId !== row.family_id) return null;
      if (this.db.prepare(`SELECT token_hash FROM oauth_refresh_tokens WHERE token_hash = ?`).get(next.tokenHash)) return null;
      this.db.prepare(`UPDATE oauth_refresh_tokens SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL`).run(nowIso, tokenHash);
      // Backfill: successor takes identity and resource from the consumed row.
      insertRefreshToken(this.db, nextFromRow(next, row));
      return refreshTokenFromRow(row);
    });
  }

  async revokeRefreshTokenFamily(familyId: string, revokedAtIso: string, expectedResource?: string): Promise<void> {
    this.ensureOpen();
    assertUtcIsoTimestamp(revokedAtIso, "revokedAtIso");
    if (expectedResource !== undefined) assertRefreshResource(expectedResource, "expectedResource");
    this.transaction(() => revokeFamily(this.db, familyId, revokedAtIso, expectedResource));
  }

  async findRefreshToken(tokenHash: string): Promise<RefreshTokenRecord | null> {
    this.ensureOpen();
    return this.transaction(() => {
      const row = this.db.prepare(
        `SELECT t.*, f.revoked_at, f.grant_generation AS f_grant_generation FROM oauth_refresh_tokens t
         JOIN oauth_refresh_token_families f ON f.family_id = t.family_id WHERE t.token_hash = ?`,
      ).get(tokenHash) as RefreshTokenRow | undefined;
      return row ? refreshTokenFromRow(row) : null;
    });
  }

  async findGrantedScopes(subject: string, clientId: string, nowIso: string, expectedGrantGeneration?: number, expectedResource?: string): Promise<string[]> {
    this.ensureOpen();
    assertStoreSubject(subject);
    assertUtcIsoTimestamp(nowIso, "nowIso");
    return this.transaction(() => {
      const generationClause = expectedGrantGeneration === undefined
        ? "" : " AND f.grant_generation = ? AND t.grant_generation = ?";
      const resourceClause = expectedResource === undefined
        ? "" : " AND f.resource = ? AND t.resource = ?";
      const params: (string | number)[] = [subject, clientId, nowIso];
      if (expectedGrantGeneration !== undefined) params.push(expectedGrantGeneration, expectedGrantGeneration);
      if (expectedResource !== undefined) params.push(expectedResource, expectedResource);
      const rows = this.db.prepare(
        `SELECT t.scopes_json FROM oauth_refresh_tokens t
         JOIN oauth_refresh_token_families f ON f.family_id = t.family_id
         WHERE t.subject = ? AND t.client_id = ? AND t.consumed_at IS NULL
         AND f.revoked_at IS NULL AND t.expires_at > ?${generationClause}${resourceClause}`,
      ).all(...params) as { scopes_json: string }[];
      const out: string[] = [];
      for (const row of rows) for (const s of parseScopes(row.scopes_json)) if (!out.includes(s)) out.push(s);
      return out;
    });
  }

  async sweepExpired(nowIso: string): Promise<void> {
    this.ensureOpen();
    assertUtcIsoTimestamp(nowIso, "nowIso");
    this.transaction(() => {
      advanceSqliteSweepWatermark(this.db, nowIso);
      this.db.prepare(`DELETE FROM oauth_auth_codes WHERE expires_at < ?`).run(nowIso);
      this.db.prepare(`DELETE FROM oauth_consent_jtis WHERE expires_at < ?`).run(nowIso);
      // Family-validity retention (addendum 8): delete a refresh token (consumed or
      // not) ONLY when its family has no still-valid member. The subquery is
      // materialized before the DELETE, so this correctly identifies families with
      // a live successor and keeps the consumed predecessor (replay signal).
      this.db.prepare(
        `DELETE FROM oauth_refresh_tokens WHERE family_id NOT IN (SELECT DISTINCT family_id FROM oauth_refresh_tokens WHERE expires_at >= ?)`,
      ).run(nowIso);
      // delete ANY empty family (not only revoked ones).
      this.db.prepare(`DELETE FROM oauth_refresh_token_families WHERE family_id NOT IN (SELECT DISTINCT family_id FROM oauth_refresh_tokens)`).run();
    });
  }

  startExpiryCollection(clock: ClockPort): void { this.ensureOpen(); this.expiry.start(clock); }

  override async close(): Promise<void> { await this.expiry.stop(); await super.close(); }

  private transaction<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

}

export function openSqliteStore(filename: string): SqliteStore {
  const path = sqlitePath(filename);
  if (path === ":memory:") return openAndMigrate(path);
  const admission = admitSqliteFile(path);
  let admissionOpen = true;
  let db: DatabaseSync | undefined;
  try {
    try {
      db = new DatabaseSync(path);
    } catch {
      throw new SqliteStateError("DatabaseSync could not open the admitted path");
    }
    verifySqlitePathIdentity(path, admission.identity);
    admissionOpen = false;
    closeSqliteAdmission(admission.fd);
    migrateSqliteStore(db);
    return new SqliteStore(db, { schemaReady: true });
  } catch (error) {
    try { db?.close(); } catch { /* preserve the boot failure */ }
    if (admissionOpen) {
      try { closeSqliteAdmission(admission.fd); } catch { /* preserve the original failure */ }
    }
    if (error instanceof SqliteStateError) throw error;
    throw new SqliteStateError("database initialization failed");
  }
}

function openAndMigrate(path: ":memory:"): SqliteStore {
  const db = new DatabaseSync(path);
  try {
    migrateSqliteStore(db);
    return new SqliteStore(db, { schemaReady: true });
  } catch (error) {
    try { db.close(); } catch { /* preserve the migration failure */ }
    throw error;
  }
}
