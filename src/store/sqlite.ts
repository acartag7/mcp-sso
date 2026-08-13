// SqliteStore — persistent StorePort + user ClientStore (contracts §6.4, §12.3).

import { DatabaseSync } from "node:sqlite";
import type {
  AuthCodeRecord, RefreshTokenRecord, SaveAuthCodeInput, SaveRefreshTokenInput, StorePort,
} from "../ports/store.ts";
import type { ClientRegistration, ClientStore } from "../ports/client-store.ts";
import {
  STORED_DCR_GRANT_GENERATION, STORED_DCR_RESOURCE_BINDING, StoreInputError, assertSha256Hex, assertUtcIsoTimestamp,
  grantGenerationForWrite, grantGenerationFromStored, normalizeRefreshTokenWrite,
  refreshResourceFromStored, UNBOUND_REFRESH_RESOURCE,
} from "../ports/store.ts";
import { migrateSqliteStore } from "./sqlite-schema.ts";
import {
  admitSqliteFile, closeSqliteAdmission, sqlitePath, SqliteStateError,
  verifySqlitePathIdentity,
} from "./sqlite-open.ts";
import {
  authCodeFromRow, insertRefreshToken, nextFromRow, parseScopes,
  refreshTokenFromRow, revokeFamily, validateAuthCode, validateRefreshToken,
  validateRotation, type AuthCodeRow, type RefreshTokenRow,
} from "./sqlite-records.ts";
import { findSqliteClient, saveSqliteClient } from "./sqlite-clients.ts";

export class SqliteStore implements StorePort, ClientStore {
  readonly storedDcrGrantGeneration = STORED_DCR_GRANT_GENERATION;
  readonly storedDcrResourceBinding = STORED_DCR_RESOURCE_BINDING;
  private closed = false;
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  async save(client: ClientRegistration): Promise<void> {
    this.ensureOpen();
    saveSqliteClient(this.db, client);
  }

  async find(clientId: string): Promise<ClientRegistration | null> {
    this.ensureOpen();
    return findSqliteClient(this.db, clientId);
  }

  async saveAuthCode(input: SaveAuthCodeInput): Promise<void> {
    this.ensureOpen();
    validateAuthCode(input);
    this.db.prepare(`INSERT INTO oauth_auth_codes (
      code_hash, client_id, subject, redirect_uri, resource, scopes_json,
      code_challenge, code_challenge_method, expires_at, grant_generation
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      input.codeHash, input.clientId, input.subject, input.redirectUri, input.resource,
      JSON.stringify(input.scopes), input.codeChallenge, input.codeChallengeMethod,
      input.expiresAt, grantGenerationForWrite(input.grantGeneration),
    );
  }

  async consumeAuthCode(codeHash: string, nowIso: string, expectedGrantGeneration?: number, expectedResource?: string): Promise<AuthCodeRecord | null> {
    this.ensureOpen();
    assertSha256Hex(codeHash, "codeHash");
    assertUtcIsoTimestamp(nowIso, "nowIso");
    return this.transaction(() => {
      const row = this.db.prepare(`SELECT * FROM oauth_auth_codes WHERE code_hash = ?`).get(codeHash) as AuthCodeRow | undefined;
      if (!row) return null;
      if (expectedResource !== undefined && row.resource !== expectedResource) return null;
      this.db.prepare(`DELETE FROM oauth_auth_codes WHERE code_hash = ?`).run(codeHash);
      const record = authCodeFromRow(row);
      return row.expires_at > nowIso
        && (expectedGrantGeneration === undefined || record.grantGeneration === expectedGrantGeneration) ? record : null;
    });
  }

  async consumeConsentJti(jti: string, expiresAtIso: string): Promise<boolean> {
    this.ensureOpen();
    assertUtcIsoTimestamp(expiresAtIso, "expiresAtIso"); // addendum 10: source left this unvalidated
    const result = this.db.prepare(
      `INSERT INTO oauth_consent_jtis (jti, expires_at) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING`,
    ).run(jti, expiresAtIso);
    return (result.changes ?? 0) > 0;
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
      if (!row || row.revoked_at !== null) return null;
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

  async revokeRefreshTokenFamily(familyId: string, revokedAtIso: string): Promise<void> {
    this.ensureOpen();
    assertUtcIsoTimestamp(revokedAtIso, "revokedAtIso");
    this.transaction(() => revokeFamily(this.db, familyId, revokedAtIso));
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

  async close(): Promise<void> {
    if (!this.closed) {
      this.db.close();
      this.closed = true;
    }
  }

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

  private ensureOpen(): void {
    if (this.closed) throw new Error("Store is closed");
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
    return new SqliteStore(db);
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
    return new SqliteStore(db);
  } catch (error) {
    try { db.close(); } catch { /* preserve the migration failure */ }
    throw error;
  }
}
