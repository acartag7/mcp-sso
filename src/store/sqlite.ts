// SqliteStore — reference persistent StorePort on node:sqlite (contracts §12.3).
// STRICT tables, BEGIN IMMEDIATE transactions, INSERT...ON CONFLICT DO NOTHING for
// single-use consent JTIs. Implements the rotation backfill (fix #3) and
// findGrantedScopes (reads active refresh records — no grant table).

import { DatabaseSync } from "node:sqlite";
import type {
  AuthCodeRecord, RefreshTokenRecord, SaveAuthCodeInput, SaveRefreshTokenInput, StorePort,
} from "../ports/store.ts";
import { StoreInputError, assertSha256Hex, assertUtcIsoTimestamp } from "../ports/store.ts";
import { migrateSqliteStore } from "./sqlite-schema.ts";

interface AuthCodeRow {
  code_hash: string; client_id: string; subject: string; redirect_uri: string; resource: string;
  scopes_json: string; code_challenge: string; code_challenge_method: "S256"; expires_at: string;
}
interface RefreshTokenRow {
  token_hash: string; family_id: string; previous_token_hash: string | null; client_id: string;
  subject: string; scopes_json: string; expires_at: string; consumed_at: string | null; revoked_at: string | null;
}

export class SqliteStore implements StorePort {
  private closed = false;
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  async saveAuthCode(input: SaveAuthCodeInput): Promise<void> {
    this.ensureOpen();
    validateAuthCode(input);
    this.db.prepare(`INSERT INTO oauth_auth_codes (
      code_hash, client_id, subject, redirect_uri, resource, scopes_json,
      code_challenge, code_challenge_method, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      input.codeHash, input.clientId, input.subject, input.redirectUri, input.resource,
      JSON.stringify(input.scopes), input.codeChallenge, input.codeChallengeMethod, input.expiresAt,
    );
  }

  async consumeAuthCode(codeHash: string, nowIso: string): Promise<AuthCodeRecord | null> {
    this.ensureOpen();
    assertSha256Hex(codeHash, "codeHash");
    assertUtcIsoTimestamp(nowIso, "nowIso");
    return this.transaction(() => {
      const row = this.db.prepare(`SELECT * FROM oauth_auth_codes WHERE code_hash = ?`).get(codeHash) as AuthCodeRow | undefined;
      if (!row) return null;
      this.db.prepare(`DELETE FROM oauth_auth_codes WHERE code_hash = ?`).run(codeHash);
      return row.expires_at > nowIso ? authCodeFromRow(row) : null;
    });
  }

  async consumeConsentJti(jti: string, expiresAtIso: string): Promise<boolean> {
    this.ensureOpen();
    const result = this.db.prepare(
      `INSERT INTO oauth_consent_jtis (jti, expires_at) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING`,
    ).run(jti, expiresAtIso);
    return (result.changes ?? 0) > 0;
  }

  async saveRefreshToken(input: SaveRefreshTokenInput): Promise<void> {
    this.ensureOpen();
    validateRefreshToken(input);
    this.transaction(() => {
      this.db.prepare(
        `INSERT INTO oauth_refresh_token_families (family_id, revoked_at) VALUES (?, NULL) ON CONFLICT(family_id) DO NOTHING`,
      ).run(input.familyId);
      insertRefreshToken(this.db, input);
    });
  }

  async rotateRefreshToken(tokenHash: string, next: SaveRefreshTokenInput, nowIso: string): Promise<RefreshTokenRecord | null> {
    this.ensureOpen();
    validateRotation(tokenHash, next, nowIso);
    return this.transaction(() => {
      const row = this.db.prepare(
        `SELECT t.*, f.revoked_at FROM oauth_refresh_tokens t
         JOIN oauth_refresh_token_families f ON f.family_id = t.family_id WHERE t.token_hash = ?`,
      ).get(tokenHash) as RefreshTokenRow | undefined;
      if (!row || row.revoked_at !== null) return null;
      if (row.consumed_at !== null) {
        revokeFamily(this.db, row.family_id, nowIso);
        return null;
      }
      if (row.expires_at <= nowIso || next.familyId !== row.family_id) return null;
      if (this.db.prepare(`SELECT token_hash FROM oauth_refresh_tokens WHERE token_hash = ?`).get(next.tokenHash)) return null;
      this.db.prepare(`UPDATE oauth_refresh_tokens SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL`).run(nowIso, tokenHash);
      // Fix #3 backfill: successor takes clientId/subject/scopes from the consumed row.
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
        `SELECT t.*, f.revoked_at FROM oauth_refresh_tokens t
         JOIN oauth_refresh_token_families f ON f.family_id = t.family_id WHERE t.token_hash = ?`,
      ).get(tokenHash) as RefreshTokenRow | undefined;
      return row ? refreshTokenFromRow(row) : null;
    });
  }

  async findGrantedScopes(subject: string, clientId: string, nowIso: string): Promise<string[]> {
    this.ensureOpen();
    assertUtcIsoTimestamp(nowIso, "nowIso");
    return this.transaction(() => {
      const rows = this.db.prepare(
        `SELECT t.scopes_json FROM oauth_refresh_tokens t
         JOIN oauth_refresh_token_families f ON f.family_id = t.family_id
         WHERE t.subject = ? AND t.client_id = ? AND t.consumed_at IS NULL AND f.revoked_at IS NULL AND t.expires_at > ?`,
      ).all(subject, clientId, nowIso) as { scopes_json: string }[];
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
      this.db.prepare(`DELETE FROM oauth_refresh_tokens WHERE expires_at < ? AND consumed_at IS NULL`).run(nowIso);
      this.db.prepare(`DELETE FROM oauth_refresh_token_families WHERE revoked_at IS NOT NULL AND family_id NOT IN (SELECT DISTINCT family_id FROM oauth_refresh_tokens)`).run();
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
  const db = new DatabaseSync(filename);
  migrateSqliteStore(db);
  return new SqliteStore(db);
}

function insertRefreshToken(db: DatabaseSync, input: SaveRefreshTokenInput): void {
  db.prepare(`INSERT INTO oauth_refresh_tokens (
    token_hash, family_id, previous_token_hash, client_id, subject, scopes_json, expires_at, consumed_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`).run(
    input.tokenHash, input.familyId, input.previousTokenHash, input.clientId, input.subject,
    JSON.stringify(input.scopes), input.expiresAt,
  );
}

function nextFromRow(input: SaveRefreshTokenInput, row: RefreshTokenRow): SaveRefreshTokenInput {
  return { ...input, clientId: row.client_id, subject: row.subject, scopes: parseScopes(row.scopes_json) };
}

function revokeFamily(db: DatabaseSync, familyId: string, revokedAtIso: string): void {
  db.prepare(
    `INSERT INTO oauth_refresh_token_families (family_id, revoked_at) VALUES (?, ?)
     ON CONFLICT(family_id) DO UPDATE SET revoked_at = COALESCE(oauth_refresh_token_families.revoked_at, excluded.revoked_at)`,
  ).run(familyId, revokedAtIso);
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

function authCodeFromRow(row: AuthCodeRow): AuthCodeRecord {
  return {
    codeHash: row.code_hash, clientId: row.client_id, subject: row.subject, redirectUri: row.redirect_uri,
    resource: row.resource, scopes: parseScopes(row.scopes_json), codeChallenge: row.code_challenge,
    codeChallengeMethod: row.code_challenge_method, expiresAt: row.expires_at,
  };
}

function refreshTokenFromRow(row: RefreshTokenRow): RefreshTokenRecord {
  return {
    tokenHash: row.token_hash, familyId: row.family_id, previousTokenHash: row.previous_token_hash,
    clientId: row.client_id, subject: row.subject, scopes: parseScopes(row.scopes_json), expiresAt: row.expires_at,
  };
}

function parseScopes(value: string): string[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some((scope) => typeof scope !== "string")) {
    throw new Error("Stored scopes are invalid");
  }
  return parsed;
}
