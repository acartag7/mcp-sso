import type { DatabaseSync } from "node:sqlite";
import type { ConsentApprovalCommitResult, SaveAuthCodeInput } from "../ports/store.ts";
import { assertUtcIsoTimestamp, grantGenerationForWrite, StoreInputError } from "../ports/store.ts";
import { readSqliteStoreInstanceId } from "./sqlite-instance.ts";

export function commitSqliteConsentApproval(
  db: DatabaseSync, expectedStoreInstanceId: string, jti: string,
  expiresAtIso: string, authCode: SaveAuthCodeInput,
): ConsentApprovalCommitResult {
  if (readSqliteStoreInstanceId(db) !== expectedStoreInstanceId) return "binding_mismatch";
  if (sqliteSweepFenceRejects(db, expiresAtIso)) return "replayed";
  const consumed = db.prepare(
    `INSERT INTO oauth_consent_jtis (jti, expires_at) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING`,
  ).run(jti, expiresAtIso);
  if ((consumed.changes ?? 0) === 0) return "replayed";
  insertSqliteAuthCode(db, authCode);
  return "stored";
}

export function consumeSqliteConsentJti(
  db: DatabaseSync, jti: string, expiresAtIso: string,
): boolean {
  if (sqliteSweepFenceRejects(db, expiresAtIso)) return false;
  const result = db.prepare(
    `INSERT INTO oauth_consent_jtis (jti, expires_at) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING`,
  ).run(jti, expiresAtIso);
  return (result.changes ?? 0) > 0;
}

export function advanceSqliteSweepWatermark(db: DatabaseSync, nowIso: string): void {
  const current = sqliteSweepWatermark(db);
  if (current === null || current < nowIso) {
    const result = db.prepare(
      "UPDATE oauth_store_metadata SET swept_through = ? WHERE singleton = 1",
    ).run(nowIso);
    if (result.changes !== 1) throw new StoreInputError("oauth_store_metadata singleton is missing");
  }
}

function sqliteSweepFenceRejects(db: DatabaseSync, expiresAtIso: string): boolean {
  const sweptThrough = sqliteSweepWatermark(db);
  return sweptThrough !== null && expiresAtIso < sweptThrough;
}

function sqliteSweepWatermark(db: DatabaseSync): string | null {
  const row = db.prepare(
    "SELECT swept_through FROM oauth_store_metadata WHERE singleton = 1",
  ).get() as { swept_through?: unknown } | undefined;
  if (!row || (row.swept_through !== null && typeof row.swept_through !== "string")) {
    throw new StoreInputError("oauth_store_metadata sweep watermark is invalid");
  }
  if (row.swept_through === null) return null;
  assertUtcIsoTimestamp(row.swept_through as string, "sweptThrough");
  return row.swept_through as string;
}

export function insertSqliteAuthCode(db: DatabaseSync, input: SaveAuthCodeInput): void {
  db.prepare(`INSERT INTO oauth_auth_codes (
    code_hash, client_id, subject, redirect_uri, resource, scopes_json,
    code_challenge, code_challenge_method, expires_at, grant_generation
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    input.codeHash, input.clientId, input.subject, input.redirectUri, input.resource,
    JSON.stringify(input.scopes), input.codeChallenge, input.codeChallengeMethod,
    input.expiresAt, grantGenerationForWrite(input.grantGeneration),
  );
}
