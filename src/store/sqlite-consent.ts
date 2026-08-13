import type { DatabaseSync } from "node:sqlite";
import type { ConsentApprovalCommitResult, SaveAuthCodeInput } from "../ports/store.ts";
import { grantGenerationForWrite } from "../ports/store.ts";
import { readSqliteStoreInstanceId } from "./sqlite-instance.ts";

export function commitSqliteConsentApproval(
  db: DatabaseSync, expectedStoreInstanceId: string, jti: string,
  expiresAtIso: string, authCode: SaveAuthCodeInput,
): ConsentApprovalCommitResult {
  if (readSqliteStoreInstanceId(db) !== expectedStoreInstanceId) return "binding_mismatch";
  const consumed = db.prepare(
    `INSERT INTO oauth_consent_jtis (jti, expires_at) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING`,
  ).run(jti, expiresAtIso);
  if ((consumed.changes ?? 0) === 0) return "replayed";
  insertSqliteAuthCode(db, authCode);
  return "stored";
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
