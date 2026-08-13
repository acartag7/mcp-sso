import type { Pool, PoolConnection, RowDataPacket } from "mysql2/promise";
import type { ConsentApprovalCommitResult, SaveAuthCodeInput } from "../ports/store.ts";
import { grantGenerationForWrite } from "../ports/store.ts";
import { isDuplicateEntry } from "./mysql-schema.ts";

export async function commitMysqlConsentApproval(
  conn: PoolConnection, expectedStoreInstanceId: string, jti: string,
  expiresAtIso: string, authCode: SaveAuthCodeInput,
): Promise<ConsentApprovalCommitResult> {
  const [metadata] = await conn.query<RowDataPacket[]>(
    "SELECT instance_id FROM oauth_store_metadata WHERE singleton = 1 FOR UPDATE",
  );
  if ((metadata[0] as { instance_id?: unknown } | undefined)?.instance_id !== expectedStoreInstanceId)
    return "binding_mismatch";
  try {
    await conn.query(`INSERT INTO oauth_consent_jtis (jti, expires_at) VALUES (?, ?)`, [jti, expiresAtIso]);
  } catch (error) {
    if (isDuplicateEntry(error)) return "replayed";
    throw error;
  }
  await insertMysqlAuthCode(conn, authCode);
  return "stored";
}

export async function insertMysqlAuthCode(
  db: Pool | PoolConnection, input: SaveAuthCodeInput,
): Promise<void> {
  await db.query(
    `INSERT INTO oauth_auth_codes (code_hash, client_id, subject, redirect_uri, resource, scopes_json, code_challenge, code_challenge_method, expires_at, grant_generation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [input.codeHash, input.clientId, input.subject, input.redirectUri, input.resource,
      JSON.stringify(input.scopes), input.codeChallenge, input.codeChallengeMethod,
      input.expiresAt, grantGenerationForWrite(input.grantGeneration)],
  );
}
