import type { Pool, PoolConnection, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import type { ConsentApprovalCommitResult, SaveAuthCodeInput } from "../ports/store.ts";
import { assertUtcIsoTimestamp, grantGenerationForWrite, StoreInputError } from "../ports/store.ts";
import { isDuplicateEntry } from "./mysql-schema.ts";

export async function commitMysqlConsentApproval(
  conn: PoolConnection, expectedStoreInstanceId: string, jti: string,
  expiresAtIso: string, authCode: SaveAuthCodeInput,
): Promise<ConsentApprovalCommitResult> {
  const [metadata] = await conn.query<RowDataPacket[]>(
    "SELECT instance_id, swept_through FROM oauth_store_metadata WHERE singleton = 1 FOR UPDATE",
  );
  const row = metadata[0] as { instance_id?: unknown; swept_through?: unknown } | undefined;
  if (row?.instance_id !== expectedStoreInstanceId)
    return "binding_mismatch";
  if (sweepFenceRejects(row.swept_through, expiresAtIso)) return "replayed";
  try {
    await conn.query(`INSERT INTO oauth_consent_jtis (jti, expires_at) VALUES (?, ?)`, [jti, expiresAtIso]);
  } catch (error) {
    if (isDuplicateEntry(error)) return "replayed";
    throw error;
  }
  await insertMysqlAuthCode(conn, authCode);
  return "stored";
}

export async function consumeMysqlConsentJti(
  conn: PoolConnection, jti: string, expiresAtIso: string,
): Promise<boolean> {
  const sweptThrough = await readMysqlSweepWatermark(conn);
  if (sweptThrough !== null && expiresAtIso < sweptThrough) return false;
  try {
    await conn.query<ResultSetHeader>(
      `INSERT INTO oauth_consent_jtis (jti, expires_at) VALUES (?, ?)`, [jti, expiresAtIso]);
    return true;
  } catch (error) {
    if (isDuplicateEntry(error)) return false;
    throw error;
  }
}

export async function advanceMysqlSweepWatermark(
  conn: PoolConnection, nowIso: string,
): Promise<void> {
  const current = await readMysqlSweepWatermark(conn);
  if (current === null || current < nowIso) {
    const [result] = await conn.query<ResultSetHeader>(
      "UPDATE oauth_store_metadata SET swept_through = ? WHERE singleton = 1", [nowIso]);
    if (result.affectedRows !== 1) throw new StoreInputError("oauth_store_metadata singleton is missing");
  }
}

async function readMysqlSweepWatermark(conn: PoolConnection): Promise<string | null> {
  const [rows] = await conn.query<RowDataPacket[]>(
    "SELECT swept_through FROM oauth_store_metadata WHERE singleton = 1 FOR UPDATE");
  return checkedSweepWatermark((rows[0] as { swept_through?: unknown } | undefined)?.swept_through);
}

function sweepFenceRejects(value: unknown, expiresAtIso: string): boolean {
  const sweptThrough = checkedSweepWatermark(value);
  return sweptThrough !== null && expiresAtIso < sweptThrough;
}

function checkedSweepWatermark(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string") throw new StoreInputError("oauth_store_metadata sweep watermark is invalid");
  assertUtcIsoTimestamp(value, "sweptThrough");
  return value;
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
