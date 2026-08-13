import { randomBytes } from "node:crypto";
import type { Pool, PoolConnection, RowDataPacket } from "mysql2/promise";
import { assertStoreInstanceId } from "../ports/store.ts";

export async function ensureMysqlStoreInstance(conn: PoolConnection): Promise<void> {
  await conn.query(
    "INSERT IGNORE INTO oauth_store_metadata (singleton, instance_id) VALUES (1, ?)",
    [randomBytes(18).toString("base64url")],
  );
}

export async function readMysqlStoreInstanceId(pool: Pool): Promise<string> {
  const [rows] = await pool.query<RowDataPacket[]>(
    "SELECT instance_id FROM oauth_store_metadata WHERE singleton = 1",
  );
  const value = (rows[0] as { instance_id?: unknown } | undefined)?.instance_id;
  assertStoreInstanceId(value);
  return value;
}
