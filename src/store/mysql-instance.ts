import { randomBytes } from "node:crypto";
import type { Pool, PoolConnection, RowDataPacket } from "mysql2/promise";
import { assertStoreInstanceId, StoreInputError } from "../ports/store.ts";

export async function assertMysqlStoreInstanceSchema(conn: PoolConnection): Promise<void> {
  const [tables] = await conn.query<RowDataPacket[]>(
    `SELECT ENGINE FROM information_schema.TABLES
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'oauth_store_metadata'`,
  );
  if ((tables[0] as { ENGINE?: unknown } | undefined)?.ENGINE !== "InnoDB") {
    throw new StoreInputError("oauth_store_metadata must use the InnoDB engine");
  }
  const [columns] = await conn.query<RowDataPacket[]>(
    `SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLLATION_NAME
     FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'oauth_store_metadata'`,
  );
  const byName = new Map((columns as Array<Record<string, unknown>>)
    .map((row) => [String(row.COLUMN_NAME).toLowerCase(), row]));
  const singleton = byName.get("singleton");
  const instance = byName.get("instance_id");
  if (byName.size !== 2 || singleton?.COLUMN_TYPE !== "tinyint unsigned"
    || singleton.IS_NULLABLE !== "NO" || instance?.COLUMN_TYPE !== "varchar(128)"
    || instance.IS_NULLABLE !== "NO" || instance.COLLATION_NAME !== "utf8mb4_bin") {
    throw new StoreInputError("oauth_store_metadata columns are incompatible");
  }
  const [indexes] = await conn.query<RowDataPacket[]>(
    `SELECT INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME, SUB_PART
     FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'oauth_store_metadata'
     ORDER BY INDEX_NAME, SEQ_IN_INDEX`,
  );
  if (indexes.length !== 2) throw new StoreInputError("oauth_store_metadata indexes are incompatible");
  const unique = new Map<string, Array<Record<string, unknown>>>();
  for (const row of indexes as Array<Record<string, unknown>>) {
    if (row.NON_UNIQUE !== 0 && row.NON_UNIQUE !== "0") continue;
    const rows = unique.get(String(row.INDEX_NAME)) ?? [];
    rows.push(row);
    unique.set(String(row.INDEX_NAME), rows);
  }
  const exactUnique = (name: string): boolean => [...unique.values()].some((rows) =>
    rows.length === 1 && String(rows[0]?.COLUMN_NAME).toLowerCase() === name
      && rows[0]?.SUB_PART == null);
  if (!exactUnique("singleton") || !exactUnique("instance_id") || unique.size !== 2) {
    throw new StoreInputError("oauth_store_metadata indexes are incompatible");
  }
  const [checks] = await conn.query<RowDataPacket[]>(
    `SELECT cc.CHECK_CLAUSE, tc.ENFORCED
     FROM information_schema.TABLE_CONSTRAINTS tc
     JOIN information_schema.CHECK_CONSTRAINTS cc
       ON cc.CONSTRAINT_SCHEMA = tc.CONSTRAINT_SCHEMA
      AND cc.CONSTRAINT_NAME = tc.CONSTRAINT_NAME
     WHERE tc.CONSTRAINT_SCHEMA = DATABASE()
       AND tc.TABLE_NAME = 'oauth_store_metadata' AND tc.CONSTRAINT_TYPE = 'CHECK'`,
  );
  const constraints = checks as Array<Record<string, unknown>>;
  const clauses = constraints.map((row) => String(row.CHECK_CLAUSE).replace(/[\s`()]/gu, "").toLowerCase());
  if (clauses.length !== 1 || clauses[0] !== "singleton=1" || constraints[0]?.ENFORCED !== "YES") {
    throw new StoreInputError("oauth_store_metadata must constrain singleton to 1");
  }
  const [triggers] = await conn.query<RowDataPacket[]>(
    `SELECT TRIGGER_NAME FROM information_schema.TRIGGERS
     WHERE TRIGGER_SCHEMA = DATABASE() AND EVENT_OBJECT_TABLE = 'oauth_store_metadata'`,
  );
  if (triggers.length > 0) throw new StoreInputError("oauth_store_metadata must not have triggers");
  const [foreignKeys] = await conn.query<RowDataPacket[]>(
    `SELECT CONSTRAINT_NAME FROM information_schema.REFERENTIAL_CONSTRAINTS
     WHERE CONSTRAINT_SCHEMA = DATABASE()
       AND (TABLE_NAME = 'oauth_store_metadata' OR REFERENCED_TABLE_NAME = 'oauth_store_metadata')`,
  );
  if (foreignKeys.length > 0) {
    throw new StoreInputError("oauth_store_metadata must not have foreign keys");
  }
}

export async function ensureMysqlStoreInstance(conn: PoolConnection): Promise<void> {
  await conn.query(
    "INSERT IGNORE INTO oauth_store_metadata (singleton, instance_id) VALUES (1, ?)",
    [randomBytes(18).toString("base64url")],
  );
  await assertMysqlStoreInstance(conn);
}

export async function assertMysqlStoreInstance(conn: PoolConnection): Promise<void> {
  const [rows] = await conn.query<RowDataPacket[]>(
    "SELECT instance_id FROM oauth_store_metadata WHERE singleton = 1",
  );
  assertStoreInstanceId((rows[0] as { instance_id?: unknown } | undefined)?.instance_id);
}

export async function readMysqlStoreInstanceId(pool: Pool): Promise<string> {
  const [rows] = await pool.query<RowDataPacket[]>(
    "SELECT instance_id FROM oauth_store_metadata WHERE singleton = 1",
  );
  const value = (rows[0] as { instance_id?: unknown } | undefined)?.instance_id;
  assertStoreInstanceId(value);
  return value;
}

export async function rotateMysqlStoreInstanceId(pool: Pool | PoolConnection): Promise<string> {
  const value = randomBytes(18).toString("base64url");
  const [result] = await pool.query(
    "UPDATE oauth_store_metadata SET instance_id = ? WHERE singleton = 1",
    [value],
  );
  const changed = (result as { affectedRows?: unknown }).affectedRows;
  if (changed !== 1) throw new Error("oauth_store_metadata singleton is missing");
  return value;
}
