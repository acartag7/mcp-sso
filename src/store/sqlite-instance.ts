import { randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { assertStoreInstanceId } from "../ports/store.ts";

export function readSqliteStoreInstanceId(db: DatabaseSync): string {
  const row = db.prepare(
    "SELECT instance_id FROM oauth_store_metadata WHERE singleton = 1",
  ).get() as { instance_id?: unknown } | undefined;
  assertStoreInstanceId(row?.instance_id);
  return row.instance_id;
}

export function rotateSqliteStoreInstanceId(db: DatabaseSync): string {
  const value = randomBytes(18).toString("base64url");
  const result = db.prepare(
    "UPDATE oauth_store_metadata SET instance_id = ? WHERE singleton = 1",
  ).run(value);
  if (result.changes !== 1) throw new Error("oauth_store_metadata singleton is missing");
  return value;
}
