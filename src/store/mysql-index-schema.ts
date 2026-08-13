import type { PoolConnection, RowDataPacket } from "mysql2/promise";
import { StoreInputError } from "../ports/store.ts";

export async function assertConsentJtiUnique(conn: PoolConnection): Promise<void> {
  const [rows] = await conn.query<RowDataPacket[]>(
    `SELECT INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME
     FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'oauth_consent_jtis'
     ORDER BY INDEX_NAME, SEQ_IN_INDEX`,
  );
  const indexes = new Map<string, { nonUnique: number; columns: string[] }>();
  for (const row of rows as { INDEX_NAME: string; NON_UNIQUE: number; COLUMN_NAME: string }[]) {
    const index = indexes.get(row.INDEX_NAME) ?? { nonUnique: row.NON_UNIQUE, columns: [] };
    index.columns.push(row.COLUMN_NAME);
    indexes.set(row.INDEX_NAME, index);
  }
  const uniqueJti = [...indexes.values()].some((index) =>
    index.nonUnique === 0 && index.columns.length === 1 && index.columns[0] === "jti");
  if (!uniqueJti) {
    throw new StoreInputError(
      "oauth_consent_jtis.jti must have a single-column PRIMARY or UNIQUE index; consent replay detection requires JTI uniqueness.",
    );
  }
}
