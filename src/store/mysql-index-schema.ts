import type { PoolConnection, RowDataPacket } from "mysql2/promise";
import { StoreInputError } from "../ports/store.ts";

export async function assertConsentJtiUnique(conn: PoolConnection): Promise<void> {
  const [rows] = await conn.query<RowDataPacket[]>(
    `SELECT INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME, SUB_PART
     FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'oauth_consent_jtis'
     ORDER BY INDEX_NAME, SEQ_IN_INDEX`,
  );
  const indexes = new Map<string, { nonUnique: number | null; columns: Array<string | null>; prefix: boolean }>();
  for (const row of rows as { INDEX_NAME: unknown; NON_UNIQUE: unknown; COLUMN_NAME: unknown; SUB_PART: unknown }[]) {
    if (typeof row.INDEX_NAME !== "string") continue;
    const nonUnique = row.NON_UNIQUE === 0 || row.NON_UNIQUE === "0" ? 0
      : row.NON_UNIQUE === 1 || row.NON_UNIQUE === "1" ? 1 : null;
    const index = indexes.get(row.INDEX_NAME) ?? { nonUnique, columns: [], prefix: false };
    index.columns.push(typeof row.COLUMN_NAME === "string" ? row.COLUMN_NAME.toLowerCase() : null);
    index.prefix ||= row.SUB_PART !== null && row.SUB_PART !== undefined;
    indexes.set(row.INDEX_NAME, index);
  }
  const uniqueJti = [...indexes.values()].some((index) =>
    index.nonUnique === 0 && !index.prefix && index.columns.length === 1 && index.columns[0] === "jti");
  if (!uniqueJti) {
    throw new StoreInputError(
      "oauth_consent_jtis.jti must have a single-column PRIMARY or UNIQUE index; consent replay detection requires JTI uniqueness.",
    );
  }
}
