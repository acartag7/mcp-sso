import type { PoolConnection, RowDataPacket } from "mysql2/promise";
import { StoreInputError } from "../ports/store.ts";

export async function assertConsentJtiUnique(conn: PoolConnection): Promise<void> {
  const [foreignKeys] = await conn.query<RowDataPacket[]>(
    `SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'oauth_consent_jtis'
       AND REFERENCED_TABLE_NAME IS NOT NULL`,
  );
  if (foreignKeys.length > 0) {
    throw new StoreInputError(
      "oauth_consent_jtis must not have foreign keys; INSERT IGNORE must mean duplicate JTI only.",
    );
  }
  const [columnRows] = await conn.query<RowDataPacket[]>(
    `SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE
     FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'oauth_consent_jtis'
       AND COLUMN_NAME IN ('jti', 'expires_at')`,
  );
  const columns = new Map((columnRows as Array<Record<string, unknown>>).map((row) => [
    String(row.COLUMN_NAME).toLowerCase(), row,
  ]));
  assertConsentColumn(columns.get("jti"), "jti", 255);
  assertConsentColumn(columns.get("expires_at"), "expires_at", 24);
  const [rows] = await conn.query<RowDataPacket[]>(
    `SELECT INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME, SUB_PART
     FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'oauth_consent_jtis'
     ORDER BY INDEX_NAME, SEQ_IN_INDEX`,
  );
  const indexes = new Map<string, {
    nonUnique: number | null;
    parts: Array<{ column: string | null; prefixed: boolean }>;
  }>();
  for (const row of rows as { INDEX_NAME: unknown; NON_UNIQUE: unknown; COLUMN_NAME: unknown; SUB_PART: unknown }[]) {
    if (typeof row.INDEX_NAME !== "string") continue;
    const nonUnique = row.NON_UNIQUE === 0 || row.NON_UNIQUE === "0" ? 0
      : row.NON_UNIQUE === 1 || row.NON_UNIQUE === "1" ? 1 : null;
    const index = indexes.get(row.INDEX_NAME) ?? { nonUnique, parts: [] };
    index.parts.push({
      column: typeof row.COLUMN_NAME === "string" ? row.COLUMN_NAME.toLowerCase() : null,
      prefixed: row.SUB_PART !== null && row.SUB_PART !== undefined,
    });
    indexes.set(row.INDEX_NAME, index);
  }
  const uniqueJti = [...indexes.values()].some((index) =>
    index.nonUnique === 0 && index.parts.length === 1
      && index.parts[0]?.column === "jti" && !index.parts[0].prefixed);
  const competingUnique = [...indexes.values()].some((index) =>
    index.nonUnique === 0 && !index.parts.some((part) => part.column === "jti" && !part.prefixed));
  if (!uniqueJti || competingUnique) {
    throw new StoreInputError(
      "oauth_consent_jtis must have a full-column JTI PRIMARY or UNIQUE index and no competing unique constraint; consent replay detection requires conflicts to mean duplicate JTI.",
    );
  }
}

function assertConsentColumn(row: Record<string, unknown> | undefined, name: string, minimum: number): void {
  if (!row || String(row.DATA_TYPE).toLowerCase() !== "varchar" || row.IS_NULLABLE !== "NO"
    || !Number.isSafeInteger(Number(row.CHARACTER_MAXIMUM_LENGTH))
    || Number(row.CHARACTER_MAXIMUM_LENGTH) < minimum) {
    throw new StoreInputError(`oauth_consent_jtis.${name} must be a non-null VARCHAR(${minimum}) or wider column`);
  }
}
