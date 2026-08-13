import type { PoolConnection, RowDataPacket } from "mysql2/promise";
import { StoreInputError } from "../ports/store.ts";

export const MYSQL_SUBJECT_CAPACITY = 384;

const SUBJECT_TABLES = ["oauth_auth_codes", "oauth_refresh_tokens"] as const;

interface SubjectColumnRow {
  data_type: string;
  max_length: number;
  is_nullable: string;
}

/** Widen only the two deployed VARCHAR(255) subject columns. Wider compatible
 *  columns are left alone; unexpected undersized/drifted shapes fail closed. */
export async function migrateMysqlSubjectColumns(conn: PoolConnection): Promise<void> {
  const legacyTables: (typeof SUBJECT_TABLES)[number][] = [];
  for (const table of SUBJECT_TABLES) {
    const [rows] = await conn.query<RowDataPacket[]>(
      `SELECT DATA_TYPE AS data_type, CHARACTER_MAXIMUM_LENGTH AS max_length, IS_NULLABLE AS is_nullable
       FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = 'subject'`,
      [table],
    );
    const column = rows[0] as SubjectColumnRow | undefined;
    if (!column || column.data_type !== "varchar" || column.is_nullable !== "NO"
      || !Number.isSafeInteger(column.max_length)) {
      throw new StoreInputError(`${table}.subject must be a non-null VARCHAR column`);
    }
    if (column.max_length >= MYSQL_SUBJECT_CAPACITY) continue;
    if (column.max_length === 255) {
      legacyTables.push(table);
    } else {
      throw new StoreInputError(`${table}.subject has unsupported VARCHAR(${column.max_length}) width`);
    }
  }
  for (const table of legacyTables) {
    await conn.query(
      `ALTER TABLE ${table} MODIFY COLUMN subject VARCHAR(${MYSQL_SUBJECT_CAPACITY}) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL`,
    );
  }
}
