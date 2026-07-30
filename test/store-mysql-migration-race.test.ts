import assert from "node:assert/strict";
import { test } from "node:test";
import type { PoolConnection } from "mysql2/promise";
import { migrateMysqlStore } from "../src/store/mysql-schema.ts";

interface RaceOptions {
  readonly errorCode: string;
  readonly materializes: boolean;
}

function racingConnection(options: RaceOptions): {
  readonly connection: PoolConnection;
  readonly columnReads: () => number;
} {
  let targetReads = 0;
  const connection = {
    query: async (sql: string, values?: unknown[]) => {
      if (sql.startsWith("SELECT @@session.sql_mode")) {
        return [[{ sql_mode: "STRICT_TRANS_TABLES" }], []];
      }
      if (sql.startsWith("SELECT 1 FROM information_schema.COLUMNS")) {
        if (values?.[0] === "oauth_auth_codes" && values?.[1] === "grant_generation") {
          targetReads += 1;
          return [targetReads > 1 && options.materializes ? [{ 1: 1 }] : [], []];
        }
        return [[{ 1: 1 }], []];
      }
      if (sql.startsWith("ALTER TABLE oauth_auth_codes")) {
        throw Object.assign(new Error("simulated ALTER race"), { code: options.errorCode });
      }
      if (sql.includes("COLLATION_NAME") || sql.includes("ENGINE")) return [[], []];
      return [[], []];
    },
  } as unknown as PoolConnection;
  return { connection, columnReads: () => targetReads };
}

test("MySQL migration accepts a duplicate-column race only after the column exists", async () => {
  const raced = racingConnection({
    errorCode: "ER_DUP_FIELDNAME",
    materializes: true,
  });
  await migrateMysqlStore(raced.connection);
  assert.equal(raced.columnReads(), 2, "duplicate race was re-checked");
});

test("MySQL migration rejects a false duplicate-column error", async () => {
  const raced = racingConnection({
    errorCode: "ER_DUP_FIELDNAME",
    materializes: false,
  });
  await assert.rejects(
    migrateMysqlStore(raced.connection),
    (error: unknown) => (error as { code?: string }).code === "ER_DUP_FIELDNAME",
  );
  assert.equal(raced.columnReads(), 2, "duplicate race was re-checked");
});

test("MySQL migration propagates every non-duplicate ALTER failure", async () => {
  const raced = racingConnection({
    errorCode: "ER_TABLEACCESS_DENIED_ERROR",
    materializes: true,
  });
  await assert.rejects(
    migrateMysqlStore(raced.connection),
    (error: unknown) => (error as { code?: string }).code === "ER_TABLEACCESS_DENIED_ERROR",
  );
  assert.equal(raced.columnReads(), 1, "unrelated errors are not reclassified");
});
