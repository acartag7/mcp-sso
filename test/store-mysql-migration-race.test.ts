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
        if (values?.[0] === "oauth_auth_codes") {
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

test("MySQL migration adds nullable resource columns to pre-resource refresh tables", async () => {
  const alters: string[] = [];
  const seen = new Set<string>();
  const connection = {
    query: async (sql: string, values?: unknown[]) => {
      if (sql.startsWith("SELECT @@session.sql_mode")) return [[{ sql_mode: "STRICT_TRANS_TABLES" }], []];
      if (sql.startsWith("SELECT 1 FROM information_schema.COLUMNS")) {
        const key = `${values?.[0]}:${values?.[1]}`;
        return [seen.has(key) ? [{ 1: 1 }] : [], []];
      }
      if (sql.startsWith("ALTER TABLE")) {
        alters.push(sql);
        const match = /^ALTER TABLE (\w+) ADD COLUMN (\w+)/.exec(sql);
        assert.ok(match);
        seen.add(`${match[1]}:${match[2]}`);
        return [[], []];
      }
      if (sql.includes("COLLATION_NAME") || sql.includes("ENGINE")) return [[], []];
      return [[], []];
    },
  } as unknown as PoolConnection;
  await migrateMysqlStore(connection);
  assert.ok(alters.includes("ALTER TABLE oauth_refresh_token_families ADD COLUMN resource VARCHAR(2048) NULL"));
  assert.ok(alters.includes("ALTER TABLE oauth_refresh_tokens ADD COLUMN resource VARCHAR(2048) NULL"));
});
