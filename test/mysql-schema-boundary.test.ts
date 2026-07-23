import assert from "node:assert/strict";
import { test } from "node:test";
import type { PoolConnection } from "mysql2/promise";
import { isDuplicateEntry, migrateMysqlStore } from "../src/store/mysql-schema.ts";

test("MySQL classifiers ignore inherited driver fields", async () => {
  const codeDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "code");
  const modeDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "sql_mode");
  Object.defineProperties(Object.prototype, {
    code: { configurable: true, value: "ER_DUP_ENTRY" },
    sql_mode: { configurable: true, value: "STRICT_TRANS_TABLES" },
  });
  try {
    assert.equal(isDuplicateEntry({}), false);
    assert.equal(isDuplicateEntry({ code: "ER_DUP_ENTRY" }), true);
    let queries = 0;
    const connection = {
      async query() { queries += 1; return [[{}], []]; },
    } as unknown as PoolConnection;
    await assert.rejects(migrateMysqlStore(connection), /sql_mode must include/);
    assert.equal(queries, 1, "schema migration continued after missing own sql_mode");
  } finally {
    if (codeDescriptor === undefined) delete (Object.prototype as Record<string, unknown>).code;
    else Object.defineProperty(Object.prototype, "code", codeDescriptor);
    if (modeDescriptor === undefined) delete (Object.prototype as Record<string, unknown>).sql_mode;
    else Object.defineProperty(Object.prototype, "sql_mode", modeDescriptor);
  }
});
