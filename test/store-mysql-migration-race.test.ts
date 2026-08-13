import assert from "node:assert/strict";
import { test } from "node:test";
import type { PoolConnection } from "mysql2/promise";
import { migrateMysqlStore } from "../src/store/mysql-schema.ts";

interface RaceOptions {
  readonly errorCode: string;
  readonly materializes: boolean;
}

const CONSENT_COLUMNS = [
  { COLUMN_NAME: "jti", DATA_TYPE: "varchar", CHARACTER_MAXIMUM_LENGTH: 255, IS_NULLABLE: "NO" },
  { COLUMN_NAME: "expires_at", DATA_TYPE: "varchar", CHARACTER_MAXIMUM_LENGTH: 24, IS_NULLABLE: "NO" },
];

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
      if (sql.includes("information_schema.KEY_COLUMN_USAGE")) return [[], []];
      if (sql.includes("COLUMN_NAME IN ('jti', 'expires_at')")) return [CONSENT_COLUMNS, []];
      if (sql.startsWith("SELECT 1 FROM information_schema.TABLES")) return [[], []];
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
      if (sql.startsWith("SELECT DATA_TYPE AS data_type")) {
        return [[{ data_type: "varchar", max_length: 384, is_nullable: "NO" }], []];
      }
      if (sql.includes("information_schema.STATISTICS")) {
        return [[{ INDEX_NAME: "PRIMARY", NON_UNIQUE: 0, SEQ_IN_INDEX: 1, COLUMN_NAME: "jti", SUB_PART: null }], []];
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
      if (sql.includes("COLUMN_NAME IN ('jti', 'expires_at')")) return [CONSENT_COLUMNS, []];
      if (sql.startsWith("SELECT 1 FROM information_schema.TABLES")) return [[], []];
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
      if (sql.startsWith("SELECT DATA_TYPE AS data_type")) {
        return [[{ data_type: "varchar", max_length: 384, is_nullable: "NO" }], []];
      }
      if (sql.includes("information_schema.STATISTICS")) {
        return [[{ INDEX_NAME: "PRIMARY", NON_UNIQUE: 0, SEQ_IN_INDEX: 1, COLUMN_NAME: "jti", SUB_PART: null }], []];
      }
      if (sql.includes("COLLATION_NAME") || sql.includes("ENGINE")) return [[], []];
      return [[], []];
    },
  } as unknown as PoolConnection;
  await migrateMysqlStore(connection);
  assert.ok(alters.includes("ALTER TABLE oauth_refresh_token_families ADD COLUMN resource VARCHAR(2048) NULL"));
  assert.ok(alters.includes("ALTER TABLE oauth_refresh_tokens ADD COLUMN resource VARCHAR(2048) NULL"));
});

test("MySQL subject migration widens only both deployed VARCHAR(255) columns and is idempotent", async () => {
  const widths = new Map([
    ["oauth_auth_codes", 255],
    ["oauth_refresh_tokens", 255],
  ]);
  const subjectAlters: string[] = [];
  const connection = {
    query: async (sql: string, values?: unknown[]) => {
      if (sql.startsWith("SELECT @@session.sql_mode")) return [[{ sql_mode: "STRICT_TRANS_TABLES" }], []];
      if (sql.includes("COLUMN_NAME IN ('jti', 'expires_at')")) return [CONSENT_COLUMNS, []];
      if (sql.startsWith("SELECT 1 FROM information_schema.COLUMNS")) return [[{ 1: 1 }], []];
      if (sql.startsWith("SELECT DATA_TYPE AS data_type")) {
        return [[{ data_type: "varchar", max_length: widths.get(String(values?.[0])), is_nullable: "NO" }], []];
      }
      if (sql.includes("MODIFY COLUMN subject")) {
        const match = /^ALTER TABLE (oauth_auth_codes|oauth_refresh_tokens) MODIFY COLUMN subject VARCHAR\(384\)/.exec(sql);
        assert.ok(match, `unexpected subject ALTER: ${sql}`);
        subjectAlters.push(sql);
        widths.set(match[1]!, 384);
        return [[], []];
      }
      if (sql.includes("information_schema.STATISTICS")) return [[{
        INDEX_NAME: "PRIMARY", NON_UNIQUE: 0, SEQ_IN_INDEX: 1, COLUMN_NAME: "jti", SUB_PART: null,
      }], []];
      if (sql.includes("COLLATION_NAME") || sql.includes("ENGINE")) return [[], []];
      return [[], []];
    },
  } as unknown as PoolConnection;

  await migrateMysqlStore(connection);
  await migrateMysqlStore(connection);
  assert.equal(subjectAlters.length, 2);
  assert.deepEqual(subjectAlters.map((sql) => sql.split(" ")[2]).sort(), ["oauth_auth_codes", "oauth_refresh_tokens"]);
  assert.ok(subjectAlters.every((sql) => !sql.includes("client_id") && !sql.includes("consent")));
});

test("MySQL subject migration rejects an unexpected undersized shape", async () => {
  let subjectAlters = 0;
  const connection = {
    query: async (sql: string, values?: unknown[]) => {
      if (sql.startsWith("SELECT @@session.sql_mode")) return [[{ sql_mode: "STRICT_TRANS_TABLES" }], []];
      if (sql.includes("COLUMN_NAME IN ('jti', 'expires_at')")) return [CONSENT_COLUMNS, []];
      if (sql.startsWith("SELECT 1 FROM information_schema.COLUMNS")) return [[{ 1: 1 }], []];
      if (sql.startsWith("SELECT DATA_TYPE AS data_type")) {
        return [[{ data_type: "varchar", max_length: values?.[0] === "oauth_auth_codes" ? 255 : 300, is_nullable: "NO" }], []];
      }
      if (sql.includes("MODIFY COLUMN subject")) subjectAlters += 1;
      return [[], []];
    },
  } as unknown as PoolConnection;
  await assert.rejects(migrateMysqlStore(connection), /oauth_refresh_tokens\.subject has unsupported VARCHAR\(300\) width/);
  assert.equal(subjectAlters, 0, "both subject shapes are validated before either ALTER");
});

test("MySQL migration preflights malformed consent uniqueness before any DDL", async () => {
  const writes: string[] = [];
  const connection = {
    query: async (sql: string) => {
      if (sql.startsWith("SELECT @@session.sql_mode")) return [[{ sql_mode: "STRICT_TRANS_TABLES" }], []];
      if (sql.includes("COLUMN_NAME IN ('jti', 'expires_at')")) return [CONSENT_COLUMNS, []];
      if (sql.startsWith("SELECT 1 FROM information_schema.TABLES")) return [[{ 1: 1 }], []];
      if (sql.includes("information_schema.KEY_COLUMN_USAGE")) return [[], []];
      if (sql.includes("information_schema.STATISTICS")) return [[{
        INDEX_NAME: "uq_prefix", NON_UNIQUE: "0", SEQ_IN_INDEX: 1, COLUMN_NAME: "jti", SUB_PART: 1,
      }], []];
      writes.push(sql);
      return [[], []];
    },
  } as unknown as PoolConnection;
  await assert.rejects(migrateMysqlStore(connection), /full-column JTI PRIMARY or UNIQUE index/);
  assert.deepEqual(writes, [], "malformed existing schema rejects before CREATE or ALTER");
});

test("MySQL migration accepts string zero metadata for a full-column JTI key", async () => {
  let statisticsReads = 0;
  const connection = {
    query: async (sql: string) => {
      if (sql.startsWith("SELECT @@session.sql_mode")) return [[{ sql_mode: "STRICT_TRANS_TABLES" }], []];
      if (sql.includes("COLUMN_NAME IN ('jti', 'expires_at')")) return [CONSENT_COLUMNS, []];
      if (sql.startsWith("SELECT 1 FROM information_schema.TABLES")) return [[{ 1: 1 }], []];
      if (sql.includes("information_schema.STATISTICS")) {
        statisticsReads += 1;
        return [[{ INDEX_NAME: "PRIMARY", NON_UNIQUE: "0", SEQ_IN_INDEX: 1, COLUMN_NAME: "jti", SUB_PART: null }], []];
      }
      if (sql.startsWith("SELECT DATA_TYPE AS data_type")) {
        return [[{ data_type: "varchar", max_length: 384, is_nullable: "NO" }], []];
      }
      if (sql.startsWith("SELECT 1 FROM information_schema.COLUMNS")) return [[{ 1: 1 }], []];
      return [[], []];
    },
  } as unknown as PoolConnection;
  await migrateMysqlStore(connection);
  assert.equal(statisticsReads, 2, "existing and post-migration checks both run");
});

test("MySQL uniqueness preflight counts functional parts and normalizes identifier case", async () => {
  const makeConnection = (rows: unknown[]) => ({
    query: async (sql: string) => {
      if (sql.startsWith("SELECT @@session.sql_mode")) return [[{ sql_mode: "STRICT_TRANS_TABLES" }], []];
      if (sql.includes("COLUMN_NAME IN ('jti', 'expires_at')")) return [CONSENT_COLUMNS, []];
      if (sql.startsWith("SELECT 1 FROM information_schema.TABLES")) return [[{ 1: 1 }], []];
      if (sql.includes("information_schema.STATISTICS")) return [rows, []];
      if (sql.startsWith("SELECT DATA_TYPE AS data_type")) {
        return [[{ data_type: "varchar", max_length: 384, is_nullable: "NO" }], []];
      }
      if (sql.startsWith("SELECT 1 FROM information_schema.COLUMNS")) return [[{ 1: 1 }], []];
      return [[], []];
    },
  }) as unknown as PoolConnection;
  await migrateMysqlStore(makeConnection([{
    INDEX_NAME: "PRIMARY", NON_UNIQUE: 0, SEQ_IN_INDEX: 1, COLUMN_NAME: "JTI", SUB_PART: null,
  }]));
  await assert.rejects(migrateMysqlStore(makeConnection([
    { INDEX_NAME: "uq", NON_UNIQUE: 0, SEQ_IN_INDEX: 1, COLUMN_NAME: "jti", SUB_PART: null },
    { INDEX_NAME: "uq", NON_UNIQUE: 0, SEQ_IN_INDEX: 2, COLUMN_NAME: null, SUB_PART: null },
  ])), /full-column JTI PRIMARY or UNIQUE index/);
});

test("MySQL uniqueness preflight rejects an unrelated unique constraint", async () => {
  const connection = {
    query: async (sql: string) => {
      if (sql.startsWith("SELECT @@session.sql_mode")) return [[{ sql_mode: "STRICT_TRANS_TABLES" }], []];
      if (sql.includes("COLUMN_NAME IN ('jti', 'expires_at')")) return [CONSENT_COLUMNS, []];
      if (sql.startsWith("SELECT 1 FROM information_schema.TABLES")) return [[{ 1: 1 }], []];
      if (sql.includes("information_schema.KEY_COLUMN_USAGE")) return [[], []];
      if (sql.includes("information_schema.STATISTICS")) return [[
        { INDEX_NAME: "PRIMARY", NON_UNIQUE: 0, SEQ_IN_INDEX: 1, COLUMN_NAME: "jti", SUB_PART: null },
        { INDEX_NAME: "uq_expiry", NON_UNIQUE: 0, SEQ_IN_INDEX: 1, COLUMN_NAME: "expires_at", SUB_PART: null },
      ], []];
      throw new Error(`unexpected query after malformed-schema preflight: ${sql}`);
    },
  } as unknown as PoolConnection;
  await assert.rejects(migrateMysqlStore(connection), /no competing unique constraint/);
});

test("MySQL uniqueness preflight accepts a secondary index containing the full JTI", async () => {
  const connection = {
    query: async (sql: string) => {
      if (sql.startsWith("SELECT @@session.sql_mode")) return [[{ sql_mode: "STRICT_TRANS_TABLES" }], []];
      if (sql.includes("COLUMN_NAME IN ('jti', 'expires_at')")) return [CONSENT_COLUMNS, []];
      if (sql.startsWith("SELECT 1 FROM information_schema.TABLES")) return [[{ 1: 1 }], []];
      if (sql.includes("information_schema.STATISTICS")) return [[
        { INDEX_NAME: "PRIMARY", NON_UNIQUE: 0, COLUMN_NAME: "jti", SUB_PART: null },
        { INDEX_NAME: "uq_jti_expiry", NON_UNIQUE: 0, COLUMN_NAME: "jti", SUB_PART: null },
        { INDEX_NAME: "uq_jti_expiry", NON_UNIQUE: 0, COLUMN_NAME: "expires_at", SUB_PART: 10 },
      ], []];
      if (sql.startsWith("SELECT DATA_TYPE AS data_type")) {
        return [[{ data_type: "varchar", max_length: 384, is_nullable: "NO" }], []];
      }
      if (sql.startsWith("SELECT 1 FROM information_schema.COLUMNS")) return [[{ 1: 1 }], []];
      return [[], []];
    },
  } as unknown as PoolConnection;
  await migrateMysqlStore(connection);
});

test("MySQL uniqueness preflight rejects undersized consent expiry storage", async () => {
  const connection = {
    query: async (sql: string) => {
      if (sql.startsWith("SELECT @@session.sql_mode")) return [[{ sql_mode: "STRICT_TRANS_TABLES" }], []];
      if (sql.startsWith("SELECT 1 FROM information_schema.TABLES")) return [[{ 1: 1 }], []];
      if (sql.includes("information_schema.KEY_COLUMN_USAGE")) return [[], []];
      if (sql.includes("COLUMN_NAME IN ('jti', 'expires_at')")) return [[
        CONSENT_COLUMNS[0], { ...CONSENT_COLUMNS[1], CHARACTER_MAXIMUM_LENGTH: 1 },
      ], []];
      throw new Error(`unexpected query after malformed consent-column preflight: ${sql}`);
    },
  } as unknown as PoolConnection;
  await assert.rejects(migrateMysqlStore(connection), /expires_at must be a non-null VARCHAR\(24\) or wider/);
});
