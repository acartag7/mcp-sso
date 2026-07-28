import assert from "node:assert/strict";
import { test } from "node:test";
import type { Pool, PoolConnection } from "mysql2/promise";
import { STORED_DCR_GRANT_GENERATION } from "../src/ports/store.ts";
import { MysqlStore } from "../src/store/mysql.ts";

const FUTURE = "2026-07-27T13:00:00.000Z";
const REVOKED = "2026-07-27T12:00:00.000Z";

interface RecordedQuery {
  readonly sql: string;
  readonly values: unknown[] | undefined;
}

function recordingStore(): { readonly store: MysqlStore; readonly queries: RecordedQuery[] } {
  const queries: RecordedQuery[] = [];
  const connection = {
    query: async (sql: string, values?: unknown[]) => {
      queries.push({ sql, values });
      if (sql.startsWith("SELECT grant_generation")) {
        return [[{ grant_generation: STORED_DCR_GRANT_GENERATION }], []];
      }
      return [[], []];
    },
    beginTransaction: async () => {},
    commit: async () => {},
    rollback: async () => {},
    release: () => {}
  } as unknown as PoolConnection;
  const pool = {
    getConnection: async () => connection,
    end: async () => {}
  } as unknown as Pool;
  return { store: new MysqlStore(pool), queries };
}

test("MysqlStore family upserts bind incoming values without row aliases", async () => {
  const created = recordingStore();
  await created.store.saveRefreshToken({
    tokenHash: "a".repeat(64),
    familyId: "family",
    previousTokenHash: null,
    clientId: "client",
    subject: "subject",
    scopes: ["mcp:read"],
    expiresAt: FUTURE
  });
  const createQuery = created.queries.find(({ sql }) =>
    sql.startsWith("INSERT INTO oauth_refresh_token_families")
  );
  assert.ok(createQuery);
  assert.doesNotMatch(createQuery.sql, /VALUES\s*\([^)]*\)\s+AS\s+/iu);
  assert.deepEqual(createQuery.values, ["family", STORED_DCR_GRANT_GENERATION]);
  const tokenQuery = created.queries.find(({ sql }) =>
    sql.startsWith("INSERT INTO oauth_refresh_tokens")
  );
  assert.ok(tokenQuery);
  assert.equal(tokenQuery.values?.at(-1), STORED_DCR_GRANT_GENERATION);

  const revoked = recordingStore();
  await revoked.store.revokeRefreshTokenFamily("family", REVOKED);
  const revokeQuery = revoked.queries.find(({ sql }) =>
    sql.startsWith("INSERT INTO oauth_refresh_token_families")
  );
  assert.ok(revokeQuery);
  assert.doesNotMatch(revokeQuery.sql, /VALUES\s*\([^)]*\)\s+AS\s+/iu);
  assert.deepEqual(revokeQuery.values, ["family", REVOKED, REVOKED]);
});
