import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import type { Pool, PoolConnection } from "mysql2/promise";
import {
  STORE_EXPIRY_SWEEP_INTERVAL_MS, StoreExpiryScheduler,
} from "../src/store/expiry-scheduler.ts";
import { MysqlStore } from "../src/store/mysql.ts";
import { migrateSqliteStore } from "../src/store/sqlite-schema.ts";
import { SqliteStore } from "../src/store/sqlite.ts";

const execFileP = promisify(execFile);
const START = Date.parse("2026-08-16T12:00:00.000Z");

test("expiry scheduler snapshots system time and never overlaps runs", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: START });
  let releaseFirst: (() => void) | undefined;
  const firstBlocked = new Promise<void>((resolve) => { releaseFirst = resolve; });
  const seen: string[] = [];
  const scheduler = new StoreExpiryScheduler({
    async sweepExpired(nowIso) {
      seen.push(nowIso);
      if (seen.length === 1) await firstBlocked;
    },
  });

  t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS);
  await settleUntil(() => seen.length === 1);
  assert.deepEqual(seen, ["2026-08-16T12:05:00.000Z"]);
  t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS * 3);
  assert.equal(seen.length, 1, "an active sweep must not overlap itself");

  releaseFirst?.();
  await new Promise<void>((resolve) => setImmediate(resolve));
  t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS);
  await settleUntil(() => seen.length === 2);
  assert.equal(seen[1], "2026-08-16T12:25:00.000Z");
  await scheduler.stop();
});

test("expiry scheduler reports a fixed failure and retries at the next interval", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: START });
  const messages: unknown[][] = [];
  t.mock.method(console, "error", (...args: unknown[]) => { messages.push(args); });
  let calls = 0;
  const scheduler = new StoreExpiryScheduler({
    async sweepExpired() {
      calls += 1;
      if (calls === 1) throw new Error("private database path and connection string");
    },
  });

  t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS);
  await settleUntil(() => messages.length === 1);
  assert.deepEqual(messages, [["[mcp-sso] store expiry sweep failed"]]);
  t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS);
  await settleUntil(() => calls === 2);
  assert.equal(messages.length, 1);
  await scheduler.stop();
});

test("a throwing stderr sink cannot stop expiry retry", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: START });
  t.mock.method(console, "error", () => { throw new Error("stderr unavailable"); });
  let calls = 0;
  const scheduler = new StoreExpiryScheduler({
    async sweepExpired() { calls += 1; if (calls === 1) throw new Error("store failed"); },
  });

  t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS);
  await settleUntil(() => calls === 1);
  t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS);
  await settleUntil(() => calls === 2);
  await scheduler.stop();
});

test("an unref'd store scheduler does not keep an idle process alive", async () => {
  const memoryUrl = new URL("../src/store/memory.ts", import.meta.url).href;
  await execFileP(process.execPath, [
    "--input-type=module", "--eval",
    `import { MemoryStore } from ${JSON.stringify(memoryUrl)}; new MemoryStore();`,
  ], { timeout: 2_000 });
});

test("SqliteStore waits for an explicit post-migration readiness declaration", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: START });
  const unready = new SqliteStore(new DatabaseSync(":memory:"));
  let unreadySweeps = 0;
  unready.sweepExpired = async () => { unreadySweeps += 1; };
  t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS * 2);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(unreadySweeps, 0, "the default constructor must not schedule against an unready schema");
  await unready.close();

  const readyDb = new DatabaseSync(":memory:");
  migrateSqliteStore(readyDb);
  const ready = new SqliteStore(readyDb, { schemaReady: true });
  let readySweeps = 0;
  ready.sweepExpired = async () => { readySweeps += 1; };
  t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS);
  await settleUntil(() => readySweeps === 1);
  await ready.close();
});

test("MysqlStore does not schedule expiry deletion before migration succeeds", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: START });
  let releaseMigration: (() => void) | undefined;
  const migrationBlocked = new Promise<void>((resolve) => { releaseMigration = resolve; });
  let getConnectionCalls = 0;
  const connection = {
    async query() {
      await migrationBlocked;
      throw new Error("migration failed");
    },
    release() {},
  } as unknown as PoolConnection;
  const pool = {
    async getConnection() {
      getConnectionCalls += 1;
      return connection;
    },
  } as unknown as Pool;
  const store = new MysqlStore(pool);
  const migration = store.migrate();
  await settleUntil(() => getConnectionCalls === 1);

  t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS * 2);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(getConnectionCalls, 1, "a pending migration must not race a scheduled sweep");

  releaseMigration?.();
  await assert.rejects(migration, /migration failed/);
  t.mock.timers.tick(STORE_EXPIRY_SWEEP_INTERVAL_MS * 2);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(getConnectionCalls, 1, "a failed migration must not leave a scheduler running");
  await store.close();
});

async function settleUntil(done: () => boolean): Promise<void> {
  for (let turn = 0; turn < 100 && !done(); turn++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  assert.equal(done(), true, "scheduled work did not settle");
}
