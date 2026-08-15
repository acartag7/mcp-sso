import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { test } from "node:test";
import {
  STORE_EXPIRY_SWEEP_INTERVAL_MS, StoreExpiryScheduler,
} from "../src/store/expiry-scheduler.ts";

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

async function settleUntil(done: () => boolean): Promise<void> {
  for (let turn = 0; turn < 100 && !done(); turn++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  assert.equal(done(), true, "scheduled work did not settle");
}
