import assert from "node:assert/strict";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { ScriptedRateLimit } from "./parity/scripted-rate-limit.ts";
import type { RateLimitCheck } from "./parity/types.ts";

const mismatch = "fixture script call does not match the next entry";
const unconsumed = "fixture script has unconsumed entries";
const sticky = "fixture script call accounting previously failed";

function isRunnerError(error: unknown, message: string): boolean {
  assert(error instanceof FixtureRunnerError);
  assert.equal(error.message, message);
  return true;
}

function check(key: string, outcome: RateLimitCheck["outcome"]): RateLimitCheck {
  return { key, outcome };
}

test("matches keys exactly, including case, whitespace, and Unicode spelling", async () => {
  const cases = [
    ["register:192.0.2.1", "Register:192.0.2.1"],
    ["register:192.0.2.1", "register:192.0.2.1 "],
    ["authorize:café", "authorize:café"],
  ] as const;
  for (const [expected, actual] of cases) {
    const limiter = new ScriptedRateLimit([check(expected, "allow")]);
    await assert.rejects(() => limiter.check(actual), (error: unknown) =>
      isRunnerError(error, mismatch));
    assert.throws(() => limiter.assertConsumed(), (error: unknown) => isRunnerError(error, sticky));
  }
});

test("returns allow and deny outcomes in declared order", async () => {
  const limiter = new ScriptedRateLimit([
    check("register:one", "allow"), check("register:two", "deny"),
  ]);
  assert.equal(await limiter.check("register:one"), true);
  assert.equal(await limiter.check("register:two"), false);
  limiter.assertConsumed();
});

test("throws the exact declared message as a plain Error", async () => {
  const message = "fixture-authored limiter unavailable";
  const limiter = new ScriptedRateLimit([check("register:one", { throws: message })]);
  await assert.rejects(() => limiter.check("register:one"), (error: unknown) => {
    assert(error instanceof Error);
    assert(!(error instanceof FixtureRunnerError));
    assert.equal(error.constructor, Error);
    assert.equal(error.message, message);
    return true;
  });
  limiter.assertConsumed();
});

test("fixed key mismatch errors never echo either key", async () => {
  const expected = "expected-secret-key";
  const actual = "actual-secret-key";
  const limiter = new ScriptedRateLimit([check(expected, "deny")]);
  let caught: unknown;
  try {
    await limiter.check(actual);
  } catch (error) {
    caught = error;
  }
  assert(caught instanceof FixtureRunnerError);
  assert.equal(caught.message, mismatch);
  assert.equal(caught.message.includes(expected), false);
  assert.equal(caught.message.includes(actual), false);
});

test("a successful retry cannot clear failed final accounting", async () => {
  const limiter = new ScriptedRateLimit([check("expected", "allow")]);
  await assert.rejects(() => limiter.check("wrong"), (error: unknown) => isRunnerError(error, mismatch));
  assert.equal(await limiter.check("expected"), true);
  assert.throws(() => limiter.assertConsumed(), (error: unknown) => isRunnerError(error, sticky));
});

test("constructor input is snapshotted through the port", async () => {
  const checks = [check("register:one", "allow")];
  const limiter = new ScriptedRateLimit(checks);
  checks[0]!.key = "changed";
  checks[0]!.outcome = "deny";
  assert.equal(await limiter.check("register:one"), true);
  limiter.assertConsumed();
});

test("assertConsumed delegates and rejects an unconsumed check", () => {
  const limiter = new ScriptedRateLimit([check("register:one", "allow")]);
  assert.throws(() => limiter.assertConsumed(), (error: unknown) => isRunnerError(error, unconsumed));
});
