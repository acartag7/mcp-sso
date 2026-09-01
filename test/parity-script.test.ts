import assert from "node:assert/strict";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { OrderedFixtureScript } from "./parity/fixture-script.ts";

interface Check {
  input: string;
  result: { allowed: boolean };
}

const NO_EXPECTED_ENTRY = "fixture script call has no expected entry";
const INPUT_MISMATCH = "fixture script call does not match the next entry";
const UNCONSUMED_ENTRIES = "fixture script has unconsumed entries";
const STICKY_FAILURE = "fixture script call accounting previously failed";

const matchesInput = (actual: string, expected: Readonly<Check>): boolean =>
  actual === expected.input;

function script(checks: readonly Check[]): OrderedFixtureScript<Check, string> {
  return new OrderedFixtureScript(checks, matchesInput);
}

function assertRunnerError(run: () => unknown, message: string): FixtureRunnerError {
  let caught: unknown;
  try {
    run();
  } catch (error) {
    caught = error;
  }
  assert.ok(caught instanceof FixtureRunnerError);
  assert.equal(caught.message, message);
  return caught;
}

test("constructor input is snapshotted", () => {
  const checks = [{ input: "first", result: { allowed: true } }];
  const ordered = script(checks);
  checks[0]!.input = "changed";
  checks[0]!.result.allowed = false;

  assert.deepEqual(ordered.consume("first"), {
    input: "first",
    result: { allowed: true },
  });
  ordered.assertConsumed();
});

test("matching calls consume in order and exact exhaustion passes", () => {
  const ordered = script([
    { input: "first", result: { allowed: true } },
    { input: "second", result: { allowed: false } },
  ]);

  assert.equal(ordered.consume("first").result.allowed, true);
  assert.equal(ordered.consume("second").result.allowed, false);
  assert.doesNotThrow(() => ordered.assertConsumed());
});

test("too few calls fail the final assertion", () => {
  const ordered = script([{ input: "first", result: { allowed: true } }]);
  assertRunnerError(() => ordered.assertConsumed(), UNCONSUMED_ENTRIES);
});

test("a call against an empty script fails immediately and remains failed", () => {
  const ordered = script([]);
  assertRunnerError(() => ordered.consume("unexpected"), NO_EXPECTED_ENTRY);
  assertRunnerError(() => ordered.assertConsumed(), STICKY_FAILURE);
});

test("an excess call after exhaustion fails immediately and remains failed", () => {
  const ordered = script([{ input: "first", result: { allowed: true } }]);
  ordered.consume("first");
  assertRunnerError(() => ordered.consume("excess"), NO_EXPECTED_ENTRY);
  assertRunnerError(() => ordered.assertConsumed(), STICKY_FAILURE);
});

test("repeated excess calls remain failed", () => {
  const ordered = script([{ input: "first", result: { allowed: true } }]);
  ordered.consume("first");
  assertRunnerError(() => ordered.consume("excess-one"), NO_EXPECTED_ENTRY);
  assertRunnerError(() => ordered.consume("excess-two"), NO_EXPECTED_ENTRY);
  assertRunnerError(() => ordered.assertConsumed(), STICKY_FAILURE);
});

test("a mismatch fails immediately, does not advance, and remains failed", () => {
  const seen: string[] = [];
  const ordered = new OrderedFixtureScript<Check, string>(
    [{ input: "expected", result: { allowed: true } }],
    (actual, expected) => {
      seen.push(expected.input);
      return actual === expected.input;
    },
  );

  assertRunnerError(() => ordered.consume("wrong"), INPUT_MISMATCH);
  assertRunnerError(() => ordered.consume("still-wrong"), INPUT_MISMATCH);
  assert.deepEqual(seen, ["expected", "expected"]);
  assertRunnerError(() => ordered.assertConsumed(), STICKY_FAILURE);
});

test("a successful retry after a mismatch cannot clear the final failure", () => {
  const ordered = script([{ input: "expected", result: { allowed: true } }]);
  assertRunnerError(() => ordered.consume("wrong"), INPUT_MISMATCH);
  assert.equal(ordered.consume("expected").result.allowed, true);
  assertRunnerError(() => ordered.assertConsumed(), STICKY_FAILURE);
});

test("returned entry mutation cannot alter stored script behavior", () => {
  const shared = { input: "expected", result: { allowed: true } };
  const ordered = script([shared, shared]);
  const returned = ordered.consume("expected");
  returned.input = "changed";
  returned.result.allowed = false;

  assert.deepEqual(ordered.consume("expected"), {
    input: "expected",
    result: { allowed: true },
  });
  ordered.assertConsumed();
});

test("fixed errors do not echo sensitive actual or expected values", () => {
  const actual = "actual-secret-value";
  const expected = "expected-secret-value";
  const mismatched = script([{ input: expected, result: { allowed: false } }]);
  const mismatch = assertRunnerError(() => mismatched.consume(actual), INPUT_MISMATCH);
  const sticky = assertRunnerError(() => mismatched.assertConsumed(), STICKY_FAILURE);
  const empty = assertRunnerError(() => script([]).consume(actual), NO_EXPECTED_ENTRY);
  const throwing = new OrderedFixtureScript<Check, string>(
    [{ input: expected, result: { allowed: false } }],
    (seenActual, seenExpected) => {
      throw new Error(`${seenActual} ${seenExpected.input}`);
    },
  );
  const matcherFailure = assertRunnerError(() => throwing.consume(actual), INPUT_MISMATCH);

  for (const error of [mismatch, sticky, empty, matcherFailure]) {
    assert.equal(error.message.includes(actual), false);
    assert.equal(error.message.includes(expected), false);
  }
});
