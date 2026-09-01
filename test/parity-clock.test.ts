import assert from "node:assert/strict";
import test from "node:test";
import { fixtureClock } from "./parity/clock.ts";
import { FixtureRunnerError } from "./parity/error.ts";

const ERROR = "given.clock is not a canonical UTC timestamp";

function assertInvalid(value: unknown, fixtureId = "fixture-clock"): void {
  assert.throws(
    () => fixtureClock(value, fixtureId),
    (error: unknown) => error instanceof FixtureRunnerError
      && error.message === `${fixtureId}: ${ERROR}`,
  );
}

test("materializes canonical UTC timestamps", () => {
  for (const value of [
    "0000-01-01T00:00:00.000Z",
    "1970-01-01T00:00:00.000Z",
    "9999-12-31T23:59:59.999Z",
    "2024-02-29T23:59:59.123Z",
  ]) {
    const clock = fixtureClock(value, "canonical");
    assert.equal(clock.nowMs(), Date.parse(value));
  }
});

test("captures one stable clock value", () => {
  const clock = fixtureClock("2024-02-29T23:59:59.123Z", "stable");
  const expected = clock.nowMs();
  const originalNow = Date.now;
  const originalParse = Date.parse;
  try {
    Date.now = () => expected + 1;
    Date.parse = () => expected + 2;
    assert.equal(clock.nowMs(), expected);
    assert.equal(clock.nowMs(), expected);
  } finally {
    Date.now = originalNow;
    Date.parse = originalParse;
  }
});

test("rejects non-string values", () => {
  for (const value of [undefined, null, 0, {}, [], new String("2024-01-01T00:00:00.000Z")]) {
    assertInvalid(value);
  }
});

test("rejects impossible dates and month rollovers", () => {
  for (const value of [
    "2024-02-30T00:00:00.000Z",
    "2023-02-29T00:00:00.000Z",
    "2024-04-31T00:00:00.000Z",
    "2024-01-32T00:00:00.000Z",
    "2024-00-01T00:00:00.000Z",
    "2024-13-01T00:00:00.000Z",
    "2024-02-29T24:00:00.000Z",
    "2024-02-29T12:60:00.000Z",
    "2024-02-29T12:00:60.000Z",
  ]) {
    assertInvalid(value);
  }
});

test("rejects offsets, fractional variants, lowercase z, and whitespace", () => {
  for (const value of [
    "2024-02-29T00:00:00.000+00:00",
    "2024-02-29T00:00:00.000+01:00",
    "2024-02-29T00:00:00.000-05:00",
    "2024-02-29T00:00:00Z",
    "2024-02-29T00:00:00.1Z",
    "2024-02-29T00:00:00.12Z",
    "2024-02-29T00:00:00.1234Z",
    "2024-02-29T00:00:00.123z",
    " 2024-02-29T00:00:00.123Z",
    "2024-02-29T00:00:00.123Z ",
  ]) {
    assertInvalid(value);
  }
});

test("rejects six-digit years outside the fixture grammar", () => {
  assertInvalid("+275760-09-13T00:00:00.001Z");
  assertInvalid("999999-12-31T23:59:59.999Z");
});
