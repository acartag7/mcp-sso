import { fixedClockSnapshot } from "../../src/ports/clock.ts";
import type { ClockPort } from "../../src/ports/clock.ts";
import { FixtureRunnerError } from "./error.ts";

const invalidClock = (fixtureId: string): FixtureRunnerError =>
  new FixtureRunnerError(`${fixtureId}: given.clock is not a canonical UTC timestamp`);
const CANONICAL_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export function fixtureClock(value: unknown, fixtureId: string): ClockPort {
  if (typeof value !== "string" || !CANONICAL_UTC.test(value)) {
    throw invalidClock(fixtureId);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw invalidClock(fixtureId);
  }
  return fixedClockSnapshot(parsed);
}
