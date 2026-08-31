import assert from "node:assert/strict";
import { RE2JS } from "re2js";
import type { Matcher } from "./types.ts";
import { compileJsonSchema } from "./schema.ts";
import { FixtureRunnerError } from "./error.ts";

export interface Observation { present: boolean; value?: unknown }

export function headerObservation(
  headers: Record<string, string | string[]>, name: string,
): Observation {
  const value = headers[name.toLowerCase()];
  return value === undefined ? { present: false } : { present: true, value };
}

export function bodyObservation(
  body: Buffer | undefined, headers: Record<string, string | string[]>,
): Observation {
  if (body === undefined || body.byteLength === 0) return { present: false };
  const text = decodeUtf8(body);
  const contentType = headers["content-type"];
  const single = typeof contentType === "string" ? contentType : undefined;
  if (single?.split(";", 1)[0]?.trim().toLowerCase() === "application/json") {
    try { return { present: true, value: JSON.parse(text) }; }
    catch (error) { throw new FixtureRunnerError("observed application/json body is invalid", { cause: error }); }
  }
  return { present: true, value: text };
}

export function assertMatcher(observed: Observation, matcher: Matcher, label: string): void {
  if (isAbsent(matcher)) {
    assert.equal(observed.present, false, `${label} must be absent`);
    return;
  }
  assert.equal(observed.present, true, `${label} must be present`);
  if (!matcherMatches(observed.value, matcher)) {
    assert.fail(`${label} did not match ${JSON.stringify(matcher)}; observed ${JSON.stringify(observed.value)}`);
  }
}

export function matcherMatches(value: unknown, matcher: Exclude<Matcher, { absent: true }>): boolean {
  if (typeof matcher === "string") return value === matcher;
  if ("equals" in matcher) return deepEqual(value, matcher.equals);
  if ("contains" in matcher) return typeof value === "string" && value.includes(matcher.contains);
  if ("matches" in matcher) {
    if (typeof value !== "string") return false;
    try { return RE2JS.compile(matcher.matches).test(new TextEncoder().encode(value)); }
    catch (error) { throw new FixtureRunnerError(`pattern is outside the RE2 dialect: ${matcher.matches}`, { cause: error }); }
  }
  const validate = compileJsonSchema(matcher.schema);
  return validate(value) as boolean;
}

export function observationMatches(observed: Observation, matcher: Matcher): boolean {
  if (isAbsent(matcher)) return !observed.present;
  return observed.present && matcherMatches(observed.value, matcher);
}

export function assertExactHeaders(
  observed: Record<string, string | string[]>, expected: Record<string, Exclude<Matcher, { absent: true }>>,
  label: string,
): void {
  assert.deepEqual(Object.keys(observed).toSorted(), Object.keys(expected).toSorted(), `${label} header-name set`);
  for (const [name, matcher] of Object.entries(expected)) {
    assertMatcher(headerObservation(observed, name), matcher, `${label} header ${name}`);
  }
}

export function partialSelectorMatches(value: Record<string, unknown>, selector: Record<string, unknown>): boolean {
  return Object.entries(selector).every(([key, expected]) => deepEqual(value[key], expected));
}

function isAbsent(matcher: Matcher): matcher is { absent: true } {
  return typeof matcher === "object" && matcher !== null && "absent" in matcher;
}

function deepEqual(left: unknown, right: unknown): boolean {
  try { assert.deepStrictEqual(left, right); return true; }
  catch { return false; }
}

function decodeUtf8(body: Buffer): string {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(body); }
  catch (error) { throw new FixtureRunnerError("observed body is not valid UTF-8", { cause: error }); }
}
