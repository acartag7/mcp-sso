import assert from "node:assert/strict";
import { RE2JS } from "re2js";
import { compileJsonSchema } from "./schema-json.ts";
import { FixtureRunnerError } from "./error.ts";
import type { Matcher } from "./types.ts";

export function matcherMatches(value: unknown, matcher: Exclude<Matcher, { absent: true }>): boolean {
  if (typeof matcher === "string") return value === matcher;
  if ("equals" in matcher) return deepEqual(value, matcher.equals);
  if ("contains" in matcher) return typeof value === "string" && value.includes(matcher.contains!);
  if ("matches" in matcher) {
    if (typeof value !== "string") return false;
    try {
      return RE2JS.compile(matcher.matches!).test(new TextEncoder().encode(value));
    } catch (error) {
      throw new FixtureRunnerError(`pattern is outside the RE2 dialect: ${matcher.matches}`, { cause: error });
    }
  }
  const validate = compileJsonSchema(matcher.schema);
  return validate(value) as boolean;
}

export function partialSelectorMatches(
  value: object,
  selector: Readonly<Record<string, unknown>>,
): boolean {
  return Object.entries(selector).every(([key, expected]) =>
    Object.hasOwn(value, key)
      && deepEqual((value as Readonly<Record<string, unknown>>)[key], expected));
}

function deepEqual(left: unknown, right: unknown): boolean {
  try {
    assert.deepStrictEqual(left, right);
    return true;
  } catch {
    return false;
  }
}
