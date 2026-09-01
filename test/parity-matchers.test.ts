import assert from "node:assert/strict";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { matcherMatches } from "./parity/matchers.ts";

test("literal string matchers require an exact string", () => {
  assert.equal(matcherMatches("value", "value"), true);
  assert.equal(matcherMatches("value-suffix", "value"), false);
  assert.equal(matcherMatches(42, "42"), false);
  assert.equal(matcherMatches(null, ""), false);
});

test("equals matchers compare JSON values structurally", () => {
  const cases: Array<[unknown, unknown, boolean]> = [
    [null, null, true],
    [true, true, true],
    [42, 42, true],
    ["value", "value", true],
    [[1, { nested: ["value"] }], [1, { nested: ["value"] }], true],
    [{ first: 1, second: [false, null] }, { first: 1, second: [false, null] }, true],
    [{ first: 1 }, { first: 2 }, false],
    [[1, 2], [2, 1], false],
  ];
  for (const [value, expected, result] of cases) {
    assert.equal(matcherMatches(value, { equals: expected }), result);
  }
});

test("contains matchers search strings, including an empty substring", () => {
  assert.equal(matcherMatches("prefix-value-suffix", { contains: "value" }), true);
  assert.equal(matcherMatches("prefix-value-suffix", { contains: "missing" }), false);
  assert.equal(matcherMatches("", { contains: "" }), true);
  assert.equal(matcherMatches(42, { contains: "" }), false);
});

test("schema matchers compile independent JSON Schema 2020-12 validators", () => {
  const firstSchema = {
    $id: "https://example.test/shared-schema",
    type: "object",
    properties: { value: { type: "string" } },
    required: ["value"],
    additionalProperties: false,
  };
  const secondSchema = {
    $id: "https://example.test/shared-schema",
    type: "object",
    properties: { value: { type: "number" } },
    required: ["value"],
    additionalProperties: false,
  };
  assert.equal(matcherMatches({ value: "text" }, { schema: firstSchema }), true);
  assert.equal(matcherMatches({ value: 7 }, { schema: firstSchema }), false);
  assert.equal(matcherMatches({ value: 7 }, { schema: secondSchema }), true);
  assert.equal(matcherMatches({ value: "text" }, { schema: secondSchema }), false);
});

test("matches uses RE2 search and explicit anchors", () => {
  assert.equal(matcherMatches("prefix-value-suffix", { matches: "value" }), true);
  assert.equal(matcherMatches("prefix-value-suffix", { matches: "^value$" }), false);
  assert.equal(matcherMatches("value", { matches: "^value$" }), true);
});

test("matches uses UTF-8 rune semantics", () => {
  assert.equal(matcherMatches("é", { matches: "^.$" }), true);
  assert.equal(matcherMatches("漢", { matches: "^.$" }), true);
  assert.equal(matcherMatches("😀", { matches: "^.$" }), true);
  assert.equal(matcherMatches("é", { matches: "é" }), true);
  assert.equal(matcherMatches("😀", { matches: "😀" }), true);
  assert.equal(matcherMatches("😀😀", { matches: "^.$" }), false);
  assert.equal(matcherMatches("éé", { matches: "^.$" }), false);
});

test("matches has no implicit flags or case folding", () => {
  assert.equal(matcherMatches("Value", { matches: "value" }), false);
  assert.equal(matcherMatches("a\nb", { matches: "a.b" }), false);
  assert.equal(matcherMatches("a\nb", { matches: "^b$" }), false);
  assert.equal(matcherMatches("abc", { matches: "" }), true);
  assert.equal(matcherMatches(42, { matches: "42" }), false);
});

test("matches rejects patterns outside the RE2 dialect", () => {
  const patterns = ["[", "(?=a)", "(?<=a)", "(?<!a)", "(a)\\1"];
  for (const pattern of patterns) {
    assert.throws(
      () => matcherMatches("a", { matches: pattern }),
      (error: unknown) => {
        assert.ok(error instanceof FixtureRunnerError);
        assert.equal(error.message, `pattern is outside the RE2 dialect: ${pattern}`);
        assert.ok(error.cause instanceof Error);
        return true;
      },
    );
  }
});
