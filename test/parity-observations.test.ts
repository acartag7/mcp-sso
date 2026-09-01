import assert from "node:assert/strict";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { bodyObservation, headerObservation } from "./parity/observations.ts";
import type { Observation } from "./parity/observations.ts";

const presentObservation = { present: true, value: "value" } satisfies Observation;
const absentObservation = { present: false } satisfies Observation;
// @ts-expect-error absent observations cannot carry a value
const absentWithValue = { present: false, value: "value" } satisfies Observation;
// @ts-expect-error present observations require a value
const presentWithoutValue = { present: true } satisfies Observation;
const UTF8_BOM = Buffer.from([0xef, 0xbb, 0xbf]);

function bomPrefixed(body: string): Buffer {
  return Buffer.concat([UTF8_BOM, Buffer.from(body, "utf8")]);
}

const JAVASCRIPT_TRIM_ONLY_BOUNDARIES = [
  "\n", "\r", "\f", "\v", "\u00a0", "\ufeff", "\u1680", "\u2000", "\u2001",
  "\u2002", "\u2003", "\u2004", "\u2005", "\u2006", "\u2007", "\u2008", "\u2009", "\u200a",
  "\u2028", "\u2029", "\u202f", "\u205f", "\u3000",
];

test("header observations distinguish missing and empty values", () => {
  const headers = { "x-empty": "", "x-many": ["first", "second"] };
  assert.deepEqual(headerObservation(headers, "x-missing"), { present: false });
  assert.deepEqual(headerObservation(headers, "x-empty"), { present: true, value: "" });
  assert.deepEqual(headerObservation(headers, "X-MANY"), {
    present: true, value: ["first", "second"],
  });
});

test("body observations treat undefined and zero bytes as absent", () => {
  assert.deepEqual(bodyObservation(undefined, {}), { present: false });
  assert.deepEqual(bodyObservation(Buffer.alloc(0), {}), { present: false });
});

test("valid non-JSON bodies are UTF-8 text, including an empty JSON string", () => {
  assert.deepEqual(bodyObservation(Buffer.from("héllo", "utf8"), { "content-type": "text/plain" }), {
    present: true, value: "héllo",
  });
  assert.deepEqual(bodyObservation(Buffer.from("\"\"", "utf8"), { "content-type": "text/plain" }), {
    present: true, value: "\"\"",
  });
});

test("JSON-looking bytes stay text without the exact application/json essence", () => {
  const body = Buffer.from("{\"key\":1}", "utf8");
  const headersList: Array<Record<string, string | string[]>> = [{}, { "content-type": "application/problem+json" }];
  for (const headers of headersList) {
    assert.deepEqual(bodyObservation(body, headers), { present: true, value: "{\"key\":1}" });
  }
});

test("application/json accepts leading and trailing SP and HTAB, including before a parameter", () => {
  const body = Buffer.from("{\"key\":1}", "utf8");
  const contentTypes = [
    " application/json ", "\tapplication/json\t", " \tapplication/json\t ; charset=utf-8",
  ];
  for (const contentType of contentTypes) {
    assert.deepEqual(bodyObservation(body, { "content-type": contentType }), {
      present: true, value: { key: 1 },
    });
  }
});

test("JavaScript-trim-only boundaries remain non-JSON content-type text", () => {
  const body = Buffer.from("{\"key\":1}", "utf8");
  for (const boundary of JAVASCRIPT_TRIM_ONLY_BOUNDARIES) {
    for (const contentType of [`${boundary}application/json`, `application/json${boundary}`]) {
      assert.deepEqual(bodyObservation(body, { "content-type": contentType }), {
        present: true, value: "{\"key\":1}",
      }, `boundary U+${boundary.codePointAt(0)!.toString(16).padStart(4, "0")}`);
    }
  }
});

test("non-JSON body observations preserve a leading UTF-8 BOM", () => {
  assert.deepEqual(bodyObservation(bomPrefixed("body"), { "content-type": "text/plain" }), {
    present: true, value: "\ufeffbody",
  });
});

test("a BOM-prefixed application/json body remains invalid with an Error cause", () => {
  assert.throws(
    () => bodyObservation(bomPrefixed("{\"key\":1}"), { "content-type": "application/json" }),
    (error: unknown) => {
      assert.ok(error instanceof FixtureRunnerError);
      assert.equal(error.message, "observed application/json body is invalid");
      assert.ok(error.cause instanceof Error);
      return true;
    },
  );
});

test("application/json essence parsing handles case, whitespace, parameters, objects, and primitives", () => {
  const cases: Array<[string, string, unknown]> = [
    ["APPLICATION/JSON", "{\"key\":\"value\"}", { key: "value" }],
    [" application/json ; charset=utf-8 ", "true", true],
    ["application/json;charset=utf-8", "42", 42],
    ["application/json; profile=example", "null", null],
    ["application/json", "\"\"", ""],
  ];
  for (const [contentType, body, expected] of cases) {
    assert.deepEqual(bodyObservation(Buffer.from(body, "utf8"), { "content-type": contentType }), {
      present: true, value: expected,
    });
  }
});

test("malformed application/json reports a FixtureRunnerError with an Error cause", () => {
  assert.throws(
    () => bodyObservation(Buffer.from("{", "utf8"), { "content-type": "application/json; charset=utf-8" }),
    (error: unknown) => {
      assert.ok(error instanceof FixtureRunnerError);
      assert.equal(error.message, "observed application/json body is invalid");
      assert.ok(error.cause instanceof Error);
      return true;
    },
  );
});

test("invalid UTF-8 reports a FixtureRunnerError with an Error cause for JSON and text", () => {
  for (const contentType of ["application/json", "text/plain"]) {
    assert.throws(
      () => bodyObservation(Buffer.from([0xc3, 0x28]), { "content-type": contentType }),
      (error: unknown) => {
        assert.ok(error instanceof FixtureRunnerError);
        assert.equal(error.message, "observed body is not valid UTF-8");
        assert.ok(error.cause instanceof Error);
        return true;
      },
    );
  }
});

test("repeated Content-Type occurrences stay ambiguous instead of being selected", () => {
  const headers = { "content-type": ["application/json", "text/plain"] };
  assert.deepEqual(headerObservation(headers, "content-type"), {
    present: true, value: ["application/json", "text/plain"],
  });
  assert.deepEqual(bodyObservation(Buffer.from("{\"key\":1}", "utf8"), headers), {
    present: true, value: "{\"key\":1}",
  });
});
