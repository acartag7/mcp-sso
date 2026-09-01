import assert from "node:assert/strict";
import test from "node:test";
import { headerObservation } from "./parity/observations.ts";
import type { Observation } from "./parity/observations.ts";

const presentObservation = { present: true, value: "value" } satisfies Observation;
const absentObservation = { present: false } satisfies Observation;
// @ts-expect-error absent observations cannot carry a value
const absentWithValue = { present: false, value: "value" } satisfies Observation;
// @ts-expect-error present observations require a value
const presentWithoutValue = { present: true } satisfies Observation;

test("header observations distinguish missing and empty values", () => {
  const headers = { "x-empty": "" };
  assert.deepEqual(headerObservation(headers, "x-missing"), { present: false });
  assert.deepEqual(headerObservation(headers, "x-empty"), { present: true, value: "" });
});

test("header observations preserve scalar and ordered multiple occurrences", () => {
  const headers = { "x-one": "only", "x-many": ["first", "second"] };
  assert.deepEqual(headerObservation(headers, "x-one"), { present: true, value: "only" });
  assert.deepEqual(headerObservation(headers, "x-many"), {
    present: true, value: ["first", "second"],
  });
});

test("header lookup lowercases the requested name", () => {
  assert.deepEqual(headerObservation({ "x-request-id": "value" }, "X-Request-ID"), {
    present: true, value: "value",
  });
});

test("inherited header names are absent", () => {
  const ordinary = {} as Record<string, string | string[]>;
  const inherited = Object.create({ "x-custom": "inherited" }) as Record<string, string | string[]>;
  for (const name of ["constructor", "__proto__", "toString"]) {
    assert.deepEqual(headerObservation(ordinary, name), { present: false }, name);
  }
  assert.deepEqual(headerObservation(inherited, "x-custom"), { present: false });
});

test("own dangerous names and null-prototype maps are observable", () => {
  const headers = Object.create(null) as Record<string, string | string[]>;
  Object.defineProperty(headers, "constructor", { value: "own", enumerable: true });
  Object.defineProperty(headers, "__proto__", {
    value: ["first", "second"], enumerable: true,
  });
  assert.deepEqual(headerObservation(headers, "constructor"), { present: true, value: "own" });
  assert.deepEqual(headerObservation(headers, "__proto__"), {
    present: true, value: ["first", "second"],
  });
  headers["x-null-prototype"] = "works";
  assert.deepEqual(headerObservation(headers, "X-NULL-PROTOTYPE"), {
    present: true, value: "works",
  });
});
