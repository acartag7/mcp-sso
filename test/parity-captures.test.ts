import assert from "node:assert/strict";
import test from "node:test";
import { materializeRequest } from "./parity/captures.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import type { CaptureReference, CaptureValues, RequestSpec } from "./parity/types.ts";

const captures: CaptureValues = new Map([
  ["first", new Map([["token", "captured-token"], ["raw", "raw value"],
    ["huge", "é".repeat(40000)], ["ascii", "b".repeat(70000)]])],
]);

function capture(format: CaptureReference["$capture"]["format"], name = "token"): CaptureReference {
  return { $capture: { fixture: "first", name, format } };
}

function request(body: RequestSpec["body"], headers: RequestSpec["headers"] = {}): RequestSpec {
  return { method: "PATCH", path: "/preserve%2Fthis?x=1", headers, body };
}

function failure(run: () => unknown, message?: RegExp): FixtureRunnerError {
  let caught: unknown;
  try { run(); } catch (error) { caught = error; }
  assert.ok(caught instanceof FixtureRunnerError);
  if (message) assert.match(caught.message, message);
  return caught;
}

test("raw and bearer captures preserve scalar and ordered repeated headers", () => {
  const materialized = materializeRequest(request(undefined, {
    authorization: [capture("bearer"), capture("raw", "raw")],
    "x-order": ["first", "second"],
  }), captures);
  assert.equal(materialized.method, "PATCH");
  assert.equal(materialized.path, "/preserve%2Fthis?x=1");
  assert.deepEqual(materialized.headers, [
    ["authorization", "Bearer captured-token"], ["authorization", "raw value"],
    ["x-order", "first"], ["x-order", "second"],
  ]);
  assert.equal(materialized.body, undefined);
});

test("missing and out-of-chain captures fail with a typed error", () => {
  for (const reference of [
    { $capture: { fixture: "first", name: "missing", format: "raw" as const } },
    { $capture: { fixture: "other", name: "token", format: "raw" as const } },
  ]) {
    failure(() => materializeRequest(request(undefined, { "x-token": reference }), captures), /missing or out-of-chain capture/);
  }
  assert.equal(failure(() => materializeRequest(request(undefined, { "x-token": capture("raw") }), new Map())).name,
    "FixtureRunnerError");
});

test("JSON capture replacement recurses and leaves non-exact capture data unchanged", () => {
  const literal = { $capture: "literal" };
  const malformed = { $capture: { fixture: "first", name: "token", format: "other" } };
  const wrongType = { $capture: { fixture: 1, name: "token", format: "raw" } };
  const missingField = { $capture: { fixture: "first", name: "token" } };
  const extra = { $capture: { fixture: "first", name: "token", format: "raw", extra: true } };
  const outerExtra = { $capture: { fixture: "first", name: "token", format: "raw" }, extra: true };
  const materialized = materializeRequest(request({ json: {
    direct: capture("raw"), nested: [capture("raw"), { value: capture("raw", "raw") }],
    literal, malformed, wrongType, missingField, extra, outerExtra, template: "prefix-$capture-suffix",
  } }, { "content-type": "application/json" }), captures);
  assert.deepEqual(JSON.parse(materialized.body!.toString("utf8")), {
    direct: "captured-token", nested: ["captured-token", { value: "raw value" }],
    literal, malformed, wrongType, missingField, extra, outerExtra, template: "prefix-$capture-suffix",
  });
});

test("non-serializable JSON request bodies fail with the typed runner error", () => {
  const error = failure(() => materializeRequest(request({ json: undefined }, {
    "content-type": "application/json",
  }), captures));
  assert.equal(error.name, "FixtureRunnerError");
  assert.equal(error.message, "JSON body value is not JSON-serializable");
});

test("bearer captures are rejected outside an Authorization header", () => {
  const invalidRequests: RequestSpec[] = [
    request(undefined, { "x-token": capture("bearer") }),
    request({ json: { token: capture("bearer") } }, { "content-type": "application/json" }),
    request({ form: [{ name: "token", value: capture("bearer") }] }, {
      "content-type": "application/x-www-form-urlencoded",
    }),
    request({ text: capture("bearer") }, { "content-type": "text/plain" }),
  ];
  for (const invalid of invalidRequests) failure(() => materializeRequest(invalid, captures), /valid only for an Authorization header/);
  failure(() => materializeRequest(request(undefined, { Authorization: capture("bearer") }), captures), /valid only for an Authorization header/);
});

test("resolved and literal request header values reject CR and LF", () => {
  for (const value of ["literal\rvalue", "literal\nvalue"]) {
    failure(() => materializeRequest(request(undefined, { "x-value": value }), captures), /cannot contain CR or LF/);
  }
  const tainted: CaptureValues = new Map([["first", new Map([["line", "captured\rvalue"]])]]);
  failure(() => materializeRequest(request(undefined, { "x-value": capture("raw", "line") }), tainted), /cannot contain CR or LF/);
});

test("JSON and form bodies require exactly one matching Content-Type essence", () => {
  const json = (headers: RequestSpec["headers"]): RequestSpec => request({ json: { ok: true } }, headers);
  for (const headers of [undefined, {}, { "content-type": ["application/json", "text/plain"] }, { "content-type": "text/plain" }] as RequestSpec["headers"][]) {
    failure(() => materializeRequest(json(headers), captures), /JSON body requires Content-Type application\/json/);
  }
  for (const boundary of ["\f", "\v", "\u00a0", "\ufeff"]) {
    failure(() => materializeRequest(json({ "content-type": `${boundary}application/json` }), captures), /JSON body requires Content-Type application\/json/);
    failure(() => materializeRequest(json({ "content-type": `application/json${boundary}` }), captures), /JSON body requires Content-Type application\/json/);
  }
  const acceptedJson = materializeRequest(json({ "content-type": " Application/JSON \t; charset=utf-8" }), captures);
  assert.equal(acceptedJson.body!.toString("utf8"), '{"ok":true}');

  const form = (headers: RequestSpec["headers"]): RequestSpec => request({ form: [{ name: "ok", value: "yes" }] }, headers);
  for (const headers of [undefined, {}, { "content-type": ["application/x-www-form-urlencoded", "text/plain"] }, { "content-type": "text/plain" }] as RequestSpec["headers"][]) {
    failure(() => materializeRequest(form(headers), captures), /form body requires Content-Type application\/x-www-form-urlencoded/);
  }
  for (const boundary of ["\f", "\v", "\u00a0", "\ufeff"]) {
    failure(() => materializeRequest(form({ "content-type": `${boundary}application/x-www-form-urlencoded` }), captures), /form body requires Content-Type application\/x-www-form-urlencoded/);
    failure(() => materializeRequest(form({ "content-type": `application/x-www-form-urlencoded${boundary}` }), captures), /form body requires Content-Type application\/x-www-form-urlencoded/);
  }
  const acceptedForm = materializeRequest(form({ "content-type": "\tAPPLICATION/X-WWW-FORM-URLENCODED ; charset=utf-8" }), captures);
  assert.equal(acceptedForm.body!.toString("utf8"), "ok=yes");
});

test("text requires one stated Content-Type and sends UTF-8 bytes verbatim", () => {
  for (const headers of [undefined, {}, { "content-type": ["text/plain", "application/json"] }] as RequestSpec["headers"][]) {
    failure(() => materializeRequest(request({ text: "{malformed" }, headers), captures), /text body requires one Content-Type occurrence/);
  }
  const materialized = materializeRequest(request({ text: "{malformed" }, {
    "content-type": "application/json",
  }), captures);
  assert.equal(materialized.body!.toString("utf8"), "{malformed");
});

test("form encoding preserves field order and duplicate names", () => {
  const materialized = materializeRequest(request({ form: [
    { name: "item", value: "one" }, { name: "item", value: capture("raw", "raw") },
    { name: "space", value: "hello world" },
  ] }, { "content-type": "application/x-www-form-urlencoded" }), captures);
  assert.equal(materialized.body!.toString("utf8"), "item=one&item=raw+value&space=hello+world");
});

test("an omitted body stays omitted and does not add Content-Type", () => {
  const materialized = materializeRequest({ method: "GET", path: "/no-body" }, captures);
  assert.equal(materialized.body, undefined);
  assert.deepEqual(materialized.headers, []);
});

test("a resolved wire header map above the byte bound is rejected after capture resolution", () => {
  failure(() => materializeRequest(request(undefined, { "x-probe": "é".repeat(33000) }), new Map()),
    /65536 byte bound/u);
  failure(() => materializeRequest(request(undefined, { "x-probe": "b".repeat(70000) }), new Map()),
    /65536 byte bound/u);
  failure(() => materializeRequest(request(undefined, { "x-probe": capture("raw", "huge") }), captures),
    /65536 byte bound/u);
  failure(() => materializeRequest(request(undefined, { "x-probe": capture("raw", "ascii") }), captures),
    /65536 byte bound/u);
});

test("repeated occurrences are counted individually before the byte bound is applied", () => {
  const value = "b".repeat(40000);
  failure(() => materializeRequest(request(undefined, { "x-probe": [value, value] }), new Map()),
    /65536 byte bound/u);
});

test("a wire header map at the byte bound is sent unchanged", () => {
  const name = "x-p";
  const value = "v".repeat(65536 - name.length - 2);
  const materialized = materializeRequest(request(undefined, { [name]: value }), new Map());
  assert.deepEqual(materialized.headers, [[name, value]]);
});