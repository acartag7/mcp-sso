import assert from "node:assert/strict";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { encodeResponseBody } from "./parity/response-body.ts";
import type { BodyValue } from "./parity/types.ts";

type Headers = Record<string, string | string[]>;

function bytes(body: BodyValue, headers: Headers = {}): string {
  return encodeResponseBody(body, headers).toString("utf8");
}

function expectEncodingError(body: BodyValue, headers: Headers): FixtureRunnerError {
  let caught: unknown;
  try { encodeResponseBody(body, headers); }
  catch (error) { caught = error; }
  assert.ok(caught instanceof FixtureRunnerError);
  assert.equal(caught.message, "response body value is not JSON-serializable");
  return caught;
}

test("absent response bodies encode to zero bytes", () => {
  const encoded = encodeResponseBody({ absent: true }, { "content-type": "application/json" });
  assert.equal(encoded.byteLength, 0);
  assert.deepEqual(encoded, Buffer.alloc(0));
});

test("application/json JSON-serializes every value, including strings", () => {
  const values: unknown[] = [null, true, 42, { kind: "object" }, ["array"], "", "ok"];
  for (const value of values) {
    assert.equal(bytes({ value }, { "content-type": "Application/JSON" }), JSON.stringify(value));
  }
});

test("application/json accepts parameters, case, one occurrence, and HTTP OWS", () => {
  const headersList: Headers[] = [
    { "content-type": "application/json; charset=utf-8" },
    { "content-type": " application/json\t; charset=utf-8" },
    { "content-type": ["application/json"] },
  ];
  for (const headers of headersList) assert.equal(bytes({ value: "ok" }, headers), '"ok"');
});

test("non-JSON, missing, and problem+json bodies preserve string bytes", () => {
  const headersList: Headers[] = [{}, { "content-type": "text/plain" }, { "content-type": "application/problem+json" }];
  for (const headers of headersList) assert.equal(bytes({ value: "ok" }, headers), "ok");
});

test("non-JSON values use JSON serialization", () => {
  assert.equal(bytes({ value: { ok: true } }, { "content-type": "text/plain" }), '{"ok":true}');
  assert.equal(bytes({ value: ["ok"] }), '["ok"]');
});

test("duplicate or inherited Content-Type occurrences are not selected", () => {
  assert.equal(bytes({ value: "ok" }, { "content-type": ["application/json", "text/plain"] }), "ok");
  const inherited = Object.create({ "content-type": "application/json" }) as Headers;
  assert.equal(bytes({ value: "ok" }, inherited), "ok");
  assert.equal(bytes({ value: "ok" }, { "content-type": "application/json" }), '"ok"');
});

test("JavaScript-trim-only characters around the essence stay non-JSON", () => {
  for (const boundary of ["\r", "\n", "\f", "\v", "\u00a0", "\ufeff", "\u2000", "\u2028", "\u3000"]) {
    for (const essence of [`${boundary}application/json`, `application/json${boundary}`]) {
      assert.equal(bytes({ value: "ok" }, { "content-type": `${essence}; charset=utf-8` }), "ok");
    }
  }
  assert.equal(bytes({ value: "ok" }, { "content-type": "application/json \t; charset=utf-8" }), '"ok"');
});

test("undefined response values fail with the fixture runner error", () => {
  const error = expectEncodingError({ value: undefined }, { "content-type": "application/json" });
  assert.equal(error.name, "FixtureRunnerError");
});
