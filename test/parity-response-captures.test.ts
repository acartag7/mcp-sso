import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { selectResponseCapture } from "./parity/captures.ts";
import { loadFixture } from "./parity/schema-json.ts";
import type { CaptureSpec, ObservedMessage } from "./parity/types.ts";

const FIXTURE_PATH = fileURLToPath(new URL("../fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable.json", import.meta.url));

type Headers = Record<string, string | string[]>;

function response(body: string | Buffer, headers: Headers = {}): ObservedMessage {
  return { status: 200, headers, body: typeof body === "string" ? Buffer.from(body) : body };
}

function bodySource(pointer: string): CaptureSpec["source"] {
  return { bodyPointer: pointer };
}

function querySource(parameter = "token"): CaptureSpec["source"] {
  return { header: "location", urlQuery: parameter };
}

function failure(source: CaptureSpec["source"], observed: ObservedMessage, message?: RegExp): FixtureRunnerError {
  let caught: unknown;
  try { selectResponseCapture(source, observed); }
  catch (error) { caught = error; }
  assert.ok(caught instanceof FixtureRunnerError);
  if (message) assert.match(caught.message, message);
  return caught;
}

test("body captures traverse RFC 6901 objects, escapes, empty names, and arrays", () => {
  const body = JSON.stringify({
    "": "empty-name", "a/b": "slash", "m~n": "tilde", nested: [{ "": "array-empty", value: "array" }],
  });
  const observed = response(body, { "content-type": "application/json" });
  assert.equal(selectResponseCapture(bodySource("/"), observed), "empty-name");
  assert.equal(selectResponseCapture(bodySource("/a~1b"), observed), "slash");
  assert.equal(selectResponseCapture(bodySource("/m~0n"), observed), "tilde");
  assert.equal(selectResponseCapture(bodySource("/nested/0/value"), observed), "array");
  assert.equal(selectResponseCapture(bodySource("/nested/0/"), observed), "array-empty");
  failure(bodySource("/nested/length"), observed, /did not select/);
});

test("body captures reject top-level and nested duplicate JSON members", () => {
  const cases: Array<[string, string]> = [
    ['{"token":"first","token":"second"}', "/token"],
    ['{"outer":{"token":"first","token":"second"}}', "/outer/token"],
    ['{"token":"first","tok\\u0065n":"second"}', "/token"],
    ['{"outer":{"token":"first","tok\\u0065n":"second"}}', "/outer/token"],
  ];
  for (const [body, pointer] of cases) {
    const error = failure(bodySource(pointer), response(body, { "content-type": "application/json" }),
      /^observed application\/json body is invalid$/u);
    assert.ok(error.cause instanceof Error);
    assert.doesNotMatch(error.message, /token|outer/u);
  }
});

test("body captures reject malformed pointers, missing members, and non-string values", () => {
  const values: unknown[] = [{ key: "value" }, ["value"], 42, true, null];
  for (const pointer of ["not-a-pointer", "/key~", "/key~2", "/key~x"]) {
    failure(bodySource(pointer), response('{"key":"value"}', { "content-type": "application/json" }), /JSON Pointer (?:is|escape is) malformed/);
  }
  failure(bodySource("/missing"), response('{"key":"value"}', { "content-type": "application/json" }), /did not select/);
  assert.equal(selectResponseCapture(bodySource(""), response('"root"', {
    "content-type": "application/json",
  })), "root");
  for (const value of values) {
    failure(bodySource(""), response(JSON.stringify(value), {
      "content-type": "application/json",
    }), /capture is not a string/);
    failure(bodySource("/value"), response(JSON.stringify({ value }), {
      "content-type": "application/json",
    }), /capture is not a string/);
  }
  assert.equal(selectResponseCapture(bodySource("/empty"), response('{"empty":""}', {
    "content-type": "application/json",
  })), "");
});

test("the corpus schema and loader admit an empty body pointer", async () => {
  const fixture = structuredClone(await loadFixture(FIXTURE_PATH));
  if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
  fixture.then.captures = [{ name: "root", source: { bodyPointer: "" } }];
  const directory = await mkdtemp(join(tmpdir(), "mcp-sso-response-capture-schema-"));
  try {
    const path = join(directory, "fixture.json");
    await writeFile(path, JSON.stringify(fixture), "utf8");
    const loaded = await loadFixture(path);
    assert.equal(loaded.kind, "fixture");
    assert.deepEqual(loaded.then.captures, fixture.then.captures);
    const invalid = structuredClone(fixture);
    invalid.then.captures = [{ name: "root", source: { bodyPointer: "not-a-pointer" } }];
    const invalidPath = join(directory, "invalid.json");
    await writeFile(invalidPath, JSON.stringify(invalid), "utf8");
    let caught: unknown;
    try { await loadFixture(invalidPath); }
    catch (error) { caught = error; }
    assert.ok(caught instanceof FixtureRunnerError);
    assert.match(caught.message, /schema validation failed/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("body captures require one own scalar application/json Content-Type", () => {
  const body = '{"token":"ok"}';
  for (const headers of [
    {}, { "content-type": "text/plain" },
    { "content-type": ["application/json", "text/plain"] },
  ] as Headers[]) failure(bodySource("/token"), response(body, headers), /Content-Type/);
  const inherited = Object.create({ "content-type": "application/json" }) as Headers;
  failure(bodySource("/token"), response(body, inherited), /Content-Type/);
  for (const boundary of ["\r", "\n", "\f", "\v", "\u00a0", "\ufeff", "\u2000"]) {
    for (const value of [`${boundary}application/json`, `application/json${boundary}`]) {
      failure(bodySource("/token"), response(body, { "content-type": value }), /Content-Type/);
    }
  }
  const accepted = response(body, { "content-type": " \tApplication/JSON\t; charset=utf-8" });
  assert.equal(selectResponseCapture(bodySource("/token"), accepted), "ok");
});

test("body capture rejects absent, malformed, invalid UTF-8, and BOM-prefixed JSON", () => {
  const json = { "content-type": "application/json" };
  failure(bodySource("/token"), response(Buffer.alloc(0), json), /no body/);
  failure(bodySource("/token"), response("{", json), /invalid/);
  failure(bodySource("/token"), response(Buffer.from([0xc3, 0x28]), json), /UTF-8/);
  const bom = Buffer.from([0xef, 0xbb, 0xbf, ...Buffer.from('{"token":"ok"}')]);
  failure(bodySource("/token"), response(bom, json), /invalid/);
});

test("query captures percent-decode Unicode and plus as space, including empty values", () => {
  const observed = response("", {
    location: "https://example.test/callback?other=1&tok%65n=%E2%9C%93+value",
  });
  assert.equal(selectResponseCapture(querySource(), observed), "✓ value");
  assert.equal(selectResponseCapture(querySource(), response("", {
    location: "https://example.test/callback?token=",
  })), "");
});

test("query captures require one own scalar URL header and one exact parameter", () => {
  const source = querySource();
  for (const headers of [
    {}, { location: ["https://example.test/?token=one", "https://example.test/?token=two"] },
    { location: ["https://example.test/?token=one"] },
  ] as Headers[]) failure(source, response("", headers), /header capture/);
  const inherited = Object.create({ location: "https://example.test/?token=one" }) as Headers;
  failure(source, response("", inherited), /header capture/);
  const invalidUrl = failure(source, response("", { location: "not a URL" }),
    /^header capture location is not a URL$/u);
  assert.ok(invalidUrl.cause instanceof Error);
  for (const url of [
    "https://example.test/?other=one", "https://example.test/?token=one&token=two",
    "https://example.test/?TOKEN=wrong", "https://example.test/?tokenized=wrong",
  ]) failure(source, response("", { location: url }), /missing or ambiguous/);
  assert.equal(selectResponseCapture(querySource("a"), response("", {
    location: "https://example.test/?b=unrelated&a=selected",
  })), "selected");
});
