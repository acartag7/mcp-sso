import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { selectBodyResponseCapture } from "./parity/captures.ts";
import { loadFixture } from "./parity/schema-json.ts";
import type { ObservedMessage } from "./parity/types.ts";

const FIXTURE_PATH = fileURLToPath(new URL(
  "../fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable.json",
  import.meta.url,
));

type Headers = Record<string, string | string[]>;

function response(body: string | Buffer, headers: Headers = {}): ObservedMessage {
  return { status: 200, headers, body: typeof body === "string" ? Buffer.from(body) : body };
}

function failure(
  pointer: string, observed: ObservedMessage, message?: RegExp,
): FixtureRunnerError {
  let caught: unknown;
  try { selectBodyResponseCapture(pointer, observed); }
  catch (error) { caught = error; }
  assert.ok(caught instanceof FixtureRunnerError);
  if (message) assert.match(caught.message, message);
  return caught;
}

test("body captures traverse RFC 6901 objects, arrays, and empty names", () => {
  const body = JSON.stringify({
    "": "empty-name", "a/b": "slash", "m~n": "tilde", "~1": "escaped-token",
    nested: [{ "": "array-empty", value: "array" }],
  });
  const observed = response(body, { "content-type": "application/json" });
  assert.equal(selectBodyResponseCapture("/", observed), "empty-name");
  assert.equal(selectBodyResponseCapture("/a~1b", observed), "slash");
  assert.equal(selectBodyResponseCapture("/m~0n", observed), "tilde");
  assert.equal(selectBodyResponseCapture("/~01", observed), "escaped-token");
  assert.equal(selectBodyResponseCapture("/nested/0/value", observed), "array");
  assert.equal(selectBodyResponseCapture("/nested/0/", observed), "array-empty");
  assert.equal(selectBodyResponseCapture("/0", response('["array"]', {
    "content-type": "application/json",
  })), "array");
});

test("body captures reject array pseudo-properties and non-canonical indices", () => {
  const observed = response('["zero", "one"]', { "content-type": "application/json" });
  for (const pointer of ["/length", "/-", "/01", "/1.0", "/2"]) {
    failure(pointer, observed, /JSON Pointer did not select/);
  }
  const object = response('{"01":"object-index", "-":"object-dash"}', {
    "content-type": "application/json",
  });
  assert.equal(selectBodyResponseCapture("/01", object), "object-index");
  assert.equal(selectBodyResponseCapture("/-", object), "object-dash");
});

test("body captures reject malformed pointers, missing members, and non-string values", () => {
  for (const pointer of ["not-a-pointer", "/key~", "/key~2", "/key~x"]) {
    failure(pointer, response('{"key":"value"}', { "content-type": "application/json" }),
      /JSON Pointer (?:is|escape is) malformed/);
  }
  failure("/missing", response('{"key":"value"}', { "content-type": "application/json" }),
    /JSON Pointer did not select/);
  assert.equal(selectBodyResponseCapture("", response('"root"', {
    "content-type": "application/json",
  })), "root");
  for (const value of [{ key: "value" }, ["value"], 42, true, null]) {
    failure("", response(JSON.stringify(value), { "content-type": "application/json" }),
      /JSON Pointer capture is not a string/);
    failure("/value", response(JSON.stringify({ value }), {
      "content-type": "application/json",
    }), /JSON Pointer capture is not a string/);
  }
  assert.equal(selectBodyResponseCapture("/empty", response('{"empty":""}', {
    "content-type": "application/json",
  })), "");
});

test("body captures require one own scalar application/json Content-Type", () => {
  const body = '{"token":"ok"}';
  for (const headers of [
    {}, { "content-type": "text/plain" },
    { "content-type": ["application/json", "text/plain"] },
  ] as Headers[]) failure("/token", response(body, headers), /Content-Type/);
  const inherited = Object.create({ "content-type": "application/json" }) as Headers;
  failure("/token", response(body, inherited), /Content-Type/);
  for (const boundary of [
    "\r", "\n", "\f", "\v", "\u00a0", "\ufeff", "\u1680", "\u2000", "\u2028", "\u3000",
  ]) {
    for (const value of [`${boundary}application/json`, `application/json${boundary}`]) {
      failure("/token", response(body, { "content-type": value }), /Content-Type/);
    }
  }
  const accepted = response(body, { "content-type": " \tApplication/JSON\t; charset=utf-8" });
  assert.equal(selectBodyResponseCapture("/token", accepted), "ok");
});

test("body captures reject absent, malformed, invalid UTF-8, and BOM-prefixed JSON", () => {
  const json = { "content-type": "application/json" };
  failure("/token", response(Buffer.alloc(0), json), /no body/);
  failure("/token", response("{", json), /invalid/);
  failure("/token", response(Buffer.from([0xc3, 0x28]), json), /UTF-8/);
  const bom = Buffer.from([0xef, 0xbb, 0xbf, ...Buffer.from('{"token":"ok"}')]);
  failure("/token", response(bom, json), /invalid/);
});

test("body captures reject top-level, nested, and decoded-equivalent duplicate members", () => {
  const cases: Array<[string, string]> = [
    ['{"token":"first","token":"second"}', "/token"],
    ['{"outer":{"token":"first","token":"second"}}', "/outer/token"],
    ['{"token":"first","tok\\u0065n":"second"}', "/token"],
    ['{"outer":{"token":"first","tok\\u0065n":"second"}}', "/outer/token"],
    ['{"a/b":"first","a\\/b":"second"}', "/a~1b"],
  ];
  for (const [body, pointer] of cases) {
    const error = failure(pointer, response(body, { "content-type": "application/json" }),
      /^observed application\/json body is invalid$/u);
    assert.ok(error.cause instanceof Error);
    assert.doesNotMatch(error.message, /token|outer|a\/b/u);
  }
});

test("the corpus schema admits an empty pointer and rejects a non-slash pointer", async () => {
  const fixture = structuredClone(await loadFixture(FIXTURE_PATH));
  if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
  fixture.then.captures = [{ name: "root", source: { bodyPointer: "" } }];
  const directory = await mkdtemp(join(tmpdir(), "mcp-sso-response-body-capture-schema-"));
  try {
    const path = join(directory, "fixture.json");
    await writeFile(path, JSON.stringify(fixture), "utf8");
    const loaded = await loadFixture(path);
    if (loaded.kind !== "fixture") throw new Error("expected HTTP fixture");
    assert.deepEqual(loaded.then.captures, fixture.then.captures);
    const invalid = structuredClone(fixture);
    const invalidPath = join(directory, "invalid.json");
    for (const pointer of ["not-a-pointer", "\n", "\r", "\u2028"]) {
      invalid.then.captures = [{ name: "root", source: { bodyPointer: pointer } }];
      await writeFile(invalidPath, JSON.stringify(invalid), "utf8");
      await assert.rejects(loadFixture(invalidPath), (error: unknown) => {
        assert.ok(error instanceof FixtureRunnerError);
        assert.match(error.message, /schema validation failed/u);
        return true;
      });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
