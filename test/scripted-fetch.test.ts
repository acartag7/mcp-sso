import assert from "node:assert/strict";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { ScriptedFetch } from "./parity/scripted-fetch.ts";
import type { HttpExchange, ObservedOutbound } from "./parity/types.ts";

const url = "https://client.example/path";
const empty = { status: 200, headers: {}, body: { absent: true } } as const;

function adapter(response: HttpExchange["response"] = empty) {
  const calls: ObservedOutbound[] = [];
  return { calls, fetch: new ScriptedFetch((call) => { calls.push(call); return response; }).fetch };
}

test("observes one normalized WHATWG Request", async () => {
  let reads = 0;
  const tuple = ["X-Fixture", ""] as [string, string];
  Object.defineProperty(tuple, 1, { get() { reads += 1; return "  one\t "; } });
  const first = adapter();
  await first.fetch("https://CLIENT.example:443/a/../path", {
    headers: [tuple, ["x-fixture", "\ttwo  "]],
  });
  assert.equal(reads, 1);
  assert.deepEqual(first.calls, [{ method: "GET", url, headers: { "x-fixture": "one, two" } }]);
  const named = adapter();
  await named.fetch(url, { headers: [
    ["__proto__", "prototype-value"], ["constructor", "constructor-value"],
  ] });
  assert.equal(Object.hasOwn(named.calls[0]!.headers, "__proto__"), true);
  assert.equal(named.calls[0]!.headers.__proto__, "prototype-value");
  assert.equal(named.calls[0]!.headers.constructor, "constructor-value");
  const method = adapter();
  await method.fetch(url, { method: "post", body: "value" });
  assert.equal(method.calls[0]!.method, "POST");
  for (const input of [new URL(url), new Request(url)]) {
    const form = adapter(); await form.fetch(input); assert.equal(form.calls[0]!.url, url);
  }
});

test("observes complete non-GET bytes and omits GET and HEAD bodies", async () => {
  const post = adapter();
  await post.fetch(url, { method: "POST", body: new Uint8Array([0, 1, 255]) });
  assert.deepEqual(post.calls[0]?.body, Buffer.from([0, 1, 255]));
  const emptyPost = adapter();
  await emptyPost.fetch(url, { method: "POST", body: "" });
  assert.ok(Object.hasOwn(emptyPost.calls[0]!, "body"));
  assert.equal(emptyPost.calls[0]?.body?.byteLength, 0);
  for (const method of ["GET", "HEAD"]) {
    const request = adapter();
    await request.fetch(url, { method });
    assert.equal(Object.hasOwn(request.calls[0]!, "body"), false);
  }
});

test("preserves distinct read-only response headers through clone", async () => {
  const headers = Object.fromEntries([
    ["x-fixture", ["one", "two"]], ["set-cookie", ["a=1", "b=2"]],
    ["__proto__", "prototype-value"], ["constructor", "constructor-value"],
  ]) as HttpExchange["response"]["headers"];
  const response = await adapter({ status: 200, headers,
    body: { absent: true } }).fetch(url);
  const expected = [["x-fixture", "one"], ["x-fixture", "two"],
    ["set-cookie", "a=1"], ["set-cookie", "b=2"],
    ["__proto__", "prototype-value"], ["constructor", "constructor-value"]];
  assert.deepEqual([...response.headers], expected);
  assert.deepEqual([...response.headers.keys()], expected.map(([name]) => name));
  assert.deepEqual([...response.headers.values()], expected.map(([, value]) => value));
  assert.deepEqual(response.headers.getSetCookie(), ["a=1", "b=2"]);
  assert.equal(response.headers.has("X-Fixture"), true);
  assert.equal(response.headers.has("missing"), false);
  assert.equal(response.headers.get("constructor"), "constructor-value");
  assert.equal(response.headers.get("missing"), null);
  const visited: Array<[string, string]> = [];
  response.headers.forEach((value, name) => { visited.push([name, value]); });
  assert.deepEqual(visited, expected);
  const exposed = response.headers.entries().next().value!;
  exposed[1] = "changed";
  assert.deepEqual([...response.headers], expected);
  assert.throws(() => response.headers.get("X-Fixture"),
    (error) => error instanceof FixtureRunnerError && error.message === "scripted response header has multiple occurrences");
  for (const mutate of [() => response.headers.append("x", "y"),
    () => response.headers.set("x", "y"), () => response.headers.delete("x")]) {
    assert.throws(mutate, /scripted response headers are read-only/);
  }
  const clone = response.clone();
  assert.deepEqual([...clone.headers], expected);
  assert.throws(() => clone.headers.set("x", "y"), /scripted response headers are read-only/);
  assert.deepEqual([...clone.clone().headers], expected);
});

test("rejects unsafe or non-string scripted headers without echoing values", async () => {
  for (const headers of [
    { "x-fixture": "safe\rmalicious" },
    { "x-fixture": ["safe", "safe\nmalicious"] },
  ]) {
    await assert.rejects(adapter({ status: 200, headers, body: { absent: true } }).fetch(url),
      (error) => error instanceof FixtureRunnerError && error.message === "scripted response header cannot contain CR or LF");
  }
  for (const raw of [{ $capture: { fixture: "source-fixture", name: "token", format: "raw" } }, 42]) {
    const headers = { "x-fixture": raw } as unknown as HttpExchange["response"]["headers"];
    await assert.rejects(adapter({ status: 200, headers, body: { absent: true } }).fetch(url),
      (error) => error instanceof FixtureRunnerError && error.message === "scripted response header contains a capture or non-string value");
  }
});

test("encodes JSON string values and keeps absent bodies absent", async () => {
  const json = await adapter({ status: 418, headers: { "content-type": "application/json" },
    body: { value: "ok" } }).fetch(url);
  assert.equal(json.status, 418);
  assert.equal(await json.text(), '"ok"');
  const absent = await adapter().fetch(url);
  assert.equal(absent.body, null);
  assert.equal(await absent.text(), "");
});

test("uses only the injected consumer", async () => {
  const original = globalThis.fetch;
  let ambientCalls = 0, consumerCalls = 0;
  globalThis.fetch = async () => { ambientCalls += 1; throw new Error("ambient fetch called"); };
  try {
    const scripted = new ScriptedFetch((call) => {
      consumerCalls += 1;
      assert.equal(call.url, url);
      return empty;
    });
    assert.equal((await scripted.fetch(url)).status, 200);
  } finally {
    globalThis.fetch = original;
  }
  assert.equal(consumerCalls, 1);
  assert.equal(ambientCalls, 0);
});
