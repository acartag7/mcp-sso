import assert from "node:assert/strict";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { HttpExchangeRegistry } from "./parity/http-exchange-registry.ts";
import type { HttpExchange, Matcher, ObservedOutbound } from "./parity/types.ts";

const unmatched = "outbound call did not match a declared HTTP exchange";
const unconsumed = "not all declared HTTP exchanges were consumed";

function exchange(
  method: string, url: string, body: Matcher = { absent: true },
  headers: Record<string, Matcher> = {}, marker = url,
): HttpExchange {
  return {
    request: { method, url, headers, body },
    response: { status: 200, headers: {}, body: { value: { marker } } },
  };
}

function call(
  method: string, url: string, body?: Buffer,
  headers: Record<string, string | string[]> = {},
): ObservedOutbound {
  return { method, url, headers, ...(body === undefined ? {} : { body }) };
}

function fixtureError(action: () => unknown, message: string): FixtureRunnerError {
  let caught: unknown;
  try { action(); }
  catch (error) { caught = error; }
  assert.ok(caught instanceof FixtureRunnerError);
  assert.equal(caught.message, message);
  return caught;
}

test("matches unused exchanges without declaration-order coupling", () => {
  const registry = new HttpExchangeRegistry([
    exchange("POST", "https://id.example/token", "first", {}, "one"),
    exchange("POST", "https://id.example/token", "second", {}, "two"),
  ]);
  assert.deepEqual(registry.consume(call("POST", "https://id.example/token", Buffer.from("second"))).body,
    { value: { marker: "two" } });
  assert.deepEqual(registry.consume(call("POST", "https://id.example/token", Buffer.from("first"))).body,
    { value: { marker: "one" } });
  registry.assertAllConsumed();
});

test("consumes duplicate declarations once each and rejects excess calls", () => {
  const registry = new HttpExchangeRegistry([
    exchange("GET", "https://id.example/jwks"),
    exchange("GET", "https://id.example/jwks"),
  ]);
  registry.consume(call("GET", "https://id.example/jwks"));
  registry.consume(call("GET", "https://id.example/jwks"));
  fixtureError(() => registry.consume(call("GET", "https://id.example/jwks")), unmatched);
  fixtureError(() => registry.assertAllConsumed(), unmatched);
});

test("requires exact method, URL, declared headers, and body presence", () => {
  const cases: Array<[HttpExchange, ObservedOutbound]> = [
    [exchange("POST", "https://id.example/token"), call("post", "https://id.example/token")],
    [exchange("POST", "https://id.example/token"), call("POST", "https://id.example/token/")],
    [exchange("POST", "https://id.example/token", { absent: true }, { authorization: "Bearer good" }),
      call("POST", "https://id.example/token", undefined, { authorization: "Bearer bad" })],
    [exchange("POST", "https://id.example/token", { equals: undefined }),
      call("POST", "https://id.example/token")],
    [exchange("POST", "https://id.example/token", { absent: true }, { missing: { equals: undefined } }),
      call("POST", "https://id.example/token")],
    [exchange("POST", "https://id.example/token", { absent: true }, { forbidden: { absent: true } }),
      call("POST", "https://id.example/token", undefined, { forbidden: "present" })],
    [exchange("POST", "https://id.example/token", { absent: true }),
      call("POST", "https://id.example/token", Buffer.from("present"))],
  ];
  for (const [declaration, observed] of cases) {
    fixtureError(() => new HttpExchangeRegistry([declaration]).consume(observed), unmatched);
  }
});

test("treats declared headers as partial and preserves repeated-value order", () => {
  const registry = new HttpExchangeRegistry([exchange(
    "GET", "https://id.example/metadata", { absent: true },
    { "x-repeat": { equals: ["one", "two"] }, missing: { absent: true } },
  )]);
  registry.consume(call("GET", "https://id.example/metadata", undefined,
    { "x-repeat": ["one", "two"], extra: "allowed" }));
  registry.assertAllConsumed();
});

test("uses the landed body observations for absent and JSON bodies", () => {
  const registry = new HttpExchangeRegistry([
    exchange("POST", "https://id.example/empty"),
    exchange("POST", "https://id.example/json", { equals: { grant_type: "authorization_code" } }),
  ]);
  registry.consume(call("POST", "https://id.example/empty", Buffer.alloc(0)));
  registry.consume(call("POST", "https://id.example/json", Buffer.from('{"grant_type":"authorization_code"}'),
    { "content-type": "application/json" }));
  registry.assertAllConsumed();
});

test("matches own __proto__ and constructor request headers", () => {
  const declared = Object.fromEntries([
    ["__proto__", "prototype-value"], ["constructor", "constructor-value"],
  ]) as Record<string, Matcher>;
  const observed = Object.fromEntries([
    ["__proto__", "prototype-value"], ["constructor", "constructor-value"],
  ]) as Record<string, string>;
  const registry = new HttpExchangeRegistry([
    exchange("GET", "https://id.example/metadata", { absent: true }, declared),
  ]);
  registry.consume(call("GET", "https://id.example/metadata", undefined, observed));
  registry.assertAllConsumed();
});

test("snapshots declarations, calls, and observations", () => {
  const declaration = exchange("POST", "https://id.example/token", "body");
  const registry = new HttpExchangeRegistry([declaration, declaration]);
  declaration.request.url = "https://changed.example";
  (declaration.response.body as { value: { marker: string } }).value.marker = "changed";
  const outbound = call("POST", "https://id.example/token", Buffer.from("body"), { x: ["one"] });
  registry.consume(outbound);
  outbound.url = "https://changed.example";
  outbound.body![0] = 0;
  (outbound.headers.x as string[])[0] = "changed";
  const firstRead = registry.observed;
  firstRead[0]!.url = "https://changed-again.example";
  firstRead[0]!.body![0] = 0;
  assert.equal(registry.observed[0]!.url, "https://id.example/token");
  assert.equal(registry.observed[0]!.body!.toString(), "body");
  assert.deepEqual(registry.observed[0]!.headers.x, ["one"]);
  const secondResponse = registry.consume(call("POST", "https://id.example/token", Buffer.from("body")));
  assert.deepEqual(secondResponse.body, { value: { marker: "https://id.example/token" } });
  registry.assertAllConsumed();
});

test("keeps mismatch failure sticky after a later success without echoing call data", () => {
  const registry = new HttpExchangeRegistry([exchange("GET", "https://id.example/good")]);
  const poison = "hostile-input-marker";
  const error = fixtureError(() => registry.consume(call(poison, `https://evil.example/${poison}`)), unmatched);
  assert.equal(error.message.includes(poison), false);
  registry.consume(call("GET", "https://id.example/good"));
  fixtureError(() => registry.assertAllConsumed(), unmatched);
  assert.deepEqual(registry.observed.map(({ method, url }) => ({ method, url })), [
    { method: poison, url: `https://evil.example/${poison}` },
    { method: "GET", url: "https://id.example/good" },
  ]);
});

test("turns matcher errors into the fixed sticky mismatch failure", () => {
  const registry = new HttpExchangeRegistry([
    exchange("POST", "https://id.example/token", { matches: "[" }),
  ]);
  fixtureError(() => registry.consume(call("POST", "https://id.example/token", Buffer.from("body"))), unmatched);
  fixtureError(() => registry.assertAllConsumed(), unmatched);
});

test("rejects unconsumed declarations", () => {
  const registry = new HttpExchangeRegistry([exchange("GET", "https://id.example/jwks")]);
  fixtureError(() => registry.assertAllConsumed(), unconsumed);
});
