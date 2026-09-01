import assert from "node:assert/strict";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { HttpExchangeRegistry } from "./parity/http-exchange-registry.ts";
import { assertOutbound } from "./parity/outbound-assertions.ts";
import type { HttpExchange, Matcher, ObservedOutbound, OutboundCall } from "./parity/types.ts";

const absent = { absent: true } as const;

test("outbound assertions accept an exact empty list and two calls in order", () => {
  assertOutbound(record([]), []);
  const calls = [call("GET", "/first"), call("POST", "/second")];
  assertOutbound(record(calls), calls.map(expectedCall));
  assert.throws(() => assertOutbound(record(calls), calls.toReversed().map(expectedCall)),
    fixed("outbound call method did not match fixture"));
});

test("outbound assertions reject either call-count difference", () => {
  const one = call("GET", "/one");
  assert.throws(() => assertOutbound(record([one]), []),
    fixed("outbound call count did not match fixture"));
  assert.throws(() => assertOutbound(record([one]), [expectedCall(one), expectedCall(one)]),
    fixed("outbound call count did not match fixture"));
});

test("outbound assertions reject an unconsumed HTTP exchange first", () => {
  const calls = [call("GET", "/used"), call("GET", "/unused")];
  assert.throws(() => assertOutbound(record(calls, 1), [expectedCall(calls[0]!)]),
    fixed("not all declared HTTP exchanges were consumed"));
});

test("outbound assertions compare each method and URL exactly", () => {
  const actual = call("GET", "/exact");
  assert.throws(() => assertOutbound(record([actual]), [
    { ...expectedCall(actual), method: "get" },
  ]), fixed("outbound call method did not match fixture"));
  assert.throws(() => assertOutbound(record([actual]), [
    { ...expectedCall(actual), url: "https://idp.example.test/other" },
  ]), fixed("outbound call URL did not match fixture"));
});

test("outbound assertions require the exact header-name set", () => {
  const withHeader = call("GET", "/headers", { "x-one": "one" });
  assert.throws(() => assertOutbound(record([withHeader]), [
    { ...expectedCall(withHeader), headers: {} },
  ]), fixed("outbound header-name set did not match fixture"));
  const withoutHeaders = call("GET", "/headers");
  assert.throws(() => assertOutbound(record([withoutHeaders]), [
    { ...expectedCall(withoutHeaders), headers: { "x-one": "one" } },
  ]), fixed("outbound header-name set did not match fixture"));
});

test("outbound header values preserve scalar and repeated occurrences", () => {
  const actual = call("GET", "/values", { "x-one": "one", "x-many": ["a", "b"] });
  assertOutbound(record([actual]), [expectedCall(actual)]);
  assertOutbound(record([actual]), [{ ...expectedCall(actual),
    headers: { "x-one": { matches: "^one$" }, "x-many": { equals: ["a", "b"] } } }]);
  assert.throws(() => assertOutbound(record([actual]), [{ ...expectedCall(actual),
    headers: { "x-one": "one", "x-many": { equals: ["b", "a"] } } }]),
  fixed("outbound header value did not match fixture"));
});

test("outbound headers retain own __proto__ and constructor keys", () => {
  const headers = ownHeaders([["__proto__", "proto"], ["constructor", "ctor"]]);
  const actual = call("GET", "/special", headers);
  assertOutbound(record([actual]), [expectedCall(actual)]);
});

test("outbound bodies distinguish absence, JSON, and UTF-8 text", () => {
  const calls = [
    call("POST", "/absent"),
    call("POST", "/zero", {}, Buffer.alloc(0)),
    call("POST", "/json", { "content-type": "application/json; charset=utf-8" },
      Buffer.from('{"value":1}')),
    call("POST", "/text", { "content-type": "text/plain" }, Buffer.from("plain text")),
  ];
  const expected = calls.map(expectedCall);
  expected[2]!.body = { schema: { type: "object", properties: { value: { const: 1 } },
    required: ["value"], additionalProperties: false } };
  expected[3]!.body = { contains: "text" };
  assertOutbound(record(calls), expected);
  assert.throws(() => assertOutbound(record([calls[3]!]), [
    { ...expectedCall(calls[3]!), body: { equals: "different" } },
  ]), fixed("outbound body did not match fixture"));
});

test("outbound body and matcher failures use fixed non-echoing errors", () => {
  const duplicate = call("POST", "/json", { "content-type": "application/json" },
    Buffer.from('{"private-value":1,"private-value":2}'));
  assert.throws(() => assertOutbound(fakeRegistry(duplicate), [
    { ...expectedCall(duplicate), body: { equals: { "private-value": 2 } } },
  ]), fixed("outbound body did not match fixture", "private-value"));
  const invalidUtf8 = call("POST", "/text", {}, Buffer.from([0xff]));
  assert.throws(() => assertOutbound(fakeRegistry(invalidUtf8), [
    { ...expectedCall(invalidUtf8), body: { contains: "hidden-body" } },
  ]), fixed("outbound body did not match fixture", "hidden-body"));
  const actual = call("GET", "/matcher", { "x-hostile": "value" });
  assert.throws(() => assertOutbound(record([actual]), [{ ...expectedCall(actual),
    headers: { "x-hostile": { matches: "[hidden-pattern" } } }]),
  fixed("outbound header value did not match fixture", "hidden-pattern"));
});

function call(method: string, path: string,
  headers: Record<string, string | string[]> = {}, body?: Buffer): ObservedOutbound {
  return { method, url: `https://idp.example.test${path}`, headers, ...(body ? { body } : {}) };
}

function record(calls: ObservedOutbound[], consume = calls.length): HttpExchangeRegistry {
  const registry = new HttpExchangeRegistry(calls.map(exchange));
  for (const outbound of calls.slice(0, consume)) registry.consume(outbound);
  return registry;
}

function exchange(outbound: ObservedOutbound): HttpExchange {
  return { request: { method: outbound.method, url: outbound.url,
    headers: headerMatchers(outbound.headers), body: bodyMatcher(outbound) },
  response: { status: 204, headers: {}, body: absent } };
}

function expectedCall(outbound: ObservedOutbound): OutboundCall {
  return { method: outbound.method, url: outbound.url,
    headers: headerMatchers(outbound.headers), body: bodyMatcher(outbound) };
}

function headerMatchers(headers: Record<string, string | string[]>): Record<string, Exclude<Matcher, { absent: true }>> {
  const matchers: Record<string, Exclude<Matcher, { absent: true }>> = {};
  for (const [name, value] of Object.entries(headers)) defineOwn(matchers, name,
    Array.isArray(value) ? { equals: value } : value);
  return matchers;
}

function bodyMatcher(outbound: ObservedOutbound): Matcher {
  if (outbound.body === undefined || outbound.body.byteLength === 0) return absent;
  const contentType = outbound.headers["content-type"];
  if (typeof contentType === "string" && contentType.startsWith("application/json")) {
    return { equals: JSON.parse(outbound.body.toString("utf8")) as unknown };
  }
  return { equals: outbound.body.toString("utf8") };
}

function ownHeaders(entries: Array<[string, string]>): Record<string, string | string[]> {
  const headers: Record<string, string | string[]> = {};
  for (const [name, value] of entries) defineOwn(headers, name, value);
  return headers;
}

function defineOwn(target: object, name: string, value: unknown): void {
  Object.defineProperty(target, name, { value, enumerable: true, configurable: true, writable: true });
}

function fakeRegistry(outbound: ObservedOutbound): Pick<HttpExchangeRegistry, "assertAllConsumed" | "observed"> {
  return { assertAllConsumed() {}, get observed() { return [outbound]; } };
}

function fixed(message: string, hidden?: string): (error: unknown) => boolean {
  return (error) => error instanceof FixtureRunnerError && error.message === message
    && error.cause === undefined && (hidden === undefined || !error.message.includes(hidden));
}
