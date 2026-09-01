import assert from "node:assert/strict";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { selectQueryResponseCapture } from "./parity/captures.ts";
import type { ObservedMessage } from "./parity/types.ts";

type Headers = Record<string, string | string[]>;

function response(headers: Headers): ObservedMessage {
  return { status: 302, headers, body: Buffer.alloc(0) };
}

function failure(
  headerName: string, parameter: string, observed: ObservedMessage, message?: RegExp,
): FixtureRunnerError {
  let caught: unknown;
  try { selectQueryResponseCapture(headerName, parameter, observed); }
  catch (error) { caught = error; }
  assert.ok(caught instanceof FixtureRunnerError);
  if (message) assert.match(caught.message, message);
  return caught;
}

test("query captures require one own scalar header and use normalized lookup", () => {
  const url = "https://example.test/callback?token=selected";
  assert.equal(selectQueryResponseCapture("LoCaTiOn", "token", response({ location: url })), "selected");
  for (const headers of [
    {},
    { location: [url, "https://example.test/callback?token=other"] },
    { location: [url] },
    { location: 42 },
    { location: null },
    { location: { toString: () => url } },
  ] as unknown as Headers[]) {
    failure("location", "token", response(headers), /header capture/u);
  }
  const inherited = Object.create({ location: url }) as Headers;
  failure("location", "token", response(inherited), /header capture/u);
});

test("query captures require an absolute URL without coercing URL-like values", () => {
  for (const url of [
    "./callback?token=value", "/callback?token=value", "not a URL", "https://",
    "https://[invalid/callback?token=value",
  ]) {
    const error = failure("location", "token", response({ location: url }), /not a URL/u);
    assert.doesNotMatch(error.message, /token=value|example\.test/u);
  }
  const getter = Object.defineProperty({}, "toString", {
    get() { throw new Error("URL getter detail"); },
  });
  const error = failure("location", "token", response({ location: getter } as unknown as Headers));
  assert.doesNotMatch(error.message, /URL getter detail/u);
});

test("query captures require exactly one decoded parameter", () => {
  for (const url of [
    "https://example.test/callback",
    "https://example.test/callback?other=value",
    "https://example.test/callback?token=one&token=two",
    "https://example.test/callback?token=one&tok%65n=two",
    "https://example.test/callback?TOKEN=wrong",
    "https://example.test/callback?tokenized=wrong",
  ]) {
    failure("location", "token", response({ location: url }), /missing or ambiguous/u);
  }
  assert.equal(selectQueryResponseCapture("location", "token", response({
    location: "https://example.test/callback?before=one&token=selected&after=two",
  })), "selected");
  assert.equal(selectQueryResponseCapture("location", "token", response({
    location: "https://example.test/callback?token=selected&before=one",
  })), "selected");
});

test("query captures decode form components strictly and keep delimiters in values", () => {
  assert.equal(selectQueryResponseCapture("location", "token", response({
    location: "https://example.test/callback?t%6fk%65n=%e2%9C%93+value%2Bplus%26%3D",
  })), "✓ value+plus&=");
  assert.equal(selectQueryResponseCapture("location", "token", response({
    location: "https://example.test/callback?token=first=second",
  })), "first=second");
  assert.equal(selectQueryResponseCapture("location", "token", response({
    location: "https://example.test/callback?token=",
  })), "");
  assert.equal(selectQueryResponseCapture("location", "token", response({
    location: "https://example.test/callback?token",
  })), "");
});

test("query captures reject every malformed percent triplet in the URL", () => {
  for (const url of [
    "https://example.test/callback?token=value%",
    "https://example.test/callback?token=value%0",
    "https://example.test/callback?token=value%ZZ",
    "https://example.test/callback?token=value&other=%ZZ",
    "https://example.test/callback%ZZ?token=value",
    "https://example.test/callback?token=value#fragment%ZZ",
  ]) {
    const error = failure("location", "token", response({ location: url }), /URL encoding is invalid/u);
    assert.doesNotMatch(error.message, /value|example\.test|fragment/u);
  }
});

test("query captures reject non-UTF-8 percent byte sequences", () => {
  for (const encoded of [
    "%80",       // invalid continuation
    "%C3%28",    // invalid continuation
    "%E2%82",    // truncated sequence
    "%C0%AF",    // overlong encoding
    "%ED%A0%80", // surrogate encoding
    "%F4%90%80%80", // code point above U+10FFFF
  ]) {
    const error = failure("location", "token", response({
      location: `https://example.test/callback?token=${encoded}`,
    }), /URL encoding is invalid/u);
    assert.doesNotMatch(error.message, /�|example\.test|token/u);
  }
  const outside = failure("location", "token", response({
    location: "https://example.test/callback?token=value&other=%C3%28",
  }), /URL encoding is invalid/u);
  assert.doesNotMatch(outside.message, /value|other|example\.test/u);
});

test("query captures stop at a fragment and keep fixed errors generic", () => {
  const selected = "https://example.test/callback?token=good#fragment?token=bad";
  assert.equal(selectQueryResponseCapture("location", "token", response({ location: selected })), "good");
  const fragmentOnly = failure("location", "token", response({
    location: "https://example.test/callback#fragment?token=bad",
  }), /missing or ambiguous/u);
  assert.doesNotMatch(fragmentOnly.message, /bad|fragment/u);
  const malformed = failure("location", "token", response({
    location: "https://example.test/callback?token=attacker-value%",
  }), /URL encoding is invalid/u);
  assert.doesNotMatch(malformed.message, /attacker-value|example\.test/u);
});

test("query captures reject unpaired surrogates before URL parsing or selection", () => {
  const high = "\ud800";
  const low = "\udfff";
  for (const surrogate of [high, low]) {
    for (const url of [
      `https://example.test/callback${surrogate}?token=value`,
      `https://example.test/callback?token=value${surrogate}`,
      `https://example.test/callback?to${surrogate}ken=value`,
    ]) {
      const error = failure("location", "token", response({ location: url }), /malformed Unicode/u);
      assert.doesNotMatch(error.message, /example\.test|value/u);
    }
    const error = failure("location", `to${surrogate}ken`, response({
      location: "https://example.test/callback?token=value",
    }), /malformed Unicode/u);
    assert.doesNotMatch(error.message, /example\.test|value|token/u);
  }
});

test("query captures preserve valid supplementary-plane Unicode", () => {
  const value = "🦄";
  assert.equal(selectQueryResponseCapture("location", "token", response({
    location: `https://example.test/callback?token=${value}`,
  })), value);
});
