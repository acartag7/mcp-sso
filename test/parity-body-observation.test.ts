import assert from "node:assert/strict";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { bodyObservation } from "./parity/observations.ts";

type Headers = Record<string, string | string[]>;

function expectRunnerError(body: Buffer, headers: Headers): FixtureRunnerError {
  try {
    bodyObservation(body, headers);
  } catch (error) {
    assert.ok(error instanceof FixtureRunnerError);
    return error;
  }
  assert.fail("expected body observation to fail");
}

test("undefined and zero-byte bodies are absent", () => {
  assert.deepEqual(bodyObservation(undefined, {}), { present: false });
  assert.deepEqual(bodyObservation(Buffer.alloc(0), { "content-type": "application/json" }), {
    present: false,
  });
});

test("non-JSON bodies keep JSON-looking bytes as text", () => {
  const body = Buffer.from('{"ok":true}', "utf8");
  const headersList: Headers[] = [{}, { "content-type": "application/problem+json" }];
  for (const headers of headersList) {
    assert.deepEqual(bodyObservation(body, headers), { present: true, value: '{"ok":true}' });
  }
});

test("application/json essence parses JSON values", () => {
  const cases: Array<[string, unknown]> = [
    ['{"kind":"object"}', { kind: "object" }], ["true", true], ["42", 42],
    ["null", null], ['""', ""],
  ];
  for (const [body, value] of cases) {
    assert.deepEqual(bodyObservation(Buffer.from(body), { "content-type": "Application/JSON" }), {
      present: true, value,
    });
  }
});

test("HTTP OWS around a JSON essence is accepted", () => {
  const contentTypes = [
    " application/json ", "\tapplication/json\t", " \tapplication/json\t ; charset=utf-8",
  ];
  for (const contentType of contentTypes) {
    assert.deepEqual(bodyObservation(Buffer.from("false"), { "content-type": contentType }), {
      present: true, value: false,
    });
  }
});

test("malformed application/json is a FixtureRunnerError with an Error cause", () => {
  const error = expectRunnerError(Buffer.from("{"), { "content-type": "application/json" });
  assert.equal(error.message, "observed application/json body is invalid");
  assert.ok(error.cause instanceof Error);
});

test("invalid UTF-8 is fatal for JSON and non-JSON bodies", () => {
  const body = Buffer.from([0xc3, 0x28]);
  const headersList: Headers[] = [{}, { "content-type": "application/json" }];
  for (const headers of headersList) {
    const error = expectRunnerError(body, headers);
    assert.equal(error.message, "observed body is not valid UTF-8");
    assert.ok(error.cause instanceof Error);
  }
});

test("multiple Content-Type occurrences are not selected", () => {
  assert.deepEqual(bodyObservation(Buffer.from('{"ok":true}'), {
    "content-type": ["application/json", "text/plain"],
  }), { present: true, value: '{"ok":true}' });
});

test("inherited Content-Type is ignored and an own value parses JSON", () => {
  const inherited = Object.create({ "content-type": "application/json" }) as Headers;
  assert.deepEqual(bodyObservation(Buffer.from('{"ok":true}'), inherited), {
    present: true, value: '{"ok":true}',
  });
  assert.deepEqual(bodyObservation(Buffer.from('{"ok":true}'), { "content-type": "application/json" }), {
    present: true, value: { ok: true },
  });
});

test("a leading UTF-8 BOM stays in text", () => {
  const body = Buffer.from([0xef, 0xbb, 0xbf, ...Buffer.from('{"ok":true}')]);
  assert.deepEqual(bodyObservation(body, {}), { present: true, value: '\uFEFF{"ok":true}' });
});

test("a leading UTF-8 BOM invalidates application/json", () => {
  const body = Buffer.from([0xef, 0xbb, 0xbf, ...Buffer.from('{"ok":true}')]);
  const error = expectRunnerError(body, { "content-type": "application/json" });
  assert.equal(error.message, "observed application/json body is invalid");
  assert.ok(error.cause instanceof Error);
});

test("JavaScript-trim-only boundaries stay non-JSON text", () => {
  const boundaries = [
    "\r", "\n", "\f", "\v", "\u00a0", "\ufeff", "\u1680", "\u2000", "\u2001",
    "\u2002", "\u2003", "\u2004", "\u2005", "\u2006", "\u2007", "\u2008", "\u2009",
    "\u200a", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000",
  ];
  const body = Buffer.from('{"kind":"text"}');
  for (const boundary of boundaries) {
    for (const essence of [`${boundary}application/json`, `application/json${boundary}`]) {
      assert.deepEqual(bodyObservation(body, { "content-type": `${essence}; charset=utf-8` }), {
        present: true, value: '{"kind":"text"}',
      });
    }
  }
});
