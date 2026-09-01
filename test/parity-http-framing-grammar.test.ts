import assert from "node:assert/strict";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { parseHttpResponse } from "./parity/http-framing.ts";
import type { ObservedMessage } from "./parity/types.ts";

/** Response bytes are latin1, so one code unit is one wire byte. */
function byte(code: number): string {
  return String.fromCharCode(code);
}

function frame(lines: string[], body = ""): Buffer {
  return Buffer.from(`${lines.join("\r\n")}\r\n\r\n${body}`, "latin1");
}

function chunked(body: string, status = "200 OK"): Buffer {
  return frame([`HTTP/1.1 ${status}`, "transfer-encoding: chunked"], body);
}

function parse(raw: Buffer, ended = false): ObservedMessage | undefined {
  return parseHttpResponse(raw, "GET", ended);
}

function observed(raw: Buffer, ended = false): ObservedMessage {
  const message = parse(raw, ended);
  assert.ok(message, "expected a complete observed message");
  return message;
}

function fails(raw: Buffer, ended: boolean, expected: RegExp): void {
  assert.throws(() => parseHttpResponse(raw, "GET", ended), FixtureRunnerError);
  assert.throws(() => parseHttpResponse(raw, "GET", ended), (error: unknown) =>
    error instanceof FixtureRunnerError && expected.test(error.message));
}

test("a reason phrase outside the allowed byte range is rejected", () => {
  for (const code of [0x00, 0x01, 0x0b, 0x0c, 0x0d, 0x1f, 0x7f]) {
    for (const ended of [true, false]) {
      fails(frame([`HTTP/1.1 200 O${byte(code)}K`, "content-length: 0"]), ended,
        /HTTP response status line is malformed/u);
    }
  }
});

test("a reason phrase of tabs, spaces, VCHAR and obs-text is accepted", () => {
  const obsText = `R${byte(0xe9)}initialis${byte(0xe9)}!`;
  assert.equal(observed(frame([`HTTP/1.1 200 OK \t${obsText}`, "content-length: 0"])).status, 200);
  assert.equal(observed(frame(["HTTP/1.1 200", "content-length: 0"])).status, 200);
  assert.equal(observed(frame(["HTTP/1.1 200 ", "content-length: 0"])).status, 200);
});

test("a header value containing a disallowed byte is rejected", () => {
  for (const code of [0x00, 0x01, 0x0b, 0x0c, 0x0d, 0x0a, 0x1f, 0x7f]) {
    for (const ended of [true, false]) {
      fails(frame(["HTTP/1.1 200 OK", `x-value: a${byte(code)}b`, "content-length: 0"]), ended,
        /HTTP response header value contains a disallowed byte/u);
    }
  }
});

test("a header value of tabs, spaces, VCHAR and obs-text is preserved", () => {
  const value = `a\tb ${byte(0xe9)}`;
  const message = observed(frame(["HTTP/1.1 200 OK", `x-value: ${value}`, "content-length: 0"]));
  assert.equal(message.headers["x-value"], value);
});

test("a trailer value containing a disallowed byte is rejected", () => {
  for (const ended of [true, false]) {
    fails(chunked(`0\r\nx-trailer: a${byte(0)}b\r\n\r\n`), ended,
      /HTTP response header value contains a disallowed byte/u);
  }
});

test("a 204 response may not declare Content-Length or Transfer-Encoding", () => {
  for (const field of ["content-length: 0", "content-length: 5", "transfer-encoding: chunked"]) {
    for (const ended of [true, false]) {
      fails(frame(["HTTP/1.1 204 No Content", field]), ended,
        /HTTP 204 response declared Content-Length or Transfer-Encoding/u);
    }
  }
});

test("a 205 response frames like a 200 and decodes to an empty body", () => {
  assert.equal(observed(frame(["HTTP/1.1 205 Reset Content", "content-length: 0"])).body.byteLength, 0);
  assert.equal(observed(chunked("0\r\n\r\n", "205 Reset Content")).body.byteLength, 0);
  const closeDelimited = frame(["HTTP/1.1 205 Reset Content"]);
  assert.equal(parse(closeDelimited), undefined);
  assert.equal(observed(closeDelimited, true).body.byteLength, 0);
});

test("a 205 response carrying body bytes is rejected", () => {
  fails(frame(["HTTP/1.1 205 Reset Content", "content-length: 1"], "x"), false,
    /HTTP 205 response contained a body/u);
  fails(chunked("1\r\nx\r\n0\r\n\r\n", "205 Reset Content"), false,
    /HTTP 205 response contained a body/u);
  fails(frame(["HTTP/1.1 205 Reset Content"], "x"), true, /HTTP 205 response contained a body/u);
});

test("a chunk extension outside the chunk-ext grammar is rejected", () => {
  const lines = ["2;", "2; =x", "2;name=", "2;na me=v", "2;=v", "2;n=", "2;n=a\"b",
    `2;n${byte(1)}=v`, `2;n="a${byte(0)}b"`, '2;n="unterminated', '2;n="a\\'];
  for (const line of lines) {
    fails(chunked(`${line}\r\nhi\r\n0\r\n\r\n`), true, /HTTP response chunk size is malformed/u);
  }
});

test("a chunk extension inside the chunk-ext grammar is accepted", () => {
  const lines = ["2;a=b", "2;a", "2 ; a = b", "2;a=b;c;d=e", '2;a="q x"', '2;a="q\\"x"', '2;a=""'];
  for (const line of lines) {
    assert.equal(observed(chunked(`${line}\r\nhi\r\n0\r\n\r\n`), true).body.toString("latin1"), "hi");
  }
});

test("a trailer may not carry a framing or routing field", () => {
  for (const name of ["transfer-encoding", "content-length", "trailer", "host", "Content-Length"]) {
    for (const ended of [true, false]) {
      fails(chunked(`0\r\n${name}: x\r\n\r\n`), ended, /HTTP response trailer field is not allowed/u);
    }
  }
});
