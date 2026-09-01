import assert from "node:assert/strict";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { parseHttpResponse } from "./parity/http-framing.ts";
import type { ObservedMessage } from "./parity/types.ts";

function frame(lines: string[], body = ""): Buffer {
  return Buffer.from(`${lines.join("\r\n")}\r\n\r\n${body}`, "latin1");
}

function chunked(body: string): Buffer {
  return frame(["HTTP/1.1 200 OK", "transfer-encoding: chunked"], body);
}

function parse(raw: Buffer, ended = false, method = "GET"): ObservedMessage | undefined {
  return parseHttpResponse(raw, method, ended);
}

function observed(raw: Buffer, ended = false, method = "GET"): ObservedMessage {
  const message = parse(raw, ended, method);
  assert.ok(message, "expected a complete observed message");
  return message;
}

function headersOf(message: ObservedMessage): Record<string, string | string[]> {
  return { ...message.headers };
}

function fails(raw: Buffer, ended: boolean, expected: RegExp, method = "GET"): void {
  assert.throws(() => parseHttpResponse(raw, method, ended), FixtureRunnerError);
  assert.throws(() => parseHttpResponse(raw, method, ended), (error: unknown) =>
    error instanceof FixtureRunnerError && expected.test(error.message));
}

test("a complete Content-Length response is observed before the socket ends", () => {
  const message = observed(frame(["HTTP/1.1 200 OK", "content-length: 5"], "hello"));
  assert.equal(message.status, 200);
  assert.equal(message.body.toString("latin1"), "hello");
  assert.deepEqual(headersOf(message), { "content-length": "5" });
});

test("a bodyless response is observed before the socket ends and rejects trailing bytes", () => {
  const message = observed(frame(["HTTP/1.1 204 No Content"]));
  assert.equal(message.status, 204);
  assert.equal(message.body.byteLength, 0);
  fails(frame(["HTTP/1.1 204 No Content"], "x"), false, /bodyless HTTP response contained bytes/u);
  fails(frame(["HTTP/1.1 304 Not Modified"], "x"), true, /bodyless HTTP response contained bytes/u);
});

test("an incomplete Content-Length body waits for more bytes and fails once the socket ends", () => {
  const partial = frame(["HTTP/1.1 200 OK", "content-length: 5"], "he");
  assert.equal(parse(partial), undefined);
  fails(partial, true, /HTTP response Content-Length mismatch/u);
});

test("more body bytes than Content-Length declares are rejected", () => {
  fails(frame(["HTTP/1.1 200 OK", "content-length: 2"], "hello"), false, /HTTP response Content-Length mismatch/u);
  fails(frame(["HTTP/1.1 200 OK", "content-length: 2"], "hello"), true, /HTTP response Content-Length mismatch/u);
});

test("an interim 100 Continue is consumed before the final response", () => {
  const raw = Buffer.concat([
    frame(["HTTP/1.1 100 Continue"]),
    frame(["HTTP/1.1 200 OK", "content-length: 2"], "ok"),
  ]);
  const message = observed(raw);
  assert.equal(message.status, 200);
  assert.equal(message.body.toString("latin1"), "ok");
  assert.deepEqual(headersOf(message), { "content-length": "2" });
});

test("an interim response alone waits for the final response and fails once the socket ends", () => {
  const interim = frame(["HTTP/1.1 100 Continue"]);
  assert.equal(parse(interim), undefined);
  fails(interim, true, /HTTP response has no header boundary/u);
});

test("upgrade and body-bearing informational responses are rejected", () => {
  fails(frame(["HTTP/1.1 101 Switching Protocols", "upgrade: websocket"]), false,
    /HTTP protocol upgrade responses are unsupported/u);
  fails(frame(["HTTP/1.1 100 Continue", "content-length: 0"]), false,
    /HTTP informational response declared a body/u);
  fails(frame(["HTTP/1.1 103 Early Hints", "transfer-encoding: chunked"]), false,
    /HTTP informational response declared a body/u);
});

test("bodyless responses are held to the same framing validation as a 200", () => {
  fails(frame(["HTTP/1.1 204 No Content", "content-length: 0", "content-length: 0"]), false,
    /HTTP response Content-Length is ambiguous or malformed/u);
  fails(frame(["HTTP/1.1 204 No Content", "transfer-encoding: chunked", "content-length: 0"]), false,
    /HTTP response declared both Transfer-Encoding and Content-Length/u);
  fails(frame(["HTTP/1.1 200 OK", "content-length: 01"]), false,
    /HTTP response Content-Length is ambiguous or malformed/u, "HEAD");
  fails(frame(["HTTP/1.1 304 Not Modified", "transfer-encoding: gzip"]), false,
    /HTTP response Transfer-Encoding is ambiguous or unsupported/u);
});

test("a header name outside the HTTP token grammar is rejected", () => {
  for (const name of [
    "Content-Length ", "Transfer-Encoding ", "x\tname", "x\u0001name", "x(name", 'x"name', "x\u00e9name",
  ]) {
    fails(frame(["HTTP/1.1 200 OK", `${name}: 2`], "hi"), true,
      /HTTP response header name is not a token/u);
    fails(frame(["HTTP/1.1 200 OK", `${name}: 2`], "hi"), false,
      /HTTP response header name is not a token/u);
  }
});

test("a trailer name outside the HTTP token grammar is rejected", () => {
  fails(chunked("2\r\nhi\r\n0\r\nx trailer: t\r\n\r\n"), true,
    /HTTP response header name is not a token/u);
});

test("a HEAD response reports no body even when Content-Length is declared", () => {
  const message = observed(frame(["HTTP/1.1 200 OK", "content-length: 12"]), false, "HEAD");
  assert.equal(message.body.byteLength, 0);
  assert.deepEqual(headersOf(message), { "content-length": "12" });
  fails(frame(["HTTP/1.1 200 OK", "content-length: 12"], "hello world!"), true,
    /bodyless HTTP response contained bytes/u, "HEAD");
});

test("repeated header names keep their order and single occurrences stay strings", () => {
  const message = observed(frame([
    "HTTP/1.1 200 OK", "Set-Cookie: a=1", "Content-Length: 0", "SET-COOKIE: b=2",
  ]));
  assert.deepEqual(headersOf(message), { "set-cookie": ["a=1", "b=2"], "content-length": "0" });
});

test("header values are trimmed of spaces and tabs only", () => {
  const message = observed(frame([
    "HTTP/1.1 200 OK", "content-length: 0", "x-tabs:\t \tvalue \t", "x-latin1: \u00a0value\u00a0",
  ]));
  assert.deepEqual(headersOf(message), {
    "content-length": "0", "x-tabs": "value", "x-latin1": "\u00a0value\u00a0",
  });
});

test("a malformed status line is rejected", () => {
  for (const line of ["HTTP/2 200 OK", "HTTP/1.1 20 OK", "200 OK", "HTTP/1.1 200OK", "http/1.1 200 OK"]) {
    fails(frame([line, "content-length: 0"]), true, /HTTP response status line is malformed/u);
  }
});

test("a malformed or folded header line is rejected", () => {
  fails(frame(["HTTP/1.1 200 OK", "content-length 0"]), true, /HTTP response header line is malformed/u);
  fails(frame(["HTTP/1.1 200 OK", ": 0"]), true, /HTTP response header line is malformed/u);
  fails(frame(["HTTP/1.1 200 OK", "x-name: one", "  two"]), true,
    /HTTP response header line uses obsolete folding/u);
  fails(frame(["HTTP/1.1 200 OK", "x-name: one", "\t"]), true,
    /HTTP response header line uses obsolete folding/u);
});

test("an ambiguous or malformed Content-Length is rejected", () => {
  for (const value of ["01", "-1", "1e3", "\u00a05", "0x5", "9007199254740992", ""]) {
    fails(frame(["HTTP/1.1 200 OK", `content-length:${value}`]), true,
      /HTTP response Content-Length is ambiguous or malformed/u);
  }
  fails(frame(["HTTP/1.1 200 OK", "content-length: 0", "content-length: 0"]), true,
    /HTTP response Content-Length is ambiguous or malformed/u);
});

test("a Content-Length padded with spaces and tabs is accepted", () => {
  const message = observed(frame(["HTTP/1.1 200 OK", "content-length: \t5 \t"], "hello"));
  assert.equal(message.body.toString("latin1"), "hello");
});

test("conflicting framing headers are rejected and chunked matches case-insensitively", () => {
  fails(frame(["HTTP/1.1 200 OK", "transfer-encoding: chunked", "content-length: 0"], "0\r\n\r\n"), true,
    /HTTP response declared both Transfer-Encoding and Content-Length/u);
  fails(frame(["HTTP/1.1 200 OK", "transfer-encoding: gzip"], "0\r\n\r\n"), true,
    /HTTP response Transfer-Encoding is ambiguous or unsupported/u);
  fails(frame(["HTTP/1.1 200 OK", "transfer-encoding: chunked", "transfer-encoding: chunked"], "0\r\n\r\n"), true,
    /HTTP response Transfer-Encoding is ambiguous or unsupported/u);
  const message = observed(frame(["HTTP/1.1 200 OK", "transfer-encoding: Chunked"], "2\r\nhi\r\n0\r\n\r\n"));
  assert.equal(message.body.toString("latin1"), "hi");
});

test("a chunked body decodes chunk extensions and leaves trailers out of the headers", () => {
  const message = observed(chunked("5;name=value\r\nhello\r\n2\r\n, \r\n6\r\nworld!\r\n0\r\nx-trailer: t\r\n\r\n"));
  assert.equal(message.body.toString("latin1"), "hello, world!");
  assert.deepEqual(headersOf(message), { "transfer-encoding": "chunked" });
});

test("a truncated chunked body waits for more bytes and fails once the socket ends", () => {
  for (const tail of ["", "5", "5\r\nhel", "5\r\nhello\r\n", "5\r\nhello\r\n0\r\n", "0\r\nx-trailer: t\r\n"]) {
    assert.equal(parse(chunked(tail)), undefined);
    fails(chunked(tail), true, /HTTP response chunked body is truncated/u);
  }
});

test("chunked framing defects are rejected", () => {
  fails(chunked("2\r\nhi\r\n0\r\n\r\nextra"), true, /HTTP response contained bytes after the chunked terminator/u);
  fails(chunked("2\r\nhi\r\n0\r\nx-trailer: t\r\n\r\nextra"), false,
    /HTTP response contained bytes after the chunked terminator/u);
  fails(chunked("zz\r\nhi\r\n0\r\n\r\n"), true, /HTTP response chunk size is malformed/u);
  fails(chunked("2\r\nhixx0\r\n\r\n"), true, /HTTP response chunk is not terminated by CRLF/u);
  fails(chunked(`${"f".repeat(16)}\r\n`), true, /HTTP response chunk size is out of range/u);
  fails(chunked("2\r\nhi\r\n0\r\nnot-a-trailer\r\n\r\n"), true, /HTTP response header line is malformed/u);
});

test("a response without framing headers ends when the socket closes", () => {
  const raw = frame(["HTTP/1.1 200 OK", "content-type: text/plain"], "body bytes");
  assert.equal(parse(raw), undefined);
  assert.equal(observed(raw, true).body.toString("latin1"), "body bytes");
  const empty = frame(["HTTP/1.0 200 OK", "content-type: text/plain"]);
  assert.equal(parse(empty), undefined);
  assert.equal(observed(empty, true).body.byteLength, 0);
});

test("a response with no header boundary is incomplete until the socket ends", () => {
  const partial = Buffer.from("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n", "latin1");
  assert.equal(parse(partial), undefined);
  fails(partial, true, /HTTP response has no header boundary/u);
});

test("a header named __proto__ is kept as an own value", () => {
  const message = observed(frame(["HTTP/1.1 200 OK", "content-length: 0", "__proto__: polluted"]));
  assert.equal(Object.getPrototypeOf(message.headers), null);
  assert.equal(Object.hasOwn(message.headers, "__proto__"), true);
  assert.equal(message.headers["__proto__"], "polluted");
});
