import assert from "node:assert/strict";
import test from "node:test";
import { createServer, type ServerResponse } from "node:http";
import { createServer as createRawServer, type AddressInfo } from "node:net";
import { FixtureRunnerError } from "./parity/error.ts";
import { sendRealHttp, type RealHttpRequest } from "./parity/http-client.ts";

interface Mounted { base: string; close(): Promise<void> }

async function mount(handle: (response: ServerResponse, method: string) => void): Promise<Mounted> {
  const server = createServer((incoming, response) => {
    incoming.resume();
    incoming.on("end", () => { handle(response, incoming.method ?? ""); });
  });
  await new Promise<void>((resolve) => { server.listen(0, "127.0.0.1", resolve); });
  const { port } = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${port}`,
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => { server.close(() => { resolve(); }); });
    },
  };
}

async function mountRaw(bytes: string): Promise<Mounted> {
  const server = createRawServer((socket) => {
    socket.on("error", () => {});
    socket.on("data", () => { socket.write(bytes); });
  });
  await new Promise<void>((resolve) => { server.listen(0, "127.0.0.1", resolve); });
  const { port } = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${port}`,
    async close() { await new Promise<void>((resolve) => { server.close(() => { resolve(); }); }); },
  };
}

async function expectRejection(input: RealHttpRequest, message: string): Promise<FixtureRunnerError> {
  let caught: unknown;
  try { await sendRealHttp(input); }
  catch (error) { caught = error; }
  assert.ok(caught instanceof FixtureRunnerError, `expected FixtureRunnerError, got ${String(caught)}`);
  assert.equal(caught.message, message);
  return caught;
}

function get(mounted: Mounted, path: string, timeoutMs = 2000): RealHttpRequest {
  return { base: mounted.base, method: "GET", path, headers: [], timeoutMs };
}

function parserCode(error: FixtureRunnerError): string {
  const cause = error.cause;
  assert.ok(cause instanceof Error);
  return (cause as NodeJS.ErrnoException).code ?? "";
}

const WIRE_FAILURE = "HTTP request failed on the wire";

test("repeated response header occurrences are observed as ordered arrays", async (t) => {
  const mounted = await mount((response) => {
    response.writeHead(200, [
      "Set-Cookie", "a=1", "X-Dup", "one", "Content-Type", "text/plain",
      "Set-Cookie", "b=2", "X-Dup", "two", "__proto__", "polluted",
    ]);
    response.end("z");
  });
  t.after(() => mounted.close());
  const observed = await sendRealHttp(get(mounted, "/dup"));
  assert.equal(observed.status, 200);
  assert.deepEqual(observed.headers["set-cookie"], ["a=1", "b=2"]);
  assert.deepEqual(observed.headers["x-dup"], ["one", "two"]);
  assert.equal(observed.headers["content-type"], "text/plain");
  assert.equal(observed.body.toString("utf8"), "z");
});

test("an observed header map is null-prototype and keeps __proto__ as an own property", async (t) => {
  const mounted = await mount((response) => {
    response.writeHead(200, ["__proto__", "polluted", "Content-Length", "0"]);
    response.end();
  });
  t.after(() => mounted.close());
  const observed = await sendRealHttp(get(mounted, "/proto"));
  assert.equal(Object.getPrototypeOf(observed.headers), null);
  assert.ok(Object.hasOwn(observed.headers, "__proto__"));
  assert.equal(Object.getOwnPropertyDescriptor(observed.headers, "__proto__")?.value, "polluted");
  assert.equal(Object.getPrototypeOf({}), Object.prototype);
});

test("a chunked response body is observed byte for byte", async (t) => {
  const payload = Buffer.from([0x00, 0x01, 0x7f, 0x80, 0xfa, 0xff]);
  const mounted = await mount((response) => {
    response.writeHead(200, ["Content-Type", "application/octet-stream"]);
    response.write(payload.subarray(0, 3));
    response.end(payload.subarray(3));
  });
  t.after(() => mounted.close());
  const observed = await sendRealHttp(get(mounted, "/chunked"));
  assert.equal(observed.headers["transfer-encoding"], "chunked");
  assert.deepEqual(observed.body, payload);
});

test("a Content-Length response body is observed byte for byte", async (t) => {
  const payload = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00]);
  const mounted = await mount((response) => {
    response.writeHead(200, ["Content-Length", String(payload.byteLength)]);
    response.end(payload);
  });
  t.after(() => mounted.close());
  const observed = await sendRealHttp(get(mounted, "/sized"));
  assert.equal(observed.headers["content-length"], "5");
  assert.deepEqual(observed.body, payload);
});

test("a HEAD response observes an empty body even when Content-Length is declared", async (t) => {
  const mounted = await mount((response) => {
    response.writeHead(200, ["Content-Length", "11", "Content-Type", "text/plain"]);
    response.end();
  });
  t.after(() => mounted.close());
  const observed = await sendRealHttp({ ...get(mounted, "/head"), method: "HEAD" });
  assert.equal(observed.status, 200);
  assert.equal(observed.headers["content-length"], "11");
  assert.equal(observed.body.byteLength, 0);
});

test("a header block far above the parser default is observed in full", async (t) => {
  const mounted = await mountRaw(
    "HTTP/1.1 200 OK\r\n" + Array.from({ length: 5 }, (_, i) => `x-big-${i}: ${"b".repeat(8192)}`).join("\r\n")
    + "\r\nContent-Length: 2\r\n\r\nok");
  t.after(() => mounted.close());
  const observed = await sendRealHttp(get(mounted, "/wide", 5000));
  assert.equal(observed.status, 200);
  assert.equal(observed.body.toString("utf8"), "ok");
  for (let i = 0; i < 5; i += 1) {
    assert.equal(observed.headers[`x-big-${i}`], "b".repeat(8192));
  }
});

test("a response with two Content-Length header lines is rejected by the parser", async (t) => {
  const mounted = await mountRaw(
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello");
  t.after(() => mounted.close());
  const error = await expectRejection(get(mounted, "/"), WIRE_FAILURE);
  assert.equal(parserCode(error), "HPE_UNEXPECTED_CONTENT_LENGTH");
});

test("a response using obsolete line folding is rejected by the parser", async (t) => {
  const mounted = await mountRaw("HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 0\r\n\r\n");
  t.after(() => mounted.close());
  const error = await expectRejection(get(mounted, "/"), WIRE_FAILURE);
  assert.equal(parserCode(error), "HPE_INVALID_HEADER_TOKEN");
});

test("a response declaring both Transfer-Encoding and Content-Length is rejected", async (t) => {
  const mounted = await mountRaw(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
  t.after(() => mounted.close());
  const error = await expectRejection(get(mounted, "/"), WIRE_FAILURE);
  assert.equal(parserCode(error), "HPE_INVALID_CONTENT_LENGTH");
});

test("a 101 protocol upgrade response is rejected", { timeout: 10000 }, async (t) => {
  const mounted = await mountRaw(
    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
  t.after(() => mounted.close());
  await expectRejection(get(mounted, "/", 1000), "HTTP protocol upgrade responses are unsupported");
});

test("a large response body is observed byte for byte", { timeout: 10000 }, async (t) => {
  const payload = Buffer.alloc(1536 * 1024, 0x61);
  const mounted = await mount((response) => {
    response.writeHead(200, ["Content-Type", "application/octet-stream"]);
    response.end(payload);
  });
  t.after(() => mounted.close());
  const observed = await sendRealHttp(get(mounted, "/big", 5000));
  assert.deepEqual(observed.body, payload);
});
