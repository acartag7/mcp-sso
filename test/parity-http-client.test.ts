import assert from "node:assert/strict";
import test from "node:test";
import { createServer, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { materializeRequest } from "./parity/captures.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import { sendRealHttp, type RealHttpRequest } from "./parity/http-client.ts";

interface Recorded { method: string; url: string; rawHeaders: string[]; body: Buffer }
interface Mounted {
  base: string;
  host: string;
  recorded: Recorded[];
  connections: number;
  openConnections: number;
  close(): Promise<void>;
}

async function mount(handle: (recorded: Recorded, response: ServerResponse) => void): Promise<Mounted> {
  const recorded: Recorded[] = [];
  const counts = { total: 0, open: 0 };
  const server = createServer((incoming, response) => {
    const chunks: Buffer[] = [];
    incoming.on("data", (chunk: Buffer) => { chunks.push(chunk); });
    incoming.on("end", () => {
      const entry: Recorded = {
        method: incoming.method ?? "", url: incoming.url ?? "",
        rawHeaders: [...incoming.rawHeaders], body: Buffer.concat(chunks),
      };
      recorded.push(entry);
      handle(entry, response);
    });
  });
  server.on("connection", (socket) => {
    counts.total += 1;
    counts.open += 1;
    socket.on("close", () => { counts.open -= 1; });
  });
  await new Promise<void>((resolve) => { server.listen(0, "127.0.0.1", resolve); });
  const { port } = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${port}`, host: `127.0.0.1:${port}`, recorded,
    get connections() { return counts.total; },
    get openConnections() { return counts.open; },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => { server.close(() => { resolve(); }); });
    },
  };
}

function occurrences(rawHeaders: string[], name: string): string[] {
  const values: string[] = [];
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    if (rawHeaders[index]!.toLowerCase() === name) values.push(rawHeaders[index + 1]!);
  }
  return values;
}

async function expectRejection(input: RealHttpRequest, message: string): Promise<void> {
  let caught: unknown;
  try { await sendRealHttp(input); }
  catch (error) { caught = error; }
  assert.ok(caught instanceof FixtureRunnerError, `expected FixtureRunnerError, got ${String(caught)}`);
  assert.equal(caught.message, message);
}

async function waitUntil(condition: () => boolean, limitMs = 2000): Promise<void> {
  const deadline = Date.now() + limitMs;
  while (!condition() && Date.now() < deadline) {
    await new Promise((resolve) => { setTimeout(resolve, 10); });
  }
}

function ok(_recorded: Recorded, response: ServerResponse): void {
  response.writeHead(200, { "content-type": "text/plain" });
  response.end("ok");
}

test("repeated request header occurrences reach the server in wire order", async (t) => {
  const mounted = await mount(ok);
  t.after(() => mounted.close());
  const observed = await sendRealHttp({
    base: mounted.base, method: "POST", path: "/probe", timeoutMs: 2000,
    headers: [["x-probe", "one"], ["host", mounted.host], ["x-probe", "two"], ["connection", "keep-alive"]],
    body: Buffer.from("payload", "utf8"),
  });
  assert.equal(observed.status, 200);
  const record = mounted.recorded[0];
  assert.ok(record);
  assert.deepEqual(occurrences(record.rawHeaders, "x-probe"), ["one", "two"]);
  assert.deepEqual(occurrences(record.rawHeaders, "host"), [mounted.host]);
  assert.deepEqual(occurrences(record.rawHeaders, "connection"), ["keep-alive"]);
  assert.deepEqual(occurrences(record.rawHeaders, "content-length"), ["7"]);
  assert.equal(record.body.toString("utf8"), "payload");
});

test("an omitted Host and Connection are supplied for the mounted server", async (t) => {
  const mounted = await mount(ok);
  t.after(() => mounted.close());
  const observed = await sendRealHttp({
    base: mounted.base, method: "GET", path: "/plain", timeoutMs: 2000, headers: [["x-probe", "one"]],
  });
  assert.equal(observed.status, 200);
  assert.deepEqual(mounted.recorded[0]?.rawHeaders,
    ["Host", mounted.host, "x-probe", "one", "Connection", "close"]);
});

test("a body with no declared framing is sent with an exact Content-Length", async (t) => {
  const mounted = await mount(ok);
  t.after(() => mounted.close());
  await sendRealHttp({
    base: mounted.base, method: "POST", path: "/framed", timeoutMs: 2000,
    headers: [["content-type", "text/plain"]], body: Buffer.from("hello body", "utf8"),
  });
  assert.deepEqual(mounted.recorded[0]?.rawHeaders, [
    "Host", mounted.host, "content-type", "text/plain", "Connection", "close", "Content-Length", "10",
  ]);
  assert.equal(mounted.recorded[0]?.body.toString("utf8"), "hello body");
});

test("a keep-alive request completes on response framing and leaves no open socket",
  { timeout: 10000 }, async (t) => {
  const mounted = await mount((_recorded, response) => { response.writeHead(204); response.end(); });
  t.after(() => mounted.close());
  const started = Date.now();
  const observed = await sendRealHttp({
    base: mounted.base, method: "GET", path: "/none", timeoutMs: 5000,
    headers: [["connection", "keep-alive"]],
  });
  const elapsed = Date.now() - started;
  assert.equal(observed.status, 204);
  assert.ok(elapsed < 1000, `keep-alive exchange took ${elapsed} ms`);
  await waitUntil(() => mounted.openConnections === 0);
  assert.equal(mounted.openConnections, 0);
});

test("an Expect 100-continue request delivers its body and observes the final response",
  { timeout: 10000 }, async (t) => {
  const mounted = await mount((recorded, response) => {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end(`received ${recorded.body.toString("utf8")}`);
  });
  t.after(() => mounted.close());
  const observed = await sendRealHttp({
    base: mounted.base, method: "POST", path: "/expect", timeoutMs: 2000,
    headers: [["expect", "100-continue"], ["content-type", "text/plain"]],
    body: Buffer.from("continue body", "utf8"),
  });
  assert.equal(observed.status, 200);
  assert.equal(observed.body.toString("utf8"), "received continue body");
  assert.equal(mounted.recorded[0]?.body.toString("utf8"), "continue body");
});

test("CR or LF in a header name or value is rejected before connecting", async (t) => {
  const mounted = await mount(ok);
  t.after(() => mounted.close());
  const message = "HTTP request headers cannot contain CR or LF";
  await expectRejection({ base: mounted.base, method: "GET", path: "/",
    headers: [["x-probe", "one\r\nx-injected: two"]] }, message);
  await expectRejection({ base: mounted.base, method: "GET", path: "/",
    headers: [["x-probe", "one\nx-injected: two"]] }, message);
  await expectRejection({ base: mounted.base, method: "GET", path: "/",
    headers: [["x-probe\r\nx-injected", "one"]] }, message);
  assert.equal(mounted.connections, 0);
});

test("CR or LF in the method or path is rejected before connecting", async (t) => {
  const mounted = await mount(ok);
  t.after(() => mounted.close());
  const message = "HTTP request method and path cannot contain CR or LF";
  const target = (method: string, path: string): RealHttpRequest =>
    ({ base: mounted.base, method, path, headers: [] });
  await expectRejection(target("GET", "/a\r\nX-Injected: one"), message);
  await expectRejection(target("GET", "/a\nb"), message);
  await expectRejection(target("GE\r\nT", "/a"), message);
  assert.equal(mounted.connections, 0);
});

test("a path that leaves the mounted host is rejected before connecting", async (t) => {
  const mounted = await mount(ok);
  t.after(() => mounted.close());
  const message = "HTTP request path cannot leave the mounted host";
  const off = (path: string): RealHttpRequest => ({ base: mounted.base, method: "GET", path, headers: [] });
  await expectRejection(off("//169.254.169.254/latest/meta-data"), message);
  await expectRejection(off("http://other.example/oauth/token"), message);
  await expectRejection(off("\\\\169.254.169.254/latest"), message);
  assert.equal(mounted.connections, 0);
});

test("a server that never answers is rejected within the configured timeout",
  { timeout: 10000 }, async (t) => {
  const mounted = await mount(() => {});
  t.after(() => mounted.close());
  const started = Date.now();
  await expectRejection(
    { base: mounted.base, method: "GET", path: "/stall", timeoutMs: 300, headers: [] },
    "HTTP request timed out");
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 3000, `timeout took ${elapsed} ms`);
});

test("an IPv6 loopback base reaches the mounted server without DNS resolution", async (t) => {
  const server = createServer((_incoming, response) => {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("v6");
  });
  await new Promise<void>((resolve) => { server.listen(0, "::1", resolve); });
  t.after(() => { server.closeAllConnections(); return new Promise<void>((resolve) => { server.close(() => { resolve(); }); }); });
  const { port } = server.address() as AddressInfo;
  const observed = await sendRealHttp({
    base: `http://[::1]:${port}`, method: "GET", path: "/v6", timeoutMs: 2000, headers: [],
  });
  assert.equal(observed.status, 200);
  assert.equal(observed.body.toString("utf8"), "v6");
});

test("a materialized fixture request composes into the client input", async (t) => {
  const mounted = await mount((_recorded, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"ok":true}');
  });
  t.after(() => mounted.close());
  const materialized = materializeRequest({
    method: "POST", path: "/oauth/token", headers: { "content-type": "application/json" },
    body: { json: { grant_type: "authorization_code" } },
  }, new Map());
  const observed = await sendRealHttp({ base: mounted.base, ...materialized, timeoutMs: 2000 });
  assert.equal(observed.status, 200);
  assert.equal(mounted.recorded[0]?.url, "/oauth/token");
  assert.equal(mounted.recorded[0]?.body.toString("utf8"), '{"grant_type":"authorization_code"}');
});
