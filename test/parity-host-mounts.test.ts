import assert from "node:assert/strict";
import { Agent, request, type IncomingHttpHeaders, type OutgoingHttpHeaders } from "node:http";
import { connect, type Socket } from "node:net";
import test from "node:test";
import { Bridge } from "../src/adapters/bridge.ts";
import { createBridgeConfig } from "../src/config.ts";
import { signAccessToken } from "../src/crypto.ts";
import { noopAudit } from "../src/ports/audit.ts";
import { SystemClock } from "../src/ports/clock.ts";
import type { IdentityPort } from "../src/ports/identity.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { RequestAuthorizer } from "../src/verifier.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import { ECHO_PATH, mountHost, type MountedHost } from "./parity/host.ts";
import { privateJwk } from "./parity/keys.ts";
import type { AdapterKind, ProtectedResource } from "./parity/types.ts";

const ISSUER = "https://api.example.com";
const RESOURCE = "https://api.example.com/mcp";
const LISTED_ORIGIN = "https://console.example.com";
const ADAPTERS: AdapterKind[] = ["fastify", "express", "hono"];
const CLOSE_BUDGET_MS = 2_000;

const clock = new SystemClock();
const config = createBridgeConfig({
  issuer: ISSUER, resource: RESOURCE,
  consentSigningSecret: "fixture-only-consent-key-00000003",
  signingPrivateJwk: await privateJwk("keys/signing-private.pem"),
  signingKeyId: "fixture-signing-key-1",
  redirectAllowlist: ["https://client.example.com/callback"], redirectAllowlistMode: "replace",
  scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
  allowedOrigins: [ISSUER, LISTED_ORIGIN], dcr: { mode: "stateless" },
  accessTokenTtlSeconds: 300, refreshTokenTtlSeconds: 3600,
  consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
});
const authorizer = new RequestAuthorizer({ config, clock, audit: noopAudit });
const identity: IdentityPort = {
  async verify() { return { ok: true, identity: { subject: "fixture-subject" } }; },
};
const BEARER = `Bearer ${await signAccessToken(
  { subject: "fixture-subject", clientId: "fixture-client", scopes: ["mcp:read"] }, config, clock,
)}`;

const SUCCESS: ProtectedResource = {
  requiredScope: null,
  success: {
    status: 200,
    headers: {
      "content-type": "application/json",
      "set-cookie": ["first=1", "second=2"],
      "x-repeat": ["a", "b"],
      "X-Fixture-Case": "kept",
    },
    body: { value: { ok: true } },
  },
};

function jsonRpcError(message: string): unknown {
  return { jsonrpc: "2.0", error: { code: -32001, message }, id: null };
}

async function mount(adapter: AdapterKind, protectedResource: ProtectedResource = SUCCESS): Promise<MountedHost> {
  const bridge = new Bridge({ config, store: new MemoryStore(), clock, audit: noopAudit });
  return await mountHost({ adapter, bridge, authorizer, config, identity, protectedResource });
}

interface RawResponse {
  status: number; rawHeaders: string[]; headers: IncomingHttpHeaders; body: Buffer;
}

interface CallOptions {
  method: string; path: string; headers?: Record<string, string | string[]>; body?: string | Buffer; agent?: Agent;
}

/** Raw `node:http` so repeated request headers reach the server as separate
 *  lines and every response header line stays observable in `rawHeaders`.
 *  `content-length` is declared for every body because the Node client frames a
 *  DELETE body neither with a length nor with chunked encoding, which would put
 *  the bytes on the wire as the start of a second request. */
function call(base: string, options: CallOptions): Promise<RawResponse> {
  const url = new URL(options.path, base);
  const headers: Record<string, string | string[]> = { ...options.headers };
  if (options.body !== undefined) headers["content-length"] = String(Buffer.byteLength(options.body));
  return new Promise((resolve, reject) => {
    const outgoing = request({
      hostname: url.hostname, port: url.port, path: `${url.pathname}${url.search}`,
      method: options.method, headers: headers as OutgoingHttpHeaders, timeout: 10_000,
      maxHeaderSize: 131072,
      ...options.agent === undefined ? {} : { agent: options.agent },
    }, (incoming) => {
      const chunks: Buffer[] = [];
      incoming.on("data", (chunk: Buffer) => { chunks.push(chunk); });
      incoming.on("end", () => resolve({
        status: incoming.statusCode ?? 0, rawHeaders: incoming.rawHeaders,
        headers: incoming.headers, body: Buffer.concat(chunks),
      }));
    });
    outgoing.on("timeout", () => outgoing.destroy(new Error(`${options.method} ${options.path} timed out`)));
    outgoing.on("error", reject);
    if (options.body !== undefined) outgoing.write(options.body);
    outgoing.end();
  });
}

function occurrences(rawHeaders: string[], name: string): string[] {
  const values: string[] = [];
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
    if (rawHeaders[index]!.toLowerCase() === name) values.push(rawHeaders[index + 1]!);
  }
  return values;
}

function decoded(response: RawResponse): unknown {
  return JSON.parse(response.body.toString("utf8"));
}

/** Resolve to false instead of hanging when `close` never settles: an
 *  unresolved close is the defect under test, and a hung run reports nothing. */
function settlesWithin(work: Promise<void>, budgetMs: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<boolean>((resolve) => { timer = setTimeout(() => resolve(false), budgetMs); });
  return Promise.race([work.then(() => true), deadline])
    .finally(() => { if (timer !== undefined) clearTimeout(timer); });
}

/** A client that has begun a request and stopped. The connection is neither
 *  idle nor complete, so Node's own `close()` waits on it forever; only
 *  destroying live sockets ends the wait. */
function stalledSocket(base: string): Promise<Socket> {
  const url = new URL(base);
  return new Promise((resolve, reject) => {
    const socket = connect(Number(url.port), url.hostname, () => {
      socket.write(`GET /mcp HTTP/1.1\r\nhost: ${url.host}\r\n`);
      setTimeout(() => resolve(socket), 100);
    });
    socket.on("data", () => {});
    socket.on("error", reject);
  });
}

for (const adapter of ADAPTERS) {
  test(`the ${adapter} mount serves the library's authorization-server metadata`, async () => {
    const host = await mount(adapter);
    try {
      const response = await call(host.base, { method: "GET", path: "/.well-known/oauth-authorization-server" });
      assert.equal(response.status, 200);
      assert.equal((decoded(response) as { issuer: string }).issuer, ISSUER);
      assert.equal(host.failure(), undefined);
    } finally { await host.close(); }
  });

  test(`the ${adapter} mount writes the fixture success status, header occurrences, and body bytes`, async () => {
    const host = await mount(adapter);
    try {
      const response = await call(host.base, {
        method: "POST", path: "/mcp", headers: { authorization: BEARER, origin: ISSUER },
      });
      assert.equal(response.status, 200);
      assert.deepEqual(occurrences(response.rawHeaders, "set-cookie"), ["first=1", "second=2"]);
      assert.deepEqual(occurrences(response.rawHeaders, "x-repeat"), ["a", "b"]);
      assert.deepEqual(occurrences(response.rawHeaders, "content-type"), ["application/json"]);
      assert.ok(response.rawHeaders.includes("X-Fixture-Case"), "the declared header name reaches the wire unchanged");
      assert.equal(response.body.toString("utf8"), '{"ok":true}');
      assert.equal(host.failure(), undefined);
    } finally { await host.close(); }
  });

  test(`the ${adapter} mount refuses an unlisted Origin on every method before reading a body`, async () => {
    const host = await mount(adapter);
    try {
      for (const method of ["POST", "DELETE"]) {
        const response = await call(host.base, {
          method, path: "/mcp",
          headers: { authorization: BEARER, origin: "https://evil.example.com", "content-type": "text/plain" },
          body: "this body is not JSON and is never parsed",
        });
        assert.equal(response.status, 403, `${method} /mcp reached the Origin gate`);
        assert.deepEqual(decoded(response), jsonRpcError("Origin not allowed"));
      }
      assert.equal(host.failure(), undefined);
    } finally { await host.close(); }
  });

  test(`the ${adapter} mount refuses two Origin occurrences as ambiguous`, async () => {
    const host = await mount(adapter);
    try {
      const response = await call(host.base, {
        method: "GET", path: "/mcp", headers: { authorization: BEARER, origin: [ISSUER, LISTED_ORIGIN] },
      });
      assert.equal(response.status, 403);
      assert.deepEqual(decoded(response), jsonRpcError("Origin not allowed"));
      assert.equal(host.failure(), undefined);
    } finally { await host.close(); }
  });

  test(`the ${adapter} mount answers 500 and records the error when the fixture has no success response`, async () => {
    const host = await mount(adapter, { requiredScope: null });
    try {
      const response = await call(host.base, {
        method: "POST", path: "/mcp", headers: { authorization: BEARER },
      });
      assert.equal(response.status, 500);
      assert.deepEqual(decoded(response), jsonRpcError("fixture host failure"));
      const failure = host.failure();
      assert.ok(failure instanceof FixtureRunnerError);
      assert.match(failure.message, /protectedResource\.success/);
    } finally { await host.close(); }
  });

  test(`the ${adapter} mount closes promptly while clients still hold sockets open`, async () => {
    const host = await mount(adapter);
    const agent = new Agent({ keepAlive: true });
    const stalled = await stalledSocket(host.base);
    try {
      const response = await call(host.base, {
        method: "GET", path: "/.well-known/oauth-authorization-server",
        headers: { connection: "keep-alive" }, agent,
      });
      assert.equal(response.status, 200);
      const closed = await settlesWithin(host.close(), CLOSE_BUDGET_MS);
      assert.ok(closed, `close was still pending ${CLOSE_BUDGET_MS}ms after it was called`);
    } finally { stalled.destroy(); agent.destroy(); await host.close(); }
  });
}

test("the hono mount echoes a body larger than 1 MiB byte for byte", async () => {
  const host = await mount("hono");
  try {
    const body = Buffer.alloc(1_048_576 + 1);
    for (let index = 0; index < body.length; index += 1) body[index] = index % 251;
    const response = await call(host.base, { method: "POST", path: ECHO_PATH, body });
    assert.equal(response.status, 200);
    assert.ok(response.body.equals(body), "the exact request bytes arrive at the body-reading route");
    assert.equal(host.failure(), undefined);
  } finally { await host.close(); }
});

test("the hono dispatcher records a throw outside the routes and answers a bare 500", async () => {
  const host = await mount("hono");
  try {
    const response = await call(host.base, {
      method: "GET", path: "/mcp", headers: { host: "fixture host with a space" },
    });
    assert.equal(response.status, 500);
    assert.equal(response.body.byteLength, 0, "a dispatcher throw is answered bare, not as a JSON-RPC document");
    const failure = host.failure();
    assert.ok(failure instanceof Error);
    assert.match(failure.message, /URL/u);
  } finally { await host.close(); }
});
