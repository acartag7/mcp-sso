// Wire behaviors every adapter mount must answer identically: the authorize
// failure with its challenge, the 204 bodyless success, and the failure
// document a rendering error produces.

import assert from "node:assert/strict";
import { request, type IncomingHttpHeaders, type OutgoingHttpHeaders } from "node:http";
import { connect, type Socket } from "node:net";
import test from "node:test";
import { Bridge } from "../src/adapters/bridge.ts";
import { buildUnauthorizedChallenge } from "../src/challenge.ts";
import { createBridgeConfig } from "../src/config.ts";
import { signAccessToken } from "../src/crypto.ts";
import { noopAudit } from "../src/ports/audit.ts";
import { SystemClock } from "../src/ports/clock.ts";
import type { IdentityPort } from "../src/ports/identity.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { RequestAuthorizer } from "../src/verifier.ts";
import { mountHost, type MountedHost } from "./parity/host.ts";
import { privateJwk } from "./parity/keys.ts";
import type { AdapterKind, ProtectedResource } from "./parity/types.ts";

const ISSUER = "https://api.example.com";
const RESOURCE = "https://api.example.com/mcp";
const ADAPTERS: AdapterKind[] = ["fastify", "express", "hono"];
const clock = new SystemClock();
const config = createBridgeConfig({
  issuer: ISSUER, resource: RESOURCE,
  consentSigningSecret: "fixture-only-consent-key-00000004",
  signingPrivateJwk: await privateJwk("keys/signing-private.pem"),
  signingKeyId: "fixture-signing-key-1",
  redirectAllowlist: ["https://client.example.com/callback"], redirectAllowlistMode: "replace",
  scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
  allowedOrigins: [ISSUER], dcr: { mode: "stateless" },
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
const CHALLENGE = buildUnauthorizedChallenge(config, {
  scope: config.scopeCatalog, error: "invalid_token", errorDescription: "Bearer token is required",
});

type SuccessBody = NonNullable<ProtectedResource["success"]>["body"];

function success(status: number, headers: Record<string, string>, body: SuccessBody = { absent: true }): ProtectedResource {
  return { requiredScope: null, success: { status, headers, body } };
}

interface RawResponse {
  status: number; rawHeaders: string[]; headers: IncomingHttpHeaders; body: Buffer;
}

function call(base: string, options: {
  method: string; path: string; headers?: Record<string, string>;
}): Promise<RawResponse> {
  const url = new URL(options.path, base);
  return new Promise((resolve, reject) => {
    const outgoing = request({
      hostname: url.hostname, port: url.port, path: url.pathname, method: options.method,
      maxHeaderSize: 131072,
      headers: options.headers as OutgoingHttpHeaders, timeout: 10_000,
    }, (incoming) => {
      const chunks: Buffer[] = [];
      incoming.on("data", (chunk: Buffer) => { chunks.push(chunk); });
      incoming.on("end", () => resolve({
        status: incoming.statusCode ?? 0, rawHeaders: incoming.rawHeaders,
        headers: incoming.headers, body: Buffer.concat(chunks),
      }));
    });
    outgoing.on("timeout", () => outgoing.destroy(new Error("timed out")));
    outgoing.on("error", reject);
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

function jsonRpcError(message: string): unknown {
  return { jsonrpc: "2.0", error: { code: -32001, message }, id: null };
}

for (const adapter of ADAPTERS) {
  test(`${adapter}: /mcp without a bearer answers 401 with the library challenge`, async (t) => {
    const host = await (async () => {
      const bridge = new Bridge({ config, store: new MemoryStore(), clock, audit: noopAudit });
      return await mountHost({ adapter, bridge, authorizer, config, identity, protectedResource: success(204, {}) });
    })();
    t.after(() => host.close());
    const response = await call(host.base, { method: "GET", path: "/mcp", headers: { origin: ISSUER } });
    assert.equal(response.status, 401);
    assert.deepEqual(occurrences(response.rawHeaders, "www-authenticate"), [CHALLENGE]);
    assert.deepEqual(JSON.parse(response.body.toString("utf8")), jsonRpcError("invalid_token: Bearer token is required"));
  });

  test(`${adapter}: a success header the adapter cannot render answers the failure document`, async (t) => {
    const host = await (async () => {
      const bridge = new Bridge({ config, store: new MemoryStore(), clock, audit: noopAudit });
      return await mountHost({
        adapter, bridge, authorizer, config, identity,
        protectedResource: success(200, { "x-unrenderable": "a\u0000b" }),
      });
    })();
    t.after(() => host.close());
    const response = await call(host.base, {
      method: "POST", path: "/mcp", headers: { authorization: BEARER },
    });
    assert.equal(response.status, 500);
    assert.deepEqual(JSON.parse(response.body.toString("utf8")), jsonRpcError("fixture host failure"));
    assert.ok(host.failure(), "the rendering error was not recorded");
  });

  test(`${adapter}: a schema-valid multibyte success header above the platform default is observed`, async (t) => {
    const host = await (async () => {
      const bridge = new Bridge({ config, store: new MemoryStore(), clock, audit: noopAudit });
      return await mountHost({
        adapter, bridge, authorizer, config, identity,
        protectedResource: success(200, {
          "x-multibyte": "é".repeat(8192), "x-second": "é".repeat(8192),
        }, { absent: true }),
      });
    })();
    t.after(() => host.close());
    const response = await call(host.base, {
      method: "POST", path: "/mcp", headers: { authorization: BEARER },
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers["x-multibyte"], "é".repeat(8192));
    assert.equal(response.headers["x-second"], "é".repeat(8192));
  });

  test(`${adapter}: a declared content-length that mismatches the encoded body fails the run`, async (t) => {
    const host = await (async () => {
      const bridge = new Bridge({ config, store: new MemoryStore(), clock, audit: noopAudit });
      return await mountHost({
        adapter, bridge, authorizer, config, identity,
        protectedResource: {
          requiredScope: null,
          success: { status: 200, headers: { "content-length": "1" }, body: { value: "ok" } },
        },
      });
    })();
    t.after(() => host.close());
    const response = await call(host.base, {
      method: "POST", path: "/mcp", headers: { authorization: BEARER },
    });
    assert.equal(response.status, 500);
    assert.deepEqual(JSON.parse(response.body.toString("utf8")), jsonRpcError("fixture host failure"));
    assert.match(String(host.failure()?.message), /content-length/u);

    const hanging = await call(host.base, {
      method: "POST", path: "/mcp", headers: { authorization: BEARER },
    });
    assert.equal(hanging.status, 500);
  });

  test(`${adapter}: repeated success occurrences survive HEAD through every mount`, async (t) => {
    const host = await (async () => {
      const bridge = new Bridge({ config, store: new MemoryStore(), clock, audit: noopAudit });
      return await mountHost({
        adapter, bridge, authorizer, config, identity,
        protectedResource: {
          requiredScope: null,
          success: {
            status: 200,
            headers: { "content-type": "application/json", "x-repeat": ["a", "b"] },
            body: { value: { ok: true } },
          },
        },
      });
    })();
    t.after(() => host.close());
    const response = await call(host.base, {
      method: "HEAD", path: "/mcp", headers: { authorization: BEARER },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(occurrences(response.rawHeaders, "x-repeat"), ["a", "b"]);
  });

  test(`${adapter}: duplicate content-length occurrences fail the run`, async (t) => {
    const host = await (async () => {
      const bridge = new Bridge({ config, store: new MemoryStore(), clock, audit: noopAudit });
      return await mountHost({
        adapter, bridge, authorizer, config, identity,
        protectedResource: {
          requiredScope: null,
          success: { status: 200, headers: { "content-length": ["2", "2"] }, body: { value: "ok" } },
        },
      });
    })();
    t.after(() => host.close());
    const response = await call(host.base, {
      method: "POST", path: "/mcp", headers: { authorization: BEARER },
    });
    assert.equal(response.status, 500);
    assert.deepEqual(JSON.parse(response.body.toString("utf8")), jsonRpcError("fixture host failure"));
    assert.match(String(host.failure()?.message), /content-length/u);
  });

  test(`${adapter}: a declared length equal to the encoded body still fails a bodyless status`, async (t) => {
    const host = await (async () => {
      const bridge = new Bridge({ config, store: new MemoryStore(), clock, audit: noopAudit });
      return await mountHost({
        adapter, bridge, authorizer, config, identity,
        protectedResource: {
          requiredScope: null,
          success: { status: 205, headers: { "content-length": "7" }, body: { value: "dropped" } },
        },
      });
    })();
    t.after(() => host.close());
    const response = await call(host.base, {
      method: "POST", path: "/mcp", headers: { authorization: BEARER },
    });
    assert.equal(response.status, 500);
    assert.deepEqual(JSON.parse(response.body.toString("utf8")), jsonRpcError("fixture host failure"));
    assert.match(String(host.failure()?.message), /content-length/u);
  });

  test(`${adapter}: a 205 success carries no entity bytes on the wire`, async (t) => {
    const host = await (async () => {
      const bridge = new Bridge({ config, store: new MemoryStore(), clock, audit: noopAudit });
      return await mountHost({
        adapter, bridge, authorizer, config, identity,
        protectedResource: success(205, { "content-type": "text/plain" }, { value: "dropped" }),
      });
    })();
    t.after(() => host.close());
    const response = await call(host.base, {
      method: "POST", path: "/mcp", headers: { authorization: BEARER },
    });
    assert.equal(response.status, 205);
    assert.equal(response.body.byteLength, 0);
  });
  test(`${adapter}: a 204 success renders as 204 with an empty body`, async (t) => {
    const host = await (async () => {
      const bridge = new Bridge({ config, store: new MemoryStore(), clock, audit: noopAudit });
      return await mountHost({
        adapter, bridge, authorizer, config, identity,
        protectedResource: success(204, { "content-type": "text/plain" }, { value: "dropped" }),
      });
    })();
    t.after(() => host.close());
    const response = await call(host.base, {
      method: "POST", path: "/mcp", headers: { authorization: BEARER },
    });
    assert.equal(response.status, 204);
    assert.equal(response.body.byteLength, 0);
  });
}

for (const adapter of ADAPTERS) {
  test(`${adapter}: a request header block far above the parser default reaches the mount`, async (t) => {
    const host = await (async () => {
      const bridge = new Bridge({ config, store: new MemoryStore(), clock, audit: noopAudit });
      return await mountHost({ adapter, bridge, authorizer, config, identity, protectedResource: success(204, {}) });
    })();
    t.after(() => host.close());
    const response = await call(host.base, {
      method: "GET", path: "/mcp",
      headers: { authorization: BEARER, "x-big": "b".repeat(30000) },
    });
    assert.equal(response.status, 204);
  });
}

test("the hono mount answers the Origin gate before the request body arrives", async (t) => {
  const host = await (async () => {
    const bridge = new Bridge({ config, store: new MemoryStore(), clock, audit: noopAudit });
    return await mountHost({
      adapter: "hono", bridge, authorizer, config, identity, protectedResource: success(204, {}),
    });
  })();
  t.after(() => host.close());
  const url = new URL("/mcp", host.base);
  const socket: Socket = await new Promise((resolve, reject) => {
    const open = connect(Number(url.port), url.hostname, () => resolve(open));
    open.on("error", reject);
  });
  t.after(() => { socket.destroy(); });
  socket.write(`POST /mcp HTTP/1.1\r\nhost: ${url.host}\r\norigin: https://evil.example.com\r\ncontent-type: text/plain\r\ncontent-length: 1024\r\n\r\nonly-half`);
  const answered = await new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => resolve(false), 1500);
    socket.on("data", (chunk: Buffer) => { clearTimeout(timer); resolve(chunk.toString("latin1").startsWith("HTTP/1.1 403")); });
    socket.on("error", () => { clearTimeout(timer); resolve(false); });
  });
  assert.equal(answered, true, "the 403 did not arrive while the declared body was still unfinished");
});
