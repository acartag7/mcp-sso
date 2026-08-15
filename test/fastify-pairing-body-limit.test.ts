import assert from "node:assert/strict";
import { test } from "node:test";
import Fastify from "fastify";
import type { Bridge } from "../src/adapters/bridge.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import { OAUTH_POST_BODY_MAX_BYTES } from "../src/adapters/http.ts";

const WIDE_BODY_LIMIT = OAUTH_POST_BODY_MAX_BYTES * 2;

function bridgeHarness(): Bridge {
  return { config: { resource: "https://api.test/mcp" } } as Bridge;
}

test("Fastify preserves automatic bounded form parsing for a caller-owned pairing POST", async () => {
  const app = Fastify({ bodyLimit: WIDE_BODY_LIMIT });
  let calls = 0;
  let body: unknown;
  try {
    await registerOAuthRoutes(app, { bridge: bridgeHarness(), skipAuthorize: true });
    app.post("/oauth/authorize", { bodyLimit: WIDE_BODY_LIMIT }, async (request, reply) => {
      calls += 1;
      body = request.body;
      await reply.code(204).send();
    });

    const admitted = await app.inject({
      method: "POST", url: "/oauth/authorize",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: "pairing_code=BBBB-BBBB-BBBB&pairing_nonce=nonce",
    });
    assert.equal(admitted.statusCode, 204);
    assert.equal(Object.getPrototypeOf(body), null);
    assert.deepEqual({ ...(body as object) }, { pairing_code: "BBBB-BBBB-BBBB", pairing_nonce: "nonce" });

    const denied = await app.inject({
      method: "POST", url: "/oauth/authorize",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: `padding=${"x".repeat(OAUTH_POST_BODY_MAX_BYTES)}`,
    });
    assert.equal(denied.statusCode, 413);
    assert.equal(calls, 1, "the caller's larger route limit cannot widen the OAuth cap");
  } finally {
    await app.close();
  }
});

test("Fastify clamps caller parsers only on the exact pairing POST", async () => {
  const app = Fastify({ bodyLimit: WIDE_BODY_LIMIT });
  let pairingCalls = 0;
  let unrelatedCalls = 0;
  let putCalls = 0;
  app.addContentTypeParser("*", { parseAs: "string" }, (_request, body, done) => {
    done(null, { parsed: String(body) });
  });
  try {
    await registerOAuthRoutes(app, { bridge: bridgeHarness(), skipAuthorize: true });
    app.post("/oauth/authorize", { bodyLimit: WIDE_BODY_LIMIT }, async (_request, reply) => {
      pairingCalls += 1;
      await reply.code(204).send();
    });
    app.post("/other", { bodyLimit: WIDE_BODY_LIMIT }, async (_request, reply) => {
      unrelatedCalls += 1;
      await reply.code(204).send();
    });
    app.put("/oauth/authorize", { bodyLimit: WIDE_BODY_LIMIT }, async (_request, reply) => {
      putCalls += 1;
      await reply.code(204).send();
    });

    const payload = "x".repeat(OAUTH_POST_BODY_MAX_BYTES + 1);
    const pairing = await app.inject({
      method: "POST", url: "/oauth/authorize",
      headers: { "content-type": "application/vnd.example" }, payload,
    });
    assert.equal(pairing.statusCode, 413);
    assert.equal(pairingCalls, 0);

    const unrelated = await app.inject({
      method: "POST", url: "/other",
      headers: { "content-type": "application/vnd.example" }, payload,
    });
    const put = await app.inject({
      method: "PUT", url: "/oauth/authorize",
      headers: { "content-type": "application/vnd.example" }, payload,
    });
    assert.equal(unrelated.statusCode, 204);
    assert.equal(put.statusCode, 204);
    assert.equal(unrelatedCalls, 1);
    assert.equal(putCalls, 1);
  } finally {
    await app.close();
  }
});

test("Fastify preserves a caller-owned stricter pairing limit", async () => {
  const app = Fastify();
  let calls = 0;
  try {
    await registerOAuthRoutes(app, { bridge: bridgeHarness(), skipAuthorize: true });
    app.post("/oauth/authorize", { bodyLimit: 64 }, async (_request, reply) => {
      calls += 1;
      await reply.code(204).send();
    });
    const denied = await app.inject({
      method: "POST", url: "/oauth/authorize",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: `padding=${"x".repeat(64)}`,
    });
    assert.equal(denied.statusCode, 413);
    assert.equal(calls, 0);
  } finally {
    await app.close();
  }
});
