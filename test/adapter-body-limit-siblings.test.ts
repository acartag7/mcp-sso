import assert from "node:assert/strict";
import { test } from "node:test";
import express from "express";
import Fastify from "fastify";
import type { Bridge } from "../src/adapters/bridge.ts";
import { createOAuthRouter } from "../src/adapters/express.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import type { NormRequest, NormResponse } from "../src/adapters/http.ts";

function bridgeHarness(): { bridge: Bridge; calls: number[] } {
  const calls: number[] = [];
  const receive = async (_request: NormRequest): Promise<NormResponse> => {
    calls.push(1);
    return { status: 200, headers: {}, body: { ok: true } };
  };
  const bridge = {
    config: { resource: "https://api.test/mcp" },
    handleRegister: receive,
    handleApprove: receive,
    handleToken: receive,
    handleRevoke: receive,
  } as unknown as Bridge;
  return { bridge, calls };
}

test("fastify sibling: default one-megabyte parser cap rejects before Bridge", async () => {
  const { bridge, calls } = bridgeHarness();
  const app = Fastify();
  await registerOAuthRoutes(app, { bridge, skipAuthorize: true });
  try {
    const response = await app.inject({
      method: "POST",
      url: "/oauth/register",
      headers: { "content-type": "application/json" },
      payload: JSON.stringify({ padding: "x".repeat(1024 * 1024) }),
    });
    assert.equal(response.statusCode, 413);
    assert.deepEqual(calls, []);
  } finally {
    await app.close();
  }
});

test("express sibling: default JSON and URL-encoded parser caps reject before Bridge", async () => {
  const { bridge, calls } = bridgeHarness();
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use("/", createOAuthRouter({ bridge, skipAuthorize: true }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const json = await fetch(`${base}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ padding: "x".repeat(101 * 1024) }),
    });
    assert.equal(json.status, 413);

    const form = await fetch(`${base}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `padding=${"x".repeat(101 * 1024)}`,
    });
    assert.equal(form.status, 413);
    assert.deepEqual(calls, []);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
