import assert from "node:assert/strict";
import { test } from "node:test";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import Fastify from "fastify";
import express from "express";
import { createOAuthRouter } from "../src/adapters/express.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import { createOAuthApp } from "../src/adapters/hono.ts";
import {
  CALLBACK, failingAudit, harness, readableCookieHeader, type FailureMode,
} from "./lib/upstream-audit-failure.ts";

type RejectionMode = FailureMode;
const DUPLICATE_CALLBACK = `${CALLBACK}?state=one&state=two&code=unused`;

async function assertFastifyMapping(mode: RejectionMode): Promise<void> {
  const { bridge, flow } = harness(failingAudit(mode));
  const app = Fastify();
  await registerOAuthRoutes(app, { bridge, upstream: flow });
  try {
  const res = await app.inject({ method: "GET", url: DUPLICATE_CALLBACK, headers: { cookie: readableCookieHeader() } });
    assert.equal(res.statusCode, 400, `fastify ${mode}`);
    assert.match(String(res.headers["set-cookie"] ?? ""), /Max-Age=0/);
    assert.equal(res.headers["cache-control"], "no-store");
  } finally {
    await app.close();
  }
}

async function assertHonoMapping(mode: RejectionMode): Promise<void> {
  const { bridge, flow } = harness(failingAudit(mode));
  const app = createOAuthApp({ bridge, upstream: flow });
  const res = await app.request(DUPLICATE_CALLBACK, { headers: { cookie: readableCookieHeader() } });
  assert.equal(res.status, 400, `hono ${mode}`);
  assert.match(res.headers.get("set-cookie") ?? "", /Max-Age=0/);
  assert.equal(res.headers.get("cache-control"), "no-store");
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

async function assertExpressMapping(mode: RejectionMode): Promise<void> {
  const { bridge, flow } = harness(failingAudit(mode));
  const app = express();
  app.use("/", createOAuthRouter({ bridge, upstream: flow }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const res = await fetch(`${base}${DUPLICATE_CALLBACK}`, {
      redirect: "manual", headers: { cookie: readableCookieHeader() },
    });
    assert.equal(res.status, 400, `express ${mode}`);
    assert.match(res.headers.get("set-cookie") ?? "", /Max-Age=0/);
    assert.equal(res.headers.get("cache-control"), "no-store");
  } finally {
    await closeServer(server);
  }
}

test("callback audit boundary: Fastify, Express, and Hono preserve duplicate-param responses for sync and async sink failure", async () => {
  for (const mode of ["sync", "async"] as const) {
    await assertFastifyMapping(mode);
    await assertExpressMapping(mode);
    await assertHonoMapping(mode);
  }
});
