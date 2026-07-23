import assert from "node:assert/strict";
import { test } from "node:test";
import Fastify from "fastify";
import type { Bridge } from "../src/adapters/bridge.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import { createOAuthApp } from "../src/adapters/hono.ts";
import type { NormRequest, NormResponse } from "../src/adapters/http.ts";

const FORM = "client_id=first&client_id=second&scope=one";

function bridgeProbe(onToken: (request: NormRequest) => void): Bridge {
  const response: NormResponse = { status: 400, headers: {}, body: { error: "probe" } };
  return {
    config: { resource: "https://api.test/mcp" },
    async handleAuthorizationServerMetadata() { return response; },
    async handleProtectedResourceMetadata() { return response; },
    async handleJwks() { return response; },
    async handleRegister() { return response; },
    async handleApprove() { return response; },
    async handleRevoke() { return response; },
    async handleToken(request: NormRequest) { onToken(request); return response; },
  } as unknown as Bridge;
}

function assertPreserved(body: unknown): void {
  assert.ok(body && typeof body === "object");
  assert.deepEqual((body as Record<string, unknown>).client_id, ["first", "second"]);
  assert.equal((body as Record<string, unknown>).scope, "one");
}

test("fastify adapter preserves repeated form fields for core rejection", async () => {
  let captured: unknown;
  const app = Fastify();
  await registerOAuthRoutes(app, {
    bridge: bridgeProbe((request) => { captured = request.body; }), skipAuthorize: true,
  });
  try {
    await app.inject({
      method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" }, payload: FORM,
    });
    assertPreserved(captured);
  } finally { await app.close(); }
});

test("fastify skipAuthorize preserves forms for the caller-owned authorize route", async () => {
  let captured: unknown;
  const app = Fastify();
  await registerOAuthRoutes(app, { bridge: bridgeProbe(() => {}), skipAuthorize: true });
  app.post("/oauth/authorize", async (request) => {
    captured = request.body;
    return { ok: true };
  });
  try {
    const response = await app.inject({
      method: "POST", url: "/oauth/authorize",
      headers: { "content-type": "application/x-www-form-urlencoded" }, payload: FORM,
    });
    assert.equal(response.statusCode, 200);
    assertPreserved(captured);
  } finally { await app.close(); }
});

test("fastify OAuth parsing is isolated from an existing parent form parser", async () => {
  let captured: unknown;
  const app = Fastify();
  app.addContentTypeParser(
    "application/x-www-form-urlencoded", { parseAs: "string" },
    (_request, body, done) => done(null, Object.fromEntries(new URLSearchParams(String(body)))),
  );
  await registerOAuthRoutes(app, {
    bridge: bridgeProbe((request) => { captured = request.body; }),
    identity: { async verify() { return { ok: true, identity: { subject: "user" } }; } },
  });
  try {
    await app.inject({
      method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" }, payload: FORM,
    });
    assertPreserved(captured);
  } finally { await app.close(); }
});

test("fastify skipAuthorize rejects a parent form parser before adding routes", async () => {
  const app = Fastify();
  app.addContentTypeParser(
    "application/x-www-form-urlencoded", { parseAs: "string" },
    (_request, body, done) => done(null, Object.fromEntries(new URLSearchParams(String(body)))),
  );
  try {
    await assert.rejects(
      registerOAuthRoutes(app, { bridge: bridgeProbe(() => {}), skipAuthorize: true }),
      /duplicate-preserving form parser/,
    );
    assert.equal(app.hasRoute({
      method: "GET", url: "/.well-known/oauth-authorization-server",
    }), false);
  } finally { await app.close(); }
});

test("fastify rejects an invalid authorize mode before mutating the app", async () => {
  const app = Fastify();
  try {
    await assert.rejects(
      registerOAuthRoutes(app, { bridge: bridgeProbe(() => {}) }),
      /identity is required/,
    );
    assert.equal(app.hasContentTypeParser("application/x-www-form-urlencoded"), false);
    assert.equal(app.hasRoute({
      method: "GET", url: "/.well-known/oauth-authorization-server",
    }), false);
  } finally { await app.close(); }
});

test("fastify rejects a malformed bridge before mutating the app", async () => {
  const app = Fastify();
  try {
    await assert.rejects(
      registerOAuthRoutes(app, { bridge: {} as Bridge, skipAuthorize: true }),
      /bridge is invalid/,
    );
    assert.equal(app.hasContentTypeParser("application/x-www-form-urlencoded"), false);
    assert.equal(app.hasRoute({
      method: "GET", url: "/.well-known/oauth-authorization-server",
    }), false);
  } finally { await app.close(); }
});

test("hono adapter preserves repeated form fields for core rejection", async () => {
  let captured: unknown;
  const app = createOAuthApp({
    bridge: bridgeProbe((request) => { captured = request.body; }), skipAuthorize: true,
  });
  await app.request("/oauth/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: FORM,
  });
  assertPreserved(captured);
});
