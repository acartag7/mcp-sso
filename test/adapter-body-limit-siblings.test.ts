import assert from "node:assert/strict";
import { test } from "node:test";
import express from "express";
import Fastify from "fastify";
import type { Bridge } from "../src/adapters/bridge.ts";
import { createOAuthRouter } from "../src/adapters/express.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import type { NormRequest, NormResponse } from "../src/adapters/http.ts";

const OAUTH_BODY_LIMIT = 256 * 1024;

function bridgeHarness(): { bridge: Bridge; calls: number[]; requests: NormRequest[] } {
  const calls: number[] = [];
  const requests: NormRequest[] = [];
  const receive = async (request: NormRequest): Promise<NormResponse> => {
    calls.push(1);
    requests.push(request);
    return { status: 200, headers: {}, body: { ok: true } };
  };
  const bridge = {
    config: { resource: "https://api.test/mcp" },
    handleRegister: receive,
    handleApprove: receive,
    handleToken: receive,
    handleRevoke: receive,
  } as unknown as Bridge;
  return { bridge, calls, requests };
}

function escapedMaximumRegistration(): { body: string; redirectUris: string[] } {
  const redirectUri = "https://client.test/" + "a".repeat(2048 - Buffer.byteLength("https://client.test/"));
  const jsonEscaped = (value: string): string => [...value]
    .map((character) => `\\u${character.codePointAt(0)!.toString(16).padStart(4, "0")}`)
    .join("");
  const escapedUri = jsonEscaped(redirectUri);
  const escapedGrantType = jsonEscaped("g".repeat(256));
  const redirectUris = Array(16).fill(redirectUri);
  return {
    body: `{"redirect_uris":[${Array(16).fill(`"${escapedUri}"`).join(",")}],"grant_types":[${Array(32).fill(`"${escapedGrantType}"`).join(",")}]}`,
    redirectUris,
  };
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

test("express OAuth router admits core-bound JSON and consent-sized forms, then rejects over-cap bodies", async () => {
  const { bridge, calls, requests } = bridgeHarness();
  const app = express();
  app.use("/", createOAuthRouter({ bridge, skipAuthorize: true }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const registration = escapedMaximumRegistration();
    assert.equal(Buffer.byteLength(registration.body), 245_939);
    const json = await fetch(`${base}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: registration.body,
    });
    assert.equal(json.status, 200);
    assert.deepEqual((requests[0]!.body as { redirect_uris: string[] }).redirect_uris, registration.redirectUris);

    const consentToken = "x".repeat(192 * 1024 - 1024);
    const approvalBody = new URLSearchParams({ consent_token: consentToken, approved: "true" }).toString();
    assert.ok(Buffer.byteLength(approvalBody) <= OAUTH_BODY_LIMIT);
    const form = await fetch(`${base}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: approvalBody,
    });
    assert.equal(form.status, 200);
    assert.equal((requests[1]!.body as { consent_token: string }).consent_token, consentToken);

    const malformed = await fetch(`${base}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{",
    });
    assert.equal(malformed.status, 400);
    assert.deepEqual(await malformed.json(), { error: "invalid_request", error_description: "Invalid request" });

    const overCap = await fetch(`${base}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ padding: "x".repeat(OAUTH_BODY_LIMIT) }),
    });
    assert.equal(overCap.status, 413);
    assert.deepEqual(await overCap.json(), { error: "invalid_request", error_description: "Request body is too large" });
    assert.deepEqual(calls, [1, 1]);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
