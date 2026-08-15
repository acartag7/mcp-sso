import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import express from "express";
import Fastify from "fastify";
import type { Bridge } from "../src/adapters/bridge.ts";
import { createOAuthRouter } from "../src/adapters/express.ts";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import { OAUTH_POST_BODY_MAX_BYTES, type NormRequest, type NormResponse } from "../src/adapters/http.ts";

const OAUTH_POST_ROUTES = [
  "/oauth/register",
  "/oauth/authorize/approve",
  "/oauth/token",
  "/oauth/revoke",
] as const;

function bridgeHarness(): { bridge: Bridge; calls: number[]; requests: NormRequest[] } {
  const calls: number[] = [];
  const requests: NormRequest[] = [];
  const receive = async (request: NormRequest): Promise<NormResponse> => {
    calls.push(1);
    requests.push(request);
    const bodyIsRecord = typeof request.body === "object" && request.body !== null
      && !Array.isArray(request.body) && !Buffer.isBuffer(request.body);
    return { status: bodyIsRecord ? 200 : 400, headers: {}, body: { ok: bodyIsRecord } };
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

test("OAuth POST body budget has one shared declaration imported by every adapter", () => {
  assert.equal(OAUTH_POST_BODY_MAX_BYTES, 256 * 1024);
  for (const adapter of ["fastify", "express", "hono"]) {
    const source = readFileSync(fileURLToPath(new URL(`../src/adapters/${adapter}.ts`, import.meta.url)), "utf8");
    const declarations = adapter === "express"
      ? source.replace(/export const EXPRESS_OAUTH_BODY_MAX_BYTES = OAUTH_POST_BODY_MAX_BYTES;/, "") : source;
    assert.match(
      declarations,
      /import\s*\{[^}]*\bOAUTH_POST_BODY_MAX_BYTES\b[^}]*\}\s*from "\.\/http\.ts";/s,
      `${adapter} imports the shared budget`,
    );
    assert.doesNotMatch(
      declarations,
      /\b(?:export\s+)?const\s+\w*(?:BODY_MAX_BYTES|BODY_LIMIT_BYTES|BODY_BYTE_LIMIT)\w*\s*=/i,
      `${adapter} must not declare a local body-budget constant`,
    );
    assert.doesNotMatch(
      source,
      /(?:256\s*\*\s*1024|262_?144)/,
      `${adapter} must not duplicate the shared budget as a numeric literal`,
    );
  }
});

test("fastify OAuth POST routes enforce the shared budget for every content-type parser", async () => {
  const { bridge, calls, requests } = bridgeHarness();
  const app = Fastify();
  app.addContentTypeParser("application/vnd.example", { parseAs: "string" }, (_req, body, done) => done(null, body));
  await registerOAuthRoutes(app, { bridge, skipAuthorize: true });
  try {
    const bodies = [
      { contentType: "application/json", payload: JSON.stringify({ padding: "x".repeat(OAUTH_POST_BODY_MAX_BYTES) }) },
      { contentType: "application/x-www-form-urlencoded", payload: `padding=${"x".repeat(OAUTH_POST_BODY_MAX_BYTES)}` },
      { contentType: "application/octet-stream", payload: Buffer.alloc(OAUTH_POST_BODY_MAX_BYTES + 1) },
      { contentType: "application/vnd.example", payload: "x".repeat(OAUTH_POST_BODY_MAX_BYTES + 1) },
    ];
    for (const route of OAUTH_POST_ROUTES) {
      for (const body of bodies) {
        const response = await app.inject({
          method: "POST", url: route, headers: { "content-type": body.contentType }, payload: body.payload,
        });
        assert.equal(response.statusCode, 413, `${route} ${body.contentType}`);
      }
    }
    assert.deepEqual(calls, []);

    const unsupported = await app.inject({
      method: "POST", url: "/oauth/register",
      headers: { "content-type": "multipart/form-data; boundary=example" },
      payload: "--example\r\ncontent-disposition: form-data; name=redirect_uris\r\n\r\nhttps://client.test/callback\r\n--example--",
    });
    assert.equal(unsupported.statusCode, 400);
    assert.ok(Buffer.isBuffer(requests.at(-1)?.body), "unsupported media reaches Bridge only as non-object bytes");
  } finally {
    await app.close();
  }
});

test("fastify OAuth parser scope preserves caller parsing on unrelated routes", async () => {
  const { bridge, calls } = bridgeHarness();
  const app = Fastify();
  let unrelatedBody: unknown;
  app.addContentTypeParser("*", { parseAs: "string" }, (_req, body, done) => {
    done(null, { source: "caller", body });
  });
  app.post("/other", async (request) => { unrelatedBody = request.body; return { ok: true }; });
  await registerOAuthRoutes(app, { bridge, skipAuthorize: true });
  try {
    const unrelated = await app.inject({
      method: "POST", url: "/other", headers: { "content-type": "application/octet-stream" }, payload: "caller-body",
    });
    assert.deepEqual(unrelated.json(), { ok: true });
    assert.deepEqual(unrelatedBody, { source: "caller", body: "caller-body" });
    const oauth = await app.inject({
      method: "POST", url: "/oauth/register", headers: { "content-type": "application/octet-stream" },
      payload: Buffer.alloc(OAUTH_POST_BODY_MAX_BYTES + 1),
    });
    assert.equal(oauth.statusCode, 413);
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
    assert.ok(Buffer.byteLength(approvalBody) <= OAUTH_POST_BODY_MAX_BYTES);
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
      body: JSON.stringify({ padding: "x".repeat(OAUTH_POST_BODY_MAX_BYTES) }),
    });
    assert.equal(overCap.status, 413);
    assert.deepEqual(await overCap.json(), { error: "invalid_request", error_description: "Request body is too large" });
    assert.deepEqual(calls, [1, 1]);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("express OAuth POST routes enforce the shared budget for every content type", async () => {
  const { bridge, calls, requests } = bridgeHarness();
  const app = express();
  app.use("/", createOAuthRouter({ bridge, skipAuthorize: true }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const bodies = [
      { contentType: "application/json", body: JSON.stringify({ padding: "x".repeat(OAUTH_POST_BODY_MAX_BYTES) }) },
      { contentType: "application/x-www-form-urlencoded", body: `padding=${"x".repeat(OAUTH_POST_BODY_MAX_BYTES)}` },
      { contentType: "application/octet-stream", body: "x".repeat(OAUTH_POST_BODY_MAX_BYTES + 1) },
    ];
    for (const route of OAUTH_POST_ROUTES) {
      for (const requestBody of bodies) {
        const response = await fetch(`${base}${route}`, {
          method: "POST", headers: { "content-type": requestBody.contentType }, body: requestBody.body,
        });
        assert.equal(response.status, 413, `${route} ${requestBody.contentType}`);
        assert.deepEqual(await response.json(), {
          error: "invalid_request", error_description: "Request body is too large",
        });
      }
    }
    assert.deepEqual(calls, []);

    const multipartBody = new FormData();
    multipartBody.set("redirect_uris", "https://client.test/callback");
    const unsupported = await fetch(`${base}/oauth/register`, { method: "POST", body: multipartBody });
    assert.equal(unsupported.status, 400);
    assert.ok(Buffer.isBuffer(requests.at(-1)?.body), "unsupported media reaches Bridge only as non-object bytes");
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("express OAuth parser scope preserves later caller parsing on unrelated routes", async () => {
  const { bridge, calls } = bridgeHarness();
  const app = express();
  let unrelatedBody: unknown;
  app.use("/", createOAuthRouter({ bridge, skipAuthorize: true }));
  app.post("/other", express.text({ type: () => true }), (request, response) => {
    unrelatedBody = request.body;
    response.json({ ok: true });
  });
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const unrelated = await fetch(`${base}/other`, {
      method: "POST", headers: { "content-type": "application/octet-stream" }, body: "caller-body",
    });
    assert.deepEqual(await unrelated.json(), { ok: true });
    assert.equal(unrelatedBody, "caller-body");
    const oauth = await fetch(`${base}/oauth/register`, {
      method: "POST", headers: { "content-type": "application/octet-stream" },
      body: "x".repeat(OAUTH_POST_BODY_MAX_BYTES + 1),
    });
    assert.equal(oauth.status, 413);
    assert.deepEqual(calls, []);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
