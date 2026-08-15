import assert from "node:assert/strict";
import { test } from "node:test";
import express from "express";
import type { Bridge } from "../src/adapters/bridge.ts";
import {
  createOAuthRouter, EXPRESS_OAUTH_BODY_MAX_BYTES,
} from "../src/adapters/express.ts";
import { OAUTH_POST_BODY_MAX_BYTES } from "../src/adapters/http.ts";

test("Express preserves its budget export and bounds a caller-owned pairing POST", async () => {
  assert.equal(EXPRESS_OAUTH_BODY_MAX_BYTES, OAUTH_POST_BODY_MAX_BYTES);
  const bridge = { config: { resource: "https://api.test/mcp" } } as Bridge;
  const app = express();
  let pairingCalls = 0;
  let pairingBody: unknown;
  app.use("/", createOAuthRouter({ bridge, skipAuthorize: true }));
  app.post("/oauth/authorize", (request, response) => {
    pairingCalls += 1;
    pairingBody = request.body;
    response.status(204).end();
  });
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const admitted = await fetch(`${base}/oauth/authorize`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "pairing_code=BBBB-BBBB-BBBB&pairing_nonce=nonce",
    });
    assert.equal(admitted.status, 204);
    assert.deepEqual(pairingBody, { pairing_code: "BBBB-BBBB-BBBB", pairing_nonce: "nonce" });

    const overCapBodies = [
      { contentType: "application/json", body: JSON.stringify({ padding: "x".repeat(OAUTH_POST_BODY_MAX_BYTES) }) },
      { contentType: "application/x-www-form-urlencoded", body: `padding=${"x".repeat(OAUTH_POST_BODY_MAX_BYTES)}` },
      { contentType: "application/octet-stream", body: "x".repeat(OAUTH_POST_BODY_MAX_BYTES + 1) },
      { contentType: "multipart/form-data; boundary=example", body: "x".repeat(OAUTH_POST_BODY_MAX_BYTES + 1) },
    ];
    for (const requestBody of overCapBodies) {
      const denied = await fetch(`${base}/oauth/authorize`, {
        method: "POST", headers: { "content-type": requestBody.contentType }, body: requestBody.body,
      });
      assert.equal(denied.status, 413, requestBody.contentType);
      assert.deepEqual(await denied.json(), {
        error: "invalid_request", error_description: "Request body is too large",
      });
    }
    assert.equal(pairingCalls, 1, "over-cap bodies are denied before the caller handler");
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
