import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import type { Bridge } from "../src/adapters/bridge.ts";
import { FASTIFY_PAIRING_AUTHORIZE_RATE_LIMIT } from "../src/adapters/fastify.ts";
import {
  handlePairingAuthorize, PAIRING_AUTHORIZE_MAX_REQUESTS, PAIRING_AUTHORIZE_WINDOW_MS,
} from "../src/adapters/pairing-flow.ts";
import type { NormRequest } from "../src/adapters/http.ts";
import type { ConsolePairingIdentity } from "../src/identity/console-pairing.ts";

class Pairing implements ConsolePairingIdentity {
  beginCalls = 0;
  verifyCalls = 0;
  async beginSession() {
    this.beginCalls += 1;
    return { nonce: "pairing-nonce", expiresAt: "2026-08-15T12:10:00.000Z" };
  }
  async verify() {
    this.verifyCalls += 1;
    return { ok: true as const, identity: { subject: "operator" } };
  }
}

function request(ip: string, body: unknown = undefined): NormRequest {
  return { query: {}, body, headers: {}, ip };
}

test("pairing authorize hard cap covers GET and POST before pairing or Bridge effects", async () => {
  assert.deepEqual(FASTIFY_PAIRING_AUTHORIZE_RATE_LIMIT, {
    max: PAIRING_AUTHORIZE_MAX_REQUESTS, timeWindow: PAIRING_AUTHORIZE_WINDOW_MS,
  });
  const pairing = new Pairing();
  const bridge = {
    config: { resource: "https://api.test/mcp" },
    guardPairingAuthorize: async () => {},
  } as unknown as Bridge;
  for (let count = 0; count < PAIRING_AUTHORIZE_MAX_REQUESTS; count += 1) {
    const admitted = await handlePairingAuthorize(
      { bridge, pairing }, "GET", request(`203.0.113.${count}`),
    );
    assert.equal(admitted.status, 200);
  }
  assert.equal(pairing.beginCalls, PAIRING_AUTHORIZE_MAX_REQUESTS);

  const deniedGet = await handlePairingAuthorize(
    { bridge, pairing }, "GET", request("198.51.100.1"),
  );
  assert.equal(deniedGet.status, 429);
  assert.deepEqual(deniedGet.body, {
    error: "temporarily_unavailable", error_description: "Too many requests",
  });
  assert.equal(deniedGet.redirect, undefined);
  assert.equal(
    pairing.beginCalls, PAIRING_AUTHORIZE_MAX_REQUESTS,
    "denial precedes session creation and code output",
  );

  const deniedPost = await handlePairingAuthorize(
    { bridge, pairing }, "POST", request("198.51.100.2", {
      pairing_code: "BBBB-BBBB-BBBB", pairing_nonce: "pairing-nonce",
    }),
  );
  assert.equal(deniedPost.status, 429);
  assert.equal(pairing.verifyCalls, 0, "denial precedes code verification and Bridge authorization");
  assert.equal(pairing.beginCalls, PAIRING_AUTHORIZE_MAX_REQUESTS);
});

test("pairing authorize window resets exactly and clock rollback fails closed", async (t) => {
  let now = 1_000_000;
  t.mock.method(Date, "now", () => now);
  const bridge = {
    config: { resource: "https://api.test/mcp" },
    guardPairingAuthorize: async () => {},
  } as unknown as Bridge;
  const saturated = new Pairing();
  for (let count = 0; count < PAIRING_AUTHORIZE_MAX_REQUESTS; count += 1) {
    assert.equal((await handlePairingAuthorize(
      { bridge, pairing: saturated }, "GET", request("127.0.0.1"),
    )).status, 200);
  }
  assert.equal((await handlePairingAuthorize(
    { bridge, pairing: saturated }, "GET", request("127.0.0.1"),
  )).status, 429);
  now += PAIRING_AUTHORIZE_WINDOW_MS - 1;
  assert.equal((await handlePairingAuthorize(
    { bridge, pairing: saturated }, "GET", request("127.0.0.1"),
  )).status, 429);
  now += 1;
  assert.equal((await handlePairingAuthorize(
    { bridge, pairing: saturated }, "GET", request("127.0.0.1"),
  )).status, 200);

  const rollback = new Pairing();
  now = 2_000_000;
  assert.equal((await handlePairingAuthorize(
    { bridge, pairing: rollback }, "GET", request("127.0.0.1"),
  )).status, 200);
  now -= 1;
  assert.equal((await handlePairingAuthorize(
    { bridge, pairing: rollback }, "GET", request("127.0.0.1"),
  )).status, 429);
  assert.equal(rollback.beginCalls, 1, "rollback denial precedes pairing work");
  now = 2_000_000 + PAIRING_AUTHORIZE_WINDOW_MS;
  assert.equal((await handlePairingAuthorize(
    { bridge, pairing: rollback }, "GET", request("127.0.0.1"),
  )).status, 200);
  assert.equal(rollback.beginCalls, 2);
});

test("every shipped Fastify pairing route attaches the shared rate-limit metadata", () => {
  const files = [
    new URL("../examples/api-key-gateway/app.ts", import.meta.url),
    new URL("../examples/fastify-sqlite/app.ts", import.meta.url),
    new URL("../src/bin/templates.ts", import.meta.url),
  ];
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    assert.match(source, /import\s*\{[^}]*FASTIFY_PAIRING_AUTHORIZE_RATE_LIMIT[^}]*\}\s*from/s);
    assert.equal(
      source.match(/config:\s*\{\s*rateLimit:\s*FASTIFY_PAIRING_AUTHORIZE_RATE_LIMIT\s*\}/g)?.length,
      2,
      `${file.pathname} protects pairing GET and POST`,
    );
  }
});
