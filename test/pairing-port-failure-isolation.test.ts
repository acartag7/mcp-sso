import assert from "node:assert/strict";
import { test } from "node:test";

import type { Bridge } from "../src/adapters/bridge.ts";
import { handlePairingAuthorize } from "../src/adapters/pairing-flow.ts";
import type { NormRequest, NormResponse } from "../src/adapters/http.ts";
import { OAuthError } from "../src/errors.ts";
import type { ConsolePairingIdentity } from "../src/identity/console-pairing.ts";

const ISSUER = "https://auth.test";
const EXPIRY = "2026-08-16T20:00:00.000Z";

function bridge(): Bridge {
  return {
    config: {
      issuer: ISSUER,
      resource: "https://api.test/mcp",
      allowedOrigins: [ISSUER],
    },
    guardPairingAuthorize: async () => {},
    handleAuthorize: async () => {
      throw new Error("Bridge authorization must not run after a pairing-port failure");
    },
  } as unknown as Bridge;
}

function request(method: "GET" | "POST"): NormRequest {
  if (method === "GET") return { query: {}, body: undefined, headers: {}, ip: "192.0.2.1" };
  return {
    query: {},
    body: { pairing_code: "BBBB-BBBB-BBBB", pairing_nonce: "pairing-nonce" },
    formBody: { pairing_code: "BBBB-BBBB-BBBB", pairing_nonce: "pairing-nonce" },
    headers: { origin: ISSUER, "content-type": "application/x-www-form-urlencoded" },
    ip: "192.0.2.1",
  };
}

function assertInternalError(response: NormResponse): void {
  assert.equal(response.status, 500);
  assert.deepEqual(response.body, {
    error: "internal_error",
    error_description: "OAuth request failed",
  });
  assert.equal(response.redirect, undefined);
  assert.equal(response.headers.location, undefined);
}

function oauthBoom(): never {
  throw new OAuthError(
    "port_selected_code", "port selected description", 418,
    { redirectUri: "https://attacker.test/callback", state: "leak" },
  );
}

test("pairing beginSession throws map to a fixed framework-free response", async () => {
  const pairing: ConsolePairingIdentity = {
    async beginSession() { return oauthBoom(); },
    async verify() { throw new Error("unused"); },
  };
  assertInternalError(await handlePairingAuthorize({ bridge: bridge(), pairing }, "GET", request("GET")));
});

test("pairing beginSession returned accessors stay inside the port boundary", async () => {
  const session = new Proxy({ nonce: "pairing-nonce", expiresAt: EXPIRY }, {
    get(target, property, receiver) {
      if (property === "nonce") return oauthBoom();
      return Reflect.get(target, property, receiver);
    },
  });
  const pairing: ConsolePairingIdentity = {
    async beginSession() { return session; },
    async verify() { throw new Error("unused"); },
  };
  assertInternalError(await handlePairingAuthorize({ bridge: bridge(), pairing }, "GET", request("GET")));
});

test("pairing session snapshots reject the full malformed field class", async (t) => {
  const malformed = [
    null,
    { nonce: "", expiresAt: EXPIRY },
    { nonce: "é".repeat(129), expiresAt: EXPIRY },
    { nonce: "pairing-nonce", expiresAt: "2026-13-16T20:00:00.000Z" },
    { nonce: "pairing-nonce", expiresAt: "2026-08-16T20:00:00Z" },
  ];
  for (const [index, session] of malformed.entries()) {
    await t.test(String(index), async () => {
      const pairing: ConsolePairingIdentity = {
        async beginSession() { return session as never; },
        async verify() { throw new Error("unused"); },
      };
      assertInternalError(await handlePairingAuthorize({ bridge: bridge(), pairing }, "GET", request("GET")));
    });
  }
});

test("pairing verify throws map to a fixed response without starting a session", async () => {
  let beginCalls = 0;
  const pairing: ConsolePairingIdentity = {
    async beginSession() { beginCalls += 1; return { nonce: "unused", expiresAt: EXPIRY }; },
    async verify() { return oauthBoom(); },
  };
  assertInternalError(await handlePairingAuthorize({ bridge: bridge(), pairing }, "POST", request("POST")));
  assert.equal(beginCalls, 0);
});

test("pairing verify returned accessors stay inside the port boundary", async () => {
  let beginCalls = 0;
  const result = new Proxy({ ok: true, identity: { subject: "operator" } }, {
    get(target, property, receiver) {
      if (property === "ok") return oauthBoom();
      return Reflect.get(target, property, receiver);
    },
  });
  const pairing: ConsolePairingIdentity = {
    async beginSession() { beginCalls += 1; return { nonce: "unused", expiresAt: EXPIRY }; },
    async verify() { return result; },
  } as ConsolePairingIdentity;
  assertInternalError(await handlePairingAuthorize({ bridge: bridge(), pairing }, "POST", request("POST")));
  assert.equal(beginCalls, 0);
});

test("a rejected pairing cannot escape through its follow-up beginSession", async () => {
  let beginCalls = 0;
  const pairing: ConsolePairingIdentity = {
    async beginSession() { beginCalls += 1; return oauthBoom(); },
    async verify() { return { ok: false, reason: "pairing_wrong_code" }; },
  };
  assertInternalError(await handlePairingAuthorize({ bridge: bridge(), pairing }, "POST", request("POST")));
  assert.equal(beginCalls, 1);
});

test("a valid pairing session still renders library-owned fields", async () => {
  const pairing: ConsolePairingIdentity = {
    async beginSession() { return { nonce: "pairing-nonce", expiresAt: EXPIRY }; },
    async verify() { throw new Error("unused"); },
  };
  const response = await handlePairingAuthorize({ bridge: bridge(), pairing }, "GET", request("GET"));
  assert.equal(response.status, 200);
  assert.match(String(response.body), /name="pairing_nonce" value="pairing-nonce"/);
  assert.match(String(response.body), new RegExp(EXPIRY.replaceAll(".", "\\.")));
});
