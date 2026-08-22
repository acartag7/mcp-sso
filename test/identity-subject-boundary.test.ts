import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { handlePairingAuthorize } from "../src/adapters/pairing-flow.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import type { ConsolePairingIdentity } from "../src/identity/console-pairing.ts";
import { MemoryStore } from "../src/store/memory.ts";
import {
  changingIdentitySubject, INVALID_IDENTITY_SUBJECTS, VALID_IDENTITY_SUBJECTS,
} from "./lib/identity-subject-cases.ts";

const NOW = Date.parse("2026-08-22T10:00:00.000Z");
const REDIRECT = "https://client.test/callback";

function bridge(): Bridge {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return new Bridge({
    config: createBridgeConfig({
      issuer: "https://auth.test", resource: "https://auth.test/mcp",
      consentSigningSecret: "test-consent-secret-with-enough-entropy-0123456789",
      signingPrivateJwk: { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK,
      signingKeyId: "k", redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"],
      defaultScopes: ["mcp:read"], allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" },
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600,
      consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    }),
    store: new MemoryStore(), clock: { nowMs: () => NOW },
    audit: { async writeAuthEvent() { /* noop */ } },
  });
}

function pairingRequest() {
  return {
    query: {
      response_type: "code", client_id: "client", redirect_uri: REDIRECT,
      code_challenge: pkceChallenge("v".repeat(43)), code_challenge_method: "S256",
      scope: "mcp:read", state: "state",
    },
    body: { pairing_code: "BBBBBBBBBBBB", pairing_nonce: "nonce" },
    headers: { origin: "https://auth.test" }, ip: "203.0.113.9",
  } as const;
}

test("direct identity applies the complete shared subject grammar and snapshots a changing getter once", async () => {
  for (const subject of INVALID_IDENTITY_SUBJECTS) {
    await assert.rejects(bridge().resolveIdentity({ async verify() { return { ok: true, identity: { subject } }; } }, "credential"));
  }
  for (const subject of VALID_IDENTITY_SUBJECTS) {
    assert.equal((await bridge().resolveIdentity({ async verify() { return { ok: true, identity: { subject } }; } }, "credential")).subject, subject);
  }
  const changing = changingIdentitySubject();
  const resolved = await bridge().resolveIdentity({ async verify() { return { ok: true, identity: changing.identity }; } }, "credential");
  assert.equal(resolved.subject, "changing-subject");
  assert.equal(changing.reads(), 1);
});

test("console pairing applies the complete shared subject grammar and snapshots a changing getter once", async () => {
  const run = async (identity: { readonly subject: string }) => {
    const pairing = { async beginSession() { throw new Error("must not render a retry"); }, async verify() { return { ok: true, identity }; } } as ConsolePairingIdentity;
    return handlePairingAuthorize({ bridge: bridge(), pairing }, "POST", pairingRequest());
  };
  for (const subject of INVALID_IDENTITY_SUBJECTS) assert.equal((await run({ subject })).status, 500);
  for (const subject of VALID_IDENTITY_SUBJECTS) assert.equal((await run({ subject })).status, 200);
  const changing = changingIdentitySubject();
  assert.equal((await run(changing.identity)).status, 200);
  assert.equal(changing.reads(), 1);
});
