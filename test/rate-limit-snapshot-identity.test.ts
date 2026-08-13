import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createUpstreamRedirectFlow } from "../src/adapters/upstream-flow.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import type { CimdTransport, DnsResolver } from "../src/cimd/transport.ts";
import { MemoryStore } from "../src/store/memory.ts";

const CLIENT_ID = "https://client.example/metadata";
const REDIRECT = "https://client.example/callback";
const IP = "203.0.113.7";

test("a shared limiter is charged once for an upstream CIMD resolution after binding", async () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const config = createBridgeConfig({
    issuer: "https://auth.example", resource: "https://api.example/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: privateKey.export({ format: "jwk" }) as JWK,
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.example"], dcr: { mode: "stateless" },
    cimd: { enabled: true }, accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const counts = new Map<string, number>();
  const rateLimit = {
    async check(key: string): Promise<boolean> {
      const next = (counts.get(key) ?? 0) + 1;
      counts.set(key, next);
      return !key.startsWith("cimd:") || next <= 1;
    },
  };
  const resolver: DnsResolver = { async resolve() { return [{ address: "93.184.216.34", family: 4 }]; } };
  const body = new TextEncoder().encode(JSON.stringify({
    client_id: CLIENT_ID, client_name: "Client", redirect_uris: [REDIRECT],
  }));
  const transport: CimdTransport = {
    async connectAndGet() {
      return {
        status: 200, redirected: false, finalUrl: CLIENT_ID,
        headersDistinct: { "content-type": ["application/json"] },
        encodedBody: (async function* () { yield body; })(),
      };
    },
  };
  const store = new MemoryStore();
  const clock = { nowMs: () => Date.parse("2026-08-13T12:00:00Z") };
  const audit = { async writeAuthEvent() {} };
  const bridge = new Bridge({ config, store, clock, audit, rateLimit, cimdResolver: resolver, cimdTransport: transport });
  const flow = createUpstreamRedirectFlow({
    bridge, store, clock, audit, rateLimit,
    identity: {
      redirectUri: "https://auth.example/oauth/callback",
      buildAuthorizationUrl: () => "https://idp.example/authorize",
      async exchangeAndVerify() { return { ok: true, identity: { subject: "operator" } }; },
    },
  });
  const response = await flow.handleAuthorize({
    ip: IP, headers: {}, body: undefined,
    query: {
      response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT,
      code_challenge: pkceChallenge("v".repeat(43)), code_challenge_method: "S256",
      scope: "mcp:read", state: "state",
    },
  });
  assert.equal(response.status, 302);
  assert.equal(counts.get(`cimd:${IP}`), 1, "the shared counting limiter is not double-charged");
  assert.equal(counts.get(`upstream:${IP}`), 1);
});
