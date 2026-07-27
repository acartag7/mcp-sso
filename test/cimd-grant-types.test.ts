import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createUpstreamRedirectFlow } from "../src/adapters/upstream-flow.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import type { CimdTransport, DnsResolver } from "../src/cimd/transport.ts";
import { noopAudit } from "../src/ports/audit.ts";
import { MemoryStore } from "../src/store/memory.ts";

const NOW = Date.parse("2026-07-03T12:00:00.000Z");
const CIMD_ID = "https://metadata.example.test/client";
const REDIRECT_URI = "https://client.example.test/callback";
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const VERIFIER = "correct-horse-battery-staple-0123456789abcdef0123";
const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const SIGNING_JWK = {
  ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "test-key",
} as JWK;

const clock = { nowMs: () => NOW };
const resolver: DnsResolver = {
  async resolve() {
    return [{ address: "93.184.216.34", family: 4 }];
  },
};

async function* encodedDocument(grantTypes: unknown): AsyncGenerator<Uint8Array> {
  yield new TextEncoder().encode(JSON.stringify({
    client_id: CIMD_ID,
    client_name: "Example client",
    redirect_uris: [REDIRECT_URI],
    grant_types: grantTypes,
  }));
}

function runtime(grantTypes: unknown) {
  const config = createBridgeConfig({
    issuer: "https://auth.example.test",
    resource: "https://resource.example.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: SIGNING_JWK,
    signingKeyId: "test-key",
    redirectAllowlist: ["https://opaque-client.example.test/callback"],
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.example.test"],
    dcr: { mode: "stateless" },
    cimd: { enabled: true },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
  const transport: CimdTransport = {
    async connectAndGet() {
      return {
        status: 200,
        redirected: false,
        finalUrl: CIMD_ID,
        headersDistinct: { "content-type": ["application/json"] },
        encodedBody: encodedDocument(grantTypes),
      };
    },
  };
  const store = new MemoryStore();
  const bridge = new Bridge({
    config, store, clock, audit: noopAudit,
    cimdTransport: transport, cimdResolver: resolver,
  });
  const identity = {
    redirectUri: "https://auth.example.test/oauth/callback",
    buildAuthorizationUrl({ state }: { state: string }) {
      return `https://idp.example.test/authorize?state=${state}`;
    },
    async exchangeAndVerify() {
      return { ok: true as const, identity: { subject: "user@example.test" } };
    },
  };
  const upstream = createUpstreamRedirectFlow({
    bridge, identity, store, clock, audit: noopAudit,
    cimdTransport: transport, cimdResolver: resolver,
  });
  return { bridge, upstream };
}

function authorizeRequest() {
  return {
    query: {
      response_type: "code",
      client_id: CIMD_ID,
      redirect_uri: REDIRECT_URI,
      code_challenge: pkceChallenge(VERIFIER),
      code_challenge_method: "S256",
      scope: "mcp:read",
    },
    body: undefined,
    headers: {},
    ip: "203.0.113.7",
  };
}

test("direct CIMD resolution accepts an extra JWT-bearer declaration without enabling its token grant", async () => {
  const { bridge } = runtime(["authorization_code", JWT_BEARER]);

  const authorized = await bridge.handleAuthorize(
    authorizeRequest(),
    { subject: "user@example.test" },
  );
  assert.equal(authorized.status, 200);

  const token = await bridge.handleToken({
    query: {},
    body: { grant_type: JWT_BEARER, client_id: CIMD_ID },
    headers: {},
    ip: "203.0.113.7",
  });
  assert.equal(token.status, 400);
  assert.deepEqual(token.body, {
    error: "unsupported_grant_type",
    error_description: "grant_type is not supported",
  });
});

test("upstream CIMD resolution accepts an extra JWT-bearer declaration", async () => {
  const { upstream } = runtime(["authorization_code", JWT_BEARER]);

  const authorized = await upstream.handleAuthorize(authorizeRequest());

  assert.equal(authorized.status, 302);
  assert.match(authorized.headers.location ?? "", /^https:\/\/idp\.example\.test\/authorize\?/);
  assert.ok(authorized.headers["set-cookie"]);
});

const invalidGrantTypes: ReadonlyArray<[string, unknown]> = [
  ["missing authorization_code", ["refresh_token"]],
  ["empty", []],
  ["blank member", ["authorization_code", ""]],
  ["non-string member", ["authorization_code", 7]],
  ["non-array container", "authorization_code"],
];

test("direct CIMD resolution rejects malformed grant_types and declarations without authorization_code", async () => {
  for (const [name, grantTypes] of invalidGrantTypes) {
    const { bridge } = runtime(grantTypes);
    const rejected = await bridge.handleAuthorize(
      authorizeRequest(),
      { subject: "user@example.test" },
    );
    assert.equal(rejected.status, 401, name);
    assert.deepEqual(rejected.body, {
      error: "invalid_client",
      error_description: "client_id could not be resolved",
    }, name);
    assert.equal(rejected.redirect, undefined, name);
  }
});

test("upstream CIMD resolution rejects malformed grant_types and declarations without authorization_code", async () => {
  for (const [name, grantTypes] of invalidGrantTypes) {
    const { upstream } = runtime(grantTypes);
    const rejected = await upstream.handleAuthorize(authorizeRequest());
    assert.equal(rejected.status, 401, name);
    assert.deepEqual(rejected.body, {
      error: "invalid_client",
      error_description: "client_id could not be resolved",
    }, name);
    assert.equal(rejected.redirect, undefined, name);
    assert.equal(rejected.headers["set-cookie"], undefined, name);
  }
});
