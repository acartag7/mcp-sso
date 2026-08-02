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

async function* encodedDocument(): AsyncGenerator<Uint8Array> {
  yield new TextEncoder().encode(JSON.stringify({
    client_id: CIMD_ID,
    client_name: "Example client",
    redirect_uris: [REDIRECT_URI],
  }));
}

function runtime(contentType: string) {
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
        headersDistinct: { "content-type": [contentType] },
        encodedBody: encodedDocument(),
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

const hostileMediaTypes = [
  "text/vendor+json",
  "image/svg+json",
  "application/+json",
  "application/*+json",
];
const validMediaTypes = ["application/json; charset=utf-8", "application/scim+json"];

test("direct CIMD resolution rejects invalid +json media types", async () => {
  for (const mediaType of hostileMediaTypes) {
    const rejected = await runtime(mediaType).bridge.handleAuthorize(
      authorizeRequest(),
      { subject: "user@example.test" },
    );
    assert.equal(rejected.status, 401, mediaType);
    assert.deepEqual(rejected.body, {
      error: "invalid_client",
      error_description: "client_id could not be resolved",
    }, mediaType);
    assert.equal(rejected.redirect, undefined, mediaType);
  }
});

test("upstream CIMD resolution rejects invalid +json media types", async () => {
  for (const mediaType of hostileMediaTypes) {
    const rejected = await runtime(mediaType).upstream.handleAuthorize(authorizeRequest());
    assert.equal(rejected.status, 401, mediaType);
    assert.deepEqual(rejected.body, {
      error: "invalid_client",
      error_description: "client_id could not be resolved",
    }, mediaType);
    assert.equal(rejected.redirect, undefined, mediaType);
    assert.equal(rejected.headers["set-cookie"], undefined, mediaType);
  }
});

test("direct CIMD resolution preserves JSON parameters and application +json", async () => {
  for (const mediaType of validMediaTypes) {
    const accepted = await runtime(mediaType).bridge.handleAuthorize(
      authorizeRequest(),
      { subject: "user@example.test" },
    );
    assert.equal(accepted.status, 200, mediaType);
  }
});

test("upstream CIMD resolution preserves JSON parameters and application +json", async () => {
  for (const mediaType of validMediaTypes) {
    const accepted = await runtime(mediaType).upstream.handleAuthorize(authorizeRequest());
    assert.equal(accepted.status, 302, mediaType);
    assert.match(accepted.headers.location ?? "", /^https:\/\/idp\.example\.test\/authorize\?/, mediaType);
    assert.ok(accepted.headers["set-cookie"], mediaType);
  }
});
