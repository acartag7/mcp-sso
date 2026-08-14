import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createUpstreamRedirectFlow } from "../src/adapters/upstream-flow.ts";
import type { CimdTransport, DnsResolver } from "../src/cimd/transport.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
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
const resolver: DnsResolver = {
  async resolve() { return [{ address: "93.184.216.34", family: 4 }]; },
};

async function* encodedDocument(method: string | undefined): AsyncGenerator<Uint8Array> {
  yield new TextEncoder().encode(JSON.stringify({
    client_id: CIMD_ID,
    client_name: "Example client",
    redirect_uris: [REDIRECT_URI],
    ...(method === undefined ? {} : { token_endpoint_auth_method: method }),
  }));
}

function runtime(method: string | undefined) {
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
        encodedBody: encodedDocument(method),
      };
    },
  };
  const store = new MemoryStore();
  const clock = { nowMs: () => NOW };
  const bridge = new Bridge({
    config, store, clock, audit: noopAudit,
    cimdTransport: transport, cimdResolver: resolver,
  });
  let idpHops = 0;
  const upstream = createUpstreamRedirectFlow({
    bridge,
    identity: {
      redirectUri: "https://auth.example.test/oauth/callback",
      buildAuthorizationUrl({ state }) {
        idpHops += 1;
        return `https://idp.example.test/authorize?state=${state}`;
      },
      async exchangeAndVerify() {
        return { ok: true as const, identity: { subject: "user@example.test" } };
      },
    },
    store, clock, audit: noopAudit,
    cimdTransport: transport, cimdResolver: resolver,
  });
  return { bridge, upstream, idpHops: () => idpHops };
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

const symmetricMethods = [
  "client_secret_basic",
  "client_secret_post",
  "client_secret_jwt",
  "custom_shared_secret",
];
const genericFailure = {
  error: "invalid_client",
  error_description: "client_id could not be resolved",
};

test("direct CIMD resolution rejects hostile shared-secret client-auth declarations", async () => {
  for (const method of symmetricMethods) {
    const rejected = await runtime(method).bridge.handleAuthorize(
      authorizeRequest(),
      { subject: "user@example.test" },
    );
    assert.equal(rejected.status, 401, method);
    assert.deepEqual(rejected.body, genericFailure, method);
    assert.equal(rejected.redirect, undefined, method);
  }
});

test("upstream CIMD resolution rejects shared-secret declarations before an IdP hop", async () => {
  for (const method of symmetricMethods) {
    const subject = runtime(method);
    const rejected = await subject.upstream.handleAuthorize(authorizeRequest());
    assert.equal(rejected.status, 401, method);
    assert.deepEqual(rejected.body, genericFailure, method);
    assert.equal(rejected.redirect, undefined, method);
    assert.equal(rejected.headers["set-cookie"], undefined, method);
    assert.equal(subject.idpHops(), 0, method);
  }
});

test("direct CIMD resolution preserves absent and none client authentication", async () => {
  for (const method of [undefined, "none"]) {
    const accepted = await runtime(method).bridge.handleAuthorize(
      authorizeRequest(),
      { subject: "user@example.test" },
    );
    assert.equal(accepted.status, 200, String(method));
  }
});

test("upstream CIMD resolution preserves absent and none client authentication", async () => {
  for (const method of [undefined, "none"]) {
    const subject = runtime(method);
    const accepted = await subject.upstream.handleAuthorize(authorizeRequest());
    assert.equal(accepted.status, 302, String(method));
    assert.match(
      accepted.headers.location ?? "",
      /^https:\/\/idp\.example\.test\/authorize\?/,
      String(method),
    );
    assert.ok(accepted.headers["set-cookie"], String(method));
    assert.equal(subject.idpHops(), 1, String(method));
  }
});
