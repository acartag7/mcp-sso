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

const NOW = Date.parse("2026-08-14T12:00:00.000Z");
const CIMD_ID = "https://client-metadata.example.test/client.json";
const REDIRECT = "https://client.example.test/callback";
const VERIFIER = "document-url-inert-verifier-0123456789abcdef0123456789";
const HOSTILE_URLS = {
  logo_uri: "file:///etc/ignored-logo",
  jwks_uri: "http://127.0.0.1:9/ignored-jwks",
  policy_uri: "gopher://127.0.0.1/ignored-policy",
  tos_uri: "https://secondary-host.example.test/ignored-terms",
};
const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const SIGNING_JWK = {
  ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "inert-test",
} as JWK;

function runtime() {
  const requests: Array<{ hostHeader: string; requestTarget: string }> = [];
  const resolver: DnsResolver = {
    async resolve() { return [{ address: "93.184.216.34", family: 4 }]; },
  };
  const transport: CimdTransport = {
    async connectAndGet(request) {
      requests.push({ hostHeader: request.hostHeader, requestTarget: request.requestTarget });
      async function* body(): AsyncGenerator<Uint8Array> {
        yield new TextEncoder().encode(JSON.stringify({
          client_id: CIMD_ID,
          client_name: "Inert URL client",
          redirect_uris: [REDIRECT],
          ...HOSTILE_URLS,
        }));
      }
      return {
        status: 200,
        redirected: false,
        finalUrl: CIMD_ID,
        headersDistinct: { "content-type": ["application/json"] },
        encodedBody: body(),
      };
    },
  };
  const config = createBridgeConfig({
    issuer: "https://auth.example.test",
    resource: "https://resource.example.test/mcp",
    consentSigningSecret: "test-consent-secret-with-enough-entropy",
    signingPrivateJwk: SIGNING_JWK,
    signingKeyId: "inert-test",
    redirectAllowlist: ["https://opaque.example.test/callback"],
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
  const store = new MemoryStore();
  const clock = { nowMs: () => NOW };
  const bridge = new Bridge({
    config, store, clock, audit: noopAudit,
    cimdTransport: transport, cimdResolver: resolver,
  });
  const upstream = createUpstreamRedirectFlow({
    bridge,
    identity: {
      redirectUri: "https://auth.example.test/oauth/callback",
      buildAuthorizationUrl({ state }) {
        return `https://idp.example.test/authorize?state=${encodeURIComponent(state)}`;
      },
      async exchangeAndVerify() {
        return { ok: true as const, identity: { subject: "upstream-user@example.test" } };
      },
    },
    store, clock, audit: noopAudit,
    cimdTransport: transport, cimdResolver: resolver,
  });
  return { bridge, upstream, requests };
}

function authorizeRequest(headers: Record<string, string> = {}) {
  return {
    query: {
      response_type: "code",
      client_id: CIMD_ID,
      redirect_uri: REDIRECT,
      code_challenge: pkceChallenge(VERIFIER),
      code_challenge_method: "S256",
      scope: "mcp:read",
      state: "client-state",
    },
    body: undefined,
    headers,
    ip: "203.0.113.7",
  };
}

function assertOnlyClientIdentifierFetched(requests: Array<{ hostHeader: string; requestTarget: string }>): void {
  assert.deepEqual(requests, [{
    hostHeader: "client-metadata.example.test",
    requestTarget: "/client.json",
  }]);
}

function assertDocumentUrlsNotRendered(body: unknown): void {
  const rendered = String(body);
  for (const url of Object.values(HOSTILE_URLS)) assert.equal(rendered.includes(url), false, url);
}

test("direct authorization treats document-contained URLs as inert metadata", async () => {
  const subject = runtime();
  const response = await subject.bridge.handleAuthorize(
    authorizeRequest(),
    { subject: "direct-user@example.test" },
  );
  assert.equal(response.status, 200);
  assert.match(String(response.body), /Authorize access/);
  assertDocumentUrlsNotRendered(response.body);
  assertOnlyClientIdentifierFetched(subject.requests);
});

test("upstream callback-to-consent keeps document-contained URLs inert", async () => {
  const subject = runtime();
  const started = await subject.upstream.handleAuthorize(authorizeRequest());
  assert.equal(started.status, 302);
  const upstreamState = new URL(started.headers.location ?? "").searchParams.get("state");
  assert.ok(upstreamState);
  const setCookie = started.headers["set-cookie"] ?? "";
  const cookie = setCookie.split(";", 1)[0] ?? "";
  assert.ok(cookie);
  const callback = await subject.upstream.handleCallback({
    query: { state: upstreamState, code: "upstream-code" },
    body: undefined,
    headers: { cookie },
    ip: "203.0.113.7",
  });
  assert.equal(callback.status, 200);
  assert.match(String(callback.body), /Authorize access/);
  assertDocumentUrlsNotRendered(callback.body);
  assertOnlyClientIdentifierFetched(subject.requests);
});
