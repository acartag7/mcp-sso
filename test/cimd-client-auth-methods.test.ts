import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createUpstreamRedirectFlow } from "../src/adapters/upstream-flow.ts";
import type { CimdTransport, DnsResolver } from "../src/cimd/transport.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
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

const BASE_DOCUMENT = Object.freeze({
  client_id: CIMD_ID,
  client_name: "Example client",
  redirect_uris: [REDIRECT_URI],
});

const CHATGPT_DOCUMENT = Object.freeze({
  client_id: "https://chatgpt.com/oauth/AVY7bkwkV--3/client.json",
  redirect_uris: ["https://chatgpt.com/connector/oauth/AVY7bkwkV--3"],
  token_endpoint_auth_method: "private_key_jwt",
  token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
  token_endpoint_auth_signing_alg: "RS256",
  jwks_uri: "https://chatgpt.com/oauth/jwks.json",
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  client_name: "ChatGPT",
});

class MemoryAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(event); }
}

async function* encodedDocument(document: Record<string, unknown>): AsyncGenerator<Uint8Array> {
  yield new TextEncoder().encode(JSON.stringify(document));
}

function runtime(document: Record<string, unknown>) {
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
  let transportCalls = 0;
  const transport: CimdTransport = {
    async connectAndGet() {
      transportCalls += 1;
      return {
        status: 200,
        redirected: false,
        finalUrl: String(document.client_id),
        headersDistinct: {
          "content-type": ["application/json"],
          "cache-control": ["max-age=300"],
          date: [new Date(NOW).toUTCString()],
        },
        encodedBody: encodedDocument(document),
      };
    },
  };
  const store = new MemoryStore();
  const clock = { nowMs: () => NOW };
  const audit = new MemoryAudit();
  const bridge = new Bridge({
    config, store, clock, audit,
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
    store, clock, audit,
    cimdTransport: transport, cimdResolver: resolver,
  });
  return {
    audit, bridge, upstream,
    idpHops: () => idpHops,
    transportCalls: () => transportCalls,
  };
}

function authorizeRequest(document: Record<string, unknown>) {
  return {
    query: {
      response_type: "code",
      client_id: String(document.client_id),
      redirect_uri: String((document.redirect_uris as unknown[])[0]),
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

function authDocument(
  method: string | undefined,
  supported?: unknown,
): Record<string, unknown> {
  return {
    ...BASE_DOCUMENT,
    ...(method === undefined ? {} : { token_endpoint_auth_method: method }),
    ...(supported === undefined ? {} : { token_endpoint_auth_methods_supported: supported }),
  };
}

test("direct CIMD resolution rejects hostile shared-secret client-auth declarations", async () => {
  for (const method of symmetricMethods) {
    const document = authDocument(method, [method, "none"]);
    const rejected = await runtime(document).bridge.handleAuthorize(
      authorizeRequest(document),
      { subject: "user@example.test" },
    );
    assert.equal(rejected.status, 401, method);
    assert.deepEqual(rejected.body, genericFailure, method);
    assert.equal(rejected.redirect, undefined, method);
  }
});

test("upstream CIMD resolution rejects shared-secret declarations before an IdP hop", async () => {
  for (const method of symmetricMethods) {
    const document = authDocument(method, [method, "none"]);
    const subject = runtime(document);
    const rejected = await subject.upstream.handleAuthorize(authorizeRequest(document));
    assert.equal(rejected.status, 401, method);
    assert.deepEqual(rejected.body, genericFailure, method);
    assert.equal(rejected.redirect, undefined, method);
    assert.equal(rejected.headers["set-cookie"], undefined, method);
    assert.equal(subject.idpHops(), 0, method);
  }
});

test("direct CIMD resolution preserves absent and none client authentication", async () => {
  for (const method of [undefined, "none"]) {
    const document = authDocument(method);
    const subject = runtime(document);
    const accepted = await subject.bridge.handleAuthorize(
      authorizeRequest(document),
      { subject: "user@example.test" },
    );
    assert.equal(accepted.status, 200, String(method));
    const success = subject.audit.events.find((event) => event.event === "oauth.cimd.fetch" && event.status === "success");
    assert.equal(Object.hasOwn(success ?? {}, "selectedClientAuthMethod"), false, "native public auth has no negotiation marker");
  }
});

test("upstream CIMD resolution preserves absent and none client authentication", async () => {
  for (const method of [undefined, "none"]) {
    const document = authDocument(method);
    const subject = runtime(document);
    const accepted = await subject.upstream.handleAuthorize(authorizeRequest(document));
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

test("ChatGPT's published CIMD negotiates public none and audits direct plus cached upstream success", async () => {
  const subject = runtime(CHATGPT_DOCUMENT);
  const direct = await subject.bridge.handleAuthorize(
    authorizeRequest(CHATGPT_DOCUMENT),
    { subject: "user@example.test" },
  );
  assert.equal(direct.status, 200);

  const upstream = await subject.upstream.handleAuthorize(authorizeRequest(CHATGPT_DOCUMENT));
  assert.equal(upstream.status, 302);
  assert.equal(subject.idpHops(), 1);
  assert.equal(subject.transportCalls(), 1, "upstream resolution reuses the direct-mode cache entry");

  const successes = subject.audit.events.filter(
    (event) => event.event === "oauth.cimd.fetch" && event.status === "success",
  );
  assert.equal(successes.length, 2);
  assert.deepEqual(
    successes.map((event) => event.selectedClientAuthMethod),
    ["none", "none"],
    "network and cache-hit success both expose the selected public method",
  );
});

test("private_key_jwt preference rejects when no client-provided method supported by mcp-sso is advertised", async () => {
  const document = authDocument("private_key_jwt", ["private_key_jwt"]);
  const subject = runtime(document);
  const rejected = await subject.bridge.handleAuthorize(
    authorizeRequest(document),
    { subject: "user@example.test" },
  );
  assert.equal(rejected.status, 401);
  assert.deepEqual(rejected.body, genericFailure);
  assert.ok(subject.audit.events.some(
    (event) => event.event === "oauth.cimd.fetch" && event.status === "failure" && event.reason === "document_invalid",
  ));
  assert.equal(subject.audit.events.some((event) => Object.hasOwn(event, "selectedClientAuthMethod")), false);
});

test("singular auth method absent rejects when plural choices omit none", async () => {
  const document = authDocument(undefined, ["private_key_jwt"]);
  const subject = runtime(document);
  const rejected = await subject.upstream.handleAuthorize(authorizeRequest(document));
  assert.equal(rejected.status, 401);
  assert.deepEqual(rejected.body, genericFailure);
  assert.equal(subject.idpHops(), 0);
});

test("singular none rejects when plural choices omit none", async () => {
  const document = authDocument("none", ["private_key_jwt"]);
  const subject = runtime(document);
  const rejected = await subject.upstream.handleAuthorize(authorizeRequest(document));
  assert.equal(rejected.status, 401);
  assert.deepEqual(rejected.body, genericFailure);
  assert.equal(subject.idpHops(), 0);
});
