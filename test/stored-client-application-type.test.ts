import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { Bridge } from "../src/adapters/bridge.ts";
import { createUpstreamRedirectFlow } from "../src/adapters/upstream-flow.ts";
import { verifyFlowToken } from "../src/adapters/upstream-flow-internals.ts";
import type { NormRequest } from "../src/adapters/http.ts";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import type { ClockPort } from "../src/ports/clock.ts";
import type { RedirectIdentityPort } from "../src/ports/identity.ts";
import { MemoryStore } from "../src/store/memory.ts";

const NOW = Date.parse("2026-08-12T12:00:00.000Z");
const ISSUER = "https://auth.test";
const RESOURCE = "https://api.test/mcp";
const CLIENT_ID = "client-1";
const REGISTERED = "http://127.0.0.1/cb";
const PRESENTED = "http://127.0.0.1:43821/cb";
const VERIFIER = "v".repeat(43);

class Clock implements ClockPort { nowMs(): number { return NOW; } }
class Audit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(event); }
}
class MutableClientStore implements ClientStore {
  row: unknown;
  findCalls = 0;
  findError: unknown;
  constructor(row: unknown) { this.row = row; }
  async save(client: ClientRegistration): Promise<void> { this.row = client; }
  async find(): Promise<ClientRegistration | null> {
    this.findCalls += 1;
    if (this.findError !== undefined) throw this.findError;
    return this.row as ClientRegistration | null;
  }
}

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK;
}

function config(clients: ClientStore): BridgeConfig {
  return createBridgeConfig({
    issuer: ISSUER, resource: RESOURCE,
    consentSigningSecret: "test-consent-secret-with-enough-entropy-0123456789",
    signingPrivateJwk: jwk(), signingKeyId: "k",
    redirectAllowlist: [], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: [ISSUER], dcr: { mode: "stored", store: clients },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

function nativeRow(...values: [] | [unknown]): Record<string, unknown> {
  const applicationType = values.length === 0 ? "native" : values[0];
  return { clientId: CLIENT_ID, redirectUris: [REGISTERED], applicationType, issuedAtEpoch: 1 };
}

function authorizeRequest(): NormRequest {
  return {
    query: {
      response_type: "code", client_id: CLIENT_ID, redirect_uri: PRESENTED,
      code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
      scope: "mcp:read", state: "client-state",
    },
    body: undefined, headers: {}, ip: "203.0.113.9",
  };
}

function harness(row: unknown): {
  clients: MutableClientStore; bridge: Bridge; flow: ReturnType<typeof createUpstreamRedirectFlow>;
  audit: Audit; state: MemoryStore; identityBuilds: () => number; exchanges: () => number;
  jtiConsumes: () => number; codeWrites: () => number;
} {
  const clients = new MutableClientStore(row);
  const cfg = config(clients);
  const audit = new Audit();
  const clock = new Clock();
  const state = new MemoryStore();
  let jtiConsumes = 0; let codeWrites = 0;
  const consume = state.consumeConsentJti.bind(state);
  state.consumeConsentJti = async (...args) => { jtiConsumes += 1; return consume(...args); };
  const saveCode = state.saveAuthCode.bind(state);
  state.saveAuthCode = async (...args) => { codeWrites += 1; return saveCode(...args); };
  const bridge = new Bridge({ config: cfg, store: state, clock, audit });
  let identityBuilds = 0; let exchanges = 0;
  const identity: RedirectIdentityPort = {
    redirectUri: `${ISSUER}/oauth/callback`,
    buildAuthorizationUrl(args) { identityBuilds += 1; return `https://idp.test/auth?state=${args.state}`; },
    async exchangeAndVerify() { exchanges += 1; return { ok: true, identity: { subject: "user-1" } }; },
  };
  const flow = createUpstreamRedirectFlow({ bridge, identity, store: state, clock, audit });
  return {
    clients, bridge, flow, audit, state,
    identityBuilds: () => identityBuilds, exchanges: () => exchanges,
    jtiConsumes: () => jtiConsumes, codeWrites: () => codeWrites,
  };
}

const MALFORMED_APPLICATION_TYPES: readonly [string, () => Record<string, unknown>][] = [
  ["absent", () => { const row = nativeRow(); delete row.applicationType; return row; }],
  ["undefined", () => nativeRow(undefined)],
  ["null", () => nativeRow(null)],
  ["blank", () => nativeRow("")],
  ["unknown", () => nativeRow("desktop")],
  ["wrong type", () => nativeRow(7)],
];

test("direct stored authorize fails closed for every malformed applicationType", async (t) => {
  for (const [label, makeRow] of MALFORMED_APPLICATION_TYPES) await t.test(label, async () => {
    const h = harness(makeRow());
    const response = await h.bridge.handleAuthorize(authorizeRequest(), { subject: "user-1" });
    assert.equal(response.status, 401);
    assert.equal((response.body as { error: string }).error, "invalid_client");
    assert.equal(response.redirect, undefined);
    assert.doesNotMatch(JSON.stringify(response.body), /consent_token/);
    assert.equal(h.codeWrites(), 0);
    assert.equal(h.audit.events.some((e) => e.event === "oauth.authorize.prepare" && e.status === "success"), false);
  });
});

test("direct stored authorize rejects every other malformed registration snapshot", async (t) => {
  const throwing = nativeRow();
  Object.defineProperty(throwing, "applicationType", { get() { throw new Error("poison getter"); } });
  const malformed: readonly [string, unknown][] = [
    ["mismatched clientId", { ...nativeRow(), clientId: "other-client" }],
    ["missing epoch", { clientId: CLIENT_ID, redirectUris: [REGISTERED], applicationType: "native" }],
    ["negative epoch", { ...nativeRow(), issuedAtEpoch: -1 }],
    ["non-array redirects", { ...nativeRow(), redirectUris: REGISTERED }],
    ["empty native redirects", { ...nativeRow(), redirectUris: [] }],
    ["too many native redirects", { ...nativeRow(), redirectUris: Array(17).fill(REGISTERED) }],
    ["machine redirects", { ...nativeRow(), applicationType: "machine", redirectUris: [REGISTERED] }],
    ["throwing getter", throwing],
  ];
  for (const [label, row] of malformed) await t.test(label, async () => {
    const h = harness(row);
    const response = await h.bridge.handleAuthorize(authorizeRequest(), { subject: "user-1" });
    assert.equal(response.status, 401);
    assert.equal((response.body as { error: string }).error, "invalid_client");
    assert.equal(response.redirect, undefined);
    assert.equal(h.codeWrites(), 0);
    assert.equal(h.audit.events.some((e) => e.status === "success"), false);
  });
});

test("upstream initiation rejects malformed applicationType before state/cookie creation", async (t) => {
  for (const [label, makeRow] of MALFORMED_APPLICATION_TYPES) await t.test(label, async () => {
    const h = harness(makeRow());
    const response = await h.flow.handleAuthorize(authorizeRequest());
    assert.equal(response.status, 401);
    assert.equal((response.body as { error: string }).error, "invalid_client");
    assert.equal(response.headers["set-cookie"], undefined);
    assert.equal(response.redirect, undefined);
    assert.equal(h.identityBuilds(), 0);
    assert.equal(h.jtiConsumes(), 0);
    assert.equal(h.audit.events.some((e) => e.status === "success"), false);
  });
});

test("upstream callback rechecks malformed stored type before every early-return effect", async (t) => {
  for (const [label, makeRow] of MALFORMED_APPLICATION_TYPES) await t.test(label, async () => {
    for (const query of [
      { error: "access_denied" },
      {},
      { code: "upstream-code" },
    ]) {
      const h = harness(nativeRow());
      const initiated = await h.flow.handleAuthorize(authorizeRequest());
      const setCookie = initiated.headers["set-cookie"] ?? "";
      const token = setCookie.slice(setCookie.indexOf("=") + 1, setCookie.indexOf(";"));
      const claims = await verifyFlowToken(token, h.bridge.config.consentSigningSecret, ISSUER, "/oauth/callback");
      h.clients.row = makeRow();
      const response = await h.flow.handleCallback({
        query: { state: claims.state, ...query }, body: undefined,
        headers: { cookie: `__Host-mcp-sso-upstream=${token}` }, ip: "203.0.113.9",
      });
      assert.equal(response.status, 400);
      assert.equal((response.body as { error: string }).error, "invalid_request");
      assert.equal(response.headers.location, undefined);
      assert.match(response.headers["set-cookie"] ?? "", /Max-Age=0/);
      assert.equal(h.jtiConsumes(), 0);
      assert.equal(h.exchanges(), 0);
      assert.equal(h.codeWrites(), 0);
      assert.equal(h.audit.events.some((e) => e.event === "oauth.upstream.callback" && e.status === "success"), false);
      assert.equal(h.audit.events.some((e) => e.event === "oauth.authorize.prepare" && e.status === "success"), false);
    }
  });
});

test("upstream callback preserves internal_error when the client store fails", async () => {
  const h = harness(nativeRow());
  const initiated = await h.flow.handleAuthorize(authorizeRequest());
  const setCookie = initiated.headers["set-cookie"] ?? "";
  const token = setCookie.slice(setCookie.indexOf("=") + 1, setCookie.indexOf(";"));
  const claims = await verifyFlowToken(token, h.bridge.config.consentSigningSecret, ISSUER, "/oauth/callback");
  h.clients.findError = new Error("store unavailable");
  const response = await h.flow.handleCallback({
    query: { state: claims.state, code: "upstream-code" }, body: undefined,
    headers: { cookie: `__Host-mcp-sso-upstream=${token}` }, ip: "203.0.113.9",
  });
  assert.equal(response.status, 500);
  assert.equal((response.body as { error: string }).error, "internal_error");
  assert.match(response.headers["set-cookie"] ?? "", /Max-Age=0/);
  assert.equal(h.jtiConsumes(), 0);
  assert.equal(h.exchanges(), 0);
  assert.equal(h.audit.events.at(-1)?.reason, "internal_error");
});

test("stored registration is snapshotted once and valid native/web/machine behavior remains", async () => {
  let applicationTypeReads = 0; let redirectReads = 0;
  const redirects = new Proxy(["https://client.test/cb"], {
    get(target, key, receiver) {
      if (key === "0") { redirectReads += 1; return redirectReads === 1 ? target[0] : "https://evil.test/cb"; }
      return Reflect.get(target, key, receiver);
    },
  });
  const row = { clientId: CLIENT_ID, redirectUris: redirects, issuedAtEpoch: 1 } as Record<string, unknown>;
  Object.defineProperty(row, "applicationType", { get() { applicationTypeReads += 1; return applicationTypeReads === 1 ? "web" : undefined; } });
  const h = harness(row);
  const request = authorizeRequest(); request.query.redirect_uri = "https://client.test/cb";
  assert.equal((await h.bridge.handleAuthorize(request, { subject: "user-1" })).status, 200);
  assert.equal(applicationTypeReads, 1);
  assert.equal(redirectReads, 1);

  h.clients.row = { clientId: CLIENT_ID, redirectUris: [], applicationType: "machine", issuedAtEpoch: 1 };
  const machine = await h.bridge.handleAuthorize(authorizeRequest(), { subject: "user-1" });
  assert.equal(machine.status, 401);
  assert.equal((machine.body as { error: string }).error, "invalid_client");
});
