import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { OAUTH_PARAM_KEYS, OAUTH_SINGLETON_PARAM_KEYS, queryOccurrencesFromUrl } from "../src/adapters/authorize-params.ts";
import { Bridge } from "../src/adapters/bridge.ts";
import type { NormRequest } from "../src/adapters/http.ts";
import { handlePairingAuthorize } from "../src/adapters/pairing-flow.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import type { ConsolePairingIdentity } from "../src/identity/console-pairing.ts";
import type { AuditPort, AuthAuditEvent } from "../src/ports/audit.ts";
import type { ClientRegistration, ClientStore } from "../src/ports/client-store.ts";
import { MemoryStore } from "../src/store/memory.ts";

const NOW = Date.parse("2026-08-13T12:00:00.000Z");
const ISSUER = "https://auth.test";
const RESOURCE = "https://api.test/mcp";
const CLIENT_ID = "registered-client";
const ALLOWED_REDIRECT = "https://client.test/callback";
const ATTACKER_REDIRECT = "https://attacker.test/callback";
const VERIFIER = "v".repeat(43);
const KEY = (() => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK;
})();

class Audit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(event); }
}

class Clients implements ClientStore {
  findCalls = 0;
  saveCalls = 0;
  private readonly row: ClientRegistration = {
    clientId: CLIENT_ID, redirectUris: [ALLOWED_REDIRECT], applicationType: "web", issuedAtEpoch: 1,
  };
  async save(): Promise<void> { this.saveCalls += 1; }
  async find(clientId: string): Promise<ClientRegistration | null> {
    this.findCalls += 1;
    return clientId === CLIENT_ID ? this.row : null;
  }
}

class State extends MemoryStore {
  codeWrites = 0;
  consentWrites = 0;
  override async saveAuthCode(input: Parameters<MemoryStore["saveAuthCode"]>[0]): Promise<void> {
    this.codeWrites += 1;
    await super.saveAuthCode(input);
  }
  override async consumeConsentJti(jti: string, expiresAtIso: string): Promise<boolean> {
    this.consentWrites += 1;
    return super.consumeConsentJti(jti, expiresAtIso);
  }
}

class Pairing implements ConsolePairingIdentity {
  beginCalls = 0;
  verifyCalls = 0;
  async beginSession() {
    this.beginCalls += 1;
    return { nonce: "pairing-nonce", expiresAt: "2026-08-13T12:10:00.000Z" };
  }
  async verify() {
    this.verifyCalls += 1;
    return { ok: true as const, identity: { subject: "operator" } };
  }
}

function harness(): { bridge: Bridge; clients: Clients; state: State; audit: Audit; pairing: Pairing } {
  const clients = new Clients();
  const state = new State();
  const audit = new Audit();
  const config = createBridgeConfig({
    issuer: ISSUER, resource: RESOURCE,
    consentSigningSecret: "test-consent-secret-with-enough-entropy-0123456789",
    signingPrivateJwk: KEY, signingKeyId: "k", redirectAllowlist: [],
    scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"], allowedOrigins: [ISSUER],
    dcr: { mode: "stored", store: clients }, accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
  return {
    bridge: new Bridge({ config, store: state, clock: { nowMs: () => NOW }, audit }),
    clients, state, audit, pairing: new Pairing(),
  };
}

function validParams(): Record<(typeof OAUTH_PARAM_KEYS)[number], string> {
  return {
    response_type: "code", client_id: CLIENT_ID, redirect_uri: ALLOWED_REDIRECT,
    code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256",
    resource: RESOURCE, scope: "mcp:read", state: "client-state",
  };
}

function request(query: NormRequest["query"], body: unknown = undefined): NormRequest {
  return { query, body, headers: {}, ip: "203.0.113.9" };
}

function assertDirectDuplicate(response: Awaited<ReturnType<Bridge["handleAuthorize"]>>, attacker?: string): void {
  assert.equal(response.status, 400);
  assert.equal(response.headers.location, undefined);
  assert.equal(response.redirect, undefined);
  assert.equal((response.body as { error?: unknown }).error, "invalid_request");
  assert.doesNotMatch(JSON.stringify(response.body), /consent_token/);
  if (attacker) assert.equal(JSON.stringify(response.body).includes(attacker), false);
}

function assertNoAuthorizeSideEffects(h: ReturnType<typeof harness>): void {
  assert.equal(h.clients.findCalls, 0, "duplicate rejection precedes client-store lookup");
  assert.equal(h.clients.saveCalls, 0);
  assert.equal(h.state.codeWrites, 0);
  assert.equal(h.state.consentWrites, 0);
  assert.equal(h.audit.events.some((event) => event.event === "oauth.authorize.prepare"), false);
}

test("Bridge.handleAuthorize rejects every duplicated singleton authorize key before selection or consent/store work", async (t) => {
  for (const key of OAUTH_SINGLETON_PARAM_KEYS) {
    await t.test(key, async () => {
      const h = harness();
      const params = validParams();
      const second = key === "redirect_uri" ? ATTACKER_REDIRECT : `attacker-${key}`;
      const response = await h.bridge.handleAuthorize(request({ ...params, [key]: [params[key], second] }), { subject: "operator" });
      assertDirectDuplicate(response, key === "redirect_uri" ? ATTACKER_REDIRECT : undefined);
      assertNoAuthorizeSideEffects(h);
    });
  }
});

test("raw query snapshots keep inherited names as inert own data", () => {
  const query = queryOccurrencesFromUrl("/oauth/authorize?__proto__=first&toString=second&__proto__=third");
  assert.equal(Object.getPrototypeOf(query), null);
  assert.deepEqual(query.__proto__, ["first", "third"]);
  assert.equal(query.toString, "second");
});

test("Bridge.handleAuthorize maps repeated RFC 8707 resource indicators to invalid_target", async () => {
  const h = harness();
  const params = validParams();
  const response = await h.bridge.handleAuthorize(
    request({ ...params, resource: [params.resource, "https://other.test/mcp"] }), { subject: "operator" },
  );
  assert.equal(response.status, 302);
  assert.equal(new URL(response.headers.location as string).searchParams.get("error"), "invalid_target");
  assert.equal(String(response.body).includes("consent_token"), false);
  assert.equal(h.audit.events.some((event) => event.event === "oauth.authorize.prepare" && event.status === "success"), false);
});

test("Bridge.handleAuthorize treats valueless resource occurrences as omitted", async () => {
  for (const resource of ["", ["", ""], [RESOURCE, ""], ["", RESOURCE]]) {
    const h = harness();
    const response = await h.bridge.handleAuthorize(
      request({ ...validParams(), resource }), { subject: "operator" },
    );
    assert.equal(response.status, 200);
    assert.match(String(response.body), /name="consent_token"/);
  }
});

test("Bridge.handleAuthorize omits valueless singleton occurrences and deduplicates identical resources", async () => {
  for (const key of OAUTH_SINGLETON_PARAM_KEYS) {
    const h = harness();
    const params = validParams();
    const response = await h.bridge.handleAuthorize(
      request({ ...params, [key]: ["", params[key]] }), { subject: "operator" },
    );
    assert.equal(response.status, 200, `${key} keeps its one nonempty occurrence`);
  }
  const h = harness();
  const params = validParams();
  const response = await h.bridge.handleAuthorize(
    request({ ...params, resource: [RESOURCE, RESOURCE] }), { subject: "operator" },
  );
  assert.equal(response.status, 200);
});

test("Bridge.handleAuthorize preserves the adjacent valid single-value authorize flow", async () => {
  const h = harness();
  const response = await h.bridge.handleAuthorize(request(validParams()), { subject: "operator" });
  assert.equal(response.status, 200);
  assert.match(String(response.body), /name="consent_token"/);
  assert.equal(h.clients.findCalls, 1, "stored authorize uses the registered client");
  assert.equal(h.audit.events.some((event) => event.event === "oauth.authorize.prepare" && event.status === "success"), true);
});

test("handlePairingAuthorize GET rejects every duplicated singleton authorize key before session/output/rendering", async (t) => {
  for (const key of OAUTH_SINGLETON_PARAM_KEYS) {
    await t.test(key, async () => {
      const h = harness();
      const params = validParams();
      const second = key === "redirect_uri" ? ATTACKER_REDIRECT : `attacker-${key}`;
      const response = await handlePairingAuthorize({ bridge: h.bridge, pairing: h.pairing }, "GET",
        request({ ...params, [key]: [params[key], second] }));
      assertDirectDuplicate(response, key === "redirect_uri" ? ATTACKER_REDIRECT : undefined);
      assert.equal(h.pairing.beginCalls, 0);
      assert.equal(h.pairing.verifyCalls, 0);
      assertNoAuthorizeSideEffects(h);
    });
  }
});

test("handlePairingAuthorize preserves repeated resource input for invalid_target after pairing", async () => {
  const h = harness();
  const params = validParams();
  const response = await handlePairingAuthorize(
    { bridge: h.bridge, pairing: h.pairing }, "POST",
    request({ resource: [params.resource, "https://other.test/mcp"] }, {
      ...params, resource: undefined, pairing_code: "BBBB-BBBB-BBBB", pairing_nonce: "pairing-nonce",
    }),
  );
  assert.equal(response.status, 302);
  assert.equal(new URL(response.headers.location as string).searchParams.get("error"), "invalid_target");
  assert.equal(h.pairing.verifyCalls, 1);
  assert.equal(h.audit.events.some((event) => event.event === "oauth.authorize.prepare" && event.status === "success"), false);
});

test("handlePairingAuthorize treats valueless resource occurrences as omitted", async () => {
  for (const resource of ["", ["", ""], [RESOURCE, ""], ["", RESOURCE]]) {
    const h = harness();
    const response = await handlePairingAuthorize(
      { bridge: h.bridge, pairing: h.pairing }, "POST",
      request({ resource }, {
        ...validParams(), resource: undefined, pairing_code: "BBBB-BBBB-BBBB", pairing_nonce: "pairing-nonce",
      }),
    );
    assert.equal(response.status, 200);
    assert.match(String(response.body), /name="consent_token"/);
  }
});

test("handlePairingAuthorize preserves adjacent valid single-value GET and POST flows", async () => {
  const getHarness = harness();
  const get = await handlePairingAuthorize(
    { bridge: getHarness.bridge, pairing: getHarness.pairing }, "GET", request(validParams()),
  );
  assert.equal(get.status, 200);
  assert.equal(getHarness.pairing.beginCalls, 1);
  assert.match(String(get.body), /name="redirect_uri" value="https:\/\/client\.test\/callback"/);

  const postHarness = harness();
  const post = await handlePairingAuthorize(
    { bridge: postHarness.bridge, pairing: postHarness.pairing }, "POST",
    request({}, { ...validParams(), pairing_code: "BBBB-BBBB-BBBB", pairing_nonce: "pairing-nonce" }),
  );
  assert.equal(post.status, 200);
  assert.equal(postHarness.pairing.verifyCalls, 1);
  assert.equal(postHarness.pairing.beginCalls, 0);
  assert.match(String(post.body), /name="consent_token"/);
});
