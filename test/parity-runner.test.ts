import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { importPKCS8, SignJWT, type CryptoKey } from "jose";
import { adapterForChainMember, adaptersForChain } from "./parity/adapters.ts";
import { materializeConfig, materializeConfigInput } from "./parity/config.ts";
import { FIXTURES_ROOT, loadCorpus } from "./parity/corpus.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import { runFixture } from "./parity/runner.ts";
import { assertPreStateEstablished } from "./parity/state-assertions.ts";
import { SeededRandom } from "./parity/random.ts";
import { FixtureStore } from "./parity/store.ts";
import type { BootFixture, BootThen, CaptureValues, HttpFixture, LogicalState } from "./parity/types.ts";

const CLOCK = "2026-08-26T12:00:00.000Z";
const ISSUER = "https://api.example.com";
const RESOURCE = "https://api.example.com/mcp";
const CALLBACK = "https://client.example.com/callback";
const CIMD_CLIENT = "https://client.example.com/mcp-client.json";
const CLIENT_ID = "mcpdc_0f1e2d3c4b5a69788796a5b4c3d2e1f0";
const INSTANCE_ID = "fixture-store-instance-00000000A";
const CAPTURED = "fixture-captured-access-token";
const KEYS = { signingPrivate: "keys/signing-private.pem", signingPublic: "keys/signing-public.pem" };
const ADAPTERS = ["fastify", "express", "hono"] as const;
const CONTRACT = { section: "08", clause: "8.4", quote: "runner exercise" };

function baseConfig(): Record<string, unknown> {
  return {
    issuer: ISSUER, resource: RESOURCE,
    consentSigningSecret: "fixture-only-consent-key-00000010",
    signingKeyId: "fixture-signing-key-1",
    redirectAllowlist: [CALLBACK], redirectAllowlistMode: "replace",
    scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: [ISSUER], dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 300, refreshTokenTtlSeconds: 3600,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  };
}

let signingKey: CryptoKey | undefined;
async function bearerToken(): Promise<string> {
  signingKey ??= await importPKCS8(
    await readFile(join(FIXTURES_ROOT, "keys", "signing-private.pem"), "utf8"), "ES256");
  return await new SignJWT({ client_id: "protected-client", scope: "mcp:read", iss: ISSUER,
    sub: "protected-subject", aud: RESOURCE, iat: 1787745600, exp: 1787745900 })
    .setProtectedHeader({ alg: "ES256", kid: "fixture-signing-key-1", typ: "JWT" })
    .sign(signingKey);
}

async function protectedFixture(id: string): Promise<HttpFixture> {
  const registration = { client_id: CLIENT_ID, redirect_uris: [CALLBACK],
    application_type: "web" as const, issued_at_epoch: 1787745600 };
  const state: LogicalState = {
    client_registration: [registration], store_instance: [{ instance_id: INSTANCE_ID }] };
  return {
    id, kind: "fixture", profile: "portable", status: "draft", contract: CONTRACT,
    given: {
      config: { ...baseConfig(), dcr: { mode: "stored" } },
      clock: CLOCK, random: { seed: "runner-protected-seed" }, keys: KEYS, state,
      http: [], identity: { checks: [] }, rateLimit: { checks: [] },
      protectedResource: { requiredScope: null, success: { status: 200,
        headers: { "content-type": "application/json" }, body: { value: { access_token: CAPTURED } } } },
    },
    when: { request: { method: "POST", path: "/mcp",
      headers: { authorization: `Bearer ${await bearerToken()}`, "content-type": "application/json",
        accept: "application/json", "mcp-protocol-version": "2025-06-18" },
      body: { json: { jsonrpc: "2.0", id: 1, method: "initialize", params: {} } } } },
    then: {
      status: 200,
      headers: { "content-type": { contains: "application/json" } },
      body: { equals: { access_token: CAPTURED } },
      audit: { events: [{ occurredAt: CLOCK, event: "auth.request", status: "success",
        clientId: "protected-client", subject: "protected-subject", scopes: ["mcp:read"] }], absent: [] },
      state: { mode: "exact", rows: { client_registration: [registration],
        store_instance: [{ instance_id: INSTANCE_ID }] }, absent: [] },
      captures: [{ name: "captured_token", source: { bodyPointer: "/access_token" } }],
      outbound: [],
    },
  };
}

function authorizeFixture(): HttpFixture {
  const document = { client_id: CIMD_CLIENT, client_name: "Fixture Client", redirect_uris: [CALLBACK] };
  const exchangeHeaders = { host: "client.example.com", accept: "application/json",
    "accept-encoding": "identity" };
  const query = `client_id=${encodeURIComponent(CIMD_CLIENT)}&redirect_uri=${encodeURIComponent(CALLBACK)}`
    + "&response_type=code&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    + "&code_challenge_method=S256&scope=mcp:read&state=fixture-state";
  return {
    id: "runner-test/authorize-cimd", kind: "fixture", profile: "portable", status: "draft", contract: CONTRACT,
    given: {
      config: { ...baseConfig(), cimd: { enabled: true } },
      clock: CLOCK, random: { seed: "runner-authorize-seed" }, keys: KEYS,
      state: { store_instance: [{ instance_id: INSTANCE_ID }] },
      http: [{ request: { method: "GET", url: CIMD_CLIENT, headers: exchangeHeaders, body: { absent: true } },
        response: { status: 200, headers: { "content-type": "application/json" }, body: { value: document } } }],
      identity: { checks: [{ input: { value: "fixture-identity-credential" },
        result: { ok: true, identity: { subject: "authorize-subject" } } }] },
      rateLimit: { checks: [
        { key: "authorize:127.0.0.1", outcome: "allow" }, { key: "cimd:127.0.0.1", outcome: "allow" }] },
      protectedResource: { requiredScope: null },
    },
    when: { request: { method: "GET", path: `/oauth/authorize?${query}`,
      headers: { accept: "application/json", "cf-access-jwt-assertion": "fixture-identity-credential" } } },
    then: {
      status: 200,
      headers: { "content-type": { contains: "text/html" }, "x-frame-options": "DENY" },
      body: { contains: CALLBACK },
      audit: { events: [
        { occurredAt: CLOCK, event: "identity.verify", status: "success",
          subject: "authorize-subject", ip: "127.0.0.1" },
        { occurredAt: CLOCK, event: "oauth.cimd.fetch", status: "success",
          clientId: CIMD_CLIENT, ip: "127.0.0.1" },
        { occurredAt: CLOCK, event: "oauth.authorize.prepare", status: "success",
          clientId: CIMD_CLIENT, subject: "authorize-subject", resource: RESOURCE,
          scopes: ["mcp:read"], redirectHost: "https://client.example.com" }], absent: [] },
      state: { mode: "exact", rows: { store_instance: [{ instance_id: INSTANCE_ID }] }, absent: [] },
      outbound: [{ method: "GET", url: CIMD_CLIENT, headers: exchangeHeaders, body: { absent: true } }],
    },
  };
}

function bootFixture(entrypoint: "createBridgeConfig" | "Bridge", config: unknown,
  boot: BootThen["boot"]): BootFixture {
  return {
    id: `runner-test/boot-${entrypoint}-${boot.outcome}`, kind: "boot", profile: "host", status: "draft",
    contract: CONTRACT,
    given: { entrypoint, config, clock: CLOCK, random: { seed: "runner-boot-seed" },
      keys: { signingPrivate: "keys/signing-private.pem" }, state: {},
      http: [], identity: { checks: [] }, rateLimit: { checks: [] } },
    then: { boot, outbound: [] },
  };
}

for (const adapter of ADAPTERS) {
  test(`parity runner serves a protected request [${adapter}]`, async () => {
    const captures: CaptureValues = new Map();
    await runFixture(await protectedFixture("runner-test/protected-success"), adapter, captures);
    assert.equal(captures.get("runner-test/protected-success")?.get("captured_token"), CAPTURED);
  });
}

for (const adapter of ADAPTERS) {
  test(`parity runner drives the scripted ports [${adapter}]`, async () => {
    await runFixture(authorizeFixture(), adapter);
  });
}

test("Bridge entrypoint receives the still-literal config", async () => {
  const config = { ...baseConfig(), unknown_fixture_key: true };
  const store = new FixtureStore({}, new SeededRandom("literal-dcr"));
  try {
    await assert.rejects(materializeConfig(config, KEYS, store), /unknown BridgeConfig key/);
    const materialized = await materializeConfigInput(
      { ...baseConfig(), dcr: { mode: "stored", nested_marker: "kept" } }, {}, FIXTURES_ROOT, store,
    ) as { dcr: { nested_marker: string; store: unknown } };
    assert.equal(materialized.dcr.nested_marker, "kept");
    assert.equal(materialized.dcr.store, store);
  } finally { await store.close(); }
  await runFixture(bootFixture("Bridge", config, { outcome: "accepted" }));
});

test("an impossible clock fails an HTTP fixture before composition", async () => {
  const fixture = authorizeFixture();
  fixture.given.clock = "2026-02-31T00:00:00.000Z";
  await assert.rejects(runFixture(fixture), /given\.clock is not a canonical UTC timestamp/);
});

test("an impossible clock fails a boot fixture before composition", async () => {
  const fixture = bootFixture("createBridgeConfig", baseConfig(), { outcome: "accepted" });
  fixture.given.clock = "2026-02-31T00:00:00.000Z";
  await assert.rejects(runFixture(fixture), /given\.clock is not a canonical UTC timestamp/);
});

test("a rejected boot pins the error code, name, and message", async () => {
  await runFixture(bootFixture("createBridgeConfig", { ...baseConfig(), unknown_fixture_key: true },
    { outcome: "rejected", error: { code: "invalid_auth_config", name: "Error",
      message: { contains: "unknown BridgeConfig key" } } }));
});

test("a superseded fixture is rejected without composition", async () => {
  const fixture = authorizeFixture();
  fixture.status = "superseded";
  fixture.supersededBy = "runner-test/authorize-cimd-replacement";
  await assert.rejects(runFixture(fixture), /superseded fixtures are not executable/);
});

test("a failing response assertion fails the fixture and cleans up", async () => {
  const fixture = await protectedFixture("runner-test/protected-success");
  fixture.then.status = 418;
  const originalFetch = globalThis.fetch;
  let caught: unknown;
  try { await runFixture(fixture); } catch (error) { caught = error; }
  assert.ok(caught instanceof FixtureRunnerError);
  assert.equal(caught.message, "runner-test/protected-success: fastify run failed");
  assert.ok(caught.cause instanceof Error);
  assert.match(caught.cause.message, /response status/);
  assert.equal(globalThis.fetch, originalFetch);
});

test("a mismatched state, audit, or outbound declaration fails the fixture", async () => {
  const wrongState = await protectedFixture("runner-test/state-mismatch");
  wrongState.then.state!.rows = { store_instance: [{ instance_id: "different-instance-00000000A" }] };
  await assert.rejects(runFixture(wrongState), rejectsWithCause(/exact state/));
  const wrongAudit = await protectedFixture("runner-test/audit-mismatch");
  wrongAudit.then.audit!.events[0]!.event = "auth.other";
  await assert.rejects(runFixture(wrongAudit), rejectsWithCause(/exact audit events/));
  const wrongOutbound = authorizeFixture();
  wrongOutbound.then.outbound = [wrongOutbound.then.outbound[0]!,
    { ...wrongOutbound.then.outbound[0]!, url: "https://client.example.com/extra" }];
  await assert.rejects(runFixture(wrongOutbound), rejectsWithCause(/outbound call count/));
});

function rejectsWithCause(pattern: RegExp) {
  return (error: unknown): boolean => error instanceof FixtureRunnerError
    && error.cause instanceof Error && pattern.test(error.cause.message);
}
test("chain continuity rejects a pre-state row the preceding member never produced", () => {
  const established: Required<LogicalState> = {
    authorization_code: [{
      code_hash: "a".repeat(64), client_id: "client", subject: "user", redirect_uri: CALLBACK,
      resource: RESOURCE, scopes: ["mcp:read"], code_challenge: "challenge",
      code_challenge_method: "S256", expires_at: CLOCK,
    }],
    consent_jti: [], refresh_token: [], revoked_family: [],
    client_registration: [], store_instance: [{ instance_id: INSTANCE_ID }],
  };
  assertPreStateEstablished(structuredClone(established), established, "runner-test/member-2");

  for (const [name, injected] of [
    ["an injected row", { refresh_token: [{
      token_hash: "f".repeat(64), family_id: "family", client_id: "client", subject: "user",
      resource: RESOURCE, scopes: ["mcp:read"], expires_at: CLOCK }] }],
    ["an omitted kind", { authorization_code: [], consent_jti: [], refresh_token: [],
      revoked_family: [], client_registration: [], store_instance: [] }],
    ["a differing row", { consent_jti: [{ jti: "chain-member-1-jti", expires_at: CLOCK }] }],
  ] as Array<[string, LogicalState]>) {
    assert.throws(
      () => assertPreStateEstablished(injected, established, "runner-test/member-2"),
      /member-2 pre-state is not the expected post-state/u, name,
    );
  }
});

test("a rejected boot with the wrong code fails the fixture", async () => {
  await assert.rejects(
    runFixture(bootFixture("Bridge", baseConfig(),
      { outcome: "rejected", error: { code: "not_the_code" } })),
    /boot/,
  );
});

test("a createBridgeConfig boot with a valid clock and accepted outcome passes", async () => {
  await runFixture(bootFixture("createBridgeConfig", baseConfig(), { outcome: "accepted" }));
});


test("a chain shares captures between members", async () => {
  const first = await protectedFixture("runner-test/chain-first");
  const second = await protectedFixture("runner-test/chain-second");
  second.when.request.headers!.authorization = {
    $capture: { fixture: "runner-test/chain-first", name: "captured_token", format: "bearer" } };
  second.then = { status: 401, headers: { "www-authenticate": { contains: "Bearer " } },
    audit: { events: [{ occurredAt: CLOCK, event: "auth.request", status: "failure",
      reason: "invalid_token" }], absent: [] },
    state: first.then.state, captures: [], outbound: [] };
  const members = [first, second];
  for (const adapter of adaptersForChain(members)) {
    const captures: CaptureValues = new Map();
    for (const fixture of members) {
      await runFixture(fixture, adapterForChainMember(fixture, adapter), captures);
    }
    assert.equal(captures.get("runner-test/chain-first")?.get("captured_token"), CAPTURED);
  }
});

test("the section 8.4 fixtures load with bound ids and clauses", async () => {
  const corpus = await loadCorpus();
  for (const id of ["08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable",
    "08-resource-server-verifier/8.4-duplicate-authorization-fails-closed",
    "08-resource-server-verifier/8.4-single-authorization-succeeds-portable",
    "08-resource-server-verifier/8.4-zero-authorization-fails-closed-portable"]) {
    const fixture = corpus.find((candidate) => candidate.id === id);
    assert.ok(fixture, `${id} missing from the corpus`);
    assert.equal(fixture.kind, "fixture");
    assert.equal(fixture.status, "draft");
    assert.equal(fixture.contract.section, "08");
    assert.equal(fixture.contract.clause, "8.4");
  }
});
