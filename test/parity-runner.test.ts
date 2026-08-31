import assert from "node:assert/strict";
import { test } from "node:test";
import { assertAudit, assertState } from "./parity/assertions.ts";
import { captureResponse, materializeRequest } from "./parity/captures.ts";
import { materializeConfig, materializeConfigInput, publicKey } from "./parity/config.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import { bodyObservation, matcherMatches } from "./parity/matchers.ts";
import { OutboundScript } from "./parity/ports.ts";
import { runFixture } from "./parity/runner.ts";
import { sendRealHttp } from "./parity/http-client.ts";
import { clauseSource, compileJsonSchema, loadCorpus, validateChains } from "./parity/schema.ts";
import { SeededRandom } from "./parity/random.ts";
import { FixtureStore } from "./parity/store.ts";
import { adapterForChainMember, adaptersForChain } from "./parity/adapters.ts";
import { CimdResolver } from "../src/cimd/resolve.ts";
import type { BootFixture, HttpFixture } from "./parity/types.ts";

test("fixture loader validates both section 8.4 drafts and their contract quotes", async () => {
  const fixtures = await loadCorpus();
  const profiles = new Map(fixtures.map((fixture) => [fixture.id, fixture.profile]));
  assert.equal(profiles.get("08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable"), "portable");
  assert.equal(profiles.get("08-resource-server-verifier/8.4-duplicate-authorization-fails-closed"), "host");
});

test("fixture quote validation admits a root contract clause", () => {
  const source = "# 11. Scope contract\n\nRoot-clause sentence.\n\n# 12. Next contract\n\nOther sentence.\n";
  assert.equal(clauseSource(source, "11").trim(), "Scope contract\n\nRoot-clause sentence.");
});

test("request materialization preserves real header occurrences and adds no Content-Type", () => {
  const request = materializeRequest({ method: "POST", path: "/mcp", headers: {
    authorization: ["Bearer first", "Bearer second"], "x-fixture": "one",
  } }, new Map());
  assert.deepEqual(request.headers, [
    ["authorization", "Bearer first"], ["authorization", "Bearer second"], ["x-fixture", "one"],
  ]);
  assert.equal(request.body, undefined);
});

test("request materialization and real HTTP reject header line injection", () => {
  for (const value of ["safe\rmalicious: one", "safe\nmalicious: two"]) {
    assert.throws(() => materializeRequest({ method: "GET", path: "/", headers: {
      "x-fixture": value,
    } }, new Map()), /cannot contain CR or LF/);
    assert.throws(() => sendRealHttp({ base: "http://127.0.0.1:1", method: "GET", path: "/",
      headers: [["x-fixture", value]] }), /cannot contain CR or LF/);
  }
  const captures = new Map([["previous-fixture", new Map([["value", "safe\rmalicious: captured"]])]]);
  assert.throws(() => materializeRequest({ method: "GET", path: "/", headers: {
    "x-fixture": { $capture: { fixture: "previous-fixture", name: "value", format: "raw" } },
  } }, captures), /cannot contain CR or LF/);
  assert.throws(() => sendRealHttp({ base: "http://127.0.0.1:1", method: "GET", path: "/safe\r\nX: one",
    headers: [] }), /method and path cannot contain CR or LF/);
  assert.throws(() => sendRealHttp({ base: "http://127.0.0.1:1", method: "GET",
    path: "//169.254.169.254/latest/meta-data", headers: [] }), /cannot leave the mounted host/);
});

test("chain captures insert only as complete inbound values", () => {
  const captures = new Map([["previous-fixture", new Map([["token", "captured-token"]])]]);
  const bearer = { $capture: { fixture: "previous-fixture", name: "token", format: "bearer" as const } };
  const raw = { $capture: { fixture: "previous-fixture", name: "token", format: "raw" as const } };
  const request = materializeRequest({ method: "POST", path: "/oauth/token", headers: {
    authorization: bearer, "content-type": "application/json",
  }, body: { json: { token: raw } } }, captures);
  assert.deepEqual(request.headers, [["authorization", "Bearer captured-token"],
    ["content-type", "application/json"]]);
  assert.deepEqual(JSON.parse(String(request.body)), { token: "captured-token" });
  const literal = materializeRequest({ method: "POST", path: "/", headers: {
    "content-type": "application/json",
  }, body: { json: { $capture: "ordinary-data", nested: { $capture: {
    fixture: "previous-fixture", name: "token", format: "raw", extra: "ordinary-data",
  } } } } }, captures);
  assert.deepEqual(JSON.parse(String(literal.body)), { $capture: "ordinary-data", nested: { $capture: {
    fixture: "previous-fixture", name: "token", format: "raw", extra: "ordinary-data",
  } } });
  assert.throws(() => materializeRequest({ method: "GET", path: "/", headers: {
    "x-token": bearer,
  } }, captures), /valid only for an Authorization header/);
  assert.throws(() => materializeRequest({ method: "GET", path: "/", headers: {
    authorization: { $capture: { fixture: "other-chain", name: "token", format: "bearer" } },
  } }, captures), /missing or out-of-chain capture/);
});

test("bearer captures are invalid in every request-body encoding", () => {
  const captures = new Map([["previous-fixture", new Map([["token", "captured-token"]])]]);
  const bearer = { $capture: { fixture: "previous-fixture", name: "token", format: "bearer" as const } };
  assert.throws(() => materializeRequest({ method: "POST", path: "/", headers: {
    "content-type": "application/json",
  }, body: { json: { token: bearer } } }, captures), /valid only for an Authorization header/);
  assert.throws(() => materializeRequest({ method: "POST", path: "/", headers: {
    "content-type": "application/x-www-form-urlencoded",
  }, body: { form: [{ name: "token", value: bearer }] } }, captures), /valid only for an Authorization header/);
  assert.throws(() => materializeRequest({ method: "POST", path: "/", headers: {
    "content-type": "text/plain",
  }, body: { text: bearer } }, captures), /valid only for an Authorization header/);
});

test("chain validation rejects capture names reused by another step", async () => {
  const first = structuredClone(await hostFixture());
  const second = structuredClone(first);
  first.id = "08-resource-server-verifier/8.4-chain-first";
  first.chain = { id: "capture-chain", step: 1 };
  first.then.captures = [{ name: "token", source: { bodyPointer: "/token" } }];
  second.id = "08-resource-server-verifier/8.4-chain-second";
  second.chain = { id: "capture-chain", step: 2, previous: first.id };
  second.then.captures = [{ name: "token", source: { bodyPointer: "/other" } }];
  assert.throws(() => validateChains([first, second]), /duplicate capture name token/);
});

test("mixed-profile chains run portable members through every adapter", async () => {
  const host = structuredClone(await hostFixture());
  const portable = structuredClone(host); portable.profile = "portable";
  assert.deepEqual(adaptersForChain([host, portable]), ["fastify", "express", "hono"]);
  assert.equal(adapterForChainMember(host, "express"), "fastify");
  assert.equal(adapterForChainMember(portable, "express"), "express");
});

test("response captures require one string selected by JSON Pointer or URL query", async () => {
  const captures = new Map();
  await captureResponse("current-fixture", [
    { name: "body_token", source: { bodyPointer: "/token" } },
    { name: "query_code", source: { header: "location", urlQuery: "code" } },
  ], { status: 200, headers: { "content-type": "application/json",
    location: "https://client.example.com/callback?code=query-code" },
  body: Buffer.from(JSON.stringify({ token: "body-token" })) }, "keys/signing-public.pem", captures);
  assert.deepEqual([...captures.get("current-fixture") ?? []], [
    ["body_token", "body-token"], ["query_code", "query-code"],
  ]);
  await assert.rejects(captureResponse("ambiguous", [
    { name: "query_code", source: { header: "location", urlQuery: "code" } },
  ], { status: 302, headers: { location: "https://client.example.com/?code=one&code=two" },
    body: Buffer.alloc(0) }, "keys/signing-public.pem", captures), /missing or ambiguous/);
});

test("fixture key paths cannot escape fixtures/keys", async () => {
  await assert.rejects(publicKey("../package.json"), /outside fixtures\/keys/);
  await assert.rejects(publicKey("/tmp/fixture-key.pem"), /must be relative/);
  await assert.rejects(publicKey("keys\\signing-public.pem"), /use forward slashes/);
  await assert.rejects(publicKey("keys/missing.pem"), /cannot be inspected/);
});

test("request materialization rejects body and Content-Type mismatches", () => {
  assert.throws(() => materializeRequest({ method: "POST", path: "/", headers: {}, body: { json: {} } }, new Map()), /requires Content-Type application\/json/);
  assert.throws(() => materializeRequest({ method: "POST", path: "/", headers: {
    "content-type": "application/json",
  }, body: { form: [] } }, new Map()), /application\/x-www-form-urlencoded/);
});

test("RE2 assertions use search semantics and reject implementation-specific syntax", () => {
  assert.equal(matcherMatches("prefix-value-suffix", { matches: "value" }), true);
  assert.equal(matcherMatches("é", { matches: "^.$" }), true);
  assert.throws(() => matcherMatches("a", { matches: "(?=a)" }), FixtureRunnerError);
  assert.throws(() => matcherMatches("aa", { matches: "(a)\\1" }), FixtureRunnerError);
});

test("JSON body schemas compile independently across fixtures", () => {
  const first = compileJsonSchema({ $id: "https://fixture.example/schema", type: "string" });
  const second = compileJsonSchema({ $id: "https://fixture.example/schema", type: "number" });
  assert.equal(first("value"), true); assert.equal(second(42), true);
});

test("body observation distinguishes no bytes from an empty JSON value", () => {
  assert.deepEqual(bodyObservation(Buffer.alloc(0), {}), { present: false });
  assert.deepEqual(bodyObservation(Buffer.from('""'), { "content-type": "application/json" }), { present: true, value: "" });
});

test("an explicit empty-string response assertion is not treated as omitted", async () => {
  const fixture = await hostFixture();
  const changed = structuredClone(fixture); changed.then.body = "";
  await assert.rejects(runFixture(changed), (error: unknown) => error instanceof FixtureRunnerError
    && error.cause instanceof Error && /response body did not match/u.test(error.cause.message));
});

test("request encoding rejects before configuration or app composition", async () => {
  const fixture = await hostFixture();
  const changed = structuredClone(fixture);
  changed.given.config = {}; changed.when.request.body = { json: {} };
  delete changed.when.request.headers?.["content-type"];
  await assert.rejects(runFixture(changed), /JSON body requires Content-Type application\/json/);
});

test("HTTP execution enforces status and each listed response header", async () => {
  const fixture = await hostFixture();
  const wrongStatus = structuredClone(fixture); wrongStatus.then.status = 418;
  await assert.rejects(runFixture(wrongStatus), (error: unknown) => hasCause(error, /response status/u));
  const wrongHeader = structuredClone(fixture);
  wrongHeader.then.headers = { "www-authenticate": "Bearer wrong" };
  await assert.rejects(runFixture(wrongHeader), (error: unknown) => hasCause(error, /response header www-authenticate/u));
});

test("boot execution enforces accepted and exact rejected outcomes", async () => {
  const fixture = await hostFixture();
  const { protectedResource: _ignored, ...given } = fixture.given;
  const { when: _request, ...base } = fixture;
  const accepted: BootFixture = { ...base, kind: "boot", given: { ...given,
    entrypoint: "createBridgeConfig" }, then: { boot: { outcome: "accepted" }, outbound: [] } };
  await runFixture(accepted);
  const rejected: BootFixture = structuredClone(accepted);
  rejected.given.config = { ...rejected.given.config, unknown_fixture_key: true };
  rejected.then.boot = { outcome: "rejected", error: { code: "invalid_auth_config",
    name: "Error", message: { contains: "unknown BridgeConfig key" } } };
  await runFixture(rejected);
  const wrongCode = structuredClone(rejected);
  if (wrongCode.then.boot.outcome !== "rejected") assert.fail("rejected boot fixture changed shape");
  wrongCode.then.boot.error.code = "wrong_code";
  await assert.rejects(runFixture(wrongCode), (error: unknown) => hasCause(error, /boot error code/u));
  const bridgeBoundary = structuredClone(accepted);
  bridgeBoundary.given.entrypoint = "Bridge";
  bridgeBoundary.given.config = { ...bridgeBoundary.given.config, unknown_fixture_key: true };
  await runFixture(bridgeBoundary);
});

test("fixture clocks reject impossible dates before HTTP composition", async () => {
  const fixture = await hostFixture();
  const http = structuredClone(fixture);
  http.given.clock = "2026-02-31T00:00:00.000Z";
  http.given.config = {};
  await assert.rejects(runFixture(http), /given\.clock is not a canonical UTC timestamp/);
});

test("fixture clocks reject impossible dates before boot composition", async () => {
  const fixture = await hostFixture();
  const { protectedResource: _ignored, ...given } = fixture.given;
  const { when: _request, ...base } = fixture;
  const boot: BootFixture = { ...base, kind: "boot", given: { ...given,
    clock: "2026-13-01T00:00:00.000Z", entrypoint: "createBridgeConfig", config: {} },
  then: { boot: { outcome: "accepted" }, outbound: [] } };
  await assert.rejects(runFixture(boot), /given\.clock is not a canonical UTC timestamp/);
});

test("stored-DCR materialization retains literal nested fields while adding its port", async () => {
  const fixture = await hostFixture();
  const store = new FixtureStore({}, new SeededRandom("literal-dcr"));
  try {
    const input = await materializeConfigInput({ ...fixture.given.config,
      dcr: { mode: "stored", fixture_marker: "retained" } }, fixture.given.keys, store);
    assert.equal((input as { dcr: { fixture_marker: string } }).dcr.fixture_marker, "retained");
    assert.equal((input as { dcr: { store: unknown } }).dcr.store, store);
  } finally { await store.close(); }
});

test("fixture store revokes replayed families before predecessor expiry rejection", async () => {
  const predecessor = "a".repeat(64), successor = "b".repeat(64), family = "fixture-family";
  const store = new FixtureStore({ refresh_token: [
    { token_hash: predecessor, family_id: family, client_id: "fixture-client", subject: "fixture-subject",
      resource: "https://api.example.com/mcp", scopes: ["mcp:read"],
      expires_at: "2026-08-31T11:00:00.000Z", consumed_at: "2026-08-31T10:00:00.000Z" },
    { token_hash: successor, family_id: family, previous_token_hash: predecessor,
      client_id: "fixture-client", subject: "fixture-subject", resource: "https://api.example.com/mcp",
      scopes: ["mcp:read"], expires_at: "2026-08-31T13:00:00.000Z" },
  ] }, new SeededRandom("replay-order"));
  try {
    const now = "2026-08-31T12:00:00.000Z";
    const rotated = await store.rotateRefreshToken(predecessor, {
      tokenHash: "c".repeat(64), familyId: family, previousTokenHash: predecessor,
      clientId: "ignored-client", subject: "ignored-subject", resource: "https://api.example.com/mcp",
      scopes: ["ignored"], expiresAt: "2026-08-31T14:00:00.000Z",
    }, now);
    assert.equal(rotated, null);
    assert.deepEqual(store.snapshot().revoked_family, [{
      family_id: family, resource: "https://api.example.com/mcp", revoked_at: now,
    }]);
  } finally { await store.close(); }
});

test("audit and logical state assertions are exact and honor absent selectors", () => {
  const event = { occurredAt: "2026-08-31T10:00:00.000Z", event: "auth.request" as const,
    status: "failure" as const, reason: "duplicate_authorization" };
  assertAudit([event], { events: [event], absent: [{ status: "success" }] }, "fixture");
  assert.throws(() => assertAudit([event], { events: [], absent: [] }, "fixture"), /exact audit events/);
  assert.throws(() => assertAudit([event], { events: [event], absent: [{ reason: event.reason }] }, "fixture"), /forbidden audit selector/);
  const state = { authorization_code: [], consent_jti: [], refresh_token: [], revoked_family: [],
    client_registration: [], store_instance: [{ instance_id: "fixture-store" }] };
  assertState(state, { mode: "contains", rows: {}, absent: [{ kind: "authorization_code",
    where: { client_id: "missing" } }] }, "fixture");
  assert.throws(() => assertState(state, { mode: "exact", rows: {}, absent: [] }, "fixture"), /exact state/);
  assert.throws(() => assertState(state, { mode: "contains", rows: {}, absent: [{
    kind: "store_instance", where: { instance_id: "fixture-store" } }] }, "fixture"), /forbidden state selector/);
  for (const kind of ["authorization_code", "consent_jti", "refresh_token", "revoked_family",
    "client_registration", "store_instance"] as const) {
    assert.throws(() => assertState(state, { mode: "contains", rows: {}, absent: [{
      kind, where: { misspelled_field: "value" } }] }, "fixture"), /state selector has unknown/);
  }
});

test("outbound scripts fail on an unconsumed or unmatched exchange", async () => {
  const exchange = { request: { method: "GET", url: "https://client.example.com/metadata",
    headers: {}, body: { absent: true } as const }, response: { status: 200,
    headers: { "content-type": "application/json" }, body: { value: {} } } };
  const declared = new OutboundScript([exchange]);
  assert.throws(() => declared.assertComplete([], "fixture"), /all outbound scripts consumed/);
  await assert.rejects(() => new OutboundScript([]).fetch("https://client.example.com/metadata"), /unmatched outbound call/);
  assert.deepEqual(await declared.resolver.resolve("client.example.com"), [{ address: "93.184.216.34", family: 4 }]);
  await assert.rejects(() => new OutboundScript([]).resolver.resolve("client.example.com"),
    /unmatched DnsResolver\.resolve call/);
});

test("declared CIMD exchanges pass the guarded resolver without network I/O", async () => {
  const fixture = await hostFixture();
  const store = new FixtureStore({}, new SeededRandom("declared-cimd"));
  const url = "https://client.example.com/metadata";
  const redirectUri = "https://client.example.com/callback";
  const exchange = { request: { method: "GET", url,
    headers: {}, body: { absent: true } as const }, response: { status: 200,
    headers: { "content-type": "application/json" }, body: { value: {
      client_id: url, client_name: "Fixture client", redirect_uris: [redirectUri],
    } } } };
  const script = new OutboundScript([exchange]);
  try {
    const config = await materializeConfig({ ...fixture.given.config,
      cimd: { enabled: true } }, fixture.given.keys, store);
    const resolver = new CimdResolver({ config,
      clock: { nowMs: () => Date.parse(fixture.given.clock) }, audit: { async writeAuthEvent() {} },
      cimdTransport: script.transport, cimdResolver: script.resolver });
    const resolved = await resolver.resolve({ clientId: url, redirectUri });
    assert.equal(resolved.registration.client_id, url);
    script.assertComplete([{ method: "GET", url, headers: {
      host: { equals: "client.example.com" }, accept: { equals: "application/json" },
      "accept-encoding": { equals: "identity" },
    }, body: { absent: true } }], "fixture");
  } finally { await store.close(); }
});

test("given HTTP exchanges match independently of their listed order", async () => {
  const exchange = (url: string) => ({ request: { method: "GET", url,
    headers: {}, body: { absent: true } as const }, response: { status: 204,
    headers: {}, body: { absent: true } as const } });
  const first = exchange("https://client.example.com/first");
  const second = exchange("https://client.example.com/second");
  const script = new OutboundScript([first, second]);
  await script.fetch(second.request.url); await script.fetch(first.request.url);
  script.assertComplete([
    { method: "GET", url: second.request.url, headers: {}, body: { absent: true } },
    { method: "GET", url: first.request.url, headers: {}, body: { absent: true } },
  ], "fixture");
});

test("given HTTP responses preserve distinct header occurrences", async () => {
  const url = "https://client.example.com/repeated-response";
  const script = new OutboundScript([{ request: { method: "GET", url,
    headers: {}, body: { absent: true } }, response: { status: 200,
    headers: { "x-fixture": ["one", "two"], "set-cookie": ["a=1", "b=2"] },
    body: { absent: true } } }]);
  const response = await script.fetch(url);
  assert.deepEqual([...response.headers], [
    ["x-fixture", "one"], ["x-fixture", "two"], ["set-cookie", "a=1"], ["set-cookie", "b=2"],
  ]);
  assert.deepEqual(response.headers.getSetCookie(), ["a=1", "b=2"]);
  assert.throws(() => response.headers.get("x-fixture"), /multiple occurrences/);
});

test("scripted JSON string responses are serialized as JSON", async () => {
  const url = "https://client.example.com/json-string";
  const script = new OutboundScript([{ request: { method: "GET", url,
    headers: {}, body: { absent: true } }, response: { status: 200,
    headers: { "content-type": "application/json" }, body: { value: "ok" } } }]);
  const outbound = await script.fetch(url);
  assert.equal(await outbound.text(), '"ok"');
});

test("protected-resource JSON string responses are serialized as JSON", async () => {
  const fixture = structuredClone(await hostFixture());
  const authorization = fixture.when.request.headers?.authorization;
  if (!Array.isArray(authorization) || typeof authorization[0] !== "string") {
    assert.fail("host fixture authorization occurrences missing");
  }
  fixture.when.request.headers!.authorization = authorization[0];
  fixture.given.protectedResource.success = { status: 200,
    headers: { "content-type": "application/json" }, body: { value: "ok" } };
  fixture.then = { status: 200, headers: { "content-type": { contains: "application/json" } },
    body: { equals: "ok" }, outbound: [] };
  await runFixture(fixture);
});

test("outbound observation preserves request header occurrences", async () => {
  const url = "https://client.example.com/repeated-request";
  const script = new OutboundScript([{ request: { method: "GET", url,
    headers: { "x-fixture": { equals: ["one", "two"] } }, body: { absent: true } },
  response: { status: 204, headers: {}, body: { absent: true } } }]);
  await script.fetch(url, { headers: [["x-fixture", "one"], ["x-fixture", "two"]] });
  script.assertComplete([{ method: "GET", url, headers: {
    "x-fixture": { equals: ["one", "two"] },
  }, body: { absent: true } }], "fixture");
});

test("then outbound headers reject an extra observed header", async () => {
  const url = "https://client.example.com/exact";
  const script = new OutboundScript([{ request: { method: "GET", url,
    headers: { "x-observed": "one" }, body: { absent: true } }, response: { status: 204,
    headers: {}, body: { absent: true } } }]);
  await script.fetch(url, { headers: { "x-observed": "one" } });
  assert.throws(() => script.assertComplete([
    { method: "GET", url, headers: {}, body: { absent: true } },
  ], "fixture"), /header-name set/);
});

async function hostFixture(): Promise<HttpFixture> {
  const fixture = (await loadCorpus()).find((candidate) => candidate.profile === "host");
  if (!fixture || fixture.kind !== "fixture") assert.fail("host HTTP fixture missing");
  return fixture;
}

function hasCause(error: unknown, pattern: RegExp): boolean {
  return error instanceof FixtureRunnerError && error.cause instanceof Error && pattern.test(error.cause.message);
}
