import assert from "node:assert/strict";
import { test } from "node:test";
import { assertAudit, assertState } from "./parity/assertions.ts";
import { captureResponse, materializeRequest } from "./parity/captures.ts";
import { publicKey } from "./parity/config.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import { bodyObservation, matcherMatches } from "./parity/matchers.ts";
import { OutboundScript } from "./parity/ports.ts";
import { runFixture } from "./parity/runner.ts";
import { clauseSource, compileJsonSchema, loadCorpus } from "./parity/schema.ts";
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
  assert.throws(() => materializeRequest({ method: "GET", path: "/", headers: {
    "x-token": bearer,
  } }, captures), /valid only for an Authorization header/);
  assert.throws(() => materializeRequest({ method: "GET", path: "/", headers: {
    authorization: { $capture: { fixture: "other-chain", name: "token", format: "bearer" } },
  } }, captures), /missing or out-of-chain capture/);
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
});

test("outbound scripts fail on an unconsumed or unmatched exchange", async () => {
  const exchange = { request: { method: "GET", url: "https://client.example.com/metadata",
    headers: {}, body: { absent: true } as const }, response: { status: 200,
    headers: { "content-type": "application/json" }, body: { value: {} } } };
  assert.throws(() => new OutboundScript([exchange]).assertComplete([], "fixture"), /all outbound scripts consumed/);
  await assert.rejects(() => new OutboundScript([]).fetch("https://client.example.com/metadata"), /unmatched outbound call/);
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
