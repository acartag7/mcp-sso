import assert from "node:assert/strict";
import { test } from "node:test";
import { materializeRequest } from "./parity/captures.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import { bodyObservation, matcherMatches } from "./parity/matchers.ts";
import { OutboundScript } from "./parity/ports.ts";
import { runFixture } from "./parity/runner.ts";
import { compileJsonSchema, loadCorpus } from "./parity/schema.ts";

test("fixture loader validates both section 8.4 drafts and their contract quotes", async () => {
  const fixtures = await loadCorpus();
  const profiles = new Map(fixtures.map((fixture) => [fixture.id, fixture.profile]));
  assert.equal(profiles.get("08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable"), "portable");
  assert.equal(profiles.get("08-resource-server-verifier/8.4-duplicate-authorization-fails-closed"), "host");
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
  const fixture = (await loadCorpus()).find((candidate) => candidate.profile === "host");
  if (!fixture || fixture.kind !== "fixture") assert.fail("host HTTP fixture missing");
  const changed = structuredClone(fixture); changed.then.body = "";
  await assert.rejects(runFixture(changed), (error: unknown) => error instanceof FixtureRunnerError
    && error.cause instanceof Error && /response body did not match/u.test(error.cause.message));
});

test("request encoding rejects before configuration or app composition", async () => {
  const fixture = (await loadCorpus()).find((candidate) => candidate.profile === "host");
  if (!fixture || fixture.kind !== "fixture") assert.fail("host HTTP fixture missing");
  const changed = structuredClone(fixture);
  changed.given.config = {}; changed.when.request.body = { json: {} };
  delete changed.when.request.headers?.["content-type"];
  await assert.rejects(runFixture(changed), /JSON body requires Content-Type application\/json/);
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
