import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { loadFixture } from "./parity/schema-json.ts";
import type { CaptureReference, HeaderMap, HeaderValue, HttpFixture, ParityFixture } from "./parity/types.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const FIXTURE_PATH = resolve(PROJECT_ROOT, "fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable.json");
const CAPTURE: CaptureReference = {
  $capture: { fixture: "08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable", name: "token", format: "raw" },
};

function asHttp(fixture: ParityFixture): HttpFixture {
  if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
  return fixture;
}

async function temporaryFixture(fixture: HttpFixture): Promise<ParityFixture> {
  const directory = await mkdtemp(join(tmpdir(), "mcp-sso-response-header-schema-"));
  const path = join(directory, "fixture.json");
  try {
    await writeFile(path, JSON.stringify(fixture), "utf8");
    return await loadFixture(path);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function loadMutated(mutate: (fixture: HttpFixture) => void): Promise<ParityFixture> {
  const fixture = asHttp(structuredClone(await loadFixture(FIXTURE_PATH)));
  mutate(fixture);
  return temporaryFixture(fixture);
}

async function caught(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  return undefined;
}

function scriptedExchange(headers: HeaderMap) {
  return {
    request: { method: "GET", url: "https://idp.example.com/metadata", headers: {}, body: { absent: true as const } },
    response: { status: 200, headers, body: { value: "ok" } },
  };
}

async function expectResponseCaptureRejection(
  value: HeaderValue,
  mutate: (fixture: HttpFixture, value: HeaderValue) => void,
  path: string,
): Promise<void> {
  const error = await caught(() => loadMutated((fixture) => mutate(fixture, value)));
  assert.ok(error instanceof FixtureRunnerError);
  assert.match(error.message, /schema validation failed/u);
  assert.match(error.message, new RegExp(path, "u"));
}

test("rejects a scalar capture in a scripted response header", async () => {
  await expectResponseCaptureRejection(
    CAPTURE,
    (fixture, value) => { fixture.given.http = [scriptedExchange({ "x-response": value })]; },
    "fixture/given/http/0/response/headers/x-response",
  );
});

test("rejects a capture in a two-occurrence scripted response header", async () => {
  await expectResponseCaptureRejection(
    [CAPTURE, "literal"],
    (fixture, value) => { fixture.given.http = [scriptedExchange({ "x-response": value })]; },
    "fixture/given/http/0/response/headers/x-response",
  );
});

test("rejects a scalar capture in a protected-resource success header", async () => {
  await expectResponseCaptureRejection(
    CAPTURE,
    (fixture, value) => { fixture.given.protectedResource.success!.headers = { "x-response": value }; },
    "fixture/given/protectedResource/success/headers/x-response",
  );
});

test("rejects a capture in a two-occurrence protected-resource success header", async () => {
  await expectResponseCaptureRejection(
    [CAPTURE, "literal"],
    (fixture, value) => { fixture.given.protectedResource.success!.headers = { "x-response": value }; },
    "fixture/given/protectedResource/success/headers/x-response",
  );
});

test("accepts literal scalar and two-occurrence response headers", async () => {
  const values: HeaderValue[] = ["literal", ["first", "second"]];
  for (const value of values) {
    await loadMutated((fixture) => { fixture.given.http = [scriptedExchange({ "x-response": value })]; });
    await loadMutated((fixture) => { fixture.given.protectedResource.success!.headers = { "x-response": value }; });
  }
});

test("keeps inbound request header captures valid", async () => {
  const loaded = await loadMutated((fixture) => { fixture.when.request.headers = { authorization: CAPTURE }; });
  assert.deepEqual(asHttp(loaded).when.request.headers?.authorization, CAPTURE);
});
