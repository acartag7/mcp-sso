import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { loadFixture } from "./parity/schema-json.ts";
import type { BootFixture, HttpExchange, HttpFixture, Matcher, ParityFixture } from "./parity/types.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const HTTP_PATH = resolve(PROJECT_ROOT, "fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable.json");
const BOOT_PATH = resolve(PROJECT_ROOT, "fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed.json");
const INVALID_VALUES = [[], ["one"]] as string[][];
const VALID_VALUES: Array<string | string[]> = ["one", ["one", "two"]];
const OCCURRENCE_MESSAGE = "must use a string for one occurrence or an array for multiple occurrences";

function asHttp(fixture: ParityFixture): HttpFixture {
  if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
  return fixture;
}

function asBoot(fixture: ParityFixture): BootFixture {
  const source = asHttp(fixture);
  const { when: _when, then: _then, given, ...base } = source;
  const { protectedResource: _protectedResource, ...bootGiven } = given;
  return {
    ...base,
    kind: "boot",
    given: { ...bootGiven, entrypoint: "Bridge" },
    then: { boot: { outcome: "accepted" }, outbound: [] },
  };
}

async function writeAndLoad(fixture: ParityFixture): Promise<ParityFixture> {
  const directory = await mkdtemp(join(tmpdir(), "mcp-sso-header-schema-"));
  const path = join(directory, "fixture.json");
  try {
    await writeFile(path, JSON.stringify(fixture), "utf8");
    return await loadFixture(path);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function loadHttp(mutate: (fixture: HttpFixture) => void): Promise<ParityFixture> {
  const fixture = asHttp(structuredClone(await loadFixture(HTTP_PATH)));
  mutate(fixture);
  return writeAndLoad(fixture);
}

async function loadBoot(mutate: (fixture: BootFixture) => void): Promise<ParityFixture> {
  const fixture = asBoot(structuredClone(await loadFixture(BOOT_PATH)));
  mutate(fixture);
  return writeAndLoad(fixture);
}

async function captureError(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  return undefined;
}

function assertHeaderError(caught: unknown, message: string): void {
  assert.ok(caught instanceof FixtureRunnerError);
  assert.equal(caught.message, message);
}

function scriptedExchange(value: string | string[], headers: Record<string, Matcher> = {}): HttpExchange {
  return {
    request: { method: "GET", url: "https://idp.example.com/metadata", headers, body: { absent: true } },
    response: { status: 200, headers: { "x-scripted": value }, body: { value: "ok" } },
  };
}

test("rejects empty and one-occurrence inbound request headers", async () => {
  const fixtureId = (await loadFixture(HTTP_PATH)).id;
  const errors = await Promise.all(INVALID_VALUES.map((value) => captureError(
      () => loadHttp((fixture) => { fixture.when.request.headers = { authorization: value }; }),
  )));
  for (const error of errors) assertHeaderError(error, `${fixtureId} inbound request header authorization ${OCCURRENCE_MESSAGE}`);
});

test("rejects empty and one-occurrence scripted response headers for HTTP fixtures", async () => {
  const fixtureId = (await loadFixture(HTTP_PATH)).id;
  const errors = await Promise.all(INVALID_VALUES.map((value) => captureError(
      () => loadHttp((fixture) => { fixture.given.http = [scriptedExchange(value)]; }),
  )));
  for (const error of errors) assertHeaderError(error, `${fixtureId} HTTP response 1 header x-scripted ${OCCURRENCE_MESSAGE}`);
});

test("rejects empty and one-occurrence scripted response headers for boot fixtures", async () => {
  const fixtureId = (await loadFixture(BOOT_PATH)).id;
  const errors = await Promise.all(INVALID_VALUES.map((value) => captureError(
      () => loadBoot((fixture) => { fixture.given.http = [scriptedExchange(value)]; }),
  )));
  for (const error of errors) assertHeaderError(error, `${fixtureId} HTTP response 1 header x-scripted ${OCCURRENCE_MESSAGE}`);
});

test("rejects empty and one-occurrence protected-resource success headers", async () => {
  const fixtureId = (await loadFixture(HTTP_PATH)).id;
  const errors = await Promise.all(INVALID_VALUES.map((value) => captureError(
      () => loadHttp((fixture) => { fixture.given.protectedResource.success!.headers = { "x-protected": value }; }),
  )));
  for (const error of errors) assertHeaderError(error, `${fixtureId} protected response header x-protected ${OCCURRENCE_MESSAGE}`);
});

test("accepts scalar and two-occurrence values in each wire header map", async () => {
  for (const value of VALID_VALUES) {
    await loadHttp((fixture) => { fixture.when.request.headers = { authorization: value }; });
    await loadHttp((fixture) => { fixture.given.http = [scriptedExchange(value)]; });
    await loadBoot((fixture) => { fixture.given.http = [scriptedExchange(value)]; });
    await loadHttp((fixture) => { fixture.given.protectedResource.success!.headers = { "x-protected": value }; });
  }
});

test("keeps then and scripted request or outbound headers as matcher maps", async () => {
  await loadHttp((fixture) => {
    const matcher: Matcher = { equals: ["one", "two"] };
    const requestHeaders = { "x-request-match": matcher };
    fixture.then.headers = { "x-response-match": matcher };
    fixture.given.http = [scriptedExchange("response", requestHeaders)];
    fixture.then.outbound = [{
      method: "GET",
      url: "https://idp.example.com/metadata",
      headers: { "x-request-match": matcher },
      body: { absent: true },
    }];
  });
});
