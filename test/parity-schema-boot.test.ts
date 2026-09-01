import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { loadFixture } from "./parity/schema-json.ts";
import type { BootFixture, HttpFixture, ParityFixture } from "./parity/types.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const HTTP_FIXTURES = {
  portable: resolve(PROJECT_ROOT, "fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable.json"),
  host: resolve(PROJECT_ROOT, "fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed.json"),
} as const;

async function bootFixture(profile: "portable" | "host"): Promise<BootFixture> {
  const source = structuredClone(await loadFixture(HTTP_FIXTURES[profile])) as HttpFixture;
  const { when: _when, then: _then, given, ...base } = source;
  const { protectedResource: _protectedResource, ...bootGiven } = given;
  return {
    ...base,
    kind: "boot",
    given: { ...bootGiven, entrypoint: "Bridge" },
    then: { boot: { outcome: "rejected", error: { code: "invalid_config" } }, outbound: [] },
  } as BootFixture;
}

async function withTemporaryFixture<T>(fixture: ParityFixture, run: (path: string) => Promise<T>): Promise<T> {
  const directory = await mkdtemp(join(tmpdir(), "mcp-sso-parity-boot-schema-"));
  try {
    const path = join(directory, "fixture.json");
    await writeFile(path, JSON.stringify(fixture), "utf8");
    return await run(path);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function expectSchemaFailure(fixture: BootFixture): Promise<void> {
  await withTemporaryFixture(fixture, async (path) => {
    await assert.rejects(() => loadFixture(path), (error: unknown) => {
      assert.ok(error instanceof FixtureRunnerError);
      assert.match(error.message, /schema validation failed/u);
      return true;
    });
  });
}

async function loadBootFixture(fixture: BootFixture): Promise<BootFixture> {
  const loaded = await withTemporaryFixture(fixture, (path) => loadFixture(path));
  if (loaded.kind !== "boot") throw new Error("expected boot fixture");
  return loaded;
}

test("rejects a portable rejected boot fixture that matches error name", async () => {
  const fixture = await bootFixture("portable");
  if (fixture.then.boot.outcome !== "rejected") throw new Error("expected rejected boot fixture");
  fixture.then.boot.error.name = "Error";
  await expectSchemaFailure(fixture);
});

test("rejects a portable rejected boot fixture that matches error message", async () => {
  const fixture = await bootFixture("portable");
  if (fixture.then.boot.outcome !== "rejected") throw new Error("expected rejected boot fixture");
  fixture.then.boot.error.message = "invalid configuration";
  await expectSchemaFailure(fixture);
});

test("accepts a portable rejected boot fixture with only its public error code", async () => {
  const fixture = await bootFixture("portable");
  const loaded = await loadBootFixture(fixture);
  assert.equal(loaded.then.boot.outcome, "rejected");
  assert.deepEqual(loaded.then.boot.error, { code: "invalid_config" });
});

test("accepts host rejected boot matchers for name and message", async () => {
  const fixture = await bootFixture("host");
  if (fixture.then.boot.outcome !== "rejected") throw new Error("expected rejected boot fixture");
  fixture.then.boot.error.name = "Error";
  fixture.then.boot.error.message = "invalid configuration";
  const loaded = await loadBootFixture(fixture);
  assert.equal(loaded.profile, "host");
  assert.deepEqual(loaded.then.boot.error, {
    code: "invalid_config", name: "Error", message: "invalid configuration",
  });
});
