import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { promisify } from "node:util";
import { FixtureRunnerError } from "./parity/error.ts";
import { loadFixture, compileJsonSchema } from "./parity/schema-json.ts";
import type { FixtureGiven, FixtureReceipt, HeaderValue, ParityFixture } from "./parity/types.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const execFileAsync = promisify(execFile);
const HTTP_KEYS_WITHOUT_PUBLIC: FixtureGiven["keys"] = { signingPrivate: "keys/signing-private.pem" };
const FIXTURE_PATHS = [
  ["fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable.json", "portable"],
  ["fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed.json", "host"],
] as const;

type Assert<T extends true> = T;
type FrozenReceiptIsRequired = Extract<ParityFixture, { status: "frozen" }> extends { receipt: FixtureReceipt }
  ? true : false;
type _FrozenReceiptRequirement = Assert<FrozenReceiptIsRequired>;

async function fixtureFromRepository(path: string): Promise<ParityFixture> {
  return loadFixture(resolve(PROJECT_ROOT, path));
}

async function writeTemporaryFixture(
  fixture: ParityFixture,
  mutate: (copy: ParityFixture) => void = () => {},
): Promise<{ directory: string; path: string }> {
  const directory = await mkdtemp(join(tmpdir(), "mcp-sso-schema-json-"));
  const path = join(directory, "fixture.json");
  const copy = structuredClone(fixture);
  mutate(copy);
  await writeFile(path, JSON.stringify(copy), "utf8");
  return { directory, path };
}

async function expectFixtureError(path: string, message: RegExp): Promise<FixtureRunnerError> {
  let caught: unknown;
  try {
    await loadFixture(path);
  } catch (error) {
    caught = error;
  }
  assert.ok(caught instanceof FixtureRunnerError);
  assert.match(caught.message, message);
  return caught;
}

test("loads the fixed schema independently of the current working directory", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-sso-schema-cwd-"));
  try {
    const moduleUrl = new URL("./parity/schema-json.ts", import.meta.url).href;
    const fixturePath = resolve(PROJECT_ROOT, FIXTURE_PATHS[0][0]);
    const script = `const { loadFixture } = await import(${JSON.stringify(moduleUrl)}); await loadFixture(${JSON.stringify(fixturePath)});`;
    await execFileAsync(process.execPath, ["--input-type=module", "--eval", script], { cwd: directory });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("shares one fixed-schema compilation across concurrent first loads", async () => {
  const fixtures = await Promise.all(FIXTURE_PATHS.map(([path]) => fixtureFromRepository(path)));
  assert.deepEqual(fixtures.map((fixture) => fixture.profile), ["portable", "host"]);
});

test("loads both section 8.4 fixtures by explicit path", async () => {
  for (const [path, profile] of FIXTURE_PATHS) {
    const fixture = await fixtureFromRepository(path);
    assert.equal(fixture.profile, profile);
    assert.equal(fixture.kind, "fixture");
  }
});

test("loads zero- and one-element header arrays without selecting occurrences", async () => {
  const fixture = await fixtureFromRepository(FIXTURE_PATHS[0][0]);
  if (fixture.kind !== "fixture") throw new Error("expected an HTTP fixture");
  const authorizationValues: HeaderValue[] = [[], ["Bearer one"]];
  for (const authorization of authorizationValues) {
    const { directory, path } = await writeTemporaryFixture(fixture, (copy) => {
      if (copy.kind !== "fixture") throw new Error("expected an HTTP fixture");
      copy.when.request.headers = { ...copy.when.request.headers, authorization };
    });
    try {
      const loaded = await loadFixture(path);
      if (loaded.kind !== "fixture") throw new Error("expected an HTTP fixture");
      assert.deepEqual(loaded.when.request.headers?.authorization, authorization);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
});

test("maps malformed fixture JSON to FixtureRunnerError with its cause", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-sso-schema-json-"));
  const path = join(directory, "malformed.json");
  try {
    await writeFile(path, "{ malformed", "utf8");
    const error = await expectFixtureError(path, /invalid JSON/);
    assert.ok(error.cause instanceof SyntaxError);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("fixed schema rejects an unknown root member", async () => {
  const fixture = await fixtureFromRepository(FIXTURE_PATHS[0][0]);
  const { directory, path } = await writeTemporaryFixture(fixture, (copy) => {
    (copy as unknown as Record<string, unknown>).unknown = true;
  });
  try {
    await expectFixtureError(path, /schema validation failed/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("fixed schema rejects a missing required root field", async () => {
  const fixture = await fixtureFromRepository(FIXTURE_PATHS[0][0]);
  const { directory, path } = await writeTemporaryFixture(fixture, (copy) => {
    delete (copy as unknown as Record<string, unknown>).id;
  });
  try {
    await expectFixtureError(path, /schema validation failed/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("fixed schema rejects a wrong root field type", async () => {
  const fixture = await fixtureFromRepository(FIXTURE_PATHS[0][0]);
  const { directory, path } = await writeTemporaryFixture(fixture, (copy) => {
    (copy as unknown as Record<string, unknown>).kind = true;
  });
  try {
    await expectFixtureError(path, /schema validation failed/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("fixed schema rejects an invalid URI in configuration", async () => {
  const fixture = await fixtureFromRepository(FIXTURE_PATHS[0][0]);
  const { directory, path } = await writeTemporaryFixture(fixture, (copy) => {
    copy.given.config.issuer = "http://[invalid";
  });
  try {
    await expectFixtureError(path, /schema validation failed/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("compileJsonSchema uses draft 2020-12 and standard formats", () => {
  const validate = compileJsonSchema({
    $schema: "https://json-schema.org/draft/2020-12/schema",
    type: "array",
    prefixItems: [{ type: "string", format: "uri" }],
    minItems: 1,
    maxItems: 1,
    items: false,
  });
  assert.equal(validate(["https://example.com/mcp"]), true);
  assert.equal(validate(["http://[invalid"]), false);
  assert.equal(validate(["https://example.com/mcp", "extra"]), false);
});

test("accepts a valid structured clone", async () => {
  const fixture = await fixtureFromRepository(FIXTURE_PATHS[0][0]);
  const { directory, path } = await writeTemporaryFixture(fixture);
  try {
    assert.deepEqual(await loadFixture(path), fixture);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("loads a frozen clone with its required receipt and optional notes", async () => {
  const fixture = await fixtureFromRepository(FIXTURE_PATHS[0][0]);
  const receipt: FixtureReceipt = {
    implementation: "typescript-reference",
    version: "0.5.0",
    commit: "a".repeat(40),
    date: "2026-09-01",
  };
  const { directory, path } = await writeTemporaryFixture(fixture, (copy) => {
    copy.status = "frozen";
    copy.receipt = receipt;
    copy.notes = "frozen receipt test";
  });
  try {
    const loaded = await loadFixture(path);
    assert.equal(loaded.notes, "frozen receipt test");
    assert.equal(loaded.status, "frozen");
    if (loaded.status !== "frozen") assert.fail("fixture did not retain frozen status");
    assert.equal(loaded.receipt.implementation, receipt.implementation);
    assert.equal(loaded.receipt.commit, receipt.commit);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("accepts an HTTP fixture without the optional public key", async () => {
  assert.equal(HTTP_KEYS_WITHOUT_PUBLIC.signingPublic, undefined);
  const fixture = await fixtureFromRepository(FIXTURE_PATHS[0][0]);
  const { directory, path } = await writeTemporaryFixture(fixture, (copy) => {
    delete copy.given.keys.signingPublic;
  });
  try {
    const loaded = await loadFixture(path);
    assert.equal(loaded.kind, "fixture");
    assert.equal(loaded.given.keys.signingPublic, undefined);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
