import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { promisify } from "node:util";
import { FixtureRunnerError } from "./parity/error.ts";
import { compileJsonSchema, loadFixture } from "./parity/schema-json.ts";
import type { ParityFixture } from "./parity/types.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const execFileAsync = promisify(execFile);
const FIXTURE_PATHS = [
  ["fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable.json", "portable"],
  ["fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed.json", "host"],
] as const;

async function fixtureFromRepository(path: string): Promise<ParityFixture> {
  return loadFixture(resolve(PROJECT_ROOT, path));
}

async function expectError(path: string, pattern: RegExp): Promise<FixtureRunnerError> {
  let caught: unknown;
  try {
    await loadFixture(path);
  } catch (error) {
    caught = error;
  }
  assert.ok(caught instanceof FixtureRunnerError);
  assert.match(caught.message, pattern);
  return caught;
}

async function expectRawError(source: string, pattern: RegExp = /invalid JSON/): Promise<FixtureRunnerError> {
  const directory = await mkdtemp(join(tmpdir(), "mcp-sso-schema-json-"));
  const path = join(directory, "fixture.json");
  try {
    await writeFile(path, source, "utf8");
    return await expectError(path, pattern);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function expectMutatedError(mutate: (fixture: ParityFixture) => void): Promise<FixtureRunnerError> {
  const fixture = await fixtureFromRepository(FIXTURE_PATHS[0][0]);
  const copy = structuredClone(fixture);
  mutate(copy);
  return expectRawError(JSON.stringify(copy), /schema validation failed/);
}

test("shares one schema compilation across concurrent first loads", async () => {
  const fixtures = await Promise.all(FIXTURE_PATHS.map(([path]) => fixtureFromRepository(path)));
  assert.deepEqual(fixtures.map((fixture) => fixture.profile), ["portable", "host"]);
});

test("resolves the fixed schema independently of the current working directory", async () => {
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

test("loads both section 8.4 fixtures by explicit path", async () => {
  for (const [path, profile] of FIXTURE_PATHS) {
    const fixture = await fixtureFromRepository(path);
    assert.equal(fixture.profile, profile);
    assert.equal(fixture.kind, "fixture");
  }
});

test("rejects malformed JSON, comments, trailing commas, empty input, and multiple roots", async () => {
  const sources = ["{ malformed", "// comment\n{}", '{"value": 1,}', "", "{} {}"];
  for (const source of sources) {
    const error = await expectRawError(source);
    assert.ok(error.cause instanceof SyntaxError);
    assert.equal(error.cause.message, "invalid JSON");
  }
});

test("rejects duplicate members before schema validation", async () => {
  const fixturePath = resolve(PROJECT_ROOT, FIXTURE_PATHS[0][0]);
  const source = await readFile(fixturePath, "utf8");
  const topLevel = source.replace(/  "id": ("[^"]+"),/u, (_match, id: string) => `  "id": ${id},\n  "id": ${id},`);
  const nested = source.replace(
    '      "issuer": "https://api.example.com",',
    '      "issuer": "https://api.example.com",\n      "issuer": "https://api.example.com",',
  );
  for (const duplicate of [topLevel, nested]) {
    const error = await expectRawError(duplicate);
    assert.ok(error.cause instanceof SyntaxError);
    assert.equal(error.cause.message, "duplicate object member");
    assert.doesNotMatch(error.message, /issuer/u);
  }
});

test("rejects decoded-equivalent duplicate names and accepts sibling-object names", async () => {
  const fixturePath = resolve(PROJECT_ROOT, FIXTURE_PATHS[0][0]);
  const source = await readFile(fixturePath, "utf8");
  const duplicate = source.replace(
    '      "issuer": "https://api.example.com",',
    '      "issuer": "https://api.example.com",\n      "iss\\u0075er": "https://api.example.com",',
  );
  const error = await expectRawError(duplicate);
  assert.ok(error.cause instanceof SyntaxError);
  assert.equal(error.cause.message, "duplicate object member");
  assert.doesNotMatch(error.message, /issuer/u);
  const fixture = await fixtureFromRepository(FIXTURE_PATHS[0][0]);
  assert.equal(fixture.given.identity.checks.length, 0);
  assert.equal(fixture.given.rateLimit.checks.length, 0);
});

test("fixed schema rejects unknown, missing, wrongly typed, and invalid URI members", async () => {
  const errors = [
    await expectMutatedError((copy) => { (copy as unknown as Record<string, unknown>).unknown = true; }),
    await expectMutatedError((copy) => { delete (copy as unknown as Record<string, unknown>).id; }),
    await expectMutatedError((copy) => { (copy as unknown as Record<string, unknown>).kind = true; }),
    await expectMutatedError((copy) => { (copy.given.config as Record<string, unknown>).issuer = "http://[invalid"; }),
  ];
  assert.equal(errors.length, 4);
});

test("compileJsonSchema uses draft 2020-12 and standard URI formats", () => {
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

test("accepts a valid structured-clone fixture", async () => {
  const fixture = await fixtureFromRepository(FIXTURE_PATHS[0][0]);
  const copy = structuredClone(fixture);
  const directory = await mkdtemp(join(tmpdir(), "mcp-sso-schema-json-"));
  const path = join(directory, "fixture.json");
  try {
    await writeFile(path, JSON.stringify(copy), "utf8");
    const loaded = await loadFixture(path);
    assert.deepEqual(loaded, fixture);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
