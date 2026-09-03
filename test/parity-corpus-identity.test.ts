import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { test } from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { loadCorpus } from "./parity/corpus.ts";
import { loadFixture } from "./parity/schema-json.ts";
import type { ParityFixture } from "./parity/types.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const execFileAsync = promisify(execFile);
const REAL_IDS = [
  "08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable",
  "08-resource-server-verifier/8.4-duplicate-authorization-fails-closed",
] as const;

async function realFixture(id: string): Promise<ParityFixture> {
  return loadFixture(resolve(PROJECT_ROOT, "fixtures", `${id}.json`));
}

async function writeFixture(
  root: string,
  pathId: string,
  fixture: ParityFixture,
  mutate: (copy: ParityFixture) => void = () => {},
): Promise<void> {
  const copy = structuredClone(fixture);
  mutate(copy);
  const path = join(root, `${pathId}.json`);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(copy), "utf8");
}

async function expectCorpusError(root: string, pattern: RegExp): Promise<FixtureRunnerError> {
  let caught: unknown;
  try {
    await loadCorpus(root);
  } catch (error) {
    caught = error;
  }
  assert.ok(caught instanceof FixtureRunnerError);
  assert.match(caught.message, pattern);
  return caught;
}

async function expectCloneError(
  fixture: ParityFixture,
  pattern: RegExp,
  mutate: (copy: ParityFixture) => void = () => {},
  pathId = fixture.id,
): Promise<FixtureRunnerError> {
  const root = await mkdtemp(join(tmpdir(), "mcp-sso-parity-identity-"));
  try {
    await writeFixture(root, pathId, fixture, mutate);
    return await expectCorpusError(root, pattern);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("loadCorpus accepts both real frozen fixtures", async () => {
  const fixtures = await loadCorpus();
  assert.deepEqual(fixtures.map(({ id, profile, status }) => [id, profile, status]).toSorted(), [
    [REAL_IDS[1], "host", "frozen"],
    [REAL_IDS[0], "portable", "frozen"],
  ]);
});

test("loadCorpus rejects an id that does not match its corpus path", async () => {
  const fixture = await realFixture(REAL_IDS[0]);
  await expectCloneError(fixture, /does not match path/u, (copy) => { copy.id = `${copy.id}-renamed`; });
});

test("loadCorpus rejects a duplicate id at a second path through path/id binding", async () => {
  const fixture = await realFixture(REAL_IDS[0]);
  const root = await mkdtemp(join(tmpdir(), "mcp-sso-parity-identity-duplicate-"));
  const secondPath = "08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-copy";
  try {
    await writeFixture(root, fixture.id, fixture);
    await writeFixture(root, secondPath, fixture);
    const error = await expectCorpusError(root, /does not match path/u);
    assert.doesNotMatch(error.message, /duplicate fixture id/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("loadCorpus binds the id section to contract.section", async () => {
  const fixture = await realFixture(REAL_IDS[1]);
  await expectCloneError(fixture, /id section 08 does not match contract section 09/u, (copy) => {
    copy.contract.section = "09";
  });
});

test("loadCorpus binds the id clause to contract.clause", async () => {
  const fixture = await realFixture(REAL_IDS[1]);
  await expectCloneError(fixture, /id clause 8\.4 does not match contract clause 8\.3/u, (copy) => {
    copy.contract.clause = "8.3";
  });
});

test("loadCorpus rejects a clause whose numeric root crosses the id section", async () => {
  const fixture = await realFixture(REAL_IDS[1]);
  const pathId = "08-resource-server-verifier/9.2-cross-section";
  await expectCloneError(fixture, /contract clause 9\.2 does not belong to section 08/u, (copy) => {
    copy.id = pathId;
    copy.contract.clause = "9.2";
  }, pathId);
});

test("loadCorpus resolves the default fixture root outside the process working directory", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-sso-parity-identity-cwd-"));
  try {
    const moduleUrl = new URL("./parity/corpus.ts", import.meta.url).href;
    const script = `const { loadCorpus } = await import(${JSON.stringify(moduleUrl)}); const fixtures = await loadCorpus(); if (fixtures.length !== 2) throw new Error("unexpected fixture count");`;
    await execFileAsync(process.execPath, ["--input-type=module", "--eval", script], { cwd: directory });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
