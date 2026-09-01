import { lstat, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { relative, resolve, sep } from "node:path";
import type { Dirent } from "node:fs";
import { FixtureRunnerError } from "./error.ts";
import { loadFixture } from "./schema-json.ts";
import type { ParityFixture } from "./types.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const FIXTURES_ROOT = resolve(PROJECT_ROOT, "fixtures");
const ROOT_FILES = new Set(["README.md", "FREEZE-LOG.md", "MANIFEST.json", "CATALOGUE.md"]);
const ROOT_DIRECTORIES = new Set(["keys", "schema"]);
const SECTION_DIRECTORY = /^(0[1-9]|1[0-9])-[a-z0-9]+(?:-[a-z0-9]+)*$/u;

export async function fixturePaths(root = FIXTURES_ROOT): Promise<string[]> {
  const corpusRoot = resolve(root);
  return fixturePathsAt(corpusRoot);
}

export async function loadCorpus(root = FIXTURES_ROOT): Promise<ParityFixture[]> {
  const corpusRoot = resolve(root);
  const fixtures: ParityFixture[] = [];
  for (const path of await fixturePaths(corpusRoot)) {
    const fixture = await loadFixture(path);
    const expectedId = relative(corpusRoot, path).split(sep).join("/").replace(/\.json$/u, "");
    validateFixtureIdentity(fixture, expectedId, path);
    fixtures.push(fixture);
  }
  validateSupersededFixtures(fixtures);
  validateChainTopology(fixtures);
  return fixtures;
}

function validateChainTopology(fixtures: ParityFixture[]): void {
  const chains = new Map<string, ParityFixture[]>();
  for (const fixture of fixtures) {
    if (fixture.status === "superseded" || !fixture.chain) continue;
    const members = chains.get(fixture.chain.id) ?? [];
    members.push(fixture);
    chains.set(fixture.chain.id, members);
  }
  for (const [chainId, members] of chains) {
    const ordered = members.toSorted((a, b) => a.chain!.step - b.chain!.step);
    for (let index = 0; index < ordered.length; index += 1) {
      const fixture = ordered[index]!;
      if (fixture.chain!.step !== index + 1) {
        throw new FixtureRunnerError(`${chainId}: chain steps must be contiguous`);
      }
      const expected = index === 0 ? undefined : ordered[index - 1]!.id;
      if (fixture.chain!.previous !== expected) {
        throw new FixtureRunnerError(`${fixture.id}: wrong chain predecessor`);
      }
    }
  }
}

function validateSupersededFixtures(fixtures: ParityFixture[]): void {
  const byId = new Map(fixtures.map((fixture) => [fixture.id, fixture]));
  for (const fixture of fixtures) {
    if (fixture.status !== "superseded") continue;
    const replacement = fixture.supersededBy ? byId.get(fixture.supersededBy) : undefined;
    if (!replacement) {
      throw new FixtureRunnerError(`${fixture.id}: supersededBy must name a loaded fixture`);
    }
    if (replacement === fixture) {
      throw new FixtureRunnerError(`${fixture.id}: supersededBy must name a different fixture`);
    }
  }
  for (const fixture of fixtures) {
    if (fixture.status !== "superseded") continue;
    const seen = new Set<string>();
    let currentId = fixture.id;
    while (true) {
      const current = byId.get(currentId);
      if (current?.status !== "superseded") break;
      if (seen.has(current.id)) {
        throw new FixtureRunnerError(`${fixture.id}: supersededBy chain contains a cycle`);
      }
      seen.add(current.id);
      currentId = current.supersededBy;
    }
  }
}

function validateFixtureIdentity(fixture: ParityFixture, expectedId: string, label: string): void {
  if (fixture.id !== expectedId) {
    throw new FixtureRunnerError(`${label}: id ${fixture.id} does not match path ${expectedId}`);
  }
  const [directory, filename] = expectedId.split("/");
  const section = directory?.slice(0, directory.indexOf("-"));
  const clause = filename?.slice(0, filename.indexOf("-"));
  if (section !== fixture.contract.section) {
    throw new FixtureRunnerError(`${label}: id section ${section} does not match contract section ${fixture.contract.section}`);
  }
  if (clause !== fixture.contract.clause) {
    throw new FixtureRunnerError(`${label}: id clause ${clause} does not match contract clause ${fixture.contract.clause}`);
  }
  if (Number(clause?.split(".", 1)[0]) !== Number(section)) {
    throw new FixtureRunnerError(`${label}: contract clause ${clause} does not belong to section ${section}`);
  }
}

async function fixturePathsAt(root: string): Promise<string[]> {
  const entries = await readEntries(root, "corpus root");
  const paths: string[] = [];
  for (const entry of entries) {
    const path = resolve(root, entry.name);
    if (ROOT_FILES.has(entry.name)) {
      await requireRegular(path, `${entry.name}: corpus root artifact must be a file`);
      continue;
    }
    if (ROOT_DIRECTORIES.has(entry.name)) {
      await requireDirectory(path, `${entry.name}: corpus root artifact must be a directory`);
      continue;
    }
    if (!SECTION_DIRECTORY.test(entry.name)) {
      throw new FixtureRunnerError(`${entry.name}: unexpected corpus root entry`);
    }
    await requireDirectory(path, `${entry.name}: numbered corpus section must be a directory`);
    for (const file of await readEntries(path, `${entry.name}: section`)) {
      const filePath = resolve(path, file.name);
      if (!file.name.endsWith(".json") || file.name !== file.name.toLowerCase()) {
        throw new FixtureRunnerError(`${entry.name}/${file.name}: unexpected corpus entry`);
      }
      await requireRegular(filePath, `${entry.name}/${file.name}: unexpected corpus entry`);
      paths.push(filePath);
    }
  }
  return paths;
}

async function readEntries(path: string, label: string): Promise<Dirent[]> {
  try {
    return await readdir(path, { withFileTypes: true });
  } catch (error) {
    throw new FixtureRunnerError(`${label}: cannot read directory`, { cause: error });
  }
}

async function requireRegular(path: string, message: string): Promise<void> {
  try {
    if (!(await lstat(path)).isFile()) throw new FixtureRunnerError(message);
  } catch (error) {
    if (error instanceof FixtureRunnerError) throw error;
    throw new FixtureRunnerError(message, { cause: error });
  }
}

async function requireDirectory(path: string, message: string): Promise<void> {
  try {
    if (!(await lstat(path)).isDirectory()) throw new FixtureRunnerError(message);
  } catch (error) {
    if (error instanceof FixtureRunnerError) throw error;
    throw new FixtureRunnerError(message, { cause: error });
  }
}
