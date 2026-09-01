import { lstat, readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { relative, resolve, sep } from "node:path";
import type { Dirent } from "node:fs";
import type { ParityFixture } from "./types.ts";
import { FixtureRunnerError } from "./error.ts";
import { loadFixture } from "./schema-json.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const FIXTURES_ROOT = resolve(PROJECT_ROOT, "fixtures");
const CONTRACTS_ROOT = resolve(PROJECT_ROOT, "docs/contracts");
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
    if (fixture.status !== "superseded") await validateQuote(fixture);
    fixtures.push(fixture);
  }
  return fixtures;
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

async function validateQuote(fixture: ParityFixture): Promise<void> {
  const prefix = `${fixture.contract.section}-`;
  const names = (await readdir(CONTRACTS_ROOT)).filter((name) => name.startsWith(prefix) && name.endsWith(".md"));
  if (names.length !== 1) throw new FixtureRunnerError(`${fixture.id}: contract section file is ambiguous`);
  const source = await readFile(resolve(CONTRACTS_ROOT, names[0]!), "utf8");
  const clause = clauseSource(source, fixture.contract.clause);
  if (!clause.includes(fixture.contract.quote)) {
    throw new FixtureRunnerError(`${fixture.id}: contract quote is stale in clause ${fixture.contract.clause}`);
  }
  if (!containsCompleteSentence(clause, fixture.contract.quote)) {
    throw new FixtureRunnerError(`${fixture.id}: contract quote must be a complete sentence`);
  }
}

function containsCompleteSentence(source: string, quote: string): boolean {
  let index = source.indexOf(quote);
  while (index !== -1) {
    const before = source.slice(0, index);
    const after = source.slice(index + quote.length);
    const startsSentence = index === 0 || /[.!?](?:[`*_~"')\]}]+)?\s+$/u.test(before) || /(?:^|\n)[ \t]*(?:(?:[-+*]|\d+[.)]|>)[ \t]+)*(?:[*_~]+)?$/u.test(before);
    if (startsSentence && /[.!?](?:[`*_~"')\]}]+)?$/u.test(quote) && (after === "" || /^(?:[*_~]+)?\s/u.test(after))) return true;
    index = source.indexOf(quote, index + 1);
  }
  return false;
}

export function clauseSource(source: string, clause: string): string {
  const escaped = clause.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const heading = new RegExp(`^(#{1,6})\\s+${escaped}\\.?(?:\\s|$)`, "mu").exec(source);
  if (heading === null || !heading[1]) throw new FixtureRunnerError(`contract clause ${clause} was not found`);
  const level = heading[1].length;
  const rest = source.slice(heading.index + heading[0].length);
  const next = new RegExp(`^#{1,${level}}\\s+`, "mu").exec(rest);
  return rest.slice(0, next?.index ?? rest.length);
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
