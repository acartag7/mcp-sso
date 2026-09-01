import { lstat, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import type { Dirent } from "node:fs";
import { FixtureRunnerError } from "./error.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const FIXTURES_ROOT = resolve(PROJECT_ROOT, "fixtures");
const ROOT_FILES = new Set(["README.md", "FREEZE-LOG.md", "MANIFEST.json", "CATALOGUE.md"]);
const ROOT_DIRECTORIES = new Set(["keys", "schema"]);
const SECTION_DIRECTORY = /^(0[1-9]|1[0-9])-[a-z0-9]+(?:-[a-z0-9]+)*$/u;

export async function fixturePaths(root = FIXTURES_ROOT): Promise<string[]> {
  const corpusRoot = resolve(root);
  return fixturePathsAt(corpusRoot);
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
