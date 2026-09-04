import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { test } from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { FIXTURES_ROOT, fixturePaths } from "./parity/corpus.ts";

const ROOT_FILES = ["README.md", "FREEZE-LOG.md"];
const ROOT_DIRECTORIES = ["keys", "schema"];

async function temporaryRoot(): Promise<string> {
  return mkdtemp(join(tmpdir(), "mcp-sso-parity-layout-"));
}

async function expectLayoutError(root: string, pattern: RegExp): Promise<void> {
  let caught: unknown;
  try {
    await fixturePaths(root);
  } catch (error) {
    caught = error;
  }
  assert.ok(caught instanceof FixtureRunnerError);
  assert.match(caught.message, pattern);
}

function relativeFixturePath(path: string, root = FIXTURES_ROOT): string {
  return relative(root, path).split(sep).join("/");
}

test("discovers exactly the four real fixture paths", async () => {
  const paths = await fixturePaths();
  assert.deepEqual(paths.map((path) => relativeFixturePath(path)).toSorted(), [
    "08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable.json",
    "08-resource-server-verifier/8.4-duplicate-authorization-fails-closed.json",
    "08-resource-server-verifier/8.4-single-authorization-succeeds-portable.json",
    "08-resource-server-verifier/8.4-zero-authorization-fails-closed-portable.json",
  ]);
});

test("allows the four reserved root artifacts only at their declared types", async () => {
  const root = await temporaryRoot();
  try {
    for (const name of ROOT_FILES) await writeFile(join(root, name), "artifact", "utf8");
    for (const name of ROOT_DIRECTORIES) await mkdir(join(root, name));
    const section = join(root, "08-resource-server-verifier");
    await mkdir(section);
    await writeFile(join(section, "8.4-valid.json"), "{}", "utf8");
    assert.deepEqual((await fixturePaths(root)).map((path) => relativeFixturePath(path, root)), [
      "08-resource-server-verifier/8.4-valid.json",
    ]);

    for (const name of ROOT_FILES) {
      const path = join(root, name);
      await rm(path);
      await mkdir(path);
      await expectLayoutError(root, /corpus root artifact must be a file/);
      await rm(path, { recursive: true });
      await writeFile(path, "artifact", "utf8");
    }
    for (const name of ROOT_DIRECTORIES) {
      const path = join(root, name);
      await rm(path, { recursive: true });
      await writeFile(path, "artifact", "utf8");
      await expectLayoutError(root, /corpus root artifact must be a directory/);
      await rm(path);
      await mkdir(path);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects misplaced fixtures and misspelled or malformed section directories", async () => {
  const cases = [
    ["8.4-misplaced-fixture.json", "file"],
    ["MANIFEST.json", "file"],
    ["CATALOGUE.md", "file"],
    ["resource-server-verifier", "directory"],
    ["8-resource-server-verifier", "directory"],
    ["20-resource-server-verifier", "directory"],
    ["08-Resource-server-verifier", "directory"],
  ] as const;
  for (const [name, kind] of cases) {
    const root = await temporaryRoot();
    try {
      if (kind === "file") await writeFile(join(root, name), "{}", "utf8");
      else await mkdir(join(root, name));
      await expectLayoutError(root, /unexpected corpus root entry/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }

  const root = await temporaryRoot();
  try {
    await writeFile(join(root, "08-resource-server-verifier"), "not a directory", "utf8");
    await expectLayoutError(root, /numbered corpus section must be a directory/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects every section entry that is not an immediate regular lower-case JSON file", async () => {
  const cases = [
    ["nested", "directory"],
    ["8.4-fixture.json.bak", "file"],
    ["8.4-fixture.JSON", "file"],
    ["8.4-directory.json", "directory"],
    ["8.4-symlink.json", "symlink"],
  ] as const;
  for (const [name, kind] of cases) {
    const root = await temporaryRoot();
    try {
      const section = join(root, "08-resource-server-verifier");
      await mkdir(section);
      if (kind === "directory") await mkdir(join(section, name));
      else if (kind === "symlink") await symlink("missing-target.json", join(section, name));
      else await writeFile(join(section, name), "{}", "utf8");
      await expectLayoutError(root, /unexpected corpus entry/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});
