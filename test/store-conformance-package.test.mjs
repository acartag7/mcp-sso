// The conformance suite is shipped so §12's "downstream adapters must pass the
// same suite" can actually be satisfied. These pin the properties §12 and §15
// claim about that shipped surface.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const TESTING = join(ROOT, "src/testing");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

test("the suite is exported, and only through its entry points", () => {
  const testingSubpaths = Object.keys(pkg.exports).filter((key) => key.startsWith("./testing/"));
  assert.deepEqual(testingSubpaths.sort(),
    ["./testing/client-store-conformance", "./testing/store-conformance"],
    "exactly the two suite entries are public");
  for (const subpath of testingSubpaths) {
    assert.match(pkg.exports[subpath].types, /^\.\/dist\/testing\/.+\.d\.ts$/);
    assert.match(pkg.exports[subpath].default, /^\.\/dist\/testing\/.+\.js$/);
  }
  // Sections are deliberately NOT exported: passing part of the suite is not
  // passing the suite, and an exports map without a wildcard is what enforces it.
  assert.equal(Object.keys(pkg.exports).some((key) => key.includes("*")), false, "no wildcard subpath");
  assert.equal(Object.keys(pkg.exports).some((key) => /store-conformance-/.test(key)), false,
    "no section is individually importable");
  assert.ok(pkg.files.includes("dist"), "dist carries the compiled suite into the tarball");
});

test("the suite adds no runtime dependency and imports only Node built-ins", () => {
  const offenders = [];
  for (const name of readdirSync(TESTING)) {
    const source = readFileSync(join(TESTING, name), "utf8");
    // Only real import/export statements — a prose comment can contain `from "…"`.
    for (const [, specifier] of source.matchAll(/^\s*(?:import|export)\b[^\n]*?\bfrom "([^"]+)"/gm)) {
      if (specifier.startsWith("node:") || specifier.startsWith("./") || specifier.startsWith("../")) continue;
      offenders.push(`${name} -> ${specifier}`);
    }
  }
  assert.deepEqual(offenders, [], "a bare specifier would make the suite depend on a package");
  assert.equal(Object.keys(pkg.dependencies).join(","), "jose", "jose remains the only runtime dependency");
});

test("importing the suite registers no rows — it only registers when called", () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-sso-suite-import-"));
  try {
    const probe = join(dir, "import-only.test.mjs");
    writeFileSync(probe, `import "${join(TESTING, "store-conformance.ts")}";\n`
      + `import "${join(TESTING, "client-store-conformance.ts")}";\n`);
    // NODE_TEST_CONTEXT is inherited from this runner and would make the child
    // report over the internal channel instead of stdout.
    const childEnv = { ...process.env };
    delete childEnv.NODE_TEST_CONTEXT;
    const run = spawnSync(process.execPath, ["--test", "--test-reporter=tap", probe],
      { encoding: "utf8", timeout: 60_000, env: childEnv });
    assert.equal(run.status, 0, run.stdout + run.stderr);
    // A file that registers nothing is itself the only reported subtest; the
    // moment a row registers, the row becomes the subtest instead. So the
    // subtest NAMES are the signal — a count alone cannot tell the two apart.
    const subtests = [...run.stdout.matchAll(/^# Subtest: (.+)$/gm)].map(([, name]) => name);
    assert.deepEqual(subtests, [probe],
      `importing the suite registered rows:\n${run.stdout}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
