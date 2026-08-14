// The line limit is a cohesion nudge with a recorded-exception escape hatch.
// These pin the four behaviors the gate promises: the default stays strict,
// exceptions must be justified, and an exception whose reason expired fails.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, posix, win32 } from "node:path";
import { test } from "node:test";

import { exceptionKey } from "../scripts/check-line-length.mjs";

const CHECKER = new URL("../scripts/check-line-length.mjs", import.meta.url).pathname;

/** Run the real checker against a throwaway src/ tree with a patched EXCEPTIONS map.
 *
 *  `separator: "\\"` makes the checker's own `relative()` emit win32-style paths,
 *  so the production `walk()` → `key()` seam is what gets exercised. Asserting
 *  the helper alone would leave the wiring untested: severing `key()` from
 *  `exceptionKey()` must fail a test, not just a unit. */
async function runChecker(files, exceptions = "{}", { separator } = {}) {
  const root = await mkdtemp(join(tmpdir(), "mcp-sso-lines-"));
  try {
    for (const [name, lines] of Object.entries(files)) {
      const target = join(root, "src", ...name.split("/"));
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, "// x\n".repeat(lines));
    }
    const source = (await import("node:fs/promises")).readFile;
    const original = await source(CHECKER, "utf8");
    let patched = original
      .replace('new URL("../src", import.meta.url).pathname', JSON.stringify(join(root, "src")))
      .replace(/const EXCEPTIONS = \{[\s\S]*?\n\};/, `const EXCEPTIONS = ${exceptions};`);
    if (separator !== undefined) {
      // Shadow the imported bindings so relative() returns backslash-separated
      // names and `sep` matches — exactly what the checker sees on Windows.
      patched = patched.replace(
        'const ROOT =',
        `const __posixRelative = relative;\n`
        + `relative = (from, to) => __posixRelative(from, to).split("/").join(${JSON.stringify(separator)});\n`
        + `sep = ${JSON.stringify(separator)};\n`
        + `const ROOT =`,
      ).replace('import { join, relative, sep } from "node:path";', 'import { join, relative as __rel, sep as __sep } from "node:path";\nlet relative = __rel;\nlet sep = __sep;');
    }
    const script = join(root, "check.mjs");
    await writeFile(script, patched);
    return await new Promise((resolve) => {
      execFile(process.execPath, [script], (error, stdout, stderr) => {
        resolve({ code: error ? 1 : 0, output: `${stdout}${stderr}` });
      });
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("a file within the default limit passes", async () => {
  const { code } = await runChecker({ "small.ts": 100 });
  assert.equal(code, 0);
});

test("an unrecorded file over the limit fails closed", async () => {
  const { code, output } = await runChecker({ "big.ts": 300 });
  assert.equal(code, 1);
  assert.match(output, /big\.ts: 301 lines exceeds the 250-line limit/);
});

test("a recorded exception permits its file up to the stated ceiling", async () => {
  const ok = await runChecker({ "big.ts": 260 },
    '{ "big.ts": { limit: 280, reason: "one cohesive surface; splitting separates a guard from its effect" } }');
  assert.equal(ok.code, 0, ok.output);

  // ...but only up to it: the exception is a ceiling, not a bypass.
  const over = await runChecker({ "big.ts": 300 },
    '{ "big.ts": { limit: 280, reason: "one cohesive surface; splitting separates a guard from its effect" } }');
  assert.equal(over.code, 1);
  assert.match(over.output, /exceeds its recorded 280-line exception/);
});

test("an exception whose file dropped back under the default is stale", async () => {
  const { code, output } = await runChecker({ "big.ts": 100 },
    '{ "big.ts": { limit: 280, reason: "one cohesive surface; splitting separates a guard from its effect" } }');
  assert.equal(code, 1);
  assert.match(output, /STALE exception/);
});

test("an exception without a real reason is rejected", async () => {
  const { code, output } = await runChecker({ "big.ts": 260 },
    '{ "big.ts": { limit: 280, reason: "because" } }');
  assert.equal(code, 1);
  assert.match(output, /needs a reason/);
});

test("exception keys normalize win32 separators, not just the host platform's", () => {
  // The map is written with forward slashes; `relative()` yields backslashes on
  // win32, so an unnormalized key misses twice there — the exception reads as
  // nonexistent AND the real file as unrecorded, failing the required gate for
  // Windows contributors.
  //
  // This asserts against win32 semantics EXPLICITLY. Driving the checker through
  // the ambient `sep` would pass on a POSIX runner whether or not the
  // normalization exists, so such a test pins nothing.
  assert.equal(exceptionKey(win32.relative("C:\\repo\\src", "C:\\repo\\src\\store\\deep.ts"), win32.sep), "store/deep.ts");
  assert.equal(exceptionKey(posix.relative("/repo/src", "/repo/src/store/deep.ts"), posix.sep), "store/deep.ts");

  // Top-level names are unaffected either way — which is why only a NESTED path
  // can exercise the defect.
  assert.equal(exceptionKey(win32.relative("C:\\repo\\src", "C:\\repo\\src\\bridge.ts"), win32.sep), "bridge.ts");
});

test("a nested exception key resolves end to end through the real checker", async () => {
  const spec = '{ "store/deep.ts": { limit: 280, reason: "one cohesive surface; splitting separates a guard from its effect" } }';

  const ok = await runChecker({ "store/deep.ts": 260 }, spec);
  assert.equal(ok.code, 0, ok.output);
  assert.doesNotMatch(ok.output, /does not exist|unrecorded/);

  // The ceiling still binds through the normalized key.
  const over = await runChecker({ "store/deep.ts": 300 }, spec);
  assert.equal(over.code, 1);
  assert.match(over.output, /store\/deep\.ts: 301 lines exceeds its recorded 280-line exception/);
});

test("the checker normalizes win32 paths through walk(), not just in the helper", async () => {
  // Drives the real checker with backslash-separated relative paths. Without the
  // key() → exceptionKey() wiring this fails TWICE, exactly as Windows would:
  // the exception reads as nonexistent AND the file as unrecorded overage.
  const spec = '{ "store/deep.ts": { limit: 280, reason: "one cohesive surface; splitting separates a guard from its effect" } }';

  const ok = await runChecker({ "store/deep.ts": 260 }, spec, { separator: "\\" });
  assert.equal(ok.code, 0, ok.output);
  assert.doesNotMatch(ok.output, /does not exist/);
  assert.doesNotMatch(ok.output, /exceeds the 250-line limit/);

  // And the recorded ceiling still binds under win32 separators.
  const over = await runChecker({ "store/deep.ts": 300 }, spec, { separator: "\\" });
  assert.equal(over.code, 1);
  assert.match(over.output, /exceeds its recorded 280-line exception/);
});

test("an exception for a file that does not exist is rejected", async () => {
  const { code, output } = await runChecker({ "small.ts": 10 },
    '{ "ghost.ts": { limit: 280, reason: "one cohesive surface; splitting separates a guard from its effect" } }');
  assert.equal(code, 1);
  assert.match(output, /does not exist/);
});
