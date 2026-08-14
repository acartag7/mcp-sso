// The line limit is a cohesion nudge with a recorded-exception escape hatch.
// These pin the four behaviors the gate promises: the default stays strict,
// exceptions must be justified, and an exception whose reason expired fails.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const CHECKER = new URL("../scripts/check-line-length.mjs", import.meta.url).pathname;

/** Run the real checker against a throwaway src/ tree with a patched EXCEPTIONS map. */
async function runChecker(files, exceptions = "{}") {
  const root = await mkdtemp(join(tmpdir(), "mcp-sso-lines-"));
  try {
    await mkdir(join(root, "src", "adapters"), { recursive: true });
    for (const [name, lines] of Object.entries(files)) {
      await writeFile(join(root, "src", name), "// x\n".repeat(lines));
    }
    const source = (await import("node:fs/promises")).readFile;
    const original = await source(CHECKER, "utf8");
    const patched = original
      .replace('new URL("../src", import.meta.url).pathname', JSON.stringify(join(root, "src")))
      .replace(/const EXCEPTIONS = \{[\s\S]*?\n\};/, `const EXCEPTIONS = ${exceptions};`);
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

test("an exception for a file that does not exist is rejected", async () => {
  const { code, output } = await runChecker({ "small.ts": 10 },
    '{ "ghost.ts": { limit: 280, reason: "one cohesive surface; splitting separates a guard from its effect" } }');
  assert.equal(code, 1);
  assert.match(output, /does not exist/);
});
