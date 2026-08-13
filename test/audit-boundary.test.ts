import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { glob } from "node:fs/promises";

const SOURCE_ROOT = fileURLToPath(new URL("../src/", import.meta.url));
const DIRECT_WRITE_ALLOWLIST = new Set([
  "audit/best-effort.ts",
  "audit/combine.ts",
]);

test("all non-transactional use-case audit writes cross the shared best-effort boundary", async () => {
  const directWriters: string[] = [];
  for await (const path of glob("**/*.ts", { cwd: SOURCE_ROOT })) {
    const source = await readFile(`${SOURCE_ROOT}${path}`, "utf8");
    if (source.includes(".writeAuthEvent(")) directWriters.push(path);
  }
  assert.deepEqual(directWriters.sort(), [...DIRECT_WRITE_ALLOWLIST].sort());
});
