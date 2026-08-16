import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
const CLOCK_BOUNDARY = "ports/clock.ts";

function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? sourceFiles(path) : path.endsWith(".ts") ? [path] : [];
  });
}

test("ClockPort.nowMs is read only inside the canonical clock boundary", () => {
  const violations = sourceFiles(ROOT)
    .filter((path) => relative(ROOT, path) !== CLOCK_BOUNDARY)
    .filter((path) => /\.nowMs\s*\(/.test(readFileSync(path, "utf8")))
    .map((path) => relative(ROOT, path));

  assert.deepEqual(violations, []);
});
