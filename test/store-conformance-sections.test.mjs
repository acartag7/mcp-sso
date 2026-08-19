// The conformance suite is split into sections for readability; passing part of
// it is not passing it. This fails if a section module exists that
// runStoreConformance does not run — the way a section gets silently dropped.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const TESTING = fileURLToPath(new URL("../src/testing/", import.meta.url));
const ENTRY = readFileSync(join(TESTING, "store-conformance.ts"), "utf8");

test("every conformance section module is registered by runStoreConformance", () => {
  const sections = readdirSync(TESTING)
    .filter((name) => name.startsWith("store-conformance-") && name.endsWith(".ts")
      && name !== "store-conformance-fixtures.ts");
  assert.ok(sections.length >= 5, `expected the split sections, found ${sections.length}`);
  const registrars = sections.map((name) => {
    const source = readFileSync(join(TESTING, name), "utf8");
    const exported = /export function (register\w+)\(/.exec(source)?.[1];
    assert.ok(exported, `${name} exports no register* function`);
    return { name, exported };
  });
  const run = /const SECTIONS = \[([\s\S]*?)\] as const;/.exec(ENTRY)?.[1];
  assert.ok(run, "runStoreConformance has no SECTIONS list");
  for (const { name, exported } of registrars) {
    assert.match(ENTRY, new RegExp(`import \\{ ${exported} \\} from "\\./${name.replace(".ts", "")}\\.ts"`),
      `${name} is not imported by the suite entry`);
    assert.match(run, new RegExp(`\\b${exported}\\b`), `${name} is not run by runStoreConformance`);
  }
  assert.equal(run.split(",").filter((entry) => entry.trim().length > 0).length, registrars.length,
    "SECTIONS lists something that is not a section module, or omits one");
});
