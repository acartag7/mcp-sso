// Frozen acceptance suites pin the CONTRACT, never implementation internals.
// This gate bans test/acceptance/** from importing any `*-internals` module:
// a frozen test that reads an implementation constant (the s6b-redirect suite
// imported FLOW_AUDIENCE from upstream-flow-internals.ts) forces a frozen-file
// edit whenever that constant legitimately changes — which is how PR #109 came
// to rewrite a frozen fixture and regenerate the manifest in an impl diff.
// Modules are internals by naming convention (`-internals.ts`); testing a
// public module (src/cimd/document.ts, src/metadata.ts, …) stays allowed.
// Exits non-zero on any offender, printing each.
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = new URL("../test/acceptance", import.meta.url).pathname;
const offenders = [];

if (!existsSync(ROOT)) {
  console.error(`✓ test/acceptance/ does not exist yet (nothing to check)`);
  process.exit(0);
}

const INTERNALS_IMPORT = /import\s*\(?\s*["'][^"']*-internals(?:\.[cm]?[jt]s)?["']|from\s+["'][^"']*-internals(?:\.[cm]?[jt]s)?["']|["']\.\.[^"']*-internals\.[cm]?[jt]s["']/;

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) {
      walk(p);
    } else if (/\.(?:[cm]?ts|[cm]?js)$/.test(p)) {
      const lines = readFileSync(p, "utf8").split("\n");
      lines.forEach((line, i) => {
        if (INTERNALS_IMPORT.test(line)) {
          offenders.push({ file: relative(ROOT, p), line: i + 1, text: line.trim() });
        }
      });
    }
  }
}

walk(ROOT);

if (offenders.length > 0) {
  console.error(`✗ ${offenders.length} internals import(s) in frozen acceptance suites:`);
  for (const o of offenders) console.error(`  ${o.file}:${o.line}  ${o.text}`);
  console.error("A frozen suite pins the contract — observe behavior through the public seam instead.");
  process.exit(1);
}
console.error("✓ no internals imports in test/acceptance");
