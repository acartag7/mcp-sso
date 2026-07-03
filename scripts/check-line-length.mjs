// Enforces the DDD-lite 250-line file limit on src/ (contracts §6, "House rules").
// Tests and scripts are exempt. Exits non-zero on any offender, printing each.
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = new URL("../src", import.meta.url).pathname;
const LIMIT = 250;
const offenders = [];

if (!existsSync(ROOT)) {
  console.error(`✓ src/ does not exist yet (nothing to check)`);
  process.exit(0);
}

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) {
      walk(p);
    } else if (p.endsWith(".ts")) {
      const lines = readFileSync(p, "utf8").split("\n").length;
      if (lines > LIMIT) offenders.push({ file: relative(ROOT, p), lines });
    }
  }
}

walk(ROOT);

if (offenders.length > 0) {
  console.error(`✗ ${offenders.length} src file(s) exceed the ${LIMIT}-line limit:`);
  for (const o of offenders) console.error(`  ${o.file}: ${o.lines} lines`);
  process.exit(1);
}
console.error(`✓ all src files <= ${LIMIT} lines`);
