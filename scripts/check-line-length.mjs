// Enforces the DDD-lite 250-line file limit on src/ (contracts §6, "House rules").
// Tests and scripts are exempt. Exits non-zero on any offender, printing each.
//
// The limit is a cohesion nudge, not an end in itself. A file may exceed it ONLY
// with a recorded exception below, stating why splitting would cost more than it
// buys. Same discipline as the dependency ledger's advisory exceptions: the
// default stays strict, deviations are per-file and justified, and the gate
// fails closed on anything unrecorded.
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative, sep } from "node:path";

/** Map a platform-relative path onto the forward-slash form the EXCEPTIONS map
 *  uses. `relative()` yields backslashes on win32, so an unnormalized key would
 *  miss twice there — the exception reads as nonexistent AND the real file as
 *  unrecorded overage, failing the required gate for Windows contributors.
 *
 *  Exported and separator-injectable so the regression can exercise win32
 *  semantics on a POSIX runner; testing it through the ambient `sep` would pass
 *  on Linux whether or not the normalization exists. */
export function exceptionKey(relativePath, separator) {
  return separator === "/" ? relativePath : relativePath.split(separator).join("/");
}

const ROOT = new URL("../src", import.meta.url).pathname;
const LIMIT = 250;

/** Files permitted above the default cap.
 *  `limit` is that file's hard ceiling; `reason` says why a split would separate
 *  things that belong together. An exception whose file drops back under the
 *  default is STALE and fails — return the allowance when the reason expires. */
const EXCEPTIONS = {
  "adapters/bridge.ts": {
    limit: 255,
    reason: "The pairing admission seam belongs beside Bridge's snapshotted limiter and endpoint guards; splitting would separate one policy owner.",
  },
};

if (!existsSync(ROOT)) {
  console.error(`✓ src/ does not exist yet (nothing to check)`);
  process.exit(0);
}

const sizes = new Map();

function key(path) {
  return exceptionKey(relative(ROOT, path), sep);
}

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) walk(p);
    else if (p.endsWith(".ts")) {
      sizes.set(key(p), readFileSync(p, "utf8").split("\n").length);
    }
  }
}

walk(ROOT);

const errors = [];

for (const [file, spec] of Object.entries(EXCEPTIONS)) {
  if (typeof spec?.limit !== "number" || !Number.isInteger(spec.limit) || spec.limit <= LIMIT) {
    errors.push(`${file}: exception limit must be an integer above ${LIMIT}`);
    continue;
  }
  if (typeof spec.reason !== "string" || spec.reason.trim().length < 20) {
    errors.push(`${file}: exception needs a reason explaining why splitting costs more than it buys`);
    continue;
  }
  const lines = sizes.get(file);
  if (lines === undefined) {
    errors.push(`${file}: exception recorded for a file that does not exist`);
  } else if (lines <= LIMIT) {
    errors.push(`${file}: STALE exception — now ${lines} lines, within the ${LIMIT}-line default; remove it`);
  }
}

for (const [file, lines] of [...sizes].sort()) {
  const allowed = EXCEPTIONS[file]?.limit ?? LIMIT;
  if (lines > allowed) {
    errors.push(EXCEPTIONS[file]
      ? `${file}: ${lines} lines exceeds its recorded ${allowed}-line exception`
      : `${file}: ${lines} lines exceeds the ${LIMIT}-line limit (split it, or record an exception with a reason)`);
  }
}

if (errors.length > 0) {
  console.error(`✗ ${errors.length} line-limit violation(s):`);
  for (const e of errors) console.error(`  ${e}`);
  process.exit(1);
}

const recorded = Object.keys(EXCEPTIONS).length;
console.error(`✓ all src files within limits${recorded > 0 ? ` (${recorded} recorded exception(s))` : ""}`);
