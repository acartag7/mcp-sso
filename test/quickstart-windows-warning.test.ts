// The quickstart POSIX permission gates (`0700` dir, `0600` file, owning uid)
// are skipped on Windows — this library reads no DACLs. The threat model used
// to promise a boot failure for a group/other-readable secrets file with no
// platform qualifier, which is untrue on win32.
//
// Enforcement is tracked separately (issue #219). What ships here is that the
// gap is LOUD rather than silent, so a Windows operator is told the promise
// does not hold for them.
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadOrCreateQuickstartSecrets } from "../src/quickstart.ts";

/** Run a quickstart load with `process.platform` forced to `value`. */
async function loadUnderPlatform(value: string): Promise<string[]> {
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-quickstart-"));
  const dir = join(base, "state");
  const platform = Object.getOwnPropertyDescriptor(process, "platform");
  const warn = console.warn;
  const lines: string[] = [];
  Object.defineProperty(process, "platform", { value, configurable: true });
  console.warn = (...args: unknown[]) => { lines.push(args.join(" ")); };
  try {
    await loadOrCreateQuickstartSecrets({ dir });
  } finally {
    console.warn = warn;
    if (platform) Object.defineProperty(process, "platform", platform);
    await rm(base, { recursive: true, force: true });
  }
  return lines;
}

test("quickstart warns on Windows that its permission gates do not apply", async () => {
  const lines = await loadUnderPlatform("win32");
  const warning = lines.find((line) => line.includes("NOT permission-checked on Windows"));
  assert.ok(warning, `expected a Windows permission warning, got: ${JSON.stringify(lines)}`);
  // The operator needs to know what to do instead, not just that something is off.
  assert.match(warning, /inherited ACL/);
  assert.match(warning, /secret manager/);
});

test("quickstart stays silent about permissions on POSIX, where the gates DO apply", async () => {
  const lines = await loadUnderPlatform("linux");
  assert.equal(
    lines.find((line) => line.includes("NOT permission-checked on Windows")),
    undefined,
    "the Windows warning must not fire on a platform whose gates are enforced",
  );
});
