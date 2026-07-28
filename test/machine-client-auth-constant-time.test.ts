import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

test("machine authentication reaches the fixed-width verifier for invalid snapshots", () => {
  const source = readFileSync(
    fileURLToPath(new URL("../src/machine-client-auth.ts", import.meta.url)),
    "utf8",
  );
  assert.match(
    source,
    /const matched = verifyPresentedHash\(\s*presentedHash,\s*activeClient\?\.secrets \?\? \[\],\s*now,\s*\)/,
    "invalid, disabled, and malformed snapshots must use the empty two-comparison path",
  );
  assert.match(source, /return activeClient && matched \? activeClient : null/);
});
