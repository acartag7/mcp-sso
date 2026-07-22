// Supplementary (non-frozen) tests for createGuardedFetcher option validation
// (Fable review of PR #87). A misspelled/unknown cap key must fail closed rather
// than be silently ignored (which would use the default cap) — the repo's binding
// fail-closed configuration rule.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createGuardedFetcher } from "../src/cimd/guarded-fetcher.ts";

test("createGuardedFetcher rejects unknown / misspelled option keys (fail-closed config)", () => {
  assert.throws(() => createGuardedFetcher({ unknown: true } as never));
  assert.throws(() => createGuardedFetcher({ maxDocumentByte: 1024 } as never)); // typo: missing 's'
  assert.throws(() => createGuardedFetcher({ fetchTimeoutMS: 1000 } as never)); // typo: wrong case
});

test("createGuardedFetcher accepts exactly the documented option keys", () => {
  assert.doesNotThrow(() =>
    createGuardedFetcher({ allowLoopback: true, maxDocumentBytes: 2048, fetchTimeoutMs: 2000 }));
});
