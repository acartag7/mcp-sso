// The release matrix decides whether evidence counts. Both edges of that
// decision are load-bearing and both have been wrong: a next-line read reported
// green parents as failing, and truncating a TAP directive counted a SKIPPED
// test as a pass — a green receipt for evidence that never ran.
import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveOutcome } from "../scripts/lib/release-matrix-outcome.mjs";

const tap = (...lines) => lines.join("\n");

test("release matrix: a passing leaf test counts as evidence", () => {
  assert.equal(resolveOutcome(tap("# Subtest: alpha", "ok 1 - alpha"), "alpha"), "pass");
});

test("release matrix: a SKIPPED test is never counted as evidence", () => {
  const out = tap("# Subtest: alpha", "ok 1 - alpha # SKIP no integration env");
  assert.notEqual(resolveOutcome(out, "alpha"), "pass",
    "a skipped test must not produce a green receipt for evidence that never ran");
});

test("release matrix: a failing test is never counted as evidence", () => {
  assert.notEqual(resolveOutcome(tap("# Subtest: alpha", "not ok 1 - alpha"), "alpha"), "pass");
});

test("release matrix: a test that declares subtests still counts when green", () => {
  // The parent's own result line follows its children, so a next-line read sees
  // "# Subtest: child" and wrongly reports the parent as failing.
  const out = tap(
    "# Subtest: alpha",
    "    # Subtest: child",
    "    ok 1 - child",
    "    1..1",
    "ok 1 - alpha",
  );
  assert.equal(resolveOutcome(out, "alpha"), "pass");
});

test("release matrix: a name that prefixes another does not borrow its result", () => {
  // "alpha" is a strict prefix of "alpha extended". If the shorter name matched
  // the longer test's line, a missing or failing test would read as green.
  const out = tap(
    "# Subtest: alpha",
    "    # Subtest: child",
    "    not ok 1 - child",
    "    1..1",
    "not ok 1 - alpha",
    "# Subtest: alpha extended",
    "ok 2 - alpha extended",
  );
  assert.notEqual(resolveOutcome(out, "alpha"), "pass");
  assert.equal(resolveOutcome(out, "alpha extended"), "pass");
});

test("release matrix: an absent test reports missing rather than passing", () => {
  assert.equal(resolveOutcome(tap("# Subtest: beta", "ok 1 - beta"), "alpha"), "missing");
});
