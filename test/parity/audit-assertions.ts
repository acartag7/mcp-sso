import assert from "node:assert/strict";
import type { AuthAuditEvent } from "../../src/ports/audit.ts";
import { partialSelectorMatches } from "./matchers.ts";
import type { AuditAssertion } from "./types.ts";

export function assertAudit(
  observed: readonly AuthAuditEvent[],
  expected: AuditAssertion,
  label: string,
): void {
  assert.deepStrictEqual(observed, expected.events, `${label} exact audit events`);
  for (const selector of expected.absent) {
    const found: boolean = observed.some((event) => partialSelectorMatches(event, selector));
    assert.equal(found, false, `${label} forbidden audit selector`);
  }
}
