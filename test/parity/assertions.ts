import assert from "node:assert/strict";
import type { AuthAuditEvent } from "../../src/ports/audit.ts";
import type { AuditAssertion, LogicalState, StateAssertion } from "./types.ts";
import { partialSelectorMatches } from "./matchers.ts";
import { FixtureRunnerError } from "./error.ts";

const PRIMARY_KEYS: Record<keyof Required<LogicalState>, string> = {
  authorization_code: "code_hash", consent_jti: "jti", refresh_token: "token_hash",
  revoked_family: "family_id", client_registration: "client_id", store_instance: "instance_id",
};
const STATE_FIELDS: Record<keyof Required<LogicalState>, readonly string[]> = {
  authorization_code: ["code_hash", "client_id", "subject", "redirect_uri", "resource", "scopes",
    "code_challenge", "code_challenge_method", "expires_at", "grant_generation"],
  consent_jti: ["jti", "expires_at"],
  refresh_token: ["token_hash", "family_id", "previous_token_hash", "client_id", "subject", "resource",
    "scopes", "expires_at", "consumed_at", "grant_generation"],
  revoked_family: ["family_id", "resource", "revoked_at", "grant_generation"],
  client_registration: ["client_id", "redirect_uris", "application_type", "issued_at_epoch"],
  store_instance: ["instance_id"],
};
const KINDS = Object.keys(PRIMARY_KEYS) as Array<keyof Required<LogicalState>>;

export function assertAudit(events: AuthAuditEvent[], expected: AuditAssertion, label: string): void {
  assert.deepStrictEqual(events, expected.events, `${label} exact audit events`);
  for (const selector of expected.absent) {
    const found: boolean = events.some((event) => partialSelectorMatches(event as unknown as Record<string, unknown>, selector));
    assert.equal(found, false, `${label} forbidden audit selector ${JSON.stringify(selector)}`);
  }
}

export function assertState(observed: Required<LogicalState>, expected: StateAssertion, label: string): void {
  const wanted = normalized(expected.rows, `${label} expected state`);
  const actual = normalized(observed, `${label} observed state`);
  if (expected.mode === "exact") assert.deepStrictEqual(actual, wanted, `${label} exact state`);
  else {
    for (const kind of KINDS) {
      const key = PRIMARY_KEYS[kind];
      const actualByKey = new Map(actual[kind].map((row) => [String((row as unknown as Record<string, unknown>)[key]), row]));
      for (const row of wanted[kind]) {
        const primary = String((row as unknown as Record<string, unknown>)[key]);
        assert.deepStrictEqual(actualByKey.get(primary), row, `${label} contains ${kind}:${primary}`);
      }
    }
  }
  for (const selector of expected.absent) {
    for (const field of Object.keys(selector.where)) {
      if (!STATE_FIELDS[selector.kind].includes(field)) {
        throw new FixtureRunnerError(`${label} state selector has unknown ${selector.kind} field ${field}`);
      }
    }
    const found = actual[selector.kind].some((row) => partialSelectorMatches(
      row as unknown as Record<string, unknown>, selector.where,
    ));
    assert.equal(found, false, `${label} forbidden state selector ${JSON.stringify(selector)}`);
  }
}

function normalized(state: LogicalState, label: string): Required<LogicalState> {
  const result = {} as Required<LogicalState>;
  for (const kind of KINDS) {
    const key = PRIMARY_KEYS[kind];
    const rows = [...(state[kind] ?? [])] as unknown as Array<Record<string, unknown>>;
    const seen = new Set<string>();
    for (const row of rows) {
      const primary = String(row[key]);
      if (seen.has(primary)) throw new FixtureRunnerError(`${label} has duplicate ${kind} primary key ${primary}`);
      seen.add(primary);
    }
    (result[kind] as unknown as Array<Record<string, unknown>>) = rows.toSorted((a, b) => String(a[key]).localeCompare(String(b[key])));
  }
  return result;
}
