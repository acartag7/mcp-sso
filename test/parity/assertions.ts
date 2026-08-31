import assert from "node:assert/strict";
import type { AuthAuditEvent } from "../../src/ports/audit.ts";
import type { AuditAssertion, LogicalState, StateAssertion } from "./types.ts";
import { partialSelectorMatches } from "./matchers.ts";
import { FixtureRunnerError } from "./error.ts";

const PRIMARY_KEYS: Record<keyof Required<LogicalState>, string> = {
  authorization_code: "code_hash", consent_jti: "jti", refresh_token: "token_hash",
  revoked_family: "family_id", client_registration: "client_id", store_instance: "instance_id",
};
type FieldValidator = (value: unknown) => boolean;
const string = (value: unknown): boolean => typeof value === "string";
const nonEmpty = (value: unknown): boolean => typeof value === "string" && value.length > 0;
const strings = (value: unknown): boolean => Array.isArray(value) && value.every(string);
const nonEmptyStrings = (value: unknown): boolean => Array.isArray(value) && value.length > 0 && value.every(nonEmpty);
const sha256 = (value: unknown): boolean => typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const timestamp = (value: unknown): boolean => typeof value === "string"
  && /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u.test(value);
const positiveInteger = (value: unknown): boolean => Number.isInteger(value) && Number(value) >= 1;
const nonNegativeInteger = (value: unknown): boolean => Number.isInteger(value) && Number(value) >= 0;
const STATE_FIELD_VALIDATORS: Record<keyof Required<LogicalState>, Record<string, FieldValidator>> = {
  authorization_code: {
    code_hash: sha256, client_id: nonEmpty, subject: nonEmpty, redirect_uri: nonEmpty,
    resource: nonEmpty, scopes: strings, code_challenge: nonEmpty,
    code_challenge_method: (value) => value === "S256", expires_at: timestamp,
    grant_generation: positiveInteger,
  },
  consent_jti: { jti: nonEmpty, expires_at: timestamp },
  refresh_token: {
    token_hash: sha256, family_id: nonEmpty, previous_token_hash: sha256, client_id: nonEmpty,
    subject: nonEmpty, resource: nonEmpty, scopes: strings, expires_at: timestamp,
    consumed_at: timestamp, grant_generation: positiveInteger,
  },
  revoked_family: {
    family_id: nonEmpty, resource: nonEmpty, revoked_at: timestamp, grant_generation: positiveInteger,
  },
  client_registration: {
    client_id: nonEmpty, redirect_uris: nonEmptyStrings,
    application_type: (value) => value === "native" || value === "web",
    issued_at_epoch: nonNegativeInteger,
  },
  store_instance: {
    instance_id: (value) => typeof value === "string" && /^[A-Za-z0-9_-]{22,128}$/u.test(value),
  },
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
    for (const [field, value] of Object.entries(selector.where)) {
      const validate = STATE_FIELD_VALIDATORS[selector.kind][field];
      if (!validate) {
        throw new FixtureRunnerError(`${label} state selector has unknown ${selector.kind} field ${field}`);
      }
      if (!validate(value)) {
        throw new FixtureRunnerError(`${label} state selector has invalid ${selector.kind} field ${field}`);
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
