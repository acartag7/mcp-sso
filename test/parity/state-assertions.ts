import assert from "node:assert/strict";
import type { ValidateFunction } from "ajv/dist/2020.js";
import { FixtureRunnerError } from "./error.ts";
import { partialSelectorMatches } from "./matchers.ts";
import { logicalStateValidator, schemaErrorsText } from "./schema-json.ts";
import type { LogicalState, StateAssertion } from "./types.ts";

const PRIMARY_KEYS = {
  authorization_code: "code_hash",
  consent_jti: "jti",
  refresh_token: "token_hash",
  revoked_family: "family_id",
  client_registration: "client_id",
  store_instance: "instance_id",
} as const;

type Kind = keyof typeof PRIMARY_KEYS;
type NormalizedState = Record<Kind, object[]>;

const KINDS = Object.keys(PRIMARY_KEYS) as Kind[];

export async function assertState(
  observed: Required<LogicalState>,
  expected: StateAssertion,
  label: string,
): Promise<void> {
  const validate = await logicalStateValidator();
  assertShape(validate, expected.rows, `${label} expected state`);
  assertShape(validate, observed, `${label} observed state`);
  const wanted = normalized(expected.rows, `${label} expected state`);
  const actual = normalized(observed, `${label} observed state`);
  if (expected.mode === "exact") assert.deepStrictEqual(actual, wanted, `${label} exact state`);
  else assertContains(actual, wanted, label);
  for (const selector of expected.absent) {
    const found: boolean = actual[selector.kind]
      .some((row) => partialSelectorMatches(row, selector.where));
    assert.equal(found, false, `${label} forbidden state selector ${JSON.stringify(selector)}`);
  }
}

function assertShape(validate: ValidateFunction, state: LogicalState, label: string): void {
  if (validate(state)) return;
  const detail = schemaErrorsText(validate.errors, "state");
  throw new FixtureRunnerError(`${label} is outside the logical record shape: ${detail}`);
}

function assertContains(actual: NormalizedState, wanted: NormalizedState, label: string): void {
  for (const kind of KINDS) {
    const key = PRIMARY_KEYS[kind];
    const byPrimary = new Map(actual[kind].map((row) => [primaryValue(row, key), row]));
    for (const row of wanted[kind]) {
      const primary = primaryValue(row, key);
      assert.deepStrictEqual(byPrimary.get(primary), row, `${label} contains ${kind}:${primary}`);
    }
  }
}

function normalized(state: LogicalState, label: string): NormalizedState {
  const result = {} as NormalizedState;
  for (const kind of KINDS) {
    const key = PRIMARY_KEYS[kind];
    const rows: ReadonlyArray<object> = state[kind] ?? [];
    const seen = new Set<string>();
    for (const row of rows) {
      const primary = primaryValue(row, key);
      if (seen.has(primary)) {
        throw new FixtureRunnerError(`${label} has duplicate ${kind} primary key ${primary}`);
      }
      seen.add(primary);
    }
    result[kind] = [...rows]
      .sort((left, right) => byCodeUnit(primaryValue(left, key), primaryValue(right, key)));
  }
  return result;
}

function primaryValue(row: object, key: string): string {
  return String((row as Record<string, unknown>)[key]);
}

function byCodeUnit(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
