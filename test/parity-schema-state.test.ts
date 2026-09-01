import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { loadFixture } from "./parity/schema-json.ts";
import type {
  BootFixture, HttpFixture, LogicalState, ParityFixture, StateAssertion, StateSelector,
} from "./parity/types.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const HTTP_PATH = resolve(PROJECT_ROOT, "fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed-portable.json");
const BOOT_PATH = resolve(PROJECT_ROOT, "fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed.json");
const SCHEMA_PATH = resolve(PROJECT_ROOT, "fixtures/schema/fixture.schema.json");
const HASH = "a".repeat(64);
const AT = "2026-09-01T00:00:00.000Z";
const INSTANCE_ID = "abcdefghijklmnopqrstuv";
const SHAPES = ["http", "boot"] as const;
type Shape = (typeof SHAPES)[number];
type Kind = keyof LogicalState;
type RowOf<K extends Kind> = NonNullable<LogicalState[K]>[number];
interface SchemaNode {
  [keyword: string]: unknown;
  properties?: Record<string, SchemaNode>; items?: SchemaNode; oneOf?: SchemaNode[];
}

const ROWS: { [K in Kind]-?: RowOf<K> } = {
  authorization_code: {
    code_hash: HASH, client_id: "client", subject: "subject", redirect_uri: "https://client.example/cb",
    resource: "https://mcp.example", scopes: ["mcp:read"], code_challenge: "challenge",
    code_challenge_method: "S256", expires_at: AT,
  },
  consent_jti: { jti: "jti", expires_at: AT },
  refresh_token: {
    token_hash: HASH, family_id: "family", client_id: "client", subject: "subject",
    resource: "https://mcp.example", scopes: ["mcp:read"], expires_at: AT,
  },
  revoked_family: { family_id: "family", resource: "https://mcp.example", revoked_at: AT },
  client_registration: {
    client_id: "client", redirect_uris: ["https://client.example/cb"], application_type: "web", issued_at_epoch: 0,
  },
  store_instance: { instance_id: INSTANCE_ID },
};
const KINDS = Object.keys(ROWS) as Kind[];
const ALL_ROWS = Object.fromEntries(KINDS.map((kind) => [kind, [ROWS[kind]]])) as LogicalState;
const VALID_SELECTORS: StateSelector[] = [
  { kind: "authorization_code", where: { client_id: "client", grant_generation: 2 } },
  { kind: "consent_jti", where: { jti: "jti" } },
  { kind: "refresh_token", where: { consumed_at: AT } },
  { kind: "revoked_family", where: { family_id: "family" } },
  { kind: "client_registration", where: { application_type: "native" } },
  { kind: "store_instance", where: { instance_id: INSTANCE_ID } },
];
const WRONGLY_TYPED: Array<{ kind: Kind; where: Record<string, unknown> }> = [
  { kind: "authorization_code", where: { code_hash: 42 } },
  { kind: "authorization_code", where: { code_challenge_method: "plain" } },
  { kind: "consent_jti", where: { expires_at: [] } },
  { kind: "refresh_token", where: { scopes: "mcp:read" } },
  { kind: "refresh_token", where: { consumed_at: 123 } },
  { kind: "revoked_family", where: { grant_generation: "1" } },
  { kind: "revoked_family", where: { grant_generation: 0 } },
  { kind: "client_registration", where: { issued_at_epoch: "0" } },
  { kind: "client_registration", where: { application_type: "service" } },
  { kind: "store_instance", where: { instance_id: false } },
];
// @ts-expect-error selectors name only fields of the selected kind
const unknownFieldSelector: StateSelector = { kind: "refresh_token", where: { consumed_att: AT } };
// @ts-expect-error selector values keep the field type of the selected kind
const wronglyTypedSelector: StateSelector = { kind: "refresh_token", where: { consumed_at: 123 } };

function asHttp(fixture: ParityFixture): HttpFixture {
  if (fixture.kind !== "fixture") throw new Error("expected HTTP fixture");
  return fixture;
}

function asBoot(fixture: ParityFixture): BootFixture {
  const source = asHttp(fixture);
  const { when: _when, then: _then, given, ...base } = source;
  const { protectedResource: _protectedResource, ...bootGiven } = given;
  return {
    ...base,
    kind: "boot",
    given: { ...bootGiven, entrypoint: "Bridge" },
    then: { boot: { outcome: "accepted" }, outbound: [] },
  };
}

async function writeAndLoad(fixture: ParityFixture): Promise<ParityFixture> {
  const directory = await mkdtemp(join(tmpdir(), "mcp-sso-state-schema-"));
  const path = join(directory, "fixture.json");
  try {
    await writeFile(path, JSON.stringify(fixture), "utf8");
    return await loadFixture(path);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function loadWith(shape: Shape, mutate: (fixture: ParityFixture) => void): Promise<ParityFixture> {
  const source = structuredClone(await loadFixture(shape === "http" ? HTTP_PATH : BOOT_PATH));
  const fixture = shape === "http" ? asHttp(source) : asBoot(source);
  mutate(fixture);
  return writeAndLoad(fixture);
}

async function captureError(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  return undefined;
}

function assertSchemaError(caught: unknown, detail: string): void {
  assert.ok(caught instanceof FixtureRunnerError, `expected a schema rejection carrying: ${detail}`);
  assert.match(caught.message, /schema validation failed/u);
  assert.ok(caught.message.includes(detail), `${caught.message} does not carry: ${detail}`);
}

function absent(selectors: unknown[]): StateAssertion {
  return { mode: "exact", rows: {}, absent: selectors as StateSelector[] };
}

function rowsOf(kind: Kind, row: unknown): LogicalState {
  return { [kind]: [row] } as unknown as LogicalState;
}

function defName(kind: Kind, suffix: "Row" | "Selector"): string {
  return `${kind.replace(/_([a-z])/gu, (_match, letter: string) => letter.toUpperCase())}${suffix}`;
}

test("rejects an absent selector that names an unknown field for every record kind", async () => {
  for (const shape of SHAPES) {
    for (const kind of KINDS) {
      const error = await captureError(() => loadWith(shape, (fixture) => {
        fixture.then.state = absent([{ kind, where: { misspelled_field: "value" } }]);
      }));
      assertSchemaError(error, "fixture/then/state/absent/0/where must NOT have additional properties");
    }
  }
});

test("rejects an absent selector that names a field of another record kind", async () => {
  for (const shape of SHAPES) {
    const error = await captureError(() => loadWith(shape, (fixture) => {
      fixture.then.state = absent([{ kind: "consent_jti", where: { code_hash: HASH } }]);
    }));
    assertSchemaError(error, "fixture/then/state/absent/0/where must NOT have additional properties");
  }
});

test("rejects an absent selector whose value leaves the field schema of its kind", async () => {
  for (const shape of SHAPES) {
    for (const selector of WRONGLY_TYPED) {
      const [field] = Object.keys(selector.where);
      const error = await captureError(() => loadWith(shape, (fixture) => { fixture.then.state = absent([selector]); }));
      assertSchemaError(error, `fixture/then/state/absent/0/where/${field} must `);
    }
  }
});

test("rejects an absent selector with no fields", async () => {
  for (const shape of SHAPES) {
    const error = await captureError(() => loadWith(shape, (fixture) => {
      fixture.then.state = absent([{ kind: "refresh_token", where: {} }]);
    }));
    assertSchemaError(error, "fixture/then/state/absent/0/where must NOT have fewer than 1 properties");
  }
});

test("accepts a partial absent selector for every record kind and loads it unchanged", async () => {
  assert.deepEqual(new Set(VALID_SELECTORS.map((selector) => selector.kind)), new Set(KINDS));
  for (const shape of SHAPES) {
    const loaded = await loadWith(shape, (fixture) => { fixture.then.state = absent(VALID_SELECTORS); });
    assert.deepEqual(loaded.then.state?.absent, VALID_SELECTORS);
  }
});

test("accepts a complete row for every record kind in given.state and then.state.rows", async () => {
  for (const shape of SHAPES) {
    const loaded = await loadWith(shape, (fixture) => {
      fixture.given.state = ALL_ROWS;
      fixture.then.state = { mode: "exact", rows: ALL_ROWS, absent: [] };
    });
    assert.deepEqual(loaded.given.state, ALL_ROWS);
    assert.deepEqual(loaded.then.state?.rows, ALL_ROWS);
  }
});

test("rejects a row missing a required field in given.state and then.state.rows for every record kind", async () => {
  for (const shape of SHAPES) {
    for (const kind of KINDS) {
      const [field] = Object.keys(ROWS[kind]);
      assert.ok(field, `${kind} has a primary key field`);
      const row: Record<string, unknown> = { ...ROWS[kind] };
      delete row[field];
      const givenError = await captureError(() => loadWith(shape, (fixture) => { fixture.given.state = rowsOf(kind, row); }));
      assertSchemaError(givenError, `fixture/given/state/${kind}/0 must have required property '${field}'`);
      const thenError = await captureError(() => loadWith(shape, (fixture) => {
        fixture.then.state = { mode: "exact", rows: rowsOf(kind, row), absent: [] };
      }));
      assertSchemaError(thenError, `fixture/then/state/rows/${kind}/0 must have required property '${field}'`);
    }
  }
});

test("rejects a row with an unknown field in given.state and then.state.rows for every record kind", async () => {
  for (const shape of SHAPES) {
    for (const kind of KINDS) {
      const row = { ...ROWS[kind], misspelled_field: "value" };
      const givenError = await captureError(() => loadWith(shape, (fixture) => { fixture.given.state = rowsOf(kind, row); }));
      assertSchemaError(givenError, `fixture/given/state/${kind}/0 must NOT have additional properties`);
      const thenError = await captureError(() => loadWith(shape, (fixture) => {
        fixture.then.state = { mode: "exact", rows: rowsOf(kind, row), absent: [] };
      }));
      assertSchemaError(thenError, `fixture/then/state/rows/${kind}/0 must NOT have additional properties`);
    }
  }
});

test("binds every absent selector field to the row field schema of its kind", async () => {
  const schema = JSON.parse(await readFile(SCHEMA_PATH, "utf8")) as { $defs: Record<string, SchemaNode> };
  const branches = schema.$defs.stateAssertion?.properties?.absent?.items?.oneOf ?? [];
  assert.deepEqual(branches.map((branch) => branch.properties?.kind?.const), KINDS);
  for (const [index, kind] of KINDS.entries()) {
    const row = schema.$defs[defName(kind, "Row")];
    const selector = schema.$defs[defName(kind, "Selector")];
    assert.ok(row?.properties, `${defName(kind, "Row")} lists its fields`);
    assert.ok(selector?.properties, `${defName(kind, "Selector")} lists its fields`);
    assert.equal(branches[index]?.properties?.where?.$ref, `#/$defs/${defName(kind, "Selector")}`);
    assert.equal(selector.additionalProperties, false);
    assert.equal(selector.minProperties, 1);
    assert.equal(selector.required, undefined);
    assert.deepEqual(Object.keys(selector.properties), Object.keys(row.properties));
    for (const field of Object.keys(row.properties)) {
      assert.deepEqual(selector.properties[field], { $ref: `#/$defs/${defName(kind, "Row")}/properties/${field}` });
    }
  }
});
