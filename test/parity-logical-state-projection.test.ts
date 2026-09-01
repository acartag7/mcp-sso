import assert from "node:assert/strict";
import test from "node:test";
import { UNBOUND_REFRESH_RESOURCE } from "../src/ports/store.ts";
import { FixtureRunnerError } from "./parity/error.ts";
import type { LogicalTables } from "./parity/logical-state.ts";
import { hydrateLogicalState, projectLogicalState } from "./parity/logical-state.ts";
import type { LogicalState, RevokedFamilyRow } from "./parity/types.ts";

const RESOURCE = "https://api.example.com/mcp";
const OTHER_RESOURCE = "https://reports.example.com/mcp";
const REDIRECT_URI = "https://app.example.com/callback";
const INSTANCE_ID = "Kd9tR2wLxQ7pZm4Vb1Ns6A";
const EXPIRES_AT = "2026-09-01T12:00:00.000Z";
const REVOKED_AT = "2026-09-01T11:00:00.000Z";
const CODE_HASH = "a1".padEnd(64, "0");
const TOKEN_HASH = "c3".padEnd(64, "0");
const CLIENT_ID = "client-a";

const HEALTHY: LogicalState = {
  authorization_code: [{ code_hash: CODE_HASH, client_id: CLIENT_ID, subject: "user-a",
    redirect_uri: REDIRECT_URI, resource: RESOURCE, scopes: ["mcp:read"],
    code_challenge: "challenge-a", code_challenge_method: "S256", expires_at: EXPIRES_AT }],
  refresh_token: [{ token_hash: TOKEN_HASH, family_id: "family-a", client_id: CLIENT_ID,
    subject: "user-a", resource: RESOURCE, scopes: ["mcp:read"], expires_at: EXPIRES_AT }],
  client_registration: [{ client_id: CLIENT_ID, redirect_uris: [REDIRECT_URI],
    application_type: "native", issued_at_epoch: 1_756_684_800 }],
};

const REVOKED: RevokedFamilyRow = { family_id: "family-r", resource: RESOURCE, revoked_at: REVOKED_AT };

function rejects(tables: LogicalTables, message: string): void {
  assert.throws(() => projectLogicalState(tables, INSTANCE_ID), (error: unknown) =>
    error instanceof FixtureRunnerError && error.message === message);
}

const BROKEN_FAMILIES: Array<[string, string, (tables: LogicalTables) => void]> = [
  ["a refresh row whose family is missing", `refresh_token ${TOKEN_HASH} has no family`,
    (t) => { t.families.delete("family-a"); }],
  ["a family whose resource differs from its rows", "projected refresh family mismatch",
    (t) => { t.families.set("family-a", { resource: OTHER_RESOURCE, grantGeneration: null }); }],
  ["a family whose generation differs from its rows", "projected refresh family mismatch",
    (t) => { t.families.set("family-a", { resource: RESOURCE, grantGeneration: 1 }); }],
  ["an unrevoked family with no refresh rows", "family family-a has no refresh rows",
    (t) => { t.refreshTokens.clear(); }],
];

for (const [broken, message, breakTables] of BROKEN_FAMILIES) {
  test(`projection rejects ${broken}`, () => {
    const tables = hydrateLogicalState(HEALTHY);
    breakTables(tables);
    rejects(tables, message);
  });
}

const MISKEYED_TABLES: Array<[string, string, (tables: LogicalTables) => Map<string, unknown>]> = [
  ["authorization_code", CODE_HASH, (t) => t.authCodes],
  ["refresh_token", TOKEN_HASH, (t) => t.refreshTokens],
  ["client_registration", CLIENT_ID, (t) => t.clients],
];

for (const [kind, key, pick] of MISKEYED_TABLES) {
  test(`projection rejects ${kind} stored under a key that is not its id`, () => {
    for (const keepOriginal of [false, true]) {
      const tables = hydrateLogicalState(HEALTHY);
      const table = pick(tables);
      const record = table.get(key);
      assert.ok(record);
      if (!keepOriginal) table.delete(key);
      table.set(`${key}-moved`, record);
      rejects(tables, `${kind} map key does not match its record`);
    }
  });
}

test("a revoked family with no refresh rows projects exactly one revoked_family row", () => {
  const snapshot = projectLogicalState(hydrateLogicalState({ revoked_family: [REVOKED] }), INSTANCE_ID);

  assert.deepStrictEqual(snapshot.revoked_family, [REVOKED]);
  assert.deepStrictEqual(snapshot.refresh_token, []);
});

test("projection rejects a token or family resource that has no logical representation", () => {
  for (const resource of ["", UNBOUND_REFRESH_RESOURCE, null]) {
    const tables = hydrateLogicalState({ ...HEALTHY, revoked_family: [REVOKED] });
    const record = tables.refreshTokens.get(TOKEN_HASH);
    const family = tables.families.get("family-r");
    assert.ok(record && family);
    record.resource = resource;
    rejects(tables, `refresh_token ${TOKEN_HASH} has no projectable resource`);
    record.resource = RESOURCE;
    if (resource === null) continue;
    family.resource = resource;
    rejects(tables, "revoked_family family-r has no projectable resource");
  }
});
