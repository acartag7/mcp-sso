import assert from "node:assert/strict";
import test from "node:test";
import { FixtureRunnerError } from "./parity/error.ts";
import { hydrateLogicalState, projectLogicalState } from "./parity/logical-state.ts";
import type {
  AuthorizationCodeRow, ClientRegistrationRow, ConsentJtiRow, LogicalState,
  RefreshTokenRow, RevokedFamilyRow,
} from "./parity/types.ts";

const RESOURCE = "https://api.example.com/mcp";
const OTHER_RESOURCE = "https://reports.example.com/mcp";
const REDIRECT_URI = "https://app.example.com/callback";
const INSTANCE_ID = "Kd9tR2wLxQ7pZm4Vb1Ns6A";
const EXPIRES_AT = "2026-09-01T12:00:00.000Z";
const CONSUMED_AT = "2026-09-01T11:59:00.000Z";
const REVOKED_AT = "2026-09-01T11:00:00.000Z";
const ISSUED_AT_EPOCH = 1_756_684_800;

function hash(prefix: string): string {
  return prefix.padEnd(64, "0");
}

function authRow(overrides: Partial<AuthorizationCodeRow> = {}): AuthorizationCodeRow {
  return { code_hash: hash("a1"), client_id: "client-a", subject: "user-a", redirect_uri: REDIRECT_URI,
    resource: RESOURCE, scopes: ["mcp:read"], code_challenge: "challenge-a",
    code_challenge_method: "S256", expires_at: EXPIRES_AT, ...overrides };
}

function refreshRow(overrides: Partial<RefreshTokenRow> = {}): RefreshTokenRow {
  return { token_hash: hash("c3"), family_id: "family-a", client_id: "client-a", subject: "user-a",
    resource: RESOURCE, scopes: ["mcp:read"], expires_at: EXPIRES_AT, ...overrides };
}

function revokedRow(overrides: Partial<RevokedFamilyRow> = {}): RevokedFamilyRow {
  return { family_id: "family-r", resource: RESOURCE, revoked_at: REVOKED_AT, ...overrides };
}

function jtiRow(jti: string, expiresAt = EXPIRES_AT): ConsentJtiRow {
  return { jti, expires_at: expiresAt };
}

function clientRow(overrides: Partial<ClientRegistrationRow> = {}): ClientRegistrationRow {
  return { client_id: "client-a", redirect_uris: [REDIRECT_URI],
    application_type: "native", issued_at_epoch: ISSUED_AT_EPOCH, ...overrides };
}

test("a hydrated logical state projects back to the same rows sorted by primary key", () => {
  const authA = authRow();
  const authB = authRow({ code_hash: hash("b2"), client_id: "client-b", grant_generation: 3 });
  const jtiA = jtiRow("jti-a");
  const jtiB = jtiRow("jti-b", CONSUMED_AT);
  const refreshA = refreshRow();
  const refreshB = refreshRow({ token_hash: hash("d4"), previous_token_hash: hash("c3"), consumed_at: CONSUMED_AT });
  const revoked = revokedRow({ grant_generation: 3 });
  const clientA = clientRow();
  const clientB = clientRow({ client_id: "client-b", application_type: "web" });
  const state: LogicalState = {
    authorization_code: [authB, authA],
    consent_jti: [jtiB, jtiA],
    refresh_token: [refreshB, refreshA],
    revoked_family: [revoked],
    client_registration: [clientB, clientA],
    store_instance: [{ instance_id: INSTANCE_ID }],
  };

  const snapshot = projectLogicalState(hydrateLogicalState(state), INSTANCE_ID);

  assert.deepStrictEqual(snapshot, {
    authorization_code: [authA, authB],
    consent_jti: [jtiA, jtiB],
    refresh_token: [refreshA, refreshB],
    revoked_family: [revoked],
    client_registration: [clientA, clientB],
    store_instance: [{ instance_id: INSTANCE_ID }],
  });
  assert.deepStrictEqual(JSON.parse(JSON.stringify(snapshot)) as unknown, snapshot);
  for (const rows of Object.values(snapshot)) {
    for (const row of rows) assert.ok(Object.values(row).every((v) => v !== undefined), JSON.stringify(row));
  }
});

test("grant generations hydrate as legacy null or the stated value and project back exactly", () => {
  const legacy = hydrateLogicalState({
    authorization_code: [authRow()], refresh_token: [refreshRow()], revoked_family: [revokedRow()],
  });
  const stated = hydrateLogicalState({
    authorization_code: [authRow({ grant_generation: 3 })],
    refresh_token: [refreshRow({ grant_generation: 3 })],
    revoked_family: [revokedRow({ grant_generation: 3 })],
  });

  assert.strictEqual(legacy.authCodes.get(hash("a1"))?.grantGeneration, null);
  assert.strictEqual(legacy.refreshTokens.get(hash("c3"))?.grantGeneration, null);
  assert.strictEqual(legacy.families.get("family-a")?.grantGeneration, null);
  assert.strictEqual(legacy.families.get("family-r")?.grantGeneration, null);
  assert.strictEqual(stated.authCodes.get(hash("a1"))?.grantGeneration, 3);
  assert.strictEqual(stated.refreshTokens.get(hash("c3"))?.grantGeneration, 3);
  assert.strictEqual(stated.families.get("family-a")?.grantGeneration, 3);

  const legacySnapshot = projectLogicalState(legacy, INSTANCE_ID);
  assert.deepStrictEqual(legacySnapshot.authorization_code, [authRow()]);
  assert.deepStrictEqual(legacySnapshot.refresh_token, [refreshRow()]);
  assert.deepStrictEqual(legacySnapshot.revoked_family, [revokedRow()]);
  const statedSnapshot = projectLogicalState(stated, INSTANCE_ID);
  assert.deepStrictEqual(statedSnapshot.authorization_code, [authRow({ grant_generation: 3 })]);
  assert.deepStrictEqual(statedSnapshot.refresh_token, [refreshRow({ grant_generation: 3 })]);
  assert.deepStrictEqual(statedSnapshot.revoked_family, [revokedRow({ grant_generation: 3 })]);
});

test("optional refresh members hydrate and project through their physical form", () => {
  const bare = hydrateLogicalState({ refresh_token: [refreshRow()] });
  const root = bare.refreshTokens.get(hash("c3"));
  assert.strictEqual(root?.previousTokenHash, null);
  assert.ok(root !== undefined && !("consumedAt" in root));
  assert.deepStrictEqual(projectLogicalState(bare, INSTANCE_ID).refresh_token, [refreshRow()]);

  const row = refreshRow({ consumed_at: CONSUMED_AT, previous_token_hash: hash("b2") });
  const rotated = hydrateLogicalState({ refresh_token: [row] });
  assert.strictEqual(rotated.refreshTokens.get(hash("c3"))?.consumedAt, CONSUMED_AT);
  assert.strictEqual(rotated.refreshTokens.get(hash("c3"))?.previousTokenHash, hash("b2"));
  assert.deepStrictEqual(projectLogicalState(rotated, INSTANCE_ID).refresh_token, [row]);
});

const DUPLICATE_STATES: Array<[keyof LogicalState, LogicalState]> = [
  ["authorization_code", { authorization_code: [authRow(), authRow({ subject: "user-b" })] }],
  ["consent_jti", { consent_jti: [jtiRow("jti-a"), jtiRow("jti-a", CONSUMED_AT)] }],
  ["refresh_token", { refresh_token: [refreshRow(), refreshRow({ subject: "user-b" })] }],
  ["revoked_family", { revoked_family: [revokedRow(), revokedRow()] }],
  ["client_registration", { client_registration: [clientRow(), clientRow({ application_type: "web" })] }],
  ["store_instance", { store_instance: [{ instance_id: INSTANCE_ID }, { instance_id: INSTANCE_ID }] }],
];

for (const [kind, state] of DUPLICATE_STATES) {
  test(`a duplicate ${kind} primary key is rejected`, () => {
    assert.throws(() => hydrateLogicalState(state), (error: unknown) => error instanceof FixtureRunnerError
      && error.message === `${kind} has duplicate primary key`);
  });
}

test("rows of one family that disagree on resource or generation are rejected", () => {
  assert.throws(() => hydrateLogicalState({ refresh_token: [refreshRow(),
    refreshRow({ token_hash: hash("d4"), resource: OTHER_RESOURCE })] }), /pre-state refresh family mismatch/);
  assert.throws(() => hydrateLogicalState({ refresh_token: [refreshRow(),
    refreshRow({ token_hash: hash("d4"), grant_generation: 1 })] }), /pre-state refresh family mismatch/);
  assert.throws(() => hydrateLogicalState({ refresh_token: [refreshRow()],
    revoked_family: [revokedRow({ family_id: "family-a", grant_generation: 1 })] }), /pre-state revoked family mismatch/);
  assert.throws(() => hydrateLogicalState({ refresh_token: [refreshRow()],
    revoked_family: [revokedRow({ family_id: "family-a", resource: OTHER_RESOURCE })] }), /pre-state revoked family mismatch/);
});

test("a revoked family that agrees with its refresh rows revokes that one family", () => {
  const tables = hydrateLogicalState({
    refresh_token: [refreshRow()],
    revoked_family: [revokedRow({ family_id: "family-a" })],
  });

  assert.strictEqual(tables.families.size, 1);
  assert.deepStrictEqual(tables.families.get("family-a"), {
    resource: RESOURCE, grantGeneration: null, revokedAt: REVOKED_AT,
  });
});

test("more than one store_instance row is rejected", () => {
  const rows = [{ instance_id: INSTANCE_ID }, { instance_id: "Zq8Xn3Cv6Bm1Kl9Rt2Wy4E" }];
  assert.throws(() => hydrateLogicalState({ store_instance: rows }), /state has multiple store_instance rows/);
});

test("hydration and projection copy array fields instead of sharing them", () => {
  const scopes = ["mcp:read"];
  const redirectUris = [REDIRECT_URI];
  const tables = hydrateLogicalState({
    refresh_token: [refreshRow({ scopes })],
    client_registration: [clientRow({ redirect_uris: redirectUris })],
  });

  scopes.push("mcp:write");
  redirectUris.push("https://other.example.com/callback");
  assert.deepStrictEqual(tables.refreshTokens.get(hash("c3"))?.scopes, ["mcp:read"]);
  assert.deepStrictEqual(tables.clients.get("client-a")?.redirectUris, [REDIRECT_URI]);

  const snapshot = projectLogicalState(tables, INSTANCE_ID);
  snapshot.refresh_token[0]?.scopes.push("mcp:admin");
  snapshot.client_registration[0]?.redirect_uris.push("https://other.example.com/callback");
  assert.deepStrictEqual(tables.refreshTokens.get(hash("c3"))?.scopes, ["mcp:read"]);
  assert.deepStrictEqual(tables.clients.get("client-a")?.redirectUris, [REDIRECT_URI]);
});

test("projection omits machine client records and keeps native and web ones", () => {
  const tables = hydrateLogicalState({
    client_registration: [clientRow(), clientRow({ client_id: "client-b", application_type: "web" })],
  });
  tables.clients.set("mcc_lifecycle", {
    clientId: "mcc_lifecycle", redirectUris: [], applicationType: "machine",
    issuedAtEpoch: ISSUED_AT_EPOCH, allowedScopes: ["mcp:read"], secrets: [],
  });

  assert.deepStrictEqual(projectLogicalState(tables, INSTANCE_ID).client_registration, [
    clientRow(), clientRow({ client_id: "client-b", application_type: "web" }),
  ]);
});

test("rows sort by code unit order rather than locale collation", () => {
  const rows = [jtiRow("a-jti"), jtiRow("_jti"), jtiRow("Z-jti")];
  const jtis = projectLogicalState(hydrateLogicalState({ consent_jti: rows }), INSTANCE_ID).consent_jti;

  assert.deepStrictEqual(jtis.map((row) => row.jti), ["Z-jti", "_jti", "a-jti"]);
});
