import assert from "node:assert/strict";
import test from "node:test";
import type { SaveRefreshTokenInput } from "../src/ports/store.ts";
import { UNBOUND_REFRESH_RESOURCE } from "../src/ports/store.ts";
import { MemoryStore } from "../src/store/memory.ts";
import type { LogicalTables } from "./parity/logical-state.ts";
import { hydrateLogicalState, projectLogicalState } from "./parity/logical-state.ts";
import {
  findGrantedScopes, findRefreshToken, revokeRefreshTokenFamily, rotateRefreshToken, saveRefreshToken, sweepRefresh,
} from "./parity/store-refresh.ts";

const RESOURCE = "https://api.example.com/mcp";
const OTHER_RESOURCE = "https://reports.example.com/mcp";
const INSTANCE_ID = "Kd9tR2wLxQ7pZm4Vb1Ns6A", SUBJECT = "user-a", CLIENT_ID = "client-a", FAMILY = "family-a";
const T0 = "2026-09-01T09:00:00.000Z", T1 = "2026-09-01T10:00:00.000Z";
const T2 = "2026-09-01T11:00:00.000Z", T3 = "2026-09-01T12:00:00.000Z";

function hash(prefix: string): string { return prefix.padEnd(64, "0"); }
const A = hash("1a"), B = hash("2b"), C = hash("3c"), D = hash("4d");
const E = hash("5e"), F = hash("6f"), G = hash("7a"), H = hash("8b"), I = hash("9c");

function token(tokenHash: string, overrides: Partial<SaveRefreshTokenInput> = {}): SaveRefreshTokenInput {
  return {
    tokenHash, familyId: FAMILY, previousTokenHash: null, clientId: CLIENT_ID, subject: SUBJECT,
    resource: RESOURCE, scopes: ["mcp:read"], expiresAt: T3, ...overrides,
  };
}

interface Op {
  label: string; memory: (store: MemoryStore) => unknown; tables: (tables: LogicalTables) => unknown;
}

type Outcome = { ok: true; value: unknown } | { ok: false; error: string; message: string };

const save = (input: SaveRefreshTokenInput): Op => ({
  label: `save ${input.tokenHash.slice(0, 2)}`, memory: (store) => store.saveRefreshToken(structuredClone(input)),
  tables: (tables) => saveRefreshToken(tables, structuredClone(input)),
});

const rotate = (
  tokenHash: string, next: SaveRefreshTokenInput, now: string, generation?: number, resource?: string,
): Op => ({
  label: `rotate ${tokenHash.slice(0, 2)} at ${now}`,
  memory: (s) => s.rotateRefreshToken(tokenHash, structuredClone(next), now, generation, resource),
  tables: (tables) => rotateRefreshToken(tables, tokenHash, structuredClone(next), now, generation, resource),
});

const revoke = (familyId: string, at: string, resource?: string): Op => ({
  label: `revoke ${familyId} at ${at}`, memory: (store) => store.revokeRefreshTokenFamily(familyId, at, resource),
  tables: (tables) => revokeRefreshTokenFamily(tables, familyId, at, resource),
});

const find = (tokenHash: string): Op => ({
  label: `find ${tokenHash.slice(0, 2)}`, memory: (store) => store.findRefreshToken(tokenHash),
  tables: (tables) => findRefreshToken(tables, tokenHash),
});

const scopes = (now: string, generation?: number, resource?: string, subject = SUBJECT, client = CLIENT_ID): Op => ({
  label: `scopes at ${now}`, memory: (store) => store.findGrantedScopes(subject, client, now, generation, resource),
  tables: (tables) => findGrantedScopes(tables, subject, client, now, generation, resource),
});

const sweep = (now: string): Op => ({
  label: `sweep at ${now}`, memory: (store) => store.sweepExpired(now),
  tables: (tables) => sweepRefresh(tables, now),
});

async function outcome(run: () => unknown): Promise<Outcome> {
  try { return { ok: true, value: await run() }; }
  catch (error) {
    if (!(error instanceof Error)) throw error;
    return { ok: false, error: error.constructor.name, message: error.message };
  }
}

/** Replay one operation sequence against the reference store and against the fixture tables,
 *  asserting the same returned value or the same thrown failure at every step. */
async function differential(ops: Op[]): Promise<LogicalTables> {
  const store = new MemoryStore();
  const tables = hydrateLogicalState({});
  try {
    for (const op of ops) {
      const expected = await outcome(() => op.memory(store));
      const actual = await outcome(() => op.tables(tables));
      assert.deepStrictEqual(actual, expected, op.label);
    }
  } finally {
    await store.close();
  }
  return tables;
}

test("a saved refresh token and its family appear in the projected state", async () => {
  const tables = await differential([save(token(A)), find(A), scopes(T0)]);

  const snapshot = projectLogicalState(tables, INSTANCE_ID);
  assert.deepStrictEqual(snapshot.refresh_token, [{
    token_hash: A, family_id: FAMILY, client_id: CLIENT_ID, subject: SUBJECT, resource: RESOURCE,
    scopes: ["mcp:read"], expires_at: T3, grant_generation: 1,
  }]);
  assert.deepStrictEqual(snapshot.revoked_family, []);
});

test("a token hash that already exists is rejected and the stored row is kept", async () => {
  await differential([
    save(token(A)), save(token(A, { scopes: ["mcp:admin"] })), find(A),
  ]);
});

test("a write that disagrees with its family resource or generation is rejected", async () => {
  await differential([
    save(token(A)), save(token(B, { resource: OTHER_RESOURCE })),
    save(token(C, { grantGeneration: null })), find(B), find(C),
  ]);
});

const MALFORMED: Array<[string, Partial<SaveRefreshTokenInput>]> = [
  ["a token hash that is not a digest", { tokenHash: "not-a-digest" }],
  ["a previous token hash that is not a digest", { previousTokenHash: "not-a-digest" }],
  ["a blank resource", { resource: "   " }],
  ["the reserved unbound resource", { resource: UNBOUND_REFRESH_RESOURCE }],
  ["an expiry without exactly three millisecond digits", { expiresAt: "2026-09-01T12:00:00Z" }],
  ["a grant generation that is not a positive integer", { grantGeneration: 0 }],
  ["a subject with outer whitespace", { subject: " user-a" }],
];

for (const [malformed, overrides] of MALFORMED) {
  test(`a refresh write with ${malformed} is rejected before anything is stored`, async () => {
    const input = token(A, overrides);
    const tables = await differential([save(input), find(input.tokenHash), find(A)]);
    assert.deepStrictEqual(projectLogicalState(tables, INSTANCE_ID).refresh_token, []);
  });
}

test("rotation consumes the predecessor and the successor inherits its family binding", async () => {
  const successor = token(B, {
    previousTokenHash: A, clientId: "client-other", subject: "user-other",
    resource: OTHER_RESOURCE, scopes: ["mcp:admin"], grantGeneration: null, expiresAt: T3,
  });
  const tables = await differential([
    save(token(A)), rotate(A, successor, T0), find(A), find(B), scopes(T0),
  ]);

  const snapshot = projectLogicalState(tables, INSTANCE_ID);
  assert.deepStrictEqual(snapshot.refresh_token.map((row) => [row.token_hash, row.consumed_at]),
    [[A, T0], [B, undefined]]);
  assert.deepStrictEqual(snapshot.refresh_token[1], {
    token_hash: B, family_id: FAMILY, previous_token_hash: A, client_id: CLIENT_ID, subject: SUBJECT,
    resource: RESOURCE, scopes: ["mcp:read"], expires_at: T3, grant_generation: 1,
  });
});

test("replaying a consumed token revokes the family after that token expired while its successor is live", async () => {
  const tables = await differential([
    save(token(A, { expiresAt: T1 })), rotate(A, token(B, { previousTokenHash: A, expiresAt: T3 }), T0),
    rotate(A, token(C, { previousTokenHash: A, expiresAt: T3 }), T2), find(C), scopes(T2),
    rotate(B, token(D, { previousTokenHash: B, expiresAt: T3 }), T2),
  ]);

  const snapshot = projectLogicalState(tables, INSTANCE_ID);
  assert.deepStrictEqual(snapshot.revoked_family,
    [{ family_id: FAMILY, resource: RESOURCE, revoked_at: T2, grant_generation: 1 }]);
  assert.deepStrictEqual(snapshot.refresh_token.map((row) => row.token_hash), [A, B]);
});

const NO_ROTATION: Array<[string, () => Op[]]> = [
  ["the token hash is unknown", () => [rotate(B, token(C, { previousTokenHash: B }), T0)]],
  ["the expected generation does not match", () => [rotate(A, token(B, { previousTokenHash: A }), T0, 2)]],
  ["the expected resource does not match", () => [rotate(A, token(B, { previousTokenHash: A }), T0, 1, OTHER_RESOURCE)]],
  ["the family is revoked", () => [revoke(FAMILY, T1), rotate(A, token(B, { previousTokenHash: A }), T2)]],
  ["the predecessor has expired", () => [rotate(A, token(B, { previousTokenHash: A }), T3)]],
  ["the successor hash already exists", () => [save(token(B)), rotate(A, token(B, { previousTokenHash: A }), T0)]],
  ["the successor names another family", () => [rotate(A, token(B, { previousTokenHash: A, familyId: "fam-b" }), T0)]],
];

for (const [reason, steps] of NO_ROTATION) {
  test(`rotation returns no record when ${reason} and leaves the predecessor unconsumed`, async () => {
    const tables = await differential([save(token(A, { expiresAt: T2 })), ...steps(), find(A), find(B)]);
    const stored = projectLogicalState(tables, INSTANCE_ID).refresh_token[0];
    assert.deepStrictEqual([stored?.token_hash, stored?.consumed_at], [A, undefined]);
  });
}

test("a successor whose previous token hash is not the rotated hash is rejected", async () => {
  await differential([save(token(A)), rotate(A, token(B), T0), find(B)]);
});

test("the first revocation of a family wins and a resource mismatch changes nothing", async () => {
  const tables = await differential([
    save(token(A)), revoke(FAMILY, T0, OTHER_RESOURCE), revoke(FAMILY, T1, RESOURCE),
    revoke(FAMILY, T2), scopes(T0),
    revoke(FAMILY, "2026-09-01T10:00:00Z"), revoke(FAMILY, T2, "  "),
  ]);

  assert.deepStrictEqual(projectLogicalState(tables, INSTANCE_ID).revoked_family,
    [{ family_id: FAMILY, resource: RESOURCE, revoked_at: T1, grant_generation: 1 }]);
});

test("granted scopes cover only the active rows of the requested subject, client, generation and resource", async () => {
  await differential([
    save(token(A, { scopes: ["mcp:read", "mcp:profile"] })),
    save(token(B, { familyId: "family-b", expiresAt: T1, scopes: ["mcp:expired"] })),
    save(token(C, { familyId: "family-c", scopes: ["mcp:revoked"] })), revoke("family-c", T1),
    save(token(D, { familyId: "family-d", subject: "user-b", scopes: ["mcp:other-subject"] })),
    save(token(E, { familyId: "family-e", clientId: "client-b", scopes: ["mcp:other-client"] })),
    save(token(F, { familyId: "family-f", grantGeneration: null, scopes: ["mcp:legacy"] })),
    save(token(G, { familyId: "family-g", resource: OTHER_RESOURCE, scopes: ["mcp:other-resource"] })),
    save(token(H, { familyId: "family-h", scopes: ["mcp:consumed"] })),
    rotate(H, token(I, { familyId: "family-h", previousTokenHash: H, expiresAt: T1 }), T0),
    scopes(T2, 1, RESOURCE), scopes(T2), scopes(T2, undefined, undefined, "user-b"),
  ]);
});

test("granted scopes reject a malformed subject or timestamp", async () => {
  await differential([save(token(A)), scopes(T0, undefined, undefined, " user-a"), scopes("2026-09-01T09:00:00Z")]);
});

test("a legacy family with no generation rotates into a successor that stays legacy", async () => {
  await differential([
    save(token(A, { grantGeneration: null })),
    rotate(A, token(B, { previousTokenHash: A }), T0), find(B), scopes(T0), scopes(T0, 1),
  ]);
});

test("a sweep removes a family with no valid row and keeps one that still has a live row", async () => {
  const tables = await differential([
    save(token(A, { expiresAt: T1 })),
    save(token(B, { familyId: "family-b", expiresAt: T1 })),
    save(token(C, { familyId: "family-b", previousTokenHash: B, expiresAt: T3 })),
    sweep(T2), find(A), find(B), find(C),
  ]);

  const snapshot = projectLogicalState(tables, INSTANCE_ID);
  assert.deepStrictEqual(snapshot.refresh_token.map((row) => row.token_hash), [B, C]);
  assert.deepStrictEqual(snapshot.revoked_family, []);
});

test("a sweep at a row's exact expiry keeps its family", async () => {
  await differential([save(token(A, { expiresAt: T2 })), sweep(T2), find(A)]);
});

test("a sweep removes a revoked family once its rows are gone", async () => {
  const tables = await differential([
    save(token(A, { expiresAt: T1 })), revoke(FAMILY, T1), sweep(T2), find(A),
  ]);

  const snapshot = projectLogicalState(tables, INSTANCE_ID);
  assert.deepStrictEqual(snapshot.refresh_token, []);
  assert.deepStrictEqual(snapshot.revoked_family, []);
});
