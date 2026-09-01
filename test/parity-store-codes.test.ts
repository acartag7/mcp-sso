import assert from "node:assert/strict";
import test from "node:test";
import {
  StoreInputError, type AuthCodeRecord, type ConsentApprovalCommitResult, type SaveAuthCodeInput,
} from "../src/ports/store.ts";
import { createMemoryStore } from "../src/store/memory.ts";
import { hydrateLogicalState, projectLogicalState, type LogicalTables } from "./parity/logical-state.ts";
import {
  commitConsentApproval, consumeAuthCode, consumeConsentJti, saveAuthCode, sweepCodes, type SweepWatermark,
} from "./parity/store-codes.ts";
import type { AuthorizationCodeRow, LogicalState } from "./parity/types.ts";

const EARLIEST = "2026-09-01T10:00:00.000Z";
const EARLIER = "2026-09-01T11:00:00.000Z";
const NOW = "2026-09-01T12:00:00.000Z";
const LATER = "2026-09-01T13:00:00.000Z";
const NO_MS = "2026-09-01T12:00:00Z";
const RESOURCE = "https://api.example.com/mcp";
const OTHER_RESOURCE = "https://reports.example.com/mcp";
const REDIRECT_URI = "https://app.example.com/callback";
const FIXTURE_INSTANCE = "Kd9tR2wLxQ7pZm4Vb1Ns6A";
const FOREIGN_INSTANCE = "Zq8Xn3Cv6Bm1Kl9Rt2Wy4E";
const CODE_A = "a1".padEnd(64, "0");
const CODE_B = "b2".padEnd(64, "0");
const CODE_C = "c3".padEnd(64, "0");
const EMPTY: Required<LogicalState> = {
  authorization_code: [], consent_jti: [], refresh_token: [], revoked_family: [],
  client_registration: [], store_instance: [{ instance_id: FIXTURE_INSTANCE }],
};

/** One operation family of the store, so the reference and the runner can be driven by the same step. */
interface CodeStore {
  readonly instanceId: string;
  commit(instanceId: string, jti: string, expiresAtIso: string, input: SaveAuthCodeInput): Promise<ConsentApprovalCommitResult>;
  save(input: SaveAuthCodeInput): Promise<void>;
  consume(codeHash: string, nowIso: string, generation?: number, resource?: string): Promise<AuthCodeRecord | null>;
  useJti(jti: string, expiresAtIso: string): Promise<boolean>;
  sweep(nowIso: string): Promise<void>;
}

type Step = [name: string, run: (store: CodeStore) => Promise<unknown>];

function code(overrides: Partial<SaveAuthCodeInput> = {}): SaveAuthCodeInput {
  return {
    codeHash: CODE_A, clientId: "client-a", subject: "user-a", redirectUri: REDIRECT_URI,
    resource: RESOURCE, scopes: ["mcp:read"], codeChallenge: "challenge-a", codeChallengeMethod: "S256",
    expiresAt: LATER, ...overrides,
  };
}

function authRow(overrides: Partial<AuthorizationCodeRow> = {}): AuthorizationCodeRow {
  return {
    code_hash: CODE_A, client_id: "client-a", subject: "user-a", redirect_uri: REDIRECT_URI,
    resource: RESOURCE, scopes: ["mcp:read"], code_challenge: "challenge-a", code_challenge_method: "S256",
    expires_at: LATER, grant_generation: 1, ...overrides,
  };
}

/** A legacy row carries no generation at all: an absent key, never null. */
function legacyRow(overrides: Partial<AuthorizationCodeRow> = {}): AuthorizationCodeRow {
  const row = authRow(overrides);
  delete row.grant_generation;
  return row;
}

const project = (tables: LogicalTables): Required<LogicalState> => projectLogicalState(tables, FIXTURE_INSTANCE);

function fixtureStore(): CodeStore {
  const tables = hydrateLogicalState({});
  const watermark: SweepWatermark = { sweptThrough: undefined };
  return {
    instanceId: FIXTURE_INSTANCE,
    commit: async (id, jti, expiry, input) =>
      commitConsentApproval(tables, watermark, FIXTURE_INSTANCE, id, jti, expiry, input),
    save: async (input) => { saveAuthCode(tables, input); },
    consume: async (hash, now, generation, resource) => consumeAuthCode(tables, hash, now, generation, resource),
    useJti: async (jti, expiry) => consumeConsentJti(tables, watermark, jti, expiry),
    sweep: async (now) => { sweepCodes(tables, watermark, now); },
  };
}

/** Runs every step against a fresh reference store and a fresh runner table set, failing on the first difference. */
async function differential(steps: Step[]): Promise<void> {
  const store = createMemoryStore();
  try {
    const reference: CodeStore = {
      instanceId: await store.getStoreInstanceId(),
      commit: store.commitConsentApproval.bind(store), save: store.saveAuthCode.bind(store),
      consume: store.consumeAuthCode.bind(store), useJti: store.consumeConsentJti.bind(store), sweep: store.sweepExpired.bind(store),
    };
    const runner = fixtureStore();
    for (const [name, run] of steps) {
      assert.deepStrictEqual(await outcome(() => run(runner)), await outcome(() => run(reference)), name);
    }
  } finally { await store.close(); }
}

async function outcome(run: () => Promise<unknown>): Promise<unknown> {
  try { return { returned: await run() }; }
  catch (error) {
    const failure = error as StoreInputError;
    return { thrown: failure.constructor.name, code: failure.code, message: failure.message };
  }
}

test("a consent approval stores once and refuses a replay, a foreign binding, and a swept expiry", async () => {
  await differential([
    ["a first approval stores the code", (s) => s.commit(s.instanceId, "jti-a", LATER, code())],
    ["a reused jti is replayed", (s) => s.commit(s.instanceId, "jti-a", LATER, code({ codeHash: CODE_B }))],
    ["the replayed approval stored no code", (s) => s.consume(CODE_B, NOW)],
    ["a foreign instance is a binding mismatch", (s) => s.commit(FOREIGN_INSTANCE, "jti-b", LATER, code({ codeHash: CODE_C }))],
    ["the mismatched approval stored no code", (s) => s.consume(CODE_C, NOW)],
    ["the mismatched approval consumed no jti", (s) => s.useJti("jti-b", LATER)],
    ["the approved code is consumable", (s) => s.consume(CODE_A, NOW)],
    ["the sweep raises the replay watermark", (s) => s.sweep(NOW)],
    ["an approval expiring before the sweep is replayed", (s) => s.commit(s.instanceId, "jti-c", EARLIER, code({ codeHash: CODE_C }))],
    ["the swept approval stored no code", (s) => s.consume(CODE_C, NOW)],
  ]);
});

const INVALID_APPROVALS: Step[] = [
  ["a store instance id that is not 22 to 128 base64url characters", (s) => s.commit("short", "jti-x", LATER, code())],
  ["a consent expiry without exactly three millisecond digits", (s) => s.commit(s.instanceId, "jti-x", NO_MS, code())],
  ["a subject with leading whitespace", (s) => s.commit(s.instanceId, "jti-x", LATER, code({ subject: " user-a" }))],
  ["a code hash that is not a sha-256 digest", (s) => s.commit(s.instanceId, "jti-x", LATER, code({ codeHash: "not-a-digest" }))],
  ["a code challenge method other than S256", (s) => s.commit(s.instanceId, "jti-x", LATER, code({ codeChallengeMethod: "plain" as "S256" }))],
  ["a grant generation that is not a positive integer", (s) => s.commit(s.instanceId, "jti-x", LATER, code({ grantGeneration: 0 }))],
];

for (const step of INVALID_APPROVALS) {
  test(`an approval carrying ${step[0]} is rejected before any write`, async () => {
    await differential([
      step,
      ["the rejected approval consumed no jti", (s) => s.useJti("jti-x", LATER)],
      ["the rejected approval stored no code", (s) => s.consume(CODE_A, NOW)],
    ]);
  });
}

test("a saved authorization code is consumable exactly once", async () => {
  await differential([
    ["saving a code returns nothing", (s) => s.save(code())],
    ["consuming returns the record with the stored-DCR generation", (s) => s.consume(CODE_A, NOW)],
    ["a second consume of the same hash is null", (s) => s.consume(CODE_A, NOW)],
    ["a hash that was never saved is null", (s) => s.consume(CODE_B, NOW)],
    ["saving with an explicit null generation returns nothing", (s) => s.save(code({ grantGeneration: null }))],
    ["the legacy record keeps its null generation", (s) => s.consume(CODE_A, NOW)],
  ]);
});

test("a failed expectation consumes the code, except a resource mismatch that leaves it stored", async () => {
  await differential([
    ["saving a code returns nothing", (s) => s.save(code())],
    ["a resource mismatch is null", (s) => s.consume(CODE_A, NOW, undefined, OTHER_RESOURCE)],
    ["the mismatched code is still stored", (s) => s.consume(CODE_A, NOW, undefined, RESOURCE)],
    ["saving a second code returns nothing", (s) => s.save(code({ codeHash: CODE_B }))],
    ["a grant generation mismatch is null", (s) => s.consume(CODE_B, NOW, 7)],
    ["the generation-mismatched code was consumed", (s) => s.consume(CODE_B, NOW)],
    ["saving an already expired code returns nothing", (s) => s.save(code({ codeHash: CODE_C, expiresAt: EARLIER }))],
    ["an expired code is null", (s) => s.consume(CODE_C, NOW)],
    ["the expired code was consumed", (s) => s.consume(CODE_C, NOW)],
  ]);
});

test("a consent jti is usable once, and the watermark keeps a swept jti unusable", async () => {
  await differential([
    ["a first use is accepted", (s) => s.useJti("jti-a", LATER)],
    ["a reuse is refused", (s) => s.useJti("jti-a", LATER)],
    ["the sweep raises the replay watermark", (s) => s.sweep(NOW)],
    ["a jti that expired before the sweep is refused", (s) => s.useJti("jti-old", EARLIER)],
    ["a jti that expires after the sweep is accepted", (s) => s.useJti("jti-new", LATER)],
    ["a sweep at an earlier instant does not lower the watermark", (s) => s.sweep(EARLIEST)],
    ["the jti that expired before the sweep is still refused", (s) => s.useJti("jti-old", EARLIER)],
    ["a jti expiry without three millisecond digits is rejected", (s) => s.useJti("jti-y", NO_MS)],
    ["a consume of a hash that is not a sha-256 digest is rejected", (s) => s.consume("not-a-digest", NOW)],
    ["a consume whose now has no millisecond digits is rejected", (s) => s.consume(CODE_A, NO_MS)],
    ["a sweep whose now has no millisecond digits is rejected", (s) => s.sweep(NO_MS)],
  ]);
});

const MALFORMED_SUBJECTS: Array<[string, string]> = [
  ["leading whitespace", " user-a"],
  ["more than 384 scalars", "u".repeat(385)],
];

for (const [label, subject] of MALFORMED_SUBJECTS) {
  test(`a stored subject with ${label} fails closed and leaves its code in the table`, () => {
    const tables = hydrateLogicalState({ authorization_code: [legacyRow({ subject })] });
    const watermark: SweepWatermark = { sweptThrough: undefined };
    const before = project(tables);
    assert.throws(() => consumeAuthCode(tables, CODE_A, NOW),
      (error: unknown) => error instanceof StoreInputError && error.message === "stored subject is malformed");
    // The resource mismatch is decided first, so it declines the record without reading a subject it has no claim on.
    assert.strictEqual(consumeAuthCode(tables, CODE_A, NOW, undefined, OTHER_RESOURCE), null);
    assert.throws(() => saveAuthCode(tables, code({ codeHash: CODE_B, subject })),
      (error: unknown) => error instanceof StoreInputError && error.message === "subject is malformed");
    assert.throws(() => commitConsentApproval(tables, watermark, FIXTURE_INSTANCE, FIXTURE_INSTANCE,
      "jti-a", LATER, code({ codeHash: CODE_B, subject })), StoreInputError);

    assert.deepStrictEqual(project(tables), before);
    assert.strictEqual(watermark.sweptThrough, undefined);
  });
}

test("each code mutation projects exactly the rows it left behind", () => {
  const tables = hydrateLogicalState({});
  const watermark: SweepWatermark = { sweptThrough: undefined };
  const shows = (expected: Partial<Required<LogicalState>>): void =>
    assert.deepStrictEqual(project(tables), { ...EMPTY, ...expected });

  assert.strictEqual(commitConsentApproval(tables, watermark, FIXTURE_INSTANCE, FIXTURE_INSTANCE,
    "jti-a", EARLIER, code()), "stored");
  shows({ authorization_code: [authRow()], consent_jti: [{ jti: "jti-a", expires_at: EARLIER }] });

  saveAuthCode(tables, code({ codeHash: CODE_B, grantGeneration: null }));
  saveAuthCode(tables, code({ codeHash: CODE_C, expiresAt: EARLIER }));
  assert.strictEqual(consumeConsentJti(tables, watermark, "jti-b", LATER), true);
  shows({
    authorization_code: [authRow(), legacyRow({ code_hash: CODE_B }), authRow({ code_hash: CODE_C, expires_at: EARLIER })],
    consent_jti: [{ jti: "jti-a", expires_at: EARLIER }, { jti: "jti-b", expires_at: LATER }],
  });

  sweepCodes(tables, watermark, NOW);
  shows({
    authorization_code: [authRow(), legacyRow({ code_hash: CODE_B })],
    consent_jti: [{ jti: "jti-b", expires_at: LATER }],
    store_instance: [{ instance_id: FIXTURE_INSTANCE, swept_through: NOW }],
  });

  assert.deepStrictEqual(consumeAuthCode(tables, CODE_A, NOW), { ...code(), grantGeneration: 1 });
  shows({
    authorization_code: [legacyRow({ code_hash: CODE_B })],
    consent_jti: [{ jti: "jti-b", expires_at: LATER }],
    store_instance: [{ instance_id: FIXTURE_INSTANCE, swept_through: NOW }],
  });
});

test("a sweep writes its watermark into the projected store_instance row", () => {
  const tables = hydrateLogicalState({});
  const watermark: SweepWatermark = { sweptThrough: undefined };
  assert.deepStrictEqual(project(tables).store_instance, [{ instance_id: FIXTURE_INSTANCE }]);

  sweepCodes(tables, watermark, NOW);
  assert.strictEqual(watermark.sweptThrough, NOW);
  assert.deepStrictEqual(project(tables).store_instance,
    [{ instance_id: FIXTURE_INSTANCE, swept_through: NOW }]);

  const rehydrated = hydrateLogicalState({ store_instance: [{ instance_id: FIXTURE_INSTANCE, swept_through: NOW }] });
  assert.strictEqual(consumeConsentJti(rehydrated, { sweptThrough: undefined }, "jti-swept", EARLIER), true,
    "a member that rehydrates without the fence resurrects a swept jti");
  assert.strictEqual(consumeConsentJti(rehydrated, { sweptThrough: NOW }, "jti-swept", EARLIER), false,
    "seeding the fence from the hydrated row keeps the sweep binding");
});

test("a stored code is detached from its input and a consumed record from its row", () => {
  const tables = hydrateLogicalState({});
  const input = code();
  saveAuthCode(tables, input);
  input.scopes.push("mcp:write");
  input.subject = "user-b";
  assert.deepStrictEqual(project(tables).authorization_code, [authRow()]);

  const row = tables.authCodes.get(CODE_A);
  assert.ok(row !== undefined);
  const stored = structuredClone(row);
  const consumed = consumeAuthCode(tables, CODE_A, NOW);
  assert.deepStrictEqual(consumed, stored);
  assert.ok(consumed !== null);
  consumed.scopes.push("mcp:admin");
  consumed.subject = "user-b";
  assert.deepStrictEqual(row, stored);
});
