// MemoryStore-private rotation check: the shared store-conformance suite owns
// the public detachment cells (write, read, rotation independence) for every
// adapter. This file pins only what needs MemoryStore internals: after
// rotation the predecessor and successor stored rows hold independent scopes
// arrays, which is invisible through the public API once every read returns a
// copy.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { SaveAuthCodeInput, SaveRefreshTokenInput } from "../src/ports/store.ts";
import { MemoryStore } from "../src/store/memory.ts";

const CLIENT = "client-1";
const SUBJECT = "user-1";
const FAMILY = "family-1";
const PRED_HASH = "a".repeat(64);
const SUCC_HASH = "b".repeat(64);
const CODE_HASH = "c".repeat(64);
const JTI = "jti-1";
const NOW = "2026-01-01T00:00:00.000Z";
const EXPIRES_AT = "2027-01-01T00:00:00.000Z";
const RESOURCE = "https://api.example.com/mcp";

function refreshInput(overrides: Partial<SaveRefreshTokenInput> = {}): SaveRefreshTokenInput {
  return {
    tokenHash: PRED_HASH, familyId: FAMILY, previousTokenHash: null, clientId: CLIENT, subject: SUBJECT,
    resource: RESOURCE, scopes: ["mcp:read"], expiresAt: EXPIRES_AT, ...overrides,
  };
}

function authCodeInput(overrides: Partial<SaveAuthCodeInput> = {}): SaveAuthCodeInput {
  return {
    codeHash: CODE_HASH, clientId: CLIENT, subject: SUBJECT, redirectUri: "https://app.example.com/callback",
    resource: RESOURCE, scopes: ["mcp:read"], codeChallenge: "challenge", codeChallengeMethod: "S256",
    expiresAt: EXPIRES_AT, ...overrides,
  };
}

function storedRefreshRows(store: MemoryStore): Map<string, { scopes: string[] }> {
  return (store as unknown as { refreshTokens: Map<string, { scopes: string[] }> }).refreshTokens;
}





test("after rotation the predecessor and successor rows own independent scopes", async () => {
  const store = new MemoryStore();
  await store.saveRefreshToken(refreshInput({ scopes: ["mcp:read"] }));
  const predecessor = await store.rotateRefreshToken(
    PRED_HASH, refreshInput({ tokenHash: SUCC_HASH, previousTokenHash: PRED_HASH, scopes: ["ignored"] }), NOW,
  );
  assert.ok(predecessor);
  predecessor.scopes.push("mcp:write");
  const successor = await store.findRefreshToken(SUCC_HASH);
  assert.ok(successor);
  assert.deepEqual(successor.scopes, ["mcp:read"], "successor inherits the predecessor's granted scopes");
  successor.scopes.push("mcp:admin");
  const rows = storedRefreshRows(store);
  assert.notEqual(rows.get(PRED_HASH)?.scopes, rows.get(SUCC_HASH)?.scopes, "stored rows must not share one array");
  const storedPredecessor = await store.findRefreshToken(PRED_HASH);
  assert.deepEqual(storedPredecessor?.scopes, ["mcp:read"]);
  await store.close();
});

test("findGrantedScopes returns a fresh array the caller cannot corrupt the store through", async () => {
  const store = new MemoryStore();
  await store.saveRefreshToken(refreshInput({ scopes: ["mcp:read", "mcp:write"] }));
  const granted = await store.findGrantedScopes(SUBJECT, CLIENT, NOW);
  assert.deepEqual(granted, ["mcp:read", "mcp:write"]);
  granted.push("mcp:admin");
  assert.deepEqual(await store.findGrantedScopes(SUBJECT, CLIENT, NOW), ["mcp:read", "mcp:write"]);
  await store.close();
});

test("an untouched store round-trips scopes exactly", async () => {
  const store = new MemoryStore();
  const scopes = ["mcp:read", "mcp:write", "mcp:admin"];
  await store.saveRefreshToken(refreshInput({ scopes }));
  const found = await store.findRefreshToken(PRED_HASH);
  assert.deepEqual(found?.scopes, scopes);
  assert.deepEqual(await store.findGrantedScopes(SUBJECT, CLIENT, NOW), scopes);
  await store.saveAuthCode(authCodeInput({ scopes }));
  const consumed = await store.consumeAuthCode(CODE_HASH, NOW);
  assert.deepEqual(consumed?.scopes, scopes);
  await store.close();
});


// Hostile-iterator atomicity (hosted review): validation never touches scopes,
// so a scopes iterable that throws reaches exactly the copy at the
// materialization site. If that copy moves below the map writes, the write
// burns the JTI or creates the family while the row itself never lands. These
// two regressions pin the copy-before-mutate order through the public retry
// behavior and the stored maps.

function throwingScopes(yieldCount: number): string[] {
  let yielded = 0;
  return {
    [Symbol.iterator]: (): Iterator<string> => ({
      next: () => yielded++ < yieldCount
        ? { value: "mcp:read", done: false }
        : (() => { throw new Error("hostile iterator"); })(),
    }),
  } as unknown as string[];
}

function internalMaps(store: MemoryStore): {
  consentJtis: Map<string, string>;
  authCodes: Map<string, unknown>;
  families: Map<string, unknown>;
  refreshTokens: Map<string, unknown>;
} {
  return store as unknown as {
    consentJtis: Map<string, string>;
    authCodes: Map<string, unknown>;
    families: Map<string, unknown>;
    refreshTokens: Map<string, unknown>;
  };
}

test("a throwing scopes iterator during consent commit burns nothing", async () => {
  const store = new MemoryStore();
  const instanceId = await store.getStoreInstanceId();
  await assert.rejects(store.commitConsentApproval(
    instanceId, JTI, EXPIRES_AT, authCodeInput({ scopes: throwingScopes(1) }),
  ), /hostile iterator/);
  const maps = internalMaps(store);
  assert.equal(maps.consentJtis.size, 0, "the consent JTI must not be recorded");
  assert.equal(maps.authCodes.size, 0, "the auth code must not be stored");
  // The public proof: the same JTI is still consumable, so a retry is not
  // rejected as a replay of a commit that never landed.
  assert.equal(
    await store.commitConsentApproval(instanceId, JTI, EXPIRES_AT, authCodeInput({ scopes: ["mcp:read"] })),
    "stored",
  );
});

test("a throwing scopes iterator during refresh save creates no family row", async () => {
  const store = new MemoryStore();
  await assert.rejects(store.saveRefreshToken(refreshInput({ scopes: throwingScopes(1) })), /hostile iterator/);
  const maps = internalMaps(store);
  assert.equal(maps.families.size, 0, "the family must not be created");
  assert.equal(maps.refreshTokens.size, 0, "the token row must not exist");
  // The public proof: the same familyId may still be saved under a different
  // resource. A prematurely created family row would reject this as a
  // resource mismatch instead of accepting it.
  await store.saveRefreshToken(refreshInput({ resource: "https://other.example.com/mcp", scopes: ["mcp:read"] }));
});

// Reentrancy (hosted review round two): a reentrant iterable does not throw;
// its iterator calls back into the store mid-iteration. The materialization
// must therefore run BEFORE the guards, so no caller-controlled code executes
// between a state check and its write. These regressions pin both orderings.

function reentrantScopes(afterYields: number, callback: () => void): string[] {
  let yielded = 0;
  let fired = false;
  return {
    [Symbol.iterator]: (): Iterator<string> => ({
      next: () => {
        if (!fired && yielded === afterYields) { fired = true; callback(); }
        return yielded++ < 2 ? { value: "mcp:read", done: false } : { done: true } as IteratorResult<string>;
      },
    }),
  } as unknown as string[];
}

test("a reentrant consent commit stores exactly one code for one JTI", async () => {
  const store = new MemoryStore();
  const instanceId = await store.getStoreInstanceId();
  const nested: string[] = [];
  const outer = await store.commitConsentApproval(instanceId, JTI, EXPIRES_AT, authCodeInput({
    scopes: reentrantScopes(1, () => {
      void (async () => {
        nested.push(await store.commitConsentApproval(instanceId, JTI, EXPIRES_AT, authCodeInput({ codeHash: "d".repeat(64), scopes: ["mcp:read"] })));
      })();
    }),
  }));
  const maps = internalMaps(store);
  assert.deepEqual([outer, ...nested].sort(), ["replayed", "stored"],
    "exactly one commit stores; the loser sees replayed, never both stored");
  assert.equal(maps.authCodes.size, 1, "one consent JTI stores one authorization code");
});

test("a reentrant refresh save cannot split a family's resource binding", async () => {
  const store = new MemoryStore();
  const OTHER_RESOURCE = "https://other.example.com/mcp";
  await assert.rejects(store.saveRefreshToken(refreshInput({
    scopes: reentrantScopes(1, () => { void store.saveRefreshToken(refreshInput({ tokenHash: "e".repeat(64), resource: OTHER_RESOURCE })); }),
  })), /family grantGeneration or resource mismatch/);
  const maps = internalMaps(store);
  assert.equal(maps.refreshTokens.size, 1, "only the nested token is stored");
  const rows = (store as unknown as { refreshTokens: Map<string, { resource: string }> }).refreshTokens;
  const families = (store as unknown as { families: Map<string, { resource: string }> }).families;
  const stored = [...rows.values()][0];
  assert.ok(stored, "one row is stored");
  assert.equal(families.get(FAMILY)?.resource, stored.resource,
    "the family binding matches the one stored row, never a stale write");
});
