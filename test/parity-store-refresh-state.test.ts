import assert from "node:assert/strict";
import test from "node:test";
import type { SaveRefreshTokenInput } from "../src/ports/store.ts";
import { StoreInputError } from "../src/ports/store.ts";
import { INVALID_IDENTITY_SUBJECTS } from "./lib/identity-subject-cases.ts";
import { hydrateLogicalState, projectLogicalState } from "./parity/logical-state.ts";
import {
  findGrantedScopes, findRefreshToken, rotateRefreshToken, saveRefreshToken, sweepRefresh,
} from "./parity/store-refresh.ts";
import type { RefreshTokenRow } from "./parity/types.ts";

const RESOURCE = "https://api.example.com/mcp";
const INSTANCE_ID = "Kd9tR2wLxQ7pZm4Vb1Ns6A", SUBJECT = "user-a", CLIENT_ID = "client-a", FAMILY = "family-a";
const T0 = "2026-09-01T09:00:00.000Z", T1 = "2026-09-01T10:00:00.000Z", T3 = "2026-09-01T12:00:00.000Z";
const A = "1a".padEnd(64, "0"), B = "2b".padEnd(64, "0");

function row(tokenHash: string, overrides: Partial<RefreshTokenRow> = {}): RefreshTokenRow {
  return {
    token_hash: tokenHash, family_id: FAMILY, client_id: CLIENT_ID, subject: SUBJECT,
    resource: RESOURCE, scopes: ["mcp:read"], expires_at: T3, grant_generation: 1, ...overrides,
  };
}

function successor(previousTokenHash: string): SaveRefreshTokenInput {
  return {
    tokenHash: B, familyId: FAMILY, previousTokenHash, clientId: CLIENT_ID, subject: SUBJECT,
    resource: RESOURCE, scopes: ["mcp:read"], expiresAt: T3,
  };
}

function malformedSubject(error: unknown): boolean {
  return error instanceof StoreInputError && error.message === "stored subject is malformed";
}

test("a malformed stored subject is refused by rotation and by a token read, and nothing changes", () => {
  for (const subject of INVALID_IDENTITY_SUBJECTS) {
    const tables = hydrateLogicalState({ refresh_token: [row(A, { subject })] });
    const before = projectLogicalState(tables, INSTANCE_ID);

    assert.throws(() => rotateRefreshToken(tables, A, successor(A), T0), malformedSubject);
    assert.throws(() => findRefreshToken(tables, A), malformedSubject);
    assert.deepStrictEqual(projectLogicalState(tables, INSTANCE_ID), before);
  }
});

test("replaying a consumed token with a malformed stored subject does not revoke its family", () => {
  for (const subject of INVALID_IDENTITY_SUBJECTS) {
    const tables = hydrateLogicalState({
      refresh_token: [row(A, { subject, consumed_at: T0 }), row(B, { subject, previous_token_hash: A })],
    });

    assert.throws(() => rotateRefreshToken(tables, A, successor(A), T1), malformedSubject);
    assert.equal(tables.families.get(FAMILY)?.revokedAt, undefined);
    assert.deepStrictEqual(projectLogicalState(tables, INSTANCE_ID).revoked_family, []);
  }
});

test("the derived scope union does not depend on the order of the pre-state refresh rows", () => {
  const first = row(A, { scopes: ["mcp:read"] });
  const second = row(B, { family_id: "family-b", scopes: ["mcp:write"] });
  const forward = hydrateLogicalState({ refresh_token: [first, second] });
  const reversed = hydrateLogicalState({ refresh_token: [second, first] });

  assert.deepStrictEqual(findGrantedScopes(forward, SUBJECT, CLIENT_ID, T0), ["mcp:read", "mcp:write"]);
  assert.deepStrictEqual(findGrantedScopes(reversed, SUBJECT, CLIENT_ID, T0),
    findGrantedScopes(forward, SUBJECT, CLIENT_ID, T0));
});

test("a token from a pre-state rotates into a successor the projection can hold", () => {
  const tables = hydrateLogicalState({ refresh_token: [row(A)] });

  assert.deepStrictEqual(rotateRefreshToken(tables, A, successor(A), T0), {
    tokenHash: A, familyId: FAMILY, previousTokenHash: null, clientId: CLIENT_ID, subject: SUBJECT,
    resource: RESOURCE, scopes: ["mcp:read"], expiresAt: T3, grantGeneration: 1,
  });
  assert.deepStrictEqual(projectLogicalState(tables, INSTANCE_ID).refresh_token
    .map((stored) => [stored.token_hash, stored.consumed_at]), [[A, T0], [B, undefined]]);
});

test("a sweep removes a revoked family that a pre-state declared with no refresh rows", () => {
  const tables = hydrateLogicalState({
    revoked_family: [{ family_id: FAMILY, resource: RESOURCE, revoked_at: T0, grant_generation: 1 }],
  });

  sweepRefresh(tables, T1);
  assert.deepStrictEqual(projectLogicalState(tables, INSTANCE_ID).revoked_family, []);
});

test("a returned record carries no store state and mutating it cannot reach the tables", () => {
  const tables = hydrateLogicalState({ refresh_token: [row(A, { consumed_at: T0 })] });
  const found = findRefreshToken(tables, A);
  assert.ok(found);

  assert.equal(Object.hasOwn(found, "consumedAt"), false);
  found.scopes.push("mcp:admin");
  found.clientId = "client-other";
  assert.deepStrictEqual(tables.refreshTokens.get(A)?.scopes, ["mcp:read"]);
  assert.equal(tables.refreshTokens.get(A)?.clientId, CLIENT_ID);
});

test("a saved row copies its scopes so a later caller mutation cannot reach the tables", () => {
  const tables = hydrateLogicalState({});
  const scopes = ["mcp:read"];
  saveRefreshToken(tables, {
    tokenHash: A, familyId: FAMILY, previousTokenHash: null, clientId: CLIENT_ID,
    subject: SUBJECT, resource: RESOURCE, scopes, expiresAt: T3,
  });

  scopes.push("mcp:admin");
  assert.deepStrictEqual(tables.refreshTokens.get(A)?.scopes, ["mcp:read"]);
});
