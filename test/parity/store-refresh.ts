// Refresh-token family operations of the parity runner's fixture store, as pure
// functions over the hydrated logical tables. The reference implementation is
// `MemoryStore` in `src/store/memory.ts`: every guard, the order it runs in, and
// every early return mirror that store, so a fixture exercises the same
// semantics the shipped stores are held to by the store-conformance suite.

import type { RefreshTokenRecord, SaveRefreshTokenInput } from "../../src/ports/store.ts";
import {
  StoreInputError, UNBOUND_REFRESH_RESOURCE, assertGrantGeneration, assertRefreshResource,
  assertSha256Hex, assertStoreSubject, assertUtcIsoTimestamp, grantGenerationForWrite,
  normalizeRefreshTokenWrite,
} from "../../src/ports/store.ts";
import type { LogicalTables, StoredRefresh } from "./logical-state.ts";

/** Store a new refresh token, creating its family on first use. An existing
 *  family keeps its own resource and generation, so a write that disagrees with
 *  either is rejected rather than widening what the family already binds. */
export function saveRefreshToken(tables: LogicalTables, input: SaveRefreshTokenInput): void {
  const write = normalizeRefreshTokenWrite(input);
  validateRefreshToken(write);
  if (tables.refreshTokens.has(write.tokenHash)) throw new StoreInputError("tokenHash already exists");
  const grantGeneration = grantGenerationForWrite(write.grantGeneration);
  const family = tables.families.get(write.familyId);
  if (family && (family.grantGeneration !== grantGeneration || family.resource !== write.resource)) {
    throw new StoreInputError("family grantGeneration or resource mismatch");
  }
  if (!family) tables.families.set(write.familyId, { resource: write.resource, grantGeneration });
  tables.refreshTokens.set(write.tokenHash, storedRow(write, grantGeneration));
}

/** Consume `tokenHash` and store its successor, or return null when the family
 *  cannot rotate. Replay of an already consumed token revokes the whole family,
 *  and that branch runs before the predecessor's own expiry is examined, so a
 *  replayed token kills a successor that is still live. */
export function rotateRefreshToken(
  tables: LogicalTables,
  tokenHash: string,
  next: SaveRefreshTokenInput,
  nowIso: string,
  expectedGrantGeneration?: number,
  expectedResource?: string,
): RefreshTokenRecord | null {
  const successor = normalizeRefreshTokenWrite(next);
  validateRotation(tokenHash, successor, nowIso);
  const current = tables.refreshTokens.get(tokenHash) ?? null;
  const family = current ? tables.families.get(current.familyId) : undefined;
  if (!current || !family) return null;
  assertStoreSubject(current.subject, "stored subject");
  if (family.revokedAt !== undefined
    || (expectedGrantGeneration !== undefined
      && (family.grantGeneration !== expectedGrantGeneration
        || current.grantGeneration !== expectedGrantGeneration))) return null;
  const resource = current.resource;
  if (resource === null || resource === UNBOUND_REFRESH_RESOURCE || family.resource !== resource
    || (expectedResource !== undefined && resource !== expectedResource)) return null;
  if (current.consumedAt !== undefined) {
    revokeRefreshTokenFamily(tables, current.familyId, nowIso);
    return null;
  }
  if (current.expiresAt <= nowIso || successor.familyId !== current.familyId) return null;
  // A successor-hash collision returns null WITHOUT consuming the predecessor.
  if (tables.refreshTokens.has(successor.tokenHash)) return null;
  current.consumedAt = nowIso;
  saveRefreshToken(tables, {
    ...successor, clientId: current.clientId, subject: current.subject,
    resource, scopes: current.scopes, grantGeneration: current.grantGeneration,
  });
  return refreshRecord(current);
}

/** Revoke a family once. The first revocation wins, and a supplied
 *  `expectedResource` mutates only a family bound to that exact resource. */
export function revokeRefreshTokenFamily(
  tables: LogicalTables, familyId: string, revokedAtIso: string, expectedResource?: string,
): void {
  assertUtcIsoTimestamp(revokedAtIso, "revokedAtIso");
  if (expectedResource !== undefined) assertRefreshResource(expectedResource, "expectedResource");
  const family = tables.families.get(familyId);
  if (family && family.revokedAt === undefined
    && (expectedResource === undefined || family.resource === expectedResource)) {
    family.revokedAt = revokedAtIso;
  }
}

/** Read one refresh token. The stored subject is authoritative input and is
 *  admitted before the row is handed out. */
export function findRefreshToken(tables: LogicalTables, tokenHash: string): RefreshTokenRecord | null {
  const stored = tables.refreshTokens.get(tokenHash);
  if (!stored) return null;
  assertStoreSubject(stored.subject, "stored subject");
  return refreshRecord(stored);
}

/** Union of the scopes on this subject and client's active refresh rows. Rows
 *  are read in token-hash order so an unordered logical record array derives the
 *  same union whatever order its rows were written in. */
export function findGrantedScopes(
  tables: LogicalTables,
  subject: string,
  clientId: string,
  nowIso: string,
  expectedGrantGeneration?: number,
  expectedResource?: string,
): string[] {
  assertStoreSubject(subject);
  assertUtcIsoTimestamp(nowIso, "nowIso");
  const granted: string[] = [];
  for (const row of sortedRows(tables)) {
    const family = tables.families.get(row.familyId);
    if (row.subject === subject && row.clientId === clientId && row.consumedAt === undefined
      && row.expiresAt > nowIso && family !== undefined && family.revokedAt === undefined
      && (expectedGrantGeneration === undefined || row.grantGeneration === expectedGrantGeneration)
      && (expectedResource === undefined
        || (row.resource === expectedResource && family.resource === expectedResource))) {
      for (const scope of row.scopes) if (!granted.includes(scope)) granted.push(scope);
    }
  }
  return granted;
}

/** Drop every refresh row whose family has no member valid at `nowIso`, then
 *  every family no remaining row references. A consumed predecessor survives
 *  while its successor is live, which is what keeps the replay signal readable. */
export function sweepRefresh(tables: LogicalTables, nowIso: string): void {
  assertUtcIsoTimestamp(nowIso, "nowIso");
  const rows = [...tables.refreshTokens.values()];
  for (const [tokenHash, row] of tables.refreshTokens) {
    const familyValid = rows.some((member) => member.familyId === row.familyId && member.expiresAt >= nowIso);
    if (!familyValid) tables.refreshTokens.delete(tokenHash);
  }
  const referenced = new Set([...tables.refreshTokens.values()].map((row) => row.familyId));
  for (const familyId of [...tables.families.keys()]) {
    if (!referenced.has(familyId)) tables.families.delete(familyId);
  }
}

function sortedRows(tables: LogicalTables): StoredRefresh[] {
  return [...tables.refreshTokens.values()].toSorted((left, right) => {
    if (left.tokenHash < right.tokenHash) return -1;
    return left.tokenHash > right.tokenHash ? 1 : 0;
  });
}

/** Stored rows own their scope array so a caller keeps no handle into the store. */
function storedRow(write: SaveRefreshTokenInput, grantGeneration: number | null): StoredRefresh {
  return {
    tokenHash: write.tokenHash, familyId: write.familyId, previousTokenHash: write.previousTokenHash,
    clientId: write.clientId, subject: write.subject, resource: write.resource,
    scopes: [...write.scopes], expiresAt: write.expiresAt, grantGeneration,
  };
}

/** `consumedAt` is store-internal state and never leaves the store. */
function refreshRecord(stored: StoredRefresh): RefreshTokenRecord {
  return {
    tokenHash: stored.tokenHash, familyId: stored.familyId, previousTokenHash: stored.previousTokenHash,
    clientId: stored.clientId, subject: stored.subject, resource: stored.resource,
    scopes: [...stored.scopes], expiresAt: stored.expiresAt, grantGeneration: stored.grantGeneration,
  };
}

function validateRefreshToken(input: SaveRefreshTokenInput, validateSubject = true): void {
  if (validateSubject) assertStoreSubject(input.subject);
  assertSha256Hex(input.tokenHash, "tokenHash");
  if (input.previousTokenHash !== null) assertSha256Hex(input.previousTokenHash, "previousTokenHash");
  assertRefreshResource(input.resource, "resource");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
  assertGrantGeneration(input.grantGeneration, "grantGeneration");
}

function validateRotation(tokenHash: string, next: SaveRefreshTokenInput, nowIso: string): void {
  assertSha256Hex(tokenHash, "tokenHash");
  validateRefreshToken(next, false);
  assertUtcIsoTimestamp(nowIso, "nowIso");
  if (next.previousTokenHash !== tokenHash) throw new StoreInputError("next.previousTokenHash must match tokenHash");
}
