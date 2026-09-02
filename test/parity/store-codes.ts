// Authorization-code and consent-JTI operations of the fixture store, as pure
// functions over the logical tables. The reference is MemoryStore: every check
// runs in the same order, so the runner and the reference store reach the same
// state and the same rejection from the same input.

import type {
  AuthCodeRecord, ConsentApprovalCommitResult, SaveAuthCodeInput,
} from "../../src/ports/store.ts";
import {
  StoreInputError, assertGrantGeneration, assertSha256Hex, assertStoreInstanceId,
  assertStoreSubject, assertUtcIsoTimestamp, grantGenerationForWrite,
} from "../../src/ports/store.ts";
import type { LogicalTables } from "./logical-state.ts";

/** How far the expiry sweep has collected. A consent JTI that expired before
 *  this point is refused even though the sweep deleted its row, so the replay
 *  signal outlives the row. `undefined` means nothing has been swept yet. */
export interface SweepWatermark {
  sweptThrough: string | undefined;
}

/** Validate the store binding, consume the consent JTI, and save the code as one
 *  step. Every rejection returns or throws before the first write. */
export function commitConsentApproval(
  tables: LogicalTables,
  watermark: SweepWatermark,
  currentInstanceId: string,
  expectedStoreInstanceId: string,
  jti: string,
  expiresAtIso: string,
  authCode: SaveAuthCodeInput,
): ConsentApprovalCommitResult {
  assertStoreInstanceId(expectedStoreInstanceId);
  assertUtcIsoTimestamp(expiresAtIso, "expiresAtIso");
  validateAuthCode(authCode);
  if (expectedStoreInstanceId !== currentInstanceId) return "binding_mismatch";
  if (isReplayed(tables, watermark, jti, expiresAtIso)) return "replayed";
  tables.consentJtis.set(jti, expiresAtIso);
  storeAuthCode(tables, authCode);
  return "stored";
}

export function saveAuthCode(tables: LogicalTables, input: SaveAuthCodeInput): void {
  validateAuthCode(input);
  storeAuthCode(tables, input);
}

/** Single use: the row is removed on read. A record that fails the caller's
 *  generation expectation or has expired is still removed, because the code was
 *  redeemed; only a resource mismatch leaves it for the bridge that owns it. */
export function consumeAuthCode(
  tables: LogicalTables,
  codeHash: string,
  nowIso: string,
  expectedGrantGeneration?: number,
  expectedResource?: string,
): AuthCodeRecord | null {
  assertSha256Hex(codeHash, "codeHash");
  assertUtcIsoTimestamp(nowIso, "nowIso");
  const record = tables.authCodes.get(codeHash) ?? null;
  // The record belongs to another resource, so this caller may not redeem it and
  // must not delete it either.
  if (record && expectedResource !== undefined && record.resource !== expectedResource) return null;
  // The stored subject is admitted before the row is deleted, so a malformed
  // stored subject fails closed and the record stays exactly as it was.
  if (record) assertStoreSubject(record.subject, "stored subject");
  tables.authCodes.delete(codeHash);
  return record && record.expiresAt > nowIso
    && (expectedGrantGeneration === undefined || record.grantGeneration === expectedGrantGeneration)
    ? structuredClone(record) : null;
}

/** Bind a consent token to a single use: true on first use, false on replay. */
export function consumeConsentJti(
  tables: LogicalTables,
  watermark: SweepWatermark,
  jti: string,
  expiresAtIso: string,
): boolean {
  assertUtcIsoTimestamp(expiresAtIso, "expiresAtIso");
  if (isReplayed(tables, watermark, jti, expiresAtIso)) return false;
  tables.consentJtis.set(jti, expiresAtIso);
  return true;
}

/** Delete expired authorization codes and consent JTIs, and raise the replay
 *  watermark. The watermark only moves forward, so a sweep at an earlier instant
 *  cannot reopen a JTI that a later sweep already closed. */
export function sweepCodes(tables: LogicalTables, watermark: SweepWatermark, nowIso: string): void {
  assertUtcIsoTimestamp(nowIso, "nowIso");
  if (watermark.sweptThrough === undefined || watermark.sweptThrough < nowIso) {
    watermark.sweptThrough = nowIso;
  }
  // The projection reads the tables, so the raised watermark is written back to
  // the row the contract names; a sweep a chain member performs is carried to
  // the members that rehydrate after it.
  tables.sweptThrough = watermark.sweptThrough;
  for (const [codeHash, record] of tables.authCodes) {
    if (record.expiresAt < nowIso) tables.authCodes.delete(codeHash);
  }
  for (const [jti, expiresAtIso] of tables.consentJtis) {
    if (expiresAtIso < nowIso) tables.consentJtis.delete(jti);
  }
}

function isReplayed(
  tables: LogicalTables, watermark: SweepWatermark, jti: string, expiresAtIso: string,
): boolean {
  if (tables.consentJtis.has(jti)) return true;
  return watermark.sweptThrough !== undefined && expiresAtIso < watermark.sweptThrough;
}

/** The stored row is detached from the caller's input, so a later mutation of
 *  that input cannot rewrite a record the store already accepted. */
function storeAuthCode(tables: LogicalTables, input: SaveAuthCodeInput): void {
  tables.authCodes.set(input.codeHash, structuredClone({
    ...input, grantGeneration: grantGenerationForWrite(input.grantGeneration),
  }));
}

function validateAuthCode(input: SaveAuthCodeInput): void {
  assertStoreSubject(input.subject);
  assertSha256Hex(input.codeHash, "codeHash");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
  assertGrantGeneration(input.grantGeneration, "grantGeneration");
  if (input.codeChallengeMethod !== "S256") throw new StoreInputError("codeChallengeMethod must be S256");
}
