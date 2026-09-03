// MemoryStore — in-process reference StorePort (contracts §12.3). Dev/test only,
// loudly labeled: NOT HA, single-process. Implements every §12 invariant,
// including the rotation backfill (fix #3) and findGrantedScopes derived from
// active refresh records (no grant table).

import { randomBytes } from "node:crypto";
import type { ClockPort } from "../ports/clock.ts";
import type {
  AuthCodeRecord, ConsentApprovalCommitResult, RefreshTokenRecord, SaveAuthCodeInput, SaveRefreshTokenInput, StorePort,
} from "../ports/store.ts";
import { StoreExpiryLifecycle } from "./expiry-lifecycle.ts";
import {
  STORED_DCR_GRANT_GENERATION, STORED_DCR_RESOURCE_BINDING, StoreInputError, assertGrantGeneration, assertStoreInstanceId,
  assertStoreSubject,
  assertRefreshResource, assertSha256Hex, assertUtcIsoTimestamp, grantGenerationForWrite,
  normalizeRefreshTokenWrite, UNBOUND_REFRESH_RESOURCE,
} from "../ports/store.ts";

type StoredRefresh = RefreshTokenRecord & { consumedAt: string | null };
interface StoredFamily { revokedAt: string | null; grantGeneration: number | null; resource: string | null }

export class MemoryStore implements StorePort {
  readonly storedDcrGrantGeneration = STORED_DCR_GRANT_GENERATION;
  readonly storedDcrResourceBinding = STORED_DCR_RESOURCE_BINDING;
  private closed = false;
  private readonly expiry = new StoreExpiryLifecycle(this, true);
  private readonly authCodes = new Map<string, AuthCodeRecord>();
  private readonly refreshTokens = new Map<string, StoredRefresh>();
  private readonly families = new Map<string, StoredFamily>();
  private readonly consentJtis = new Map<string, string>();
  private sweptThrough: string | null = null;
  private storeInstanceId = randomBytes(18).toString("base64url");

  async getStoreInstanceId(): Promise<string> {
    this.ensureOpen();
    return this.storeInstanceId;
  }

  async rotateStoreInstanceId(): Promise<string> {
    this.ensureOpen();
    this.storeInstanceId = randomBytes(18).toString("base64url");
    return this.storeInstanceId;
  }

  async commitConsentApproval(
    expectedStoreInstanceId: string, jti: string, expiresAtIso: string, authCode: SaveAuthCodeInput,
  ): Promise<ConsentApprovalCommitResult> {
    this.ensureOpen();
    assertStoreInstanceId(expectedStoreInstanceId);
    assertUtcIsoTimestamp(expiresAtIso, "expiresAtIso");
    validateAuthCode(authCode);
    if (expectedStoreInstanceId !== this.storeInstanceId) return "binding_mismatch";
    // Materialize the complete record BEFORE the guards: the scopes spread runs
    // caller code, so any later placement lets a reentrant iterable fire a
    // nested commit between the replay check and the write, storing two codes
    // for one consent JTI.
    const stored = {
      ...authCode, scopes: [...authCode.scopes], grantGeneration: grantGenerationForWrite(authCode.grantGeneration),
    };
    if (this.consentJtis.has(jti)) return "replayed";
    if (this.sweptThrough !== null && expiresAtIso < this.sweptThrough) return "replayed";
    this.consentJtis.set(jti, expiresAtIso);
    this.authCodes.set(stored.codeHash, stored);
    return "stored";
  }

  async saveAuthCode(input: SaveAuthCodeInput): Promise<void> {
    this.ensureOpen();
    validateAuthCode(input);
    this.authCodes.set(input.codeHash, { ...input, scopes: [...input.scopes], grantGeneration: grantGenerationForWrite(input.grantGeneration) });
  }

  async consumeAuthCode(codeHash: string, nowIso: string, expectedGrantGeneration?: number, expectedResource?: string): Promise<AuthCodeRecord | null> {
    this.ensureOpen();
    assertSha256Hex(codeHash, "codeHash");
    assertUtcIsoTimestamp(nowIso, "nowIso");
    const record = this.authCodes.get(codeHash) ?? null;
    if (record && expectedResource !== undefined && record.resource !== expectedResource) return null;
    if (record) assertStoreSubject(record.subject, "stored subject");
    this.authCodes.delete(codeHash);
    return record && record.expiresAt > nowIso
      && (expectedGrantGeneration === undefined || record.grantGeneration === expectedGrantGeneration) ? record : null;
  }

  async consumeConsentJti(jti: string, expiresAtIso: string): Promise<boolean> {
    this.ensureOpen();
    assertUtcIsoTimestamp(expiresAtIso, "expiresAtIso"); // addendum 10: source left this unvalidated
    if (this.consentJtis.has(jti)) return false;
    if (this.sweptThrough !== null && expiresAtIso < this.sweptThrough) return false;
    this.consentJtis.set(jti, expiresAtIso);
    return true;
  }

  async saveRefreshToken(input: SaveRefreshTokenInput): Promise<void> {
    this.ensureOpen();
    input = normalizeRefreshTokenWrite(input);
    validateRefreshToken(input);
    // §12.2 invariant 8: never silently overwrite — an overwrite would rebuild
    // the row with consumedAt:null, resurrecting a consumed token (parity with
    // the SQL stores' PRIMARY KEY rejection).
    if (this.refreshTokens.has(input.tokenHash)) throw new StoreInputError("tokenHash already exists");
    const grantGeneration = grantGenerationForWrite(input.grantGeneration);
    // Materialize the row BEFORE reading token/family state: the scopes spread
    // runs caller code, so any later placement lets a reentrant iterable fire a
    // nested save between the family check and the writes, binding the outer
    // row to a stale family result.
    const row = { ...input, scopes: [...input.scopes], grantGeneration, consumedAt: null };
    const family = this.families.get(input.familyId);
    if (family && (family.grantGeneration !== grantGeneration || family.resource !== input.resource)) {
      throw new StoreInputError("family grantGeneration or resource mismatch");
    }
    if (!family) this.families.set(input.familyId, { revokedAt: null, grantGeneration, resource: input.resource });
    this.refreshTokens.set(row.tokenHash, row);
  }

  async rotateRefreshToken(tokenHash: string, next: SaveRefreshTokenInput, nowIso: string, expectedGrantGeneration?: number, expectedResource?: string): Promise<RefreshTokenRecord | null> {
    this.ensureOpen();
    next = normalizeRefreshTokenWrite(next);
    validateRotation(tokenHash, next, nowIso);
    const current = this.refreshTokens.get(tokenHash) ?? null;
    const family = current ? this.families.get(current.familyId) : undefined;
    if (!current || !family) return null;
    assertStoreSubject(current.subject, "stored subject");
    if (family.revokedAt
      || (expectedGrantGeneration !== undefined
        && (family.grantGeneration !== expectedGrantGeneration
          || current.grantGeneration !== expectedGrantGeneration))) return null;
    if (current.resource === null || current.resource === UNBOUND_REFRESH_RESOURCE || family.resource === null
      || current.resource !== family.resource
      || (expectedResource !== undefined && current.resource !== expectedResource)) return null;
    if (current.consumedAt) {
      await this.revokeRefreshTokenFamily(current.familyId, nowIso);
      return null;
    }
    if (current.expiresAt <= nowIso || next.familyId !== current.familyId) return null;
    // §12.2 invariant 8: successor-hash collision ⇒ null WITHOUT consuming the
    // predecessor (mirrors sqlite's check-before-update / mysql's insert-first).
    if (this.refreshTokens.has(next.tokenHash)) return null;
    current.consumedAt = nowIso;
    // Backfill: successor takes identity and resource from the consumed row.
    await this.saveRefreshToken({
      ...next, clientId: current.clientId, subject: current.subject,
      resource: current.resource, scopes: current.scopes, grantGeneration: current.grantGeneration,
    });
    return toRecord(current);
  }

  async revokeRefreshTokenFamily(familyId: string, revokedAtIso: string, expectedResource?: string): Promise<void> {
    this.ensureOpen();
    assertUtcIsoTimestamp(revokedAtIso, "revokedAtIso");
    if (expectedResource !== undefined) assertRefreshResource(expectedResource, "expectedResource");
    const family = this.families.get(familyId);
    if (family && family.revokedAt === null
      && (expectedResource === undefined || family.resource === expectedResource)) family.revokedAt = revokedAtIso;
  }

  async findRefreshToken(tokenHash: string): Promise<RefreshTokenRecord | null> {
    this.ensureOpen();
    const t = this.refreshTokens.get(tokenHash);
    if (!t) return null;
    assertStoreSubject(t.subject, "stored subject");
    return toRecord(t);
  }

  async findGrantedScopes(subject: string, clientId: string, nowIso: string, expectedGrantGeneration?: number, expectedResource?: string): Promise<string[]> {
    this.ensureOpen();
    assertStoreSubject(subject);
    assertUtcIsoTimestamp(nowIso, "nowIso");
    const out: string[] = [];
    for (const t of this.refreshTokens.values()) {
      const family = this.families.get(t.familyId);
      if (t.subject === subject && t.clientId === clientId && !t.consumedAt
        && t.expiresAt > nowIso && family?.revokedAt === null
        && (expectedGrantGeneration === undefined || t.grantGeneration === expectedGrantGeneration)
        && (expectedResource === undefined
          || (t.resource === expectedResource && family.resource === expectedResource))) {
        for (const s of t.scopes) if (!out.includes(s)) out.push(s);
      }
    }
    return out;
  }

  async sweepExpired(nowIso: string): Promise<void> {
    this.ensureOpen();
    assertUtcIsoTimestamp(nowIso, "nowIso");
    if (this.sweptThrough === null || this.sweptThrough < nowIso) this.sweptThrough = nowIso;
    for (const [hash, record] of this.authCodes) if (record.expiresAt < nowIso) this.authCodes.delete(hash);
    for (const [jti, expiresAt] of this.consentJtis) if (expiresAt < nowIso) this.consentJtis.delete(jti);
    // Family-validity retention (addendum 8): delete a refresh token (consumed or
    // not) ONLY when no member of its family is still valid (> now). This keeps a
    // consumed predecessor while its successor (rotated, expires later) is live —
    // preserving the replay signal that a naive per-token sweep would drop.
    const tokens = [...this.refreshTokens.values()];
    for (const [hash, t] of this.refreshTokens) {
      const familyValid = tokens.some((m) => m.familyId === t.familyId && m.expiresAt >= nowIso);
      if (!familyValid) this.refreshTokens.delete(hash);
    }
    // delete ANY empty family (not only revoked ones).
    const liveFamilies = new Set([...this.refreshTokens.values()].map((t) => t.familyId));
    for (const familyId of [...this.families.keys()]) if (!liveFamilies.has(familyId)) this.families.delete(familyId);
  }

  startExpiryCollection(clock: ClockPort): void {
    this.ensureOpen();
    this.expiry.start(clock);
  }

  async close(): Promise<void> {
    await this.expiry.stop();
    this.closed = true;
  }

  private ensureOpen(): void {
    if (this.closed) throw new Error("Store is closed");
  }
}

export function createMemoryStore(): MemoryStore {
  return new MemoryStore();
}

/** Stored rows own their scopes array so a caller keeps no handle into the store. */
function toRecord(stored: StoredRefresh): RefreshTokenRecord {
  return {
    tokenHash: stored.tokenHash, familyId: stored.familyId, previousTokenHash: stored.previousTokenHash,
    clientId: stored.clientId, subject: stored.subject, resource: stored.resource, scopes: [...stored.scopes],
    expiresAt: stored.expiresAt, grantGeneration: stored.grantGeneration,
  };
}

function validateAuthCode(input: SaveAuthCodeInput): void {
  assertStoreSubject(input.subject);
  assertSha256Hex(input.codeHash, "codeHash");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
  assertGrantGeneration(input.grantGeneration, "grantGeneration");
  if (input.codeChallengeMethod !== "S256") throw new StoreInputError("codeChallengeMethod must be S256");
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
