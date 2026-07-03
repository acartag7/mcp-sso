// MemoryStore — in-process reference StorePort (contracts §12.3). Dev/test only,
// loudly labeled: NOT HA, single-process. Implements every §12 invariant,
// including the rotation backfill (fix #3) and findGrantedScopes derived from
// active refresh records (no grant table).

import type {
  AuthCodeRecord, RefreshTokenRecord, SaveAuthCodeInput, SaveRefreshTokenInput, StorePort,
} from "../ports/store.ts";
import {
  StoreInputError, assertSha256Hex, assertUtcIsoTimestamp,
} from "../ports/store.ts";

type StoredRefresh = RefreshTokenRecord & { consumedAt: string | null };

export class MemoryStore implements StorePort {
  private closed = false;
  private readonly authCodes = new Map<string, AuthCodeRecord>();
  private readonly refreshTokens = new Map<string, StoredRefresh>();
  private readonly families = new Map<string, string | null>();
  private readonly consentJtis = new Map<string, string>();

  async saveAuthCode(input: SaveAuthCodeInput): Promise<void> {
    this.ensureOpen();
    validateAuthCode(input);
    this.authCodes.set(input.codeHash, { ...input });
  }

  async consumeAuthCode(codeHash: string, nowIso: string): Promise<AuthCodeRecord | null> {
    this.ensureOpen();
    assertSha256Hex(codeHash, "codeHash");
    assertUtcIsoTimestamp(nowIso, "nowIso");
    const record = this.authCodes.get(codeHash) ?? null;
    this.authCodes.delete(codeHash);
    return record && record.expiresAt > nowIso ? record : null;
  }

  async consumeConsentJti(jti: string, expiresAtIso: string): Promise<boolean> {
    this.ensureOpen();
    if (this.consentJtis.has(jti)) return false;
    this.consentJtis.set(jti, expiresAtIso);
    return true;
  }

  async saveRefreshToken(input: SaveRefreshTokenInput): Promise<void> {
    this.ensureOpen();
    validateRefreshToken(input);
    this.families.set(input.familyId, this.families.get(input.familyId) ?? null);
    this.refreshTokens.set(input.tokenHash, { ...input, consumedAt: null });
  }

  async rotateRefreshToken(tokenHash: string, next: SaveRefreshTokenInput, nowIso: string): Promise<RefreshTokenRecord | null> {
    this.ensureOpen();
    validateRotation(tokenHash, next, nowIso);
    const current = this.refreshTokens.get(tokenHash) ?? null;
    if (!current || this.families.get(current.familyId)) return null;
    if (current.consumedAt) {
      await this.revokeRefreshTokenFamily(current.familyId, nowIso);
      return null;
    }
    if (current.expiresAt <= nowIso || next.familyId !== current.familyId) return null;
    current.consumedAt = nowIso;
    // Fix #3 backfill: successor takes clientId/subject/scopes from the consumed row.
    await this.saveRefreshToken({ ...next, clientId: current.clientId, subject: current.subject, scopes: current.scopes });
    return toRecord(current);
  }

  async revokeRefreshTokenFamily(familyId: string, revokedAtIso: string): Promise<void> {
    this.ensureOpen();
    assertUtcIsoTimestamp(revokedAtIso, "revokedAtIso");
    if (!this.families.has(familyId)) this.families.set(familyId, revokedAtIso);
    else if (this.families.get(familyId) === null) this.families.set(familyId, revokedAtIso);
  }

  async findRefreshToken(tokenHash: string): Promise<RefreshTokenRecord | null> {
    this.ensureOpen();
    const t = this.refreshTokens.get(tokenHash);
    return t ? toRecord(t) : null;
  }

  async findGrantedScopes(subject: string, clientId: string, nowIso: string): Promise<string[]> {
    this.ensureOpen();
    assertUtcIsoTimestamp(nowIso, "nowIso");
    const out: string[] = [];
    for (const t of this.refreshTokens.values()) {
      if (t.subject === subject && t.clientId === clientId && !t.consumedAt
        && t.expiresAt > nowIso && !this.families.get(t.familyId)) {
        for (const s of t.scopes) if (!out.includes(s)) out.push(s);
      }
    }
    return out;
  }

  async sweepExpired(nowIso: string): Promise<void> {
    this.ensureOpen();
    assertUtcIsoTimestamp(nowIso, "nowIso");
    for (const [hash, record] of this.authCodes) if (record.expiresAt < nowIso) this.authCodes.delete(hash);
    for (const [jti, expiresAt] of this.consentJtis) if (expiresAt < nowIso) this.consentJtis.delete(jti);
    for (const [hash, t] of this.refreshTokens) if (t.expiresAt < nowIso && !t.consumedAt) this.refreshTokens.delete(hash);
    for (const [familyId] of this.families) {
      if (this.families.get(familyId) && ![...this.refreshTokens.values()].some((t) => t.familyId === familyId)) {
        this.families.delete(familyId);
      }
    }
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  private ensureOpen(): void {
    if (this.closed) throw new Error("Store is closed");
  }
}

export function createMemoryStore(): MemoryStore {
  return new MemoryStore();
}

function toRecord(stored: StoredRefresh): RefreshTokenRecord {
  return {
    tokenHash: stored.tokenHash, familyId: stored.familyId, previousTokenHash: stored.previousTokenHash,
    clientId: stored.clientId, subject: stored.subject, scopes: stored.scopes, expiresAt: stored.expiresAt,
  };
}

function validateAuthCode(input: SaveAuthCodeInput): void {
  assertSha256Hex(input.codeHash, "codeHash");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
  if (input.codeChallengeMethod !== "S256") throw new StoreInputError("codeChallengeMethod must be S256");
}

function validateRefreshToken(input: SaveRefreshTokenInput): void {
  assertSha256Hex(input.tokenHash, "tokenHash");
  if (input.previousTokenHash !== null) assertSha256Hex(input.previousTokenHash, "previousTokenHash");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
}

function validateRotation(tokenHash: string, next: SaveRefreshTokenInput, nowIso: string): void {
  assertSha256Hex(tokenHash, "tokenHash");
  validateRefreshToken(next);
  assertUtcIsoTimestamp(nowIso, "nowIso");
  if (next.previousTokenHash !== tokenHash) throw new StoreInputError("next.previousTokenHash must match tokenHash");
}
