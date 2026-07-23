// MemoryStore — in-process reference StorePort (contracts §12.3). Dev/test only,
// loudly labeled: NOT HA, single-process. Implements every §12 invariant,
// including the rotation backfill (fix #3) and findGrantedScopes derived from
// active refresh records (no grant table).

import type {
  AuthCodeRecord, RefreshTokenRecord, SaveAuthCodeInput, SaveRefreshTokenInput, StorePort,
} from "../ports/store.ts";
import { StoreInputError, assertSha256Hex, assertUtcIsoTimestamp } from "../ports/store.ts";
import {
  requireRotationInput, requireSaveAuthCodeInput, requireSaveRefreshTokenInput,
} from "../stored-records.ts";

type StoredRefresh = RefreshTokenRecord & { consumedAt: string | null };

export class MemoryStore implements StorePort {
  private closed = false;
  private readonly authCodes = new Map<string, AuthCodeRecord>();
  private readonly refreshTokens = new Map<string, StoredRefresh>();
  private readonly families = new Map<string, string | null>();
  private readonly consentJtis = new Map<string, string>();

  async saveAuthCode(input: SaveAuthCodeInput): Promise<void> {
    this.ensureOpen();
    const safeInput = requireSaveAuthCodeInput(input);
    this.authCodes.set(safeInput.codeHash, safeInput);
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
    assertUtcIsoTimestamp(expiresAtIso, "expiresAtIso"); // addendum 10: source left this unvalidated
    if (this.consentJtis.has(jti)) return false;
    this.consentJtis.set(jti, expiresAtIso);
    return true;
  }

  async saveRefreshToken(input: SaveRefreshTokenInput): Promise<void> {
    this.ensureOpen();
    const safeInput = requireSaveRefreshTokenInput(input);
    // §12.2 invariant 8: never silently overwrite — an overwrite would rebuild
    // the row with consumedAt:null, resurrecting a consumed token (parity with
    // the SQL stores' PRIMARY KEY rejection).
    if (this.refreshTokens.has(safeInput.tokenHash)) throw new StoreInputError("tokenHash already exists");
    this.families.set(safeInput.familyId, this.families.get(safeInput.familyId) ?? null);
    this.refreshTokens.set(safeInput.tokenHash, { ...safeInput, consumedAt: null });
  }

  async rotateRefreshToken(tokenHash: string, next: SaveRefreshTokenInput, nowIso: string): Promise<RefreshTokenRecord | null> {
    this.ensureOpen();
    const safeNext = requireRotationInput(tokenHash, next, nowIso);
    const current = this.refreshTokens.get(tokenHash) ?? null;
    if (!current || this.families.get(current.familyId)) return null;
    if (current.consumedAt) {
      await this.revokeRefreshTokenFamily(current.familyId, nowIso);
      return null;
    }
    if (current.expiresAt <= nowIso || safeNext.familyId !== current.familyId) return null;
    // §12.2 invariant 8: successor-hash collision ⇒ null WITHOUT consuming the
    // predecessor (mirrors sqlite's check-before-update / mysql's insert-first).
    if (this.refreshTokens.has(safeNext.tokenHash)) return null;
    current.consumedAt = nowIso;
    // Fix #3 backfill: successor takes clientId/subject/scopes from the consumed row.
    await this.saveRefreshToken({ ...safeNext, clientId: current.clientId, subject: current.subject, scopes: current.scopes });
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
