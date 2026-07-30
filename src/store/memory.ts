// MemoryStore — in-process reference StorePort (contracts §12.3). Dev/test only,
// loudly labeled: NOT HA, single-process. Implements every §12 invariant,
// including the rotation backfill (fix #3), findGrantedScopes derived from
// active refresh records (no grant table), and the §12.2 invariant 11 resource
// lineage ordering: parse+generation → consumed replay FIRST → resource equality
// → unconsumed request expectation → copy STORED resource to the successor.

import type {
  AuthCodeRecord, RefreshRotationResult, RefreshTokenRecord, ResourceBindingExpectation,
  SaveAuthCodeInput, SaveRefreshTokenInput, StorePort,
} from "../ports/store.ts";
import {
  STORED_DCR_GRANT_GENERATION, StoreInputError, assertGrantGeneration,
  assertSha256Hex, assertUtcIsoTimestamp, grantGenerationForWrite, isCanonicalStoredResource,
} from "../ports/store.ts";

type StoredRefresh = RefreshTokenRecord & { consumedAt: string | null; resource: string | null };
interface StoredFamily { revokedAt: string | null; grantGeneration: number | null; resource: string | null }

export class MemoryStore implements StorePort {
  readonly storedDcrGrantGeneration = STORED_DCR_GRANT_GENERATION;
  readonly resourceBinding = 1 as const;
  private closed = false;
  private readonly authCodes = new Map<string, AuthCodeRecord>();
  private readonly refreshTokens = new Map<string, StoredRefresh>();
  private readonly families = new Map<string, StoredFamily>();
  private readonly consentJtis = new Map<string, string>();

  async saveAuthCode(input: SaveAuthCodeInput): Promise<void> {
    this.ensureOpen();
    validateAuthCode(input);
    this.authCodes.set(input.codeHash, { ...input, grantGeneration: grantGenerationForWrite(input.grantGeneration) });
  }

  async consumeAuthCode(codeHash: string, nowIso: string, expectedGrantGeneration?: number): Promise<AuthCodeRecord | null> {
    this.ensureOpen();
    assertSha256Hex(codeHash, "codeHash");
    assertUtcIsoTimestamp(nowIso, "nowIso");
    const record = this.authCodes.get(codeHash) ?? null;
    this.authCodes.delete(codeHash);
    return record && record.expiresAt > nowIso
      && (expectedGrantGeneration === undefined || record.grantGeneration === expectedGrantGeneration) ? record : null;
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
    validateRefreshToken(input);
    // §12.2 invariant 8: never silently overwrite — an overwrite would rebuild
    // the row with consumedAt:null, resurrecting a consumed token (parity with
    // the SQL stores' PRIMARY KEY rejection).
    if (this.refreshTokens.has(input.tokenHash)) throw new StoreInputError("tokenHash already exists");
    const grantGeneration = grantGenerationForWrite(input.grantGeneration);
    const resource = resourceForWrite(input.resource);
    const family = this.families.get(input.familyId);
    if (family) {
      if (family.grantGeneration !== grantGeneration) throw new StoreInputError("family grantGeneration mismatch");
      if (family.resource !== resource) throw new StoreInputError("family resource mismatch");
    }
    if (!family) this.families.set(input.familyId, { revokedAt: null, grantGeneration, resource });
    this.refreshTokens.set(input.tokenHash, { ...input, grantGeneration, resource, consumedAt: null });
  }

  async rotateRefreshToken(
    tokenHash: string,
    next: SaveRefreshTokenInput,
    nowIso: string,
    expectedGrantGeneration?: number,
    resourceBinding?: ResourceBindingExpectation,
  ): Promise<RefreshRotationResult> {
    this.ensureOpen();
    validateRotation(tokenHash, next, nowIso);
    // Step 1 (§12.2 inv 11): parse + generation-check the family and token rows.
    const current = this.refreshTokens.get(tokenHash) ?? null;
    const family = current ? this.families.get(current.familyId) : undefined;
    if (!current || !family || family.revokedAt
      || (expectedGrantGeneration !== undefined
        && (family.grantGeneration !== expectedGrantGeneration
          || current.grantGeneration !== expectedGrantGeneration))) return null;
    // Step 2: consumed-token replay FIRST — before ANY resource comparison. A
    // consumed token is a replay whatever resource it carries, so this revokes the
    // family even when the request names a different configured resource AND when
    // the row's own lineage disagrees. Ordering this after the equality check below
    // would silently disable replay revocation for a pre-0.4 chain: attested legacy
    // binding stamps the family and the rotated token, but OLDER consumed members
    // keep resource null, so a stolen predecessor would fail equality and return
    // early without ever revoking the still-live family.
    if (current.consumedAt) {
      await this.revokeRefreshTokenFamily(current.familyId, nowIso);
      return null;
    }
    // Step 3: establish stored family/token resource equality (family authoritative).
    const storedResource = family.resource;
    if (current.resource !== storedResource) return null; // disagreeing lineage
    // Malformed/non-canonical persisted lineage means the RECORD is unusable:
    // return null (invalid_grant) rather than compare it and report a resource
    // mismatch (invalid_target), which would tell the client to retry forever.
    if (storedResource !== null && !isCanonicalStoredResource(storedResource)) return null;
    if (current.expiresAt <= nowIso || next.familyId !== current.familyId) return null;
    // Steps 4-5: compare the optional request expectation (unconsumed token only).
    // Determined WITHOUT mutating, so a later collision (null, no successor) leaves state.
    let successorResource: string | null;
    let legacyBind = false;
    if (resourceBinding === undefined) {
      successorResource = storedResource; // source-compat: copy stored (null or string)
    } else if (storedResource !== null) {
      if (storedResource !== resourceBinding.resource) return { status: "resource_mismatch" };
      successorResource = storedResource;
    } else if (resourceBinding.allowLegacySingletonBinding) {
      // Legacy null lineage: bind atomically to the sole attested resource (singleton).
      successorResource = resourceBinding.resource;
      legacyBind = true;
    } else {
      // Null lineage without the singleton attestation (or in multi mode): invalid_grant.
      // Never assigned the request-selected resource.
      return null;
    }
    // Step 6: collision + mutate. Collision returns null WITHOUT consuming (inv 8).
    if (this.refreshTokens.has(next.tokenHash)) return null;
    if (legacyBind) { family.resource = successorResource; current.resource = successorResource; }
    current.consumedAt = nowIso;
    // Fix #3 backfill + §12.2 inv 11 resource copy: successor takes identity and the
    // STORED resource from the consumed row, never the caller-supplied values.
    await this.saveRefreshToken({
      ...next, clientId: current.clientId, subject: current.subject,
      scopes: current.scopes, grantGeneration: current.grantGeneration, resource: successorResource,
    });
    return toRecord(current);
  }

  async revokeRefreshTokenFamily(familyId: string, revokedAtIso: string): Promise<void> {
    this.ensureOpen();
    assertUtcIsoTimestamp(revokedAtIso, "revokedAtIso");
    const family = this.families.get(familyId);
    if (!family) this.families.set(familyId, { revokedAt: revokedAtIso, grantGeneration: null, resource: null });
    else if (family.revokedAt === null) family.revokedAt = revokedAtIso;
  }

  async findRefreshToken(tokenHash: string): Promise<RefreshTokenRecord | null> {
    this.ensureOpen();
    const t = this.refreshTokens.get(tokenHash);
    return t ? toRecord(t) : null;
  }

  async findGrantedScopes(
    subject: string, clientId: string, nowIso: string,
    expectedGrantGeneration?: number, resourceBinding?: ResourceBindingExpectation,
  ): Promise<string[]> {
    this.ensureOpen();
    assertUtcIsoTimestamp(nowIso, "nowIso");
    const out: string[] = [];
    for (const t of this.refreshTokens.values()) {
      if (t.subject === subject && t.clientId === clientId && !t.consumedAt
        && t.expiresAt > nowIso && this.families.get(t.familyId)?.revokedAt === null
        && (expectedGrantGeneration === undefined || t.grantGeneration === expectedGrantGeneration)) {
        if (resourceBinding !== undefined
          && t.resource !== resourceBinding.resource
          && !(t.resource === null && resourceBinding.allowLegacySingletonBinding)) continue;
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
    clientId: stored.clientId, subject: stored.subject, scopes: stored.scopes,
    expiresAt: stored.expiresAt, grantGeneration: stored.grantGeneration, resource: stored.resource,
  };
}

/** Omitted resource is a legacy pre-0.4 lineage (null); a present value is stored
 *  verbatim — the store does NOT canonicalize URLs (one parser owns that, §5.1). */
function resourceForWrite(value: string | null | undefined): string | null {
  return value === undefined ? null : value;
}

function validateAuthCode(input: SaveAuthCodeInput): void {
  assertSha256Hex(input.codeHash, "codeHash");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
  assertGrantGeneration(input.grantGeneration, "grantGeneration");
  if (input.codeChallengeMethod !== "S256") throw new StoreInputError("codeChallengeMethod must be S256");
}

function validateRefreshToken(input: SaveRefreshTokenInput): void {
  assertSha256Hex(input.tokenHash, "tokenHash");
  if (input.previousTokenHash !== null) assertSha256Hex(input.previousTokenHash, "previousTokenHash");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
  assertGrantGeneration(input.grantGeneration, "grantGeneration");
  if (input.resource !== undefined && input.resource !== null
    && (typeof input.resource !== "string" || input.resource.length === 0)) {
    throw new StoreInputError("resource must be a non-empty string or null");
  }
}

function validateRotation(tokenHash: string, next: SaveRefreshTokenInput, nowIso: string): void {
  assertSha256Hex(tokenHash, "tokenHash");
  validateRefreshToken(next);
  assertUtcIsoTimestamp(nowIso, "nowIso");
  if (next.previousTokenHash !== tokenHash) throw new StoreInputError("next.previousTokenHash must match tokenHash");
}
