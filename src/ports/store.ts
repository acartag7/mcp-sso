// StorePort — the OAuth-state storage port and the store-conformance boundary
// (contracts §6.3, §12). Stores auth-code records, refresh-token families and
// tokens, and single-use consent JTIs. All secrets are SHA-256 digests; there is
// NO grant table (prior grants are derived from active refresh-token records
// via findGrantedScopes). Every adapter (memory, sqlite, any downstream SQL)
// must satisfy the §12 invariants, asserted by the store-conformance suite.

export interface AuthCodeRecord {
  /** sha256(raw code). */
  codeHash: string;
  clientId: string;
  subject: string;
  redirectUri: string;
  resource: string;
  scopes: string[];
  codeChallenge: string;
  codeChallengeMethod: "S256";
  expiresAt: string;
  /** Opaque stored-DCR cutover generation; null means legacy/non-stored. */
  grantGeneration?: number | null;
}

export interface RefreshTokenRecord {
  /** sha256(raw token). */
  tokenHash: string;
  /** Family id; replay revokes the whole family. */
  familyId: string;
  /** sha256 of the previous token in the family (chain root has none). */
  previousTokenHash: string | null;
  clientId: string;
  subject: string;
  scopes: string[];
  expiresAt: string;
  /** Durable token/family generation; null means legacy/non-stored. */
  grantGeneration?: number | null;
}

export interface SaveAuthCodeInput {
  codeHash: string;
  clientId: string;
  subject: string;
  redirectUri: string;
  resource: string;
  scopes: string[];
  codeChallenge: string;
  codeChallengeMethod: "S256";
  expiresAt: string;
  /** Omitted defaults to the current generation; null is legacy/non-stored. */
  grantGeneration?: number | null;
}

export interface SaveRefreshTokenInput {
  tokenHash: string;
  familyId: string;
  previousTokenHash: string | null;
  clientId: string;
  subject: string;
  scopes: string[];
  expiresAt: string;
  /** Omitted defaults to the current generation; null is legacy/non-stored. */
  grantGeneration?: number | null;
}

export interface StorePort {
  /** Required capability marker when BridgeConfig uses stored DCR. */
  readonly storedDcrGrantGeneration?: number;
  saveAuthCode(input: SaveAuthCodeInput): Promise<void>;
  /** Single-use; removes on read. Returns null if missing/expired. A supplied
   *  expectedResource mismatch returns null without consuming the record. */
  consumeAuthCode(
    codeHash: string,
    nowIso: string,
    expectedGrantGeneration?: number,
    expectedResource?: string,
  ): Promise<AuthCodeRecord | null>;
  saveRefreshToken(input: SaveRefreshTokenInput): Promise<void>;
  /** Returns the consumed record (and rotates), or null if missing/expired/revoked. */
  rotateRefreshToken(
    tokenHash: string,
    next: SaveRefreshTokenInput,
    nowIso: string,
    expectedGrantGeneration?: number,
  ): Promise<RefreshTokenRecord | null>;
  /** Revoke every token in the family. Replay-detection path. */
  revokeRefreshTokenFamily(familyId: string, revokedAtIso: string): Promise<void>;
  /** Find a refresh token by its hash, or null if it does not exist. */
  findRefreshToken(tokenHash: string): Promise<RefreshTokenRecord | null>;
  /** Bind a consent token to a single use. true on first use, false on replay. */
  consumeConsentJti(jti: string, expiresAtIso: string): Promise<boolean>;
  /** Derive the union of granted scopes from this (subject, clientId)'s ACTIVE
   *  refresh tokens (unconsumed, unrevoked, unexpired). Read-only; no grant table.
   *  Invoked only in stored-DCR mode (contracts §9.3). */
  findGrantedScopes(subject: string, clientId: string, nowIso: string, expectedGrantGeneration?: number): Promise<string[]>;
  /** Delete expired auth codes, JTIs, unconsumed expired refresh tokens, orphaned
   *  revoked families. */
  sweepExpired(nowIso: string): Promise<void>;
  close(): Promise<void>;
}

/** First library-owned opaque stored-DCR grant generation (0.3.2). */
export const STORED_DCR_GRANT_GENERATION = 1 as const;

export class StoreInputError extends Error {
  readonly code = "invalid_store_input";
}

export function assertSha256Hex(value: string, label: string): void {
  if (!/^[a-f0-9]{64}$/i.test(value)) {
    throw new StoreInputError(`${label} must be a SHA-256 hex digest`);
  }
}

export function assertUtcIsoTimestamp(value: string, label: string): void {
  // EXACTLY 3 millisecond digits are required (addendum 9): stores compare expiry
  // strings lexicographically (SQLite TEXT / in-memory compare), and mixed precision
  // inverts ordering ("...00Z" sorts after "...00.500Z" -> expired flips to valid).
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    throw new StoreInputError(`${label} must be a UTC ISO timestamp with exactly 3 ms digits (e.g. 2026-07-03T13:00:00.000Z)`);
  }
}

export function assertGrantGeneration(value: unknown, label: string): void {
  if (value !== undefined && value !== null
    && (!Number.isSafeInteger(value) || (value as number) <= 0)) {
    throw new StoreInputError(`${label} must be a positive safe integer or null`);
  }
}

/** Stored rows fail closed: malformed/missing values are legacy null. */
export function grantGenerationFromStored(value: unknown): number | null {
  return Number.isSafeInteger(value) && (value as number) > 0 ? value as number : null;
}

/** Current API omission stays source-compatible; explicit null remains legacy. */
export function grantGenerationForWrite(value: number | null | undefined): number | null {
  return value === undefined ? STORED_DCR_GRANT_GENERATION : grantGenerationFromStored(value);
}
