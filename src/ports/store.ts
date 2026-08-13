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
  /** Exact stored family resource string; null only projects a legacy durable row. */
  resource: string | null;
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
  /** Exact configured resource string persisted on every new family and token row. */
  resource: string;
  scopes: string[];
  expiresAt: string;
  /** Omitted defaults to the current generation; null is legacy/non-stored. */
  grantGeneration?: number | null;
}

export type ConsentApprovalCommitResult = "stored" | "replayed" | "binding_mismatch";

/** Reserved, unmatchable marker for an omitted member from pre-resource JS callers. */
export const UNBOUND_REFRESH_RESOURCE = "mcp-sso:unbound-refresh-resource";

/**
 * Typed callers must provide an exact resource string. An old untyped caller that
 * omits it is persisted as deliberately unbound, so it cannot refresh through
 * any bridge instead of being inferred from current configuration.
 */
export function normalizeRefreshTokenWrite(input: SaveRefreshTokenInput): SaveRefreshTokenInput {
  if (input.resource === undefined) return { ...input, resource: UNBOUND_REFRESH_RESOURCE };
  assertRefreshResource(input.resource, "resource");
  if (input.resource === UNBOUND_REFRESH_RESOURCE) {
    throw new StoreInputError("resource is reserved for unbound legacy writes");
  }
  return input;
}

export interface StorePort {
  /** Opaque durable identity of this logical store. */
  getStoreInstanceId(): Promise<string>;
  /** Atomically replace the binding after cloning/restoring a store into an
   * independent deployment. Invalidates outstanding consent tokens. */
  rotateStoreInstanceId(): Promise<string>;
  /** Atomically validate the store binding, consume the consent JTI, and save
   * the authorization code. Rotation serializes against this operation. */
  commitConsentApproval(
    expectedStoreInstanceId: string,
    jti: string,
    expiresAtIso: string,
    authCode: SaveAuthCodeInput,
  ): Promise<ConsentApprovalCommitResult>;
  /** Required capability markers when BridgeConfig uses stored DCR. */
  readonly storedDcrGrantGeneration?: number;
  readonly storedDcrResourceBinding?: number;
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
  /** Returns the consumed record (and rotates), or null if missing/expired/revoked.
   * A supplied expectedResource mismatch leaves the family untouched. */
  rotateRefreshToken(
    tokenHash: string,
    next: SaveRefreshTokenInput,
    nowIso: string,
    expectedGrantGeneration?: number,
    expectedResource?: string,
  ): Promise<RefreshTokenRecord | null>;
  /** Revoke every token in the family. Replay-detection path. */
  revokeRefreshTokenFamily(familyId: string, revokedAtIso: string): Promise<void>;
  /** Find a refresh token by its hash, or null if it does not exist. */
  findRefreshToken(tokenHash: string): Promise<RefreshTokenRecord | null>;
  /** Bind a consent token to a single use. true on first use, false on replay. */
  consumeConsentJti(jti: string, expiresAtIso: string): Promise<boolean>;
  /** Derive the union of granted scopes from this (subject, clientId)'s ACTIVE
   *  refresh tokens (unconsumed, unrevoked, unexpired). Read-only; no grant table.
   *  Invoked only in stored-DCR mode (contracts §9.3). A supplied resource
   *  accepts only token/family rows bound to that exact resource. */
  findGrantedScopes(
    subject: string,
    clientId: string,
    nowIso: string,
    expectedGrantGeneration?: number,
    expectedResource?: string,
  ): Promise<string[]>;
  /** Delete expired auth codes, JTIs, unconsumed expired refresh tokens, orphaned
   *  revoked families. */
  sweepExpired(nowIso: string): Promise<void>;
  close(): Promise<void>;
}

/** First library-owned opaque stored-DCR grant generation (0.3.2). */
export const STORED_DCR_GRANT_GENERATION = 1 as const;
/** First stored-DCR capability version that binds scope accumulation to resource. */
export const STORED_DCR_RESOURCE_BINDING = 1 as const;
const STORE_INSTANCE_ID = /^[A-Za-z0-9_-]{22,128}$/u;

export class StoreInputError extends Error {
  readonly code = "invalid_store_input";
}

export function assertStoreInstanceId(value: unknown): asserts value is string {
  if (typeof value !== "string" || !STORE_INSTANCE_ID.test(value)) {
    throw new StoreInputError("store instance id must be 22-128 base64url characters");
  }
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

export function assertRefreshResource(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new StoreInputError(`${label} must be a non-empty resource string`);
  }
}

/** Stored rows without a non-blank resource are legacy and fail closed. */
export function refreshResourceFromStored(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

/** Stored rows fail closed: malformed/missing values are legacy null. */
export function grantGenerationFromStored(value: unknown): number | null {
  return Number.isSafeInteger(value) && (value as number) > 0 ? value as number : null;
}

/** Current API omission stays source-compatible; explicit null remains legacy. */
export function grantGenerationForWrite(value: number | null | undefined): number | null {
  return value === undefined ? STORED_DCR_GRANT_GENERATION : grantGenerationFromStored(value);
}
