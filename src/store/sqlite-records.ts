import type { DatabaseSync } from "node:sqlite";
import type {
  AuthCodeRecord, RefreshTokenRecord, SaveAuthCodeInput, SaveRefreshTokenInput,
} from "../ports/store.ts";
import {
  StoreInputError, assertGrantGeneration, assertSha256Hex,
  assertUtcIsoTimestamp, grantGenerationForWrite, grantGenerationFromStored,
} from "../ports/store.ts";

export interface AuthCodeRow {
  code_hash: string; client_id: string; subject: string; redirect_uri: string;
  resource: string; scopes_json: string; code_challenge: string;
  code_challenge_method: "S256"; expires_at: string; grant_generation: unknown;
}
export interface RefreshTokenRow {
  token_hash: string; family_id: string; previous_token_hash: string | null;
  client_id: string; subject: string; scopes_json: string; expires_at: string;
  consumed_at: string | null; grant_generation: unknown; resource: unknown;
  revoked_at: string | null; f_grant_generation: unknown; f_resource: unknown;
}

export function insertRefreshToken(db: DatabaseSync, input: SaveRefreshTokenInput): void {
  db.prepare(`INSERT INTO oauth_refresh_tokens (
    token_hash, family_id, previous_token_hash, client_id, subject, scopes_json,
    expires_at, consumed_at, grant_generation, resource
  ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`).run(
    input.tokenHash, input.familyId, input.previousTokenHash, input.clientId, input.subject,
    JSON.stringify(input.scopes), input.expiresAt,
    grantGenerationForWrite(input.grantGeneration), resourceForWrite(input.resource),
  );
}

export function nextFromRow(
  input: SaveRefreshTokenInput, row: RefreshTokenRow, resource: string | null,
): SaveRefreshTokenInput {
  return {
    ...input, clientId: row.client_id, subject: row.subject,
    scopes: parseScopes(row.scopes_json),
    grantGeneration: grantGenerationFromStored(row.grant_generation), resource,
  };
}

export function revokeFamily(db: DatabaseSync, familyId: string, revokedAtIso: string): void {
  db.prepare(
    `INSERT INTO oauth_refresh_token_families (family_id, revoked_at) VALUES (?, ?)
     ON CONFLICT(family_id) DO UPDATE SET revoked_at = COALESCE(oauth_refresh_token_families.revoked_at, excluded.revoked_at)`,
  ).run(familyId, revokedAtIso);
}

export function validateAuthCode(input: SaveAuthCodeInput): void {
  assertSha256Hex(input.codeHash, "codeHash");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
  assertGrantGeneration(input.grantGeneration, "grantGeneration");
  if (input.codeChallengeMethod !== "S256") throw new StoreInputError("codeChallengeMethod must be S256");
}

export function validateRefreshToken(input: SaveRefreshTokenInput): void {
  assertSha256Hex(input.tokenHash, "tokenHash");
  if (input.previousTokenHash !== null) assertSha256Hex(input.previousTokenHash, "previousTokenHash");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
  assertGrantGeneration(input.grantGeneration, "grantGeneration");
  if (input.resource !== undefined && input.resource !== null
    && (typeof input.resource !== "string" || input.resource.length === 0)) {
    throw new StoreInputError("resource must be a non-empty string or null");
  }
}

export function validateRotation(tokenHash: string, next: SaveRefreshTokenInput, nowIso: string): void {
  assertSha256Hex(tokenHash, "tokenHash");
  validateRefreshToken(next);
  assertUtcIsoTimestamp(nowIso, "nowIso");
  if (next.previousTokenHash !== tokenHash) throw new StoreInputError("next.previousTokenHash must match tokenHash");
}

export function authCodeFromRow(row: AuthCodeRow): AuthCodeRecord {
  return {
    codeHash: row.code_hash, clientId: row.client_id, subject: row.subject,
    redirectUri: row.redirect_uri, resource: row.resource,
    scopes: parseScopes(row.scopes_json), codeChallenge: row.code_challenge,
    codeChallengeMethod: row.code_challenge_method, expiresAt: row.expires_at,
    grantGeneration: grantGenerationFromStored(row.grant_generation),
  };
}

export function refreshTokenFromRow(row: RefreshTokenRow, resource?: string | null): RefreshTokenRecord {
  return {
    tokenHash: row.token_hash, familyId: row.family_id,
    previousTokenHash: row.previous_token_hash, clientId: row.client_id,
    subject: row.subject, scopes: parseScopes(row.scopes_json),
    expiresAt: row.expires_at,
    grantGeneration: grantGenerationFromStored(row.grant_generation),
    resource: resource === undefined ? resourceFromStored(row.resource) ?? null : resource,
  };
}

/** Omission is an explicit pre-0.4 legacy NULL. URL canonicalization is owned by
 *  canonicalResource before the store boundary; the store preserves exact bytes. */
export function resourceForWrite(value: string | null | undefined): string | null {
  return value === undefined ? null : value;
}

/** Distinguishes a valid SQL NULL from malformed stored data. */
export function resourceFromStored(value: unknown): string | null | undefined {
  if (value === null) return null;
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function parseScopes(value: string): string[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some((scope) => typeof scope !== "string")) {
    throw new Error("Stored scopes are invalid");
  }
  return parsed;
}
