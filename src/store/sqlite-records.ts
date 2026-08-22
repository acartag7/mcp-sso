import type { DatabaseSync } from "node:sqlite";
import type {
  AuthCodeRecord, RefreshTokenRecord, SaveAuthCodeInput, SaveRefreshTokenInput,
} from "../ports/store.ts";
import {
  StoreInputError, assertGrantGeneration, assertSha256Hex,
  assertRefreshResource, assertStoreSubject, assertUtcIsoTimestamp, grantGenerationForWrite,
  grantGenerationFromStored, refreshResourceFromStored,
} from "../ports/store.ts";

export interface AuthCodeRow {
  code_hash: string; client_id: string; subject: string; redirect_uri: string;
  resource: string; scopes_json: string; code_challenge: string;
  code_challenge_method: "S256"; expires_at: string; grant_generation: unknown;
}
export interface RefreshTokenRow {
  token_hash: string; family_id: string; previous_token_hash: string | null;
  client_id: string; subject: string; resource: unknown; scopes_json: string; expires_at: string;
  consumed_at: string | null; grant_generation: unknown; revoked_at: string | null;
  f_grant_generation: unknown; f_resource: unknown;
}

export function insertRefreshToken(db: DatabaseSync, input: SaveRefreshTokenInput): void {
  db.prepare(`INSERT INTO oauth_refresh_tokens (
    token_hash, family_id, previous_token_hash, client_id, subject, resource, scopes_json,
    expires_at, consumed_at, grant_generation
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`).run(
    input.tokenHash, input.familyId, input.previousTokenHash, input.clientId, input.subject,
    input.resource, JSON.stringify(input.scopes), input.expiresAt,
    grantGenerationForWrite(input.grantGeneration),
  );
}

export function nextFromRow(input: SaveRefreshTokenInput, row: RefreshTokenRow): SaveRefreshTokenInput {
  assertStoreSubject(row.subject, "stored subject");
  const resource = refreshResourceFromStored(row.resource);
  if (resource === null) throw new StoreInputError("stored refresh resource is invalid");
  return {
    ...input, clientId: row.client_id, subject: row.subject,
    resource, scopes: parseScopes(row.scopes_json),
    grantGeneration: grantGenerationFromStored(row.grant_generation),
  };
}

export function revokeFamily(db: DatabaseSync, familyId: string, revokedAtIso: string, expectedResource?: string): void {
  const resourceClause = expectedResource === undefined ? "" : " AND resource = ?";
  db.prepare(
    `UPDATE oauth_refresh_token_families SET revoked_at = COALESCE(revoked_at, ?) WHERE family_id = ?${resourceClause}`,
  ).run(...(expectedResource === undefined ? [revokedAtIso, familyId] : [revokedAtIso, familyId, expectedResource]));
}

export function validateAuthCode(input: SaveAuthCodeInput): void {
  assertStoreSubject(input.subject);
  assertSha256Hex(input.codeHash, "codeHash");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
  assertGrantGeneration(input.grantGeneration, "grantGeneration");
  if (input.codeChallengeMethod !== "S256") throw new StoreInputError("codeChallengeMethod must be S256");
}

export function validateRefreshToken(input: SaveRefreshTokenInput, validateSubject = true): void {
  if (validateSubject) assertStoreSubject(input.subject);
  assertSha256Hex(input.tokenHash, "tokenHash");
  if (input.previousTokenHash !== null) assertSha256Hex(input.previousTokenHash, "previousTokenHash");
  assertRefreshResource(input.resource, "resource");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
  assertGrantGeneration(input.grantGeneration, "grantGeneration");
}

export function validateRotation(tokenHash: string, next: SaveRefreshTokenInput, nowIso: string): void {
  assertSha256Hex(tokenHash, "tokenHash");
  validateRefreshToken(next, false);
  assertUtcIsoTimestamp(nowIso, "nowIso");
  if (next.previousTokenHash !== tokenHash) throw new StoreInputError("next.previousTokenHash must match tokenHash");
}

export function authCodeFromRow(row: AuthCodeRow): AuthCodeRecord {
  assertStoreSubject(row.subject, "stored subject");
  return {
    codeHash: row.code_hash, clientId: row.client_id, subject: row.subject,
    redirectUri: row.redirect_uri, resource: row.resource,
    scopes: parseScopes(row.scopes_json), codeChallenge: row.code_challenge,
    codeChallengeMethod: row.code_challenge_method, expiresAt: row.expires_at,
    grantGeneration: grantGenerationFromStored(row.grant_generation),
  };
}

export function refreshTokenFromRow(row: RefreshTokenRow): RefreshTokenRecord {
  assertStoreSubject(row.subject, "stored subject");
  return {
    tokenHash: row.token_hash, familyId: row.family_id,
    previousTokenHash: row.previous_token_hash, clientId: row.client_id,
    subject: row.subject, resource: refreshResourceFromStored(row.resource), scopes: parseScopes(row.scopes_json),
    expiresAt: row.expires_at,
    grantGeneration: grantGenerationFromStored(row.grant_generation),
  };
}

export function parseScopes(value: string): string[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some((scope) => typeof scope !== "string")) {
    throw new Error("Stored scopes are invalid");
  }
  return parsed;
}
