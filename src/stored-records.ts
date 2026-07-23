import type {
  ClientRegistration, ClientSecret, MachineClientRegistration,
  UserClientRegistration,
} from "./ports/client-store.ts";
import type {
  AuthCodeRecord, RefreshTokenRecord, SaveAuthCodeInput, SaveRefreshTokenInput,
} from "./ports/store.ts";
import { StoreInputError, assertSha256Hex, assertUtcIsoTimestamp } from "./ports/store.ts";
import { isScopeToken } from "./scopes.ts";
import {
  snapshotOwnDataArray, snapshotOwnDataRecord, snapshotOwnStringArray,
} from "./own-property.ts";

const SHA256_HEX = /^[0-9a-f]{64}$/i;
const UTC_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export function parseClientRegistration(
  value: unknown,
): ClientRegistration | null {
  const record = snapshotOwnDataRecord(value);
  if (record === null || !nonempty(record.clientId)
    || !integer(record.issuedAtEpoch)) return null;
  const redirectUris = stringArray(record.redirectUris);
  if (redirectUris === null) return null;
  if (record.applicationType === "native" || record.applicationType === "web") {
    if (redirectUris.length === 0) return null;
    return Object.freeze({
      clientId: record.clientId,
      redirectUris,
      applicationType: record.applicationType,
      issuedAtEpoch: record.issuedAtEpoch,
    }) as UserClientRegistration;
  }
  if (record.applicationType !== "machine" || redirectUris.length !== 0) return null;
  const allowedScopes = scopeArray(record.allowedScopes, true);
  const rawSecrets = snapshotOwnDataArray(record.secrets);
  if (allowedScopes === null || rawSecrets === null) return null;
  const secrets: ClientSecret[] = [];
  for (const raw of rawSecrets) {
    const secret = parseClientSecretRecord(raw);
    if (secret === null) return null;
    secrets.push(secret);
  }
  if (record.name !== undefined && !nonempty(record.name)) return null;
  return Object.freeze({
    clientId: record.clientId,
    redirectUris,
    applicationType: "machine",
    issuedAtEpoch: record.issuedAtEpoch,
    name: record.name as string | undefined,
    allowedScopes,
    secrets: Object.freeze(secrets) as ClientSecret[],
  }) as MachineClientRegistration;
}

export function parseFoundClientRegistration(
  value: unknown,
  expectedClientId: string,
): ClientRegistration | null {
  const record = parseClientRegistration(value);
  return record?.clientId === expectedClientId ? record : null;
}

function parseAuthCodeRecord(value: unknown): AuthCodeRecord | null {
  const record = snapshotOwnDataRecord(value);
  const scopes = record === null ? null : scopeArray(record.scopes);
  if (record === null || scopes === null || !digest(record.codeHash)
    || !nonempty(record.clientId) || !nonempty(record.subject)
    || !nonempty(record.redirectUri) || !nonempty(record.resource)
    || !nonempty(record.codeChallenge)
    || record.codeChallengeMethod !== "S256"
    || !timestamp(record.expiresAt)) return null;
  return Object.freeze({
    codeHash: record.codeHash,
    clientId: record.clientId,
    subject: record.subject,
    redirectUri: record.redirectUri,
    resource: record.resource,
    scopes,
    codeChallenge: record.codeChallenge,
    codeChallengeMethod: "S256",
    expiresAt: record.expiresAt,
  }) as AuthCodeRecord;
}

export function parseConsumedAuthCode(
  value: unknown,
  expected: { codeHash: string; resource: string; nowIso: string },
): AuthCodeRecord | null {
  const record = parseAuthCodeRecord(value);
  return record?.codeHash === expected.codeHash && record.resource === expected.resource
    && record.expiresAt > expected.nowIso ? record : null;
}

export function parseSaveAuthCodeInput(value: unknown): SaveAuthCodeInput | null {
  return parseAuthCodeRecord(value);
}

export function requireSaveAuthCodeInput(value: unknown): SaveAuthCodeInput {
  const parsed = parseSaveAuthCodeInput(value);
  if (parsed === null) throw new StoreInputError("auth-code input is malformed");
  return parsed;
}

function parseRefreshTokenRecord(
  value: unknown,
  allowIdentityPlaceholders = false,
): RefreshTokenRecord | null {
  const record = snapshotOwnDataRecord(value);
  const scopes = record === null ? null : scopeArray(record.scopes);
  if (record === null || scopes === null || !digest(record.tokenHash)
    || !nonempty(record.familyId)
    || (record.previousTokenHash !== null && !digest(record.previousTokenHash))
    || (allowIdentityPlaceholders
      ? typeof record.clientId !== "string" || typeof record.subject !== "string"
      : !nonempty(record.clientId) || !nonempty(record.subject))
    || !timestamp(record.expiresAt)) return null;
  return Object.freeze({
    tokenHash: record.tokenHash,
    familyId: record.familyId,
    previousTokenHash: record.previousTokenHash,
    clientId: record.clientId,
    subject: record.subject,
    scopes,
    expiresAt: record.expiresAt,
  }) as RefreshTokenRecord;
}

export function parseRotatedRefreshToken(
  value: unknown,
  expected: { tokenHash: string; familyId: string; nowIso: string },
): RefreshTokenRecord | null {
  const record = parseRefreshTokenRecord(value);
  return record?.tokenHash === expected.tokenHash && record.familyId === expected.familyId
    && record.expiresAt > expected.nowIso ? record : null;
}

export function parseFoundRefreshToken(
  value: unknown,
  expectedTokenHash: string,
): RefreshTokenRecord | null {
  const record = parseRefreshTokenRecord(value);
  return record?.tokenHash === expectedTokenHash ? record : null;
}

export function parseSaveRefreshTokenInput(value: unknown): SaveRefreshTokenInput | null {
  return parseRefreshTokenRecord(value);
}

export function requireSaveRefreshTokenInput(value: unknown): SaveRefreshTokenInput {
  const parsed = parseSaveRefreshTokenInput(value);
  if (parsed === null) throw new StoreInputError("refresh-token input is malformed");
  return parsed;
}

export function requireRotationInput(
  tokenHash: string,
  value: unknown,
  nowIso: string,
): SaveRefreshTokenInput {
  assertSha256Hex(tokenHash, "tokenHash");
  assertUtcIsoTimestamp(nowIso, "nowIso");
  // Rotation callers intentionally provide empty identity/scope placeholders;
  // every store replaces them from the consumed record in the same transaction.
  // Snapshot and validate the rest here without weakening ordinary save input.
  const parsed = parseRefreshTokenRecord(value, true);
  if (parsed === null) throw new StoreInputError("refresh-token rotation input is malformed");
  if (parsed.previousTokenHash !== tokenHash) {
    throw new StoreInputError("next.previousTokenHash must match tokenHash");
  }
  return parsed;
}

export function parseGrantedScopes(value: unknown, catalog: readonly string[]): string[] | null {
  const scopes = scopeArray(value);
  const allowed = snapshotOwnStringArray(catalog);
  return scopes !== null && allowed !== null && scopes.every((scope) => allowed.includes(scope))
    ? scopes : null;
}

export function parseClientSecretRecord(value: unknown): ClientSecret | null {
  const secret = snapshotOwnDataRecord(value);
  if (secret === null || !digest(secret.hash) || !integer(secret.createdAtEpoch)
    || (secret.expiresAtEpoch !== undefined && !integer(secret.expiresAtEpoch))) return null;
  return Object.freeze({
    hash: secret.hash,
    createdAtEpoch: secret.createdAtEpoch,
    expiresAtEpoch: secret.expiresAtEpoch as number | undefined,
  }) as ClientSecret;
}

function stringArray(value: unknown): string[] | null {
  const values = snapshotOwnStringArray(value);
  return values === null ? null : Object.freeze([...values]) as string[];
}

function scopeArray(value: unknown, requireNonempty = false): string[] | null {
  const values = snapshotOwnStringArray(value);
  if (values === null || (requireNonempty && values.length === 0)
    || !values.every(isScopeToken)) return null;
  return Object.freeze([...values]) as string[];
}

function nonempty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function integer(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function digest(value: unknown): value is string {
  return typeof value === "string" && SHA256_HEX.test(value);
}

function timestamp(value: unknown): value is string {
  return typeof value === "string" && UTC_ISO.test(value);
}
