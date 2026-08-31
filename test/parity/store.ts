import type { ClientRegistration, ClientStore, UserClientRegistration } from "../../src/ports/client-store.ts";
import {
  STORED_DCR_GRANT_GENERATION, STORED_DCR_RESOURCE_BINDING, StoreInputError,
  UNBOUND_REFRESH_RESOURCE, assertGrantGeneration, assertRefreshResource, assertSha256Hex,
  assertStoreInstanceId, assertStoreSubject, assertUtcIsoTimestamp, grantGenerationForWrite,
  normalizeRefreshTokenWrite,
  type AuthCodeRecord, type ConsentApprovalCommitResult, type RefreshTokenRecord,
  type SaveAuthCodeInput, type SaveRefreshTokenInput, type StorePort,
} from "../../src/ports/store.ts";
import { randomBytesFrom, type RandomPort } from "../../src/ports/random.ts";
import type { ClockPort } from "../../src/ports/clock.ts";
import { StoreExpiryLifecycle } from "../../src/store/expiry-lifecycle.ts";
import { assertRegistrationRedirectPolicy } from "../../src/redirect.ts";
import type {
  AuthorizationCodeRow, ClientRegistrationRow, LogicalState, RefreshTokenRow, RevokedFamilyRow,
} from "./types.ts";
import { FixtureRunnerError } from "./error.ts";

interface StoredRefresh extends RefreshTokenRecord { consumedAt?: string }
interface Family { resource: string; grantGeneration?: number; revokedAt?: string }
const GENERATED_CLIENT_ID = /^mcpdc_[0-9a-f]{32}$/u;

export class FixtureStore implements StorePort, ClientStore {
  readonly storedDcrGrantGeneration = STORED_DCR_GRANT_GENERATION;
  readonly storedDcrResourceBinding = STORED_DCR_RESOURCE_BINDING;
  readonly #authCodes = new Map<string, AuthCodeRecord>();
  readonly #refresh = new Map<string, StoredRefresh>();
  readonly #families = new Map<string, Family>();
  readonly #jtis = new Map<string, string>();
  readonly #clients = new Map<string, ClientRegistration>();
  readonly #random: RandomPort;
  readonly #expiry = new StoreExpiryLifecycle(this, true);
  #instanceId: string;
  #closed = false;
  #sweptThrough: string | undefined;

  constructor(state: LogicalState, random: RandomPort) {
    this.#random = random;
    for (const row of uniqueRows(state.authorization_code, "code_hash", "authorization_code")) {
      this.#authCodes.set(row.code_hash, authRecord(row));
    }
    for (const row of uniqueRows(state.consent_jti, "jti", "consent_jti")) this.#jtis.set(row.jti, row.expires_at);
    for (const row of uniqueRows(state.refresh_token, "token_hash", "refresh_token")) this.#hydrateRefresh(row);
    for (const row of uniqueRows(state.revoked_family, "family_id", "revoked_family")) this.#hydrateRevocation(row);
    for (const row of uniqueRows(state.client_registration, "client_id", "client_registration")) {
      this.#clients.set(row.client_id, clientRecord(row));
    }
    const instances = state.store_instance ?? [];
    if (instances.length > 1) throw new FixtureRunnerError("state has multiple store_instance rows");
    this.#instanceId = instances[0]?.instance_id ?? randomBytesFrom(random, 18).toString("base64url");
  }

  async getStoreInstanceId(): Promise<string> { this.#open(); return this.#instanceId; }
  async rotateStoreInstanceId(): Promise<string> {
    this.#open(); this.#instanceId = randomBytesFrom(this.#random, 18).toString("base64url"); return this.#instanceId;
  }
  async commitConsentApproval(instance: string, jti: string, expires: string, code: SaveAuthCodeInput): Promise<ConsentApprovalCommitResult> {
    this.#open();
    assertStoreInstanceId(instance); assertUtcIsoTimestamp(expires, "expiresAtIso"); validateAuthCode(code);
    if (instance !== this.#instanceId) return "binding_mismatch";
    if (this.#jtis.has(jti) || (this.#sweptThrough !== undefined && expires < this.#sweptThrough)) return "replayed";
    this.#jtis.set(jti, expires); await this.saveAuthCode(code); return "stored";
  }
  async saveAuthCode(input: SaveAuthCodeInput): Promise<void> {
    this.#open(); validateAuthCode(input);
    this.#authCodes.set(input.codeHash, clone({ ...input, grantGeneration: grantGenerationForWrite(input.grantGeneration) }));
  }
  async consumeAuthCode(hash: string, now: string, generation?: number, resource?: string): Promise<AuthCodeRecord | null> {
    this.#open(); assertSha256Hex(hash, "codeHash"); assertUtcIsoTimestamp(now, "nowIso");
    const row = this.#authCodes.get(hash); if (!row) return null;
    if (resource !== undefined && row.resource !== resource) return null;
    assertStoreSubject(row.subject, "stored subject");
    this.#authCodes.delete(hash);
    return row.expiresAt > now && (generation === undefined || row.grantGeneration === generation) ? clone(row) : null;
  }
  async saveRefreshToken(input: SaveRefreshTokenInput): Promise<void> {
    this.#open(); input = normalizeRefreshTokenWrite(input); validateRefreshToken(input);
    if (this.#refresh.has(input.tokenHash)) throw new StoreInputError("tokenHash already exists");
    const generation = grantGenerationForWrite(input.grantGeneration) ?? undefined;
    const family = this.#families.get(input.familyId);
    if (family && (family.resource !== input.resource || family.grantGeneration !== generation)) {
      throw new StoreInputError("family grantGeneration or resource mismatch");
    }
    this.#families.set(input.familyId, family ?? { resource: input.resource, grantGeneration: generation });
    this.#refresh.set(input.tokenHash, clone({ ...input, grantGeneration: generation }));
  }
  async rotateRefreshToken(hash: string, next: SaveRefreshTokenInput, now: string, generation?: number, resource?: string): Promise<RefreshTokenRecord | null> {
    this.#open(); next = normalizeRefreshTokenWrite(next); validateRotation(hash, next, now);
    const current = this.#refresh.get(hash); if (!current) return null;
    const family = this.#families.get(current.familyId); if (!family) return null;
    assertStoreSubject(current.subject, "stored subject");
    if (family.revokedAt) return null;
    if (generation !== undefined && (family.grantGeneration !== generation || current.grantGeneration !== generation)) return null;
    if (current.resource === null || current.resource === UNBOUND_REFRESH_RESOURCE
      || family.resource !== current.resource
      || (resource !== undefined && current.resource !== resource)) return null;
    if (current.consumedAt) { await this.revokeRefreshTokenFamily(current.familyId, now); return null; }
    if (current.expiresAt <= now || next.familyId !== current.familyId) return null;
    if (this.#refresh.has(next.tokenHash)) return null;
    current.consumedAt = now;
    await this.saveRefreshToken({ ...next, clientId: current.clientId, subject: current.subject,
      resource: current.resource ?? "", scopes: [...current.scopes], grantGeneration: current.grantGeneration });
    return refreshRecord(current);
  }
  async revokeRefreshTokenFamily(id: string, at: string, resource?: string): Promise<void> {
    this.#open(); assertUtcIsoTimestamp(at, "revokedAtIso");
    if (resource !== undefined) assertRefreshResource(resource, "expectedResource");
    const family = this.#families.get(id);
    if (family && family.revokedAt === undefined && (resource === undefined || family.resource === resource)) family.revokedAt = at;
  }
  async findRefreshToken(hash: string): Promise<RefreshTokenRecord | null> {
    this.#open(); const row = this.#refresh.get(hash);
    if (row) assertStoreSubject(row.subject, "stored subject");
    return row ? refreshRecord(row) : null;
  }
  async consumeConsentJti(jti: string, expires: string): Promise<boolean> {
    this.#open(); assertUtcIsoTimestamp(expires, "expiresAtIso");
    if (this.#jtis.has(jti) || (this.#sweptThrough !== undefined && expires < this.#sweptThrough)) return false;
    this.#jtis.set(jti, expires); return true;
  }
  async findGrantedScopes(subject: string, client: string, now: string, generation?: number, resource?: string): Promise<string[]> {
    this.#open(); assertStoreSubject(subject); assertUtcIsoTimestamp(now, "nowIso"); const scopes: string[] = [];
    for (const row of [...this.#refresh.values()].toSorted((a, b) => a.tokenHash.localeCompare(b.tokenHash))) {
      const family = this.#families.get(row.familyId);
      if (row.subject !== subject || row.clientId !== client || row.consumedAt || row.expiresAt <= now || family?.revokedAt) continue;
      if (generation !== undefined && row.grantGeneration !== generation) continue;
      if (resource !== undefined && (row.resource !== resource || family?.resource !== resource)) continue;
      for (const scope of row.scopes) if (!scopes.includes(scope)) scopes.push(scope);
    }
    return scopes;
  }
  async sweepExpired(now: string): Promise<void> {
    this.#open(); assertUtcIsoTimestamp(now, "nowIso");
    if (this.#sweptThrough === undefined || this.#sweptThrough < now) this.#sweptThrough = now;
    for (const [hash, row] of this.#authCodes) if (row.expiresAt < now) this.#authCodes.delete(hash);
    for (const [jti, expires] of this.#jtis) if (expires < now) this.#jtis.delete(jti);
    const tokens = [...this.#refresh.values()];
    for (const [hash, row] of this.#refresh) {
      if (!tokens.some((member) => member.familyId === row.familyId && member.expiresAt >= now)) {
        this.#refresh.delete(hash);
      }
    }
    const liveFamilies = new Set([...this.#refresh.values()].map((row) => row.familyId));
    for (const family of this.#families.keys()) if (!liveFamilies.has(family)) this.#families.delete(family);
  }
  startExpiryCollection(clock: ClockPort): void { this.#open(); this.#expiry.start(clock); }
  async close(): Promise<void> {
    if (this.#closed) return;
    await this.#expiry.stop(); this.#closed = true;
  }
  async save(client: ClientRegistration): Promise<void> {
    this.#open(); const snapshot = snapshotUserClient(client);
    if (this.#clients.has(snapshot.clientId)) throw new StoreInputError("client id already exists");
    this.#clients.set(snapshot.clientId, snapshot);
  }
  async find(clientId: string): Promise<ClientRegistration | null> {
    this.#open(); if (!GENERATED_CLIENT_ID.test(clientId)) return null;
    const client = this.#clients.get(clientId); return client ? snapshotUserClient(client) : null;
  }

  snapshot(): Required<LogicalState> {
    return {
      authorization_code: [...this.#authCodes.values()].map(authRow).toSorted((a, b) => a.code_hash.localeCompare(b.code_hash)),
      consent_jti: [...this.#jtis].map(([jti, expires_at]) => ({ jti, expires_at })).toSorted((a, b) => a.jti.localeCompare(b.jti)),
      refresh_token: [...this.#refresh.values()].map(refreshRow).toSorted((a, b) => a.token_hash.localeCompare(b.token_hash)),
      revoked_family: [...this.#families].flatMap(([family_id, row]) => row.revokedAt
        ? [{ family_id, resource: row.resource, revoked_at: row.revokedAt, ...optional("grant_generation", row.grantGeneration) }] : []).toSorted((a, b) => a.family_id.localeCompare(b.family_id)),
      client_registration: [...this.#clients.values()].flatMap((row) => row.applicationType === "machine" ? [] : [clientRow(row)]).toSorted((a, b) => a.client_id.localeCompare(b.client_id)),
      store_instance: [{ instance_id: this.#instanceId }],
    };
  }

  #open(): void { if (this.#closed) throw new FixtureRunnerError("Store is closed"); }
  #hydrateRefresh(row: RefreshTokenRow): void {
    const generation = row.grant_generation;
    const current = this.#families.get(row.family_id);
    if (current && (current.resource !== row.resource || current.grantGeneration !== generation)) throw new FixtureRunnerError("pre-state refresh family mismatch");
    this.#families.set(row.family_id, current ?? { resource: row.resource, grantGeneration: generation });
    this.#refresh.set(row.token_hash, {
      tokenHash: row.token_hash, familyId: row.family_id, previousTokenHash: row.previous_token_hash ?? null,
      clientId: row.client_id, subject: row.subject, resource: row.resource, scopes: [...row.scopes],
      expiresAt: row.expires_at, grantGeneration: generation, consumedAt: row.consumed_at,
    });
  }
  #hydrateRevocation(row: RevokedFamilyRow): void {
    const current = this.#families.get(row.family_id);
    if (current && (current.resource !== row.resource || current.grantGeneration !== row.grant_generation)) throw new FixtureRunnerError("pre-state revoked family mismatch");
    this.#families.set(row.family_id, { resource: row.resource, grantGeneration: row.grant_generation, revokedAt: row.revoked_at });
  }
}

function uniqueRows<T extends object, K extends keyof T>(rows: T[] | undefined, key: K, kind: string): T[] {
  const seen = new Set<T[K]>();
  for (const row of rows ?? []) { if (seen.has(row[key])) throw new FixtureRunnerError(`${kind} has duplicate primary key`); seen.add(row[key]); }
  return rows ?? [];
}
function clone<T>(value: T): T { return structuredClone(value); }
function optional<K extends string>(key: K, value: number | undefined): Partial<Record<K, number>> { return value === undefined ? {} : { [key]: value } as Record<K, number>; }
function authRecord(row: AuthorizationCodeRow): AuthCodeRecord { return { codeHash: row.code_hash, clientId: row.client_id, subject: row.subject, redirectUri: row.redirect_uri, resource: row.resource, scopes: [...row.scopes], codeChallenge: row.code_challenge, codeChallengeMethod: "S256", expiresAt: row.expires_at, grantGeneration: row.grant_generation }; }
function authRow(row: AuthCodeRecord): AuthorizationCodeRow { return { code_hash: row.codeHash, client_id: row.clientId, subject: row.subject, redirect_uri: row.redirectUri, resource: row.resource, scopes: [...row.scopes], code_challenge: row.codeChallenge, code_challenge_method: "S256", expires_at: row.expiresAt, ...optional("grant_generation", row.grantGeneration ?? undefined) }; }
function refreshRecord(row: StoredRefresh): RefreshTokenRecord { const { consumedAt: _ignored, ...record } = row; return clone(record); }
function refreshRow(row: StoredRefresh): RefreshTokenRow { return { token_hash: row.tokenHash, family_id: row.familyId, ...row.previousTokenHash === null ? {} : { previous_token_hash: row.previousTokenHash }, client_id: row.clientId, subject: row.subject, resource: row.resource ?? "", scopes: [...row.scopes], expires_at: row.expiresAt, ...row.consumedAt ? { consumed_at: row.consumedAt } : {}, ...optional("grant_generation", row.grantGeneration ?? undefined) }; }
function clientRecord(row: ClientRegistrationRow): ClientRegistration { return { clientId: row.client_id, redirectUris: [...row.redirect_uris], applicationType: row.application_type, issuedAtEpoch: row.issued_at_epoch }; }
function clientRow(row: Exclude<ClientRegistration, { applicationType: "machine" }>): ClientRegistrationRow { return { client_id: row.clientId, redirect_uris: [...row.redirectUris], application_type: row.applicationType, issued_at_epoch: row.issuedAtEpoch }; }
function validateAuthCode(input: SaveAuthCodeInput): void {
  assertStoreSubject(input.subject); assertSha256Hex(input.codeHash, "codeHash");
  assertUtcIsoTimestamp(input.expiresAt, "expiresAt"); assertGrantGeneration(input.grantGeneration, "grantGeneration");
  if (input.codeChallengeMethod !== "S256") throw new StoreInputError("codeChallengeMethod must be S256");
}
function validateRefreshToken(input: SaveRefreshTokenInput, validateSubject = true): void {
  if (validateSubject) assertStoreSubject(input.subject);
  assertSha256Hex(input.tokenHash, "tokenHash");
  if (input.previousTokenHash !== null) assertSha256Hex(input.previousTokenHash, "previousTokenHash");
  assertRefreshResource(input.resource, "resource"); assertUtcIsoTimestamp(input.expiresAt, "expiresAt");
  assertGrantGeneration(input.grantGeneration, "grantGeneration");
}
function validateRotation(hash: string, next: SaveRefreshTokenInput, now: string): void {
  assertSha256Hex(hash, "tokenHash"); validateRefreshToken(next, false); assertUtcIsoTimestamp(now, "nowIso");
  if (next.previousTokenHash !== hash) throw new StoreInputError("next.previousTokenHash must match tokenHash");
}
function snapshotUserClient(value: unknown): UserClientRegistration {
  try {
    if (value === null || typeof value !== "object") throw invalidClient();
    const record = value as Record<string, unknown>;
    const { clientId, applicationType, issuedAtEpoch } = record;
    if (typeof clientId !== "string" || !GENERATED_CLIENT_ID.test(clientId)) throw invalidClient();
    if (applicationType !== "native" && applicationType !== "web") throw invalidClient();
    if (!Number.isSafeInteger(issuedAtEpoch) || (issuedAtEpoch as number) < 0) throw invalidClient();
    const source = record.redirectUris;
    if (!Array.isArray(source) || source.length < 1 || source.length > 16) throw invalidClient();
    const redirectUris = Array.from({ length: source.length }, (_, index) => source[index]);
    for (const redirectUri of redirectUris) assertRegistrationRedirectPolicy(redirectUri, applicationType);
    return { clientId, redirectUris: redirectUris as string[], applicationType,
      issuedAtEpoch: issuedAtEpoch as number };
  } catch (error) {
    if (error instanceof StoreInputError) throw error;
    throw invalidClient();
  }
}
function invalidClient(): StoreInputError { return new StoreInputError("client registration is invalid"); }
