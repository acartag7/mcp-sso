import type { ClientRegistration, UserClientRegistration } from "../../src/ports/client-store.ts";
import type { AuthCodeRecord, RefreshTokenRecord } from "../../src/ports/store.ts";
import { UNBOUND_REFRESH_RESOURCE, grantGenerationFromStored, refreshResourceFromStored } from "../../src/ports/store.ts";
import { FixtureRunnerError } from "./error.ts";
import type {
  AuthorizationCodeRow, ClientRegistrationRow, ConsentJtiRow, LogicalState,
  RefreshTokenRow, RevokedFamilyRow,
} from "./types.ts";

export interface StoredRefresh extends RefreshTokenRecord {
  consumedAt?: string;
}

export interface RefreshFamily {
  resource: string;
  grantGeneration: number | null;
  revokedAt?: string;
}

export interface LogicalTables {
  authCodes: Map<string, AuthCodeRecord>;
  consentJtis: Map<string, string>;
  refreshTokens: Map<string, StoredRefresh>;
  families: Map<string, RefreshFamily>;
  clients: Map<string, ClientRegistration>;
  instanceId: string | undefined;
  /** The consent-replay sweep watermark the row's store already performed, so a
   *  chained fixture inherits the sweep an earlier member performed. */
  sweptThrough: string | undefined;
}

export function hydrateLogicalState(state: LogicalState): LogicalTables {
  const tables: LogicalTables = {
    authCodes: new Map(), consentJtis: new Map(), refreshTokens: new Map(),
    families: new Map(), clients: new Map(), instanceId: undefined, sweptThrough: undefined,
  };
  for (const row of uniqueRows(state.authorization_code, (r) => r.code_hash, "authorization_code")) {
    tables.authCodes.set(row.code_hash, authRecord(row));
  }
  for (const row of uniqueRows(state.consent_jti, (r) => r.jti, "consent_jti")) {
    tables.consentJtis.set(row.jti, row.expires_at);
  }
  for (const row of uniqueRows(state.refresh_token, (r) => r.token_hash, "refresh_token")) {
    hydrateRefresh(tables, row);
  }
  for (const row of uniqueRows(state.revoked_family, (r) => r.family_id, "revoked_family")) {
    hydrateRevocation(tables, row);
  }
  for (const row of uniqueRows(state.client_registration, (r) => r.client_id, "client_registration")) {
    tables.clients.set(row.client_id, clientRecord(row));
  }
  const instances = uniqueRows(state.store_instance, (r) => r.instance_id, "store_instance");
  if (instances.length > 1) throw new FixtureRunnerError("state has multiple store_instance rows");
  tables.instanceId = instances[0]?.instance_id;
  tables.sweptThrough = instances[0]?.swept_through;
  return tables;
}

export function projectLogicalState(tables: LogicalTables, instanceId: string): Required<LogicalState> {
  assertProjectableTables(tables);
  const jtis: ConsentJtiRow[] = [...tables.consentJtis].map(([jti, expiresAt]) => ({ jti, expires_at: expiresAt }));
  return {
    authorization_code: sortRows([...tables.authCodes.values()].map(authRow), (row) => row.code_hash),
    consent_jti: sortRows(jtis, (row) => row.jti),
    refresh_token: sortRows([...tables.refreshTokens.values()].map(refreshRow), (row) => row.token_hash),
    revoked_family: sortRows(revokedFamilyRows(tables.families), (row) => row.family_id),
    client_registration: sortRows(userClientRows(tables.clients), (row) => row.client_id),
    store_instance: [{ instance_id: instanceId, ...optional("swept_through", tables.sweptThrough) }],
  };
}

/** A snapshot certifies the store mutation that produced it, so every invariant
 *  the tables must hold is re-checked here before a row is built. `consentJtis`
 *  and `families` are keyed by the id itself and hold no embedded id, so they
 *  have no key that could disagree. A revoked family with no refresh rows stays
 *  valid: revocation outlives the sweep that removes its tokens. */
function assertProjectableTables(tables: LogicalTables): void {
  assertKeyedById(tables.authCodes, (record) => record.codeHash, "authorization_code");
  assertKeyedById(tables.refreshTokens, (record) => record.tokenHash, "refresh_token");
  assertKeyedById(tables.clients, (record) => record.clientId, "client_registration");
  const referenced = new Set<string>();
  for (const record of tables.refreshTokens.values()) {
    const label = `refresh_token ${record.tokenHash}`;
    const resource = projectableResource(record.resource, label);
    const family = tables.families.get(record.familyId);
    if (family === undefined) throw new FixtureRunnerError(`${label} has no family`);
    if (family.resource !== resource || family.grantGeneration !== record.grantGeneration) {
      throw new FixtureRunnerError("projected refresh family mismatch");
    }
    referenced.add(record.familyId);
  }
  for (const [familyId, family] of tables.families) {
    if (family.revokedAt === undefined && !referenced.has(familyId)) {
      throw new FixtureRunnerError(`family ${familyId} has no refresh rows`);
    }
  }
}

/** A row is looked up by its map key, so a key that is not the record's own id
 *  projects a primary key nothing can find again. */
function assertKeyedById<Row>(table: Map<string, Row>, id: (record: Row) => string, kind: string): void {
  for (const [key, record] of table) {
    if (key !== id(record)) throw new FixtureRunnerError(`${kind} map key does not match its record`);
  }
}

function uniqueRows<Row>(rows: Row[] | undefined, key: (row: Row) => string, kind: string): Row[] {
  const present = rows ?? [];
  const seen = new Set<string>();
  for (const row of present) {
    const value = key(row);
    if (seen.has(value)) throw new FixtureRunnerError(`${kind} has duplicate primary key`);
    seen.add(value);
  }
  return present;
}

function hydrateRefresh(tables: LogicalTables, row: RefreshTokenRow): void {
  const grantGeneration = grantGenerationFromStored(row.grant_generation);
  const current = agreeingFamily(tables, row.family_id, row.resource, grantGeneration, "refresh");
  tables.families.set(row.family_id, current ?? { resource: row.resource, grantGeneration });
  tables.refreshTokens.set(row.token_hash, {
    tokenHash: row.token_hash, familyId: row.family_id,
    previousTokenHash: row.previous_token_hash ?? null,
    clientId: row.client_id, subject: row.subject, resource: row.resource,
    scopes: [...row.scopes], expiresAt: row.expires_at, grantGeneration,
    ...optional("consumedAt", row.consumed_at),
  });
}

function hydrateRevocation(tables: LogicalTables, row: RevokedFamilyRow): void {
  const grantGeneration = grantGenerationFromStored(row.grant_generation);
  agreeingFamily(tables, row.family_id, row.resource, grantGeneration, "revoked");
  tables.families.set(row.family_id, { resource: row.resource, grantGeneration, revokedAt: row.revoked_at });
}

function agreeingFamily(
  tables: LogicalTables,
  familyId: string,
  resource: string,
  grantGeneration: number | null,
  kind: "refresh" | "revoked",
): RefreshFamily | undefined {
  const current = tables.families.get(familyId);
  if (current && (current.resource !== resource || current.grantGeneration !== grantGeneration)) {
    throw new FixtureRunnerError(`pre-state ${kind} family mismatch`);
  }
  return current;
}

function authRecord(row: AuthorizationCodeRow): AuthCodeRecord {
  return {
    codeHash: row.code_hash, clientId: row.client_id, subject: row.subject,
    redirectUri: row.redirect_uri, resource: row.resource, scopes: [...row.scopes],
    codeChallenge: row.code_challenge, codeChallengeMethod: row.code_challenge_method,
    expiresAt: row.expires_at, grantGeneration: grantGenerationFromStored(row.grant_generation),
  };
}

function clientRecord(row: ClientRegistrationRow): UserClientRegistration {
  return {
    clientId: row.client_id, redirectUris: [...row.redirect_uris],
    applicationType: row.application_type, issuedAtEpoch: row.issued_at_epoch,
  };
}

function authRow(record: AuthCodeRecord): AuthorizationCodeRow {
  return {
    code_hash: record.codeHash, client_id: record.clientId, subject: record.subject,
    redirect_uri: record.redirectUri, resource: record.resource, scopes: [...record.scopes],
    code_challenge: record.codeChallenge, code_challenge_method: record.codeChallengeMethod,
    expires_at: record.expiresAt, ...optional("grant_generation", record.grantGeneration),
  };
}

function refreshRow(record: StoredRefresh): RefreshTokenRow {
  return {
    token_hash: record.tokenHash, family_id: record.familyId,
    ...optional("previous_token_hash", record.previousTokenHash),
    client_id: record.clientId, subject: record.subject,
    resource: projectableResource(record.resource, `refresh_token ${record.tokenHash}`),
    scopes: [...record.scopes], expires_at: record.expiresAt,
    ...optional("consumed_at", record.consumedAt),
    ...optional("grant_generation", record.grantGeneration),
  };
}

function revokedFamilyRows(families: Map<string, RefreshFamily>): RevokedFamilyRow[] {
  const rows: RevokedFamilyRow[] = [];
  for (const [familyId, family] of families) {
    if (family.revokedAt === undefined) continue;
    rows.push({
      family_id: familyId,
      resource: projectableResource(family.resource, `revoked_family ${familyId}`),
      revoked_at: family.revokedAt,
      ...optional("grant_generation", family.grantGeneration),
    });
  }
  return rows;
}

function userClientRows(clients: Map<string, ClientRegistration>): ClientRegistrationRow[] {
  const rows: ClientRegistrationRow[] = [];
  for (const record of clients.values()) {
    if (record.applicationType === "machine") continue;
    rows.push({
      client_id: record.clientId, redirect_uris: [...record.redirectUris],
      application_type: record.applicationType, issued_at_epoch: record.issuedAtEpoch,
    });
  }
  return rows;
}

/** A blank, absent, or reserved-unbound stored resource has no logical form:
 *  the logical row requires a resource string and no optional member holds it. */
function projectableResource(resource: string | null, label: string): string {
  const stored = refreshResourceFromStored(resource);
  if (stored === null || stored === UNBOUND_REFRESH_RESOURCE) {
    throw new FixtureRunnerError(`${label} has no projectable resource`);
  }
  return stored;
}

/** An absent optional member is an absent own property, never one holding
 *  `undefined`, so a projected row and its JSON form carry the same keys. */
function optional<Key extends string, Value>(key: Key, value: Value | null | undefined): { [K in Key]?: Value } {
  return (value === null || value === undefined ? {} : { [key]: value }) as { [K in Key]?: Value };
}

function sortRows<Row>(rows: Row[], key: (row: Row) => string): Row[] {
  return rows.toSorted((left, right) => compareCodeUnits(key(left), key(right)));
}

function compareCodeUnits(left: string, right: string): number {
  if (left < right) return -1;
  return left > right ? 1 : 0;
}
