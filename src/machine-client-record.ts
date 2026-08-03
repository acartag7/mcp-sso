import type {
  ActiveMachineClientRegistration,
  ClientSecret,
  DisabledMachineClientRegistration,
} from "./ports/client-store.ts";
import { snapshotBoundedScopeList } from "./scopes.ts";

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const MAX_ACTIVE_SECRETS = 2;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** A parsed legacy row can retain expired history until its first mutation.
 * New versioned writes use the stricter tuple from the public store contract. */
export type ParsedActiveMachineClientRegistration =
  Omit<ActiveMachineClientRegistration, "secrets"> & { secrets: ClientSecret[] };

export type ParsedMachineClientRegistration =
  | ParsedActiveMachineClientRegistration
  | DisabledMachineClientRegistration;

interface MachineClientRecordSnapshot {
  clientId: unknown;
  redirectUris: unknown;
  applicationType: unknown;
  issuedAtEpoch: unknown;
  name: unknown;
  allowedScopes: unknown;
  resource: unknown;
  secrets: unknown;
  hasStatus: boolean;
  status: unknown;
  hasVersion: boolean;
  version: unknown;
  hasDisabledAtEpoch: boolean;
  disabledAtEpoch: unknown;
}

/** Parse the persisted §17.2 machine-client shape and bind it to the lookup key.
 * A resource-bound row with no lifecycle markers normalizes to active version 0.
 * Returns a fresh known-field snapshot so custom-store data is not republished. */
export function parseMachineClientRegistration(
  value: unknown,
  expectedClientId: string,
  nowEpoch: number,
): ParsedMachineClientRegistration | null {
  try {
    return parseMachineClientRegistrationRecord(value, expectedClientId, nowEpoch);
  } catch {
    return null;
  }
}

function parseMachineClientRegistrationRecord(
  value: unknown,
  expectedClientId: string,
  nowEpoch: number,
): ParsedMachineClientRegistration | null {
  if (value === null || typeof value !== "object" || !isEpoch(nowEpoch)) return null;
  const {
    clientId, redirectUris, applicationType, issuedAtEpoch, name, allowedScopes: rawAllowedScopes,
    resource: rawResource, secrets: rawSecrets, hasStatus, status, hasVersion, version,
    hasDisabledAtEpoch, disabledAtEpoch,
  } = snapshotMachineClientRecord(value);
  if (typeof clientId !== "string"
    || clientId !== expectedClientId
    || !clientId.startsWith("mcc_")
    || applicationType !== "machine"
    || !Array.isArray(redirectUris)
    || redirectUris.length !== 0
    || !isEpoch(issuedAtEpoch)
    || (name !== undefined && (typeof name !== "string" || name.length === 0))) return null;

  const allowedScopes = parseAllowedScopes(rawAllowedScopes);
  const resource = parseMachineClientResource(rawResource);
  if (!allowedScopes || !resource) return null;
  const base = {
    clientId,
    redirectUris: [] as [],
    applicationType: "machine" as const,
    issuedAtEpoch,
    ...(name === undefined ? {} : { name: name as string }),
    allowedScopes,
    resource,
  };

  if (!hasStatus && !hasVersion) {
    const secrets = parseSecrets(rawSecrets, nowEpoch);
    return secrets ? { ...base, status: "active", version: 0, secrets } : null;
  }
  if (!hasStatus || !hasVersion || !isVersion(version)) return null;

  if (status === "active") {
    if (hasDisabledAtEpoch) return null;
    const secrets = parseSecrets(rawSecrets, nowEpoch);
    if (!secrets || secrets.length < 1 || secrets.length > MAX_ACTIVE_SECRETS) return null;
    return { ...base, status: "active", version, secrets };
  }
  if (status === "disabled") {
    if (!Array.isArray(rawSecrets)
      || rawSecrets.length !== 0
      || !isEpoch(disabledAtEpoch)) return null;
    return {
      ...base,
      status: "disabled",
      version,
      secrets: [],
      disabledAtEpoch,
    };
  }
  return null;
}

function snapshotMachineClientRecord(value: object): MachineClientRecordSnapshot {
  const record = value as Record<string, unknown>;
  const clientId = record.clientId;
  const redirectUris = record.redirectUris;
  const applicationType = record.applicationType;
  const issuedAtEpoch = record.issuedAtEpoch;
  const name = record.name;
  const allowedScopes = record.allowedScopes;
  const resource = record.resource;
  const secrets = record.secrets;
  const hasStatus = Object.hasOwn(record, "status");
  const status = record.status;
  const hasVersion = Object.hasOwn(record, "version");
  const version = record.version;
  const hasDisabledAtEpoch = Object.hasOwn(record, "disabledAtEpoch");
  const disabledAtEpoch = record.disabledAtEpoch;
  return {
    clientId, redirectUris, applicationType, issuedAtEpoch, name, allowedScopes, resource,
    secrets, hasStatus, status, hasVersion, version, hasDisabledAtEpoch, disabledAtEpoch,
  };
}

function parseAllowedScopes(value: unknown): string[] | null {
  const snapshot = snapshotBoundedScopeList(value);
  if ("problem" in snapshot || snapshot.scopes.length === 0) return null;
  return snapshot.scopes;
}

/** Validate a BridgeConfig-eligible stored resource without normalizing its bytes. */
export function isMachineClientResource(value: unknown): value is string {
  if (typeof value !== "string" || value.trim().length === 0) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:"
      || (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname));
  } catch {
    return false;
  }
}

function parseMachineClientResource(value: unknown): string | null {
  return isMachineClientResource(value) ? value : null;
}

function parseSecrets(value: unknown, nowEpoch: number): ClientSecret[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  const secrets: ClientSecret[] = [];
  let withoutExpiry = 0;
  let active = 0;
  for (const candidate of value) {
    if (candidate === null || typeof candidate !== "object") return null;
    const secret = candidate as Record<string, unknown>;
    const hash = secret.hash;
    const createdAtEpoch = secret.createdAtEpoch;
    const expiresAtEpoch = secret.expiresAtEpoch;
    if (typeof hash !== "string" || !SHA256_HEX_RE.test(hash)
      || !isEpoch(createdAtEpoch)
      || (expiresAtEpoch !== undefined && !isEpoch(expiresAtEpoch))) return null;
    if (expiresAtEpoch === undefined) {
      if (++withoutExpiry > 1) return null;
      active += 1;
    } else if (expiresAtEpoch > nowEpoch) {
      active += 1;
    }
    if (active > MAX_ACTIVE_SECRETS) return null;
    secrets.push({
      hash,
      createdAtEpoch,
      ...(expiresAtEpoch === undefined ? {} : { expiresAtEpoch }),
    });
  }
  return secrets;
}

function isVersion(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function isEpoch(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
