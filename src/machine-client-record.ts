import type {
  ActiveMachineClientRegistration,
  ClientSecret,
  DisabledMachineClientRegistration,
} from "./ports/client-store.ts";
import { isScopeToken } from "./scopes.ts";

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const MAX_ACTIVE_SECRETS = 2;

/** A parsed legacy row can retain expired history until its first mutation.
 * New versioned writes use the stricter tuple from the public store contract. */
export type ParsedActiveMachineClientRegistration =
  Omit<ActiveMachineClientRegistration, "secrets"> & { secrets: ClientSecret[] };

export type ParsedMachineClientRegistration =
  | ParsedActiveMachineClientRegistration
  | DisabledMachineClientRegistration;

/** Parse the persisted §17.2 machine-client shape and bind it to the lookup key.
 * A complete v0.3.0 row with no lifecycle markers normalizes to active version
 * 0. Returns a fresh known-field snapshot so custom-store data is not republished. */
export function parseMachineClientRegistration(
  value: unknown,
  expectedClientId: string,
  nowEpoch: number,
): ParsedMachineClientRegistration | null {
  if (value === null || value === undefined || !isEpoch(nowEpoch)) return null;
  const record = value as Record<string, unknown>;
  if (typeof record.clientId !== "string"
    || record.clientId !== expectedClientId
    || !record.clientId.startsWith("mcc_")
    || record.applicationType !== "machine"
    || !Array.isArray(record.redirectUris)
    || record.redirectUris.length !== 0
    || !isEpoch(record.issuedAtEpoch)
    || (record.name !== undefined
      && (typeof record.name !== "string" || record.name.length === 0))) return null;

  const allowedScopes = parseAllowedScopes(record.allowedScopes);
  if (!allowedScopes) return null;
  const base = {
    clientId: record.clientId,
    redirectUris: [] as [],
    applicationType: "machine" as const,
    issuedAtEpoch: record.issuedAtEpoch,
    ...(record.name === undefined ? {} : { name: record.name as string }),
    allowedScopes,
  };

  const hasStatus = Object.hasOwn(record, "status");
  const hasVersion = Object.hasOwn(record, "version");
  if (!hasStatus && !hasVersion) {
    const secrets = parseSecrets(record.secrets, nowEpoch);
    return secrets ? { ...base, status: "active", version: 0, secrets } : null;
  }
  if (!hasStatus || !hasVersion || !isVersion(record.version)) return null;

  if (record.status === "active") {
    if (Object.hasOwn(record, "disabledAtEpoch")) return null;
    const secrets = parseSecrets(record.secrets, nowEpoch);
    if (!secrets || secrets.length < 1 || secrets.length > MAX_ACTIVE_SECRETS) return null;
    return { ...base, status: "active", version: record.version, secrets };
  }
  if (record.status === "disabled") {
    if (!Array.isArray(record.secrets)
      || record.secrets.length !== 0
      || !isEpoch(record.disabledAtEpoch)) return null;
    return {
      ...base,
      status: "disabled",
      version: record.version,
      secrets: [],
      disabledAtEpoch: record.disabledAtEpoch,
    };
  }
  return null;
}

function parseAllowedScopes(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  const scopes: string[] = [];
  for (const scope of value) {
    if (typeof scope !== "string" || !isScopeToken(scope)) return null;
    scopes.push(scope);
  }
  return scopes;
}

function parseSecrets(value: unknown, nowEpoch: number): ClientSecret[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  const secrets: ClientSecret[] = [];
  let withoutExpiry = 0;
  let active = 0;
  for (const candidate of value) {
    if (candidate === null || typeof candidate !== "object") return null;
    const secret = candidate as Record<string, unknown>;
    if (typeof secret.hash !== "string" || !SHA256_HEX_RE.test(secret.hash)
      || !isEpoch(secret.createdAtEpoch)
      || (secret.expiresAtEpoch !== undefined && !isEpoch(secret.expiresAtEpoch))) return null;
    if (secret.expiresAtEpoch === undefined) {
      if (++withoutExpiry > 1) return null;
      active += 1;
    } else if (secret.expiresAtEpoch > nowEpoch) {
      active += 1;
    }
    if (active > MAX_ACTIVE_SECRETS) return null;
    secrets.push({
      hash: secret.hash,
      createdAtEpoch: secret.createdAtEpoch,
      ...(secret.expiresAtEpoch === undefined ? {} : { expiresAtEpoch: secret.expiresAtEpoch }),
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
