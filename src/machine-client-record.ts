import type { ClientSecret, MachineClientRegistration } from "./ports/client-store.ts";
import { isScopeToken } from "./scopes.ts";

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const MAX_ACTIVE_SECRETS = 2;

/** Parse the persisted §17.2 machine-client shape and bind it to the lookup key.
 * Returns a fresh known-field snapshot so custom-store data is not republished. */
export function parseMachineClientRegistration(
  value: unknown,
  expectedClientId: string,
  nowEpoch: number,
): MachineClientRegistration | null {
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
  const secrets = parseSecrets(record.secrets, nowEpoch);
  if (!allowedScopes || !secrets) return null;
  return {
    clientId: record.clientId,
    redirectUris: [],
    applicationType: "machine",
    issuedAtEpoch: record.issuedAtEpoch,
    ...(record.name === undefined ? {} : { name: record.name as string }),
    allowedScopes,
    secrets,
  };
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

function isEpoch(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
