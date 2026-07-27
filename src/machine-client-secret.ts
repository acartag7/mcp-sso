import { randomBytes, timingSafeEqual } from "node:crypto";
import type {
  ActiveMachineClientRegistration,
  ActiveClientSecrets,
  ClientRegistration,
  ClientSecret,
} from "./ports/client-store.ts";
import type { ClockPort } from "./ports/clock.ts";
import { sha256Hex } from "./crypto.ts";
import { OAuthError } from "./errors.ts";
import { isScopeToken } from "./scopes.ts";

const MAX_ACTIVE_SECRETS = 2;
const ZERO_HASH = "0".repeat(64);
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

export function validateAllowedScopes(input: unknown, catalog: readonly string[]): string[] {
  if (!Array.isArray(input) || input.length === 0) {
    throw new OAuthError("invalid_scope", "allowedScopes must be a non-empty array");
  }
  const allowed = new Set(catalog);
  const out: string[] = [];
  for (const scope of input) {
    if (typeof scope !== "string" || !isScopeToken(scope)) {
      throw new OAuthError("invalid_scope", "allowedScopes entries must be single RFC 6749 scope tokens");
    }
    if (!allowed.has(scope)) {
      throw new OAuthError("invalid_scope", "allowedScopes must be a subset of scopeCatalog");
    }
    if (!out.includes(scope)) out.push(scope);
  }
  return out;
}

export function verifyPresentedHash(
  client: ClientRegistration | null,
  presented: string,
  now: number,
): boolean {
  let active: string[] = [];
  if (
    client?.applicationType === "machine"
    && client.status === "active"
    && Number.isSafeInteger(client.version)
    && client.version > 0
    && isActiveSecretSet(client.secrets)
  ) {
    active = client.secrets
      .filter((secret): secret is ClientSecret => isValidSecret(secret))
      .filter((secret) => secret.expiresAtEpoch === undefined || secret.expiresAtEpoch > now)
      .map((secret) => secret.hash);
    if (active.length === 0) active = [];
  }
  let matched = false;
  for (let index = 0; index < MAX_ACTIVE_SECRETS; index++) {
    if (timingSafeHexEqual(presented, active[index] ?? ZERO_HASH)) matched = true;
  }
  return matched;
}

export function requireActiveMachineClient(
  client: ClientRegistration | null,
): ActiveMachineClientRegistration {
  if (
    !client
    || client.applicationType !== "machine"
    || client.status !== "active"
    || !Number.isSafeInteger(client.version)
    || client.version < 1
    || client.version >= Number.MAX_SAFE_INTEGER
    || !isActiveSecretSet(client.secrets)
  ) {
    throw new OAuthError("invalid_client", "Unknown or inactive machine client", 401);
  }
  return client;
}

export function rotateSecrets(
  existing: readonly ClientSecret[],
  now: number,
  graceSeconds: number,
  newHash: string,
): ActiveClientSecrets {
  const unexpired = existing.filter(
    (secret) => secret.expiresAtEpoch === undefined || secret.expiresAtEpoch > now,
  );
  if (unexpired.length === 0) return [{ hash: newHash, createdAtEpoch: now }];
  const demoteSource = unexpired.find((secret) => secret.expiresAtEpoch === undefined)
    ?? [...unexpired].sort((a, b) => b.createdAtEpoch - a.createdAtEpoch)[0]!;
  return [
    {
      hash: demoteSource.hash,
      createdAtEpoch: demoteSource.createdAtEpoch,
      expiresAtEpoch: now + graceSeconds,
    },
    { hash: newHash, createdAtEpoch: now },
  ];
}

export function isPositiveInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

export function epochSeconds(clock: ClockPort): number {
  return Math.floor(clock.nowMs() / 1000);
}

export function mintMachineClientId(): string {
  return `mcc_${randomBytes(16).toString("base64url")}`;
}

export function mintClientSecret(): string {
  return `mcs_${randomBytes(32).toString("base64url")}`;
}

function isValidSecret(value: unknown): value is ClientSecret {
  if (value === null || typeof value !== "object") return false;
  const secret = value as Partial<ClientSecret>;
  return typeof secret.hash === "string"
    && SHA256_HEX_RE.test(secret.hash)
    && Number.isSafeInteger(secret.createdAtEpoch)
    && secret.createdAtEpoch! >= 0
    && (secret.expiresAtEpoch === undefined
      || (Number.isSafeInteger(secret.expiresAtEpoch) && secret.expiresAtEpoch >= 0));
}

function isActiveSecretSet(value: unknown): value is ActiveClientSecrets {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_ACTIVE_SECRETS) {
    return false;
  }
  if (!value.every((secret) => isValidSecret(secret))) return false;
  return value.length === 1
    || value.filter((secret) => secret.expiresAtEpoch === undefined).length === 1;
}

function timingSafeHexEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  if (leftBytes.length !== rightBytes.length) return false;
  return timingSafeEqual(leftBytes, rightBytes);
}

export function hashMachineClientSecret(secret: string): string {
  return sha256Hex(secret);
}
