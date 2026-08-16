import { randomBytes, timingSafeEqual } from "node:crypto";
import type { ActiveClientSecrets, ClientSecret } from "./ports/client-store.ts";
import { finiteClockSnapshot, type ClockPort } from "./ports/clock.ts";
import { sha256Hex } from "./crypto.ts";
import { OAuthError } from "./errors.ts";
import { isScopeToken, snapshotBoundedScopeList } from "./scopes.ts";

const MAX_ACTIVE_SECRETS = 2;
const ZERO_HASH = "0".repeat(64);

export function validateAllowedScopes(input: unknown, catalog: readonly string[]): string[] {
  const snapshot = snapshotBoundedScopeList(input);
  if ("problem" in snapshot) {
    throw new OAuthError("invalid_scope", "allowedScopes must be a bounded RFC 6749 scope list");
  }
  if (snapshot.scopes.length === 0) throw new OAuthError("invalid_scope", "allowedScopes must be a non-empty array");
  const allowed = new Set(catalog);
  const out: string[] = [];
  for (const scope of snapshot.scopes) {
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

/** Produce the exact writable active set: one new live secret and, when one
 * exists, the newest currently active secret demoted into the grace window. */
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
    ?? [...unexpired].sort((a, b) =>
      (b.expiresAtEpoch! - a.expiresAtEpoch!)
      || (b.createdAtEpoch - a.createdAtEpoch))[0]!;
  return [
    {
      hash: demoteSource.hash,
      createdAtEpoch: demoteSource.createdAtEpoch,
      expiresAtEpoch: now + graceSeconds,
    },
    { hash: newHash, createdAtEpoch: now },
  ];
}

/** Fixed two-comparison verification for already parsed active records. */
export function verifyPresentedHash(
  presentedHash: string,
  activeSecrets: readonly ClientSecret[],
  now: number,
): boolean {
  const active = activeSecrets
    .filter((secret) => secret.expiresAtEpoch === undefined || secret.expiresAtEpoch > now)
    .map((secret) => secret.hash);
  let matched = false;
  for (let index = 0; index < MAX_ACTIVE_SECRETS; index++) {
    if (timingSafeHexEqual(presentedHash, active[index] ?? ZERO_HASH)) matched = true;
  }
  return matched;
}

export function isPositiveInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

export function epochSeconds(clock: ClockPort): number {
  const epoch = Math.floor(finiteClockSnapshot(clock) / 1000);
  if (epoch < 0) throw new RangeError("ClockPort.nowMs() must not precede the Unix epoch for machine-client records");
  return epoch;
}

export function mintMachineClientId(): string {
  return `mcc_${randomBytes(16).toString("base64url")}`;
}

export function mintClientSecret(): string {
  return `mcs_${randomBytes(32).toString("base64url")}`;
}

export function hashMachineClientSecret(secret: string): string {
  return sha256Hex(secret);
}

function timingSafeHexEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  if (leftBytes.length !== rightBytes.length) return false;
  return timingSafeEqual(leftBytes, rightBytes);
}
