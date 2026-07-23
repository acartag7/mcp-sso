import { randomBytes, timingSafeEqual } from "node:crypto";
import type { AuditPort } from "./ports/audit.ts";
import type { ClientStore } from "./ports/client-store.ts";
import type { ClockPort } from "./ports/clock.ts";
import { OAuthError } from "./errors.ts";
import { snapshotOwnDataRecord, snapshotOwnStringArray } from "./own-property.ts";
import type { ClientSecret } from "./ports/client-store.ts";
import { isScopeToken } from "./scopes.ts";
import type { MachineClientDeps } from "./machine-client.ts";

export function inputFields(value: unknown): Readonly<Record<string, unknown>> {
  const fields = snapshotOwnDataRecord(value);
  if (fields === null) throw new OAuthError("invalid_request", "Machine-client input is malformed");
  return fields;
}

export function machineDeps(value: unknown): MachineClientDeps {
  const fields = snapshotOwnDataRecord(value);
  const catalog = fields && snapshotOwnStringArray(fields.catalog);
  if (fields === null || catalog === null || !fields.store || !fields.clock || !fields.audit) {
    throw new OAuthError("server_error", "Machine-client dependencies are malformed", 500);
  }
  return Object.freeze({
    store: fields.store as ClientStore,
    catalog: Object.freeze([...catalog]),
    clock: fields.clock as ClockPort,
    audit: fields.audit as AuditPort,
  });
}

export function validateAllowedScopes(input: unknown, catalog: readonly string[]): string[] {
  const values = snapshotOwnStringArray(input);
  if (values === null || values.length === 0) {
    throw new OAuthError("invalid_scope", "allowedScopes must be a non-empty array");
  }
  const allowed = new Set(catalog);
  const out: string[] = [];
  for (const scope of values) {
    if (!isScopeToken(scope)) {
      throw new OAuthError("invalid_scope", "allowedScopes entries must be single RFC 6749 scope tokens");
    }
    if (!allowed.has(scope)) {
      throw new OAuthError("invalid_scope", "allowedScopes must be a subset of scopeCatalog");
    }
    if (!out.includes(scope)) out.push(scope);
  }
  return out;
}

export function timingSafeHexEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

export function isPositiveInteger(value: number): boolean {
  return Number.isInteger(value) && value > 0;
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

/** The exported pure rotation model historically accepts opaque test/model
 * hashes. Stored machine-client records use the stricter SHA-256 parser. */
export function snapshotRotationSecret(value: unknown): ClientSecret | null {
  const fields = snapshotOwnDataRecord(value);
  if (fields === null || typeof fields.hash !== "string" || fields.hash.length === 0
    || !nonnegativeInteger(fields.createdAtEpoch)
    || (fields.expiresAtEpoch !== undefined && !nonnegativeInteger(fields.expiresAtEpoch))) {
    return null;
  }
  return Object.freeze({
    hash: fields.hash,
    createdAtEpoch: fields.createdAtEpoch,
    expiresAtEpoch: fields.expiresAtEpoch as number | undefined,
  });
}

function nonnegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}
