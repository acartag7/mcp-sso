// Known-field snapshots for caller-supplied port results. The TypeScript return
// type is not a runtime trust boundary: a custom port can return a Proxy or an
// accessor-backed record whose property read throws a published OAuthError.
// Call these INSIDE `callPort` so every selected read stays in the provenance
// boundary and later use touches only library-owned plain data (contracts §13).

import type { IdentityResult, RedirectExchangeResult } from "./ports/identity.ts";
import type {
  AuthCodeRecord, RefreshTokenRecord, SaveRefreshTokenInput, StorePort,
} from "./ports/store.ts";
import { MAX_SCOPE_ENTRIES } from "./scopes.ts";
import { callPort } from "./port-failure.ts";
import { identitySubject, snapshotIdentityClaims } from "./identity-boundary.ts";

export async function readGrantedScopeSnapshot(
  store: StorePort,
  subject: string,
  clientId: string,
  nowIso: string,
  expectedGrantGeneration: number | undefined,
  resource: string,
): Promise<unknown> {
  return await callPort("StorePort", "findGrantedScopes", async () => snapshotPortScopeCarrier(
    await store.findGrantedScopes(subject, clientId, nowIso, expectedGrantGeneration, resource),
  ));
}

export async function consumeConsentJtiSnapshot(
  store: StorePort,
  jti: string,
  expiresAtIso: string,
): Promise<boolean> {
  return await callPort("StorePort", "consumeConsentJti", async () => {
    const consumed = await store.consumeConsentJti(jti, expiresAtIso);
    if (typeof consumed !== "boolean") {
      throw new TypeError("StorePort.consumeConsentJti must return a boolean");
    }
    return consumed;
  });
}

export async function rotateRefreshTokenSnapshot(
  store: StorePort,
  tokenHash: string,
  next: SaveRefreshTokenInput,
  rotatedAtIso: string,
  expectedGrantGeneration: number | undefined,
  resource: string,
  familyId: string,
): Promise<RefreshTokenRecord | null> {
  try {
    return await callPort("StorePort", "rotateRefreshToken", async () =>
      snapshotRefreshTokenRecord(await store.rotateRefreshToken(
        tokenHash, next, rotatedAtIso, expectedGrantGeneration, resource,
      )));
  } catch (error) {
    // The successor may have committed before the throw or unreadable return.
    await callPort("StorePort", "revokeRefreshTokenFamily", () =>
      store.revokeRefreshTokenFamily(familyId, rotatedAtIso));
    throw error;
  }
}

export function snapshotIdentityResult(value: IdentityResult): IdentityResult {
  const record = requiredRecord(value, "IdentityPort.verify result");
  const ok = record.ok;
  if (ok === false) {
    const reason = record.reason;
    return { ok: false, reason: typeof reason === "string" ? reason : "identity_rejected" };
  }
  if (ok !== true) throw new TypeError("IdentityPort.verify result must have an ok discriminant");
  const identity = requiredRecord(record.identity, "IdentityPort.verify identity");
  const subject = identitySubject(identity.subject);
  const allowedScopes = snapshotPortScopeCarrier(identity.allowedScopes);
  return {
    ok: true,
    identity: {
      subject,
      ...(allowedScopes === undefined ? {} : { allowedScopes: allowedScopes as string[] }),
    },
  };
}

export function snapshotRedirectExchangeResult(
  value: RedirectExchangeResult,
  includeClaims = false,
): RedirectExchangeResult {
  const record = requiredRecord(value, "RedirectIdentityPort.exchangeAndVerify result");
  const ok = record.ok;
  if (ok === true) {
    const identity = requiredRecord(record.identity, "redirect identity result");
    if (includeClaims) return { ok: true, identity: snapshotIdentityClaims(identity, true) };
    const subject = identitySubject(identity.subject);
    const allowedScopes = snapshotPortScopeCarrier(identity.allowedScopes);
    return {
      ok: true,
      identity: {
        subject,
        ...(allowedScopes === undefined ? {} : { allowedScopes: allowedScopes as string[] }),
      },
    };
  }
  const kind = record.kind;
  if (ok !== false || (kind !== "exchange_failed" && kind !== "identity_rejected")) {
    throw new TypeError("redirect identity result must have a valid discriminant");
  }
  const reason = record.reason;
  return { ok: false, kind, reason: typeof reason === "string" ? reason : "identity_rejected" };
}

export function snapshotAuthCodeRecord(value: AuthCodeRecord | null): AuthCodeRecord | null {
  if (value === null) return null;
  const record = requiredRecord(value, "StorePort.consumeAuthCode result");
  const snapshot = {
    codeHash: record.codeHash,
    clientId: record.clientId,
    subject: record.subject,
    redirectUri: record.redirectUri,
    resource: record.resource,
    scopes: snapshotStringArray(record.scopes),
    codeChallenge: record.codeChallenge,
    codeChallengeMethod: record.codeChallengeMethod,
    expiresAt: record.expiresAt,
    grantGeneration: record.grantGeneration,
  };
  return validAuthCodeSnapshot(snapshot) ? Object.freeze(snapshot) as AuthCodeRecord : null;
}

export function snapshotRefreshTokenRecord(value: RefreshTokenRecord | null): RefreshTokenRecord | null {
  if (value === null) return null;
  const record = requiredRecord(value, "StorePort refresh-token result");
  const snapshot = {
    tokenHash: record.tokenHash,
    familyId: record.familyId,
    previousTokenHash: record.previousTokenHash,
    clientId: record.clientId,
    subject: record.subject,
    resource: record.resource,
    scopes: snapshotStringArray(record.scopes),
    expiresAt: record.expiresAt,
    grantGeneration: record.grantGeneration,
  };
  if (!validRefreshSnapshot(snapshot)) {
    throw new TypeError("StorePort returned a malformed refresh-token record");
  }
  return Object.freeze(snapshot) as RefreshTokenRecord;
}

export function snapshotPortScopeCarrier(value: unknown): unknown {
  if (value === undefined || !Array.isArray(value)) return value;
  const length = value.length;
  if (!Number.isSafeInteger(length) || length < 0 || length > MAX_SCOPE_ENTRIES) return null;
  return Object.freeze(Array.from({ length }, (_, index) => value[index]));
}

function snapshotStringArray(value: unknown): string[] | null {
  const snapshot = snapshotPortScopeCarrier(value);
  return Array.isArray(snapshot) && snapshot.every((entry) => typeof entry === "string")
    ? [...snapshot] as string[] : null;
}

function requiredRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function validGrantGeneration(value: unknown): value is number | null | undefined {
  return value === undefined || value === null || (Number.isSafeInteger(value) && (value as number) > 0);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function validIdentitySubject(value: unknown): value is string {
  try { identitySubject(value); return true; } catch { return false; }
}

function validAuthCodeSnapshot(value: Record<string, unknown>): boolean {
  return nonEmptyString(value.codeHash)
    && nonEmptyString(value.clientId)
    && validIdentitySubject(value.subject)
    && nonEmptyString(value.redirectUri)
    && nonEmptyString(value.resource)
    && Array.isArray(value.scopes)
    && nonEmptyString(value.codeChallenge)
    && value.codeChallengeMethod === "S256"
    && nonEmptyString(value.expiresAt)
    && validGrantGeneration(value.grantGeneration);
}

function validRefreshSnapshot(value: Record<string, unknown>): boolean {
  return nonEmptyString(value.tokenHash)
    && nonEmptyString(value.familyId)
    && (value.previousTokenHash === null || nonEmptyString(value.previousTokenHash))
    && nonEmptyString(value.clientId)
    && validIdentitySubject(value.subject)
    && (value.resource === null || nonEmptyString(value.resource))
    && Array.isArray(value.scopes)
    && nonEmptyString(value.expiresAt)
    && validGrantGeneration(value.grantGeneration);
}
