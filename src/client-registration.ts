// Runtime parser for ClientStore output used by the authorization-code flow.
// The port's TypeScript return type is not a trust boundary (contracts §6.4).

import type { ApplicationType } from "./ports/client-store.ts";

export interface AuthorizationClientRegistration {
  readonly clientId: string;
  readonly redirectUris: readonly unknown[];
  readonly applicationType: ApplicationType;
  readonly issuedAtEpoch: number;
}

/** Parse one ClientStore lookup into a fresh read-once authorization snapshot.
 * Returns null for malformed, throwing, or key-mismatched runtime data. */
export function parseAuthorizationClientRegistration(
  value: unknown,
  expectedClientId: string,
): AuthorizationClientRegistration | null {
  try {
    if (value === null || typeof value !== "object") return null;
    const record = value as Record<string, unknown>;
    const clientId = record.clientId;
    const redirectUrisValue = record.redirectUris;
    const applicationType = record.applicationType;
    const issuedAtEpoch = record.issuedAtEpoch;
    if (clientId !== expectedClientId
      || !isApplicationType(applicationType)
      || !isEpoch(issuedAtEpoch)
      || !Array.isArray(redirectUrisValue)) return null;

    const length = redirectUrisValue.length;
    const expectedLength = applicationType === "machine"
      ? length === 0
      : Number.isInteger(length) && length >= 1 && length <= 16;
    if (!expectedLength) return null;
    const redirectUris = Object.freeze(Array.from(
      { length },
      (_, index) => redirectUrisValue[index],
    ));
    return Object.freeze({ clientId, redirectUris, applicationType, issuedAtEpoch });
  } catch {
    return null;
  }
}

function isApplicationType(value: unknown): value is ApplicationType {
  return value === "native" || value === "web" || value === "machine";
}

function isEpoch(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
