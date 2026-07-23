import { OAuthError } from "./errors.ts";
import { snapshotOwnDataRecord, snapshotOwnStringArray } from "./own-property.ts";
import { isScopeToken } from "./scopes.ts";

export function grantFields(value: unknown): Readonly<Record<string, unknown>> {
  const fields = snapshotOwnDataRecord(value);
  if (fields === null) throw new OAuthError("invalid_request", "Token request is malformed");
  return fields;
}

export function requiredStr(value: string | undefined, label: string): string {
  if (typeof value === "string" && value) return value;
  throw new OAuthError("invalid_request", `${label} is required`);
}

export function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "string") return value;
  throw new OAuthError("invalid_request", `${label} must be a string`);
}

export function storedScopes(value: unknown, catalog: readonly string[]): string[] {
  const scopes = snapshotOwnStringArray(value);
  if (scopes === null || !scopes.every((scope) => isScopeToken(scope) && catalog.includes(scope))) {
    throw new OAuthError("invalid_grant", "Stored grant scopes are malformed");
  }
  return [...scopes];
}
