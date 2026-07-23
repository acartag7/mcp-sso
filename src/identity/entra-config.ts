import { AuthConfigError } from "../config.ts";
import { snapshotOwnDataRecord, snapshotOwnStringArray } from "../own-property.ts";
import type { EntraConfig } from "./entra-types.ts";
import { assertGroupAuthorizationMapping } from "./entra-groups.ts";

export function snapshotEntraConfig(
  value: unknown,
  scopeCatalog?: readonly string[],
): Readonly<EntraConfig> {
  const fields = snapshotOwnDataRecord(value);
  if (fields === null) throw new AuthConfigError("Entra config must be a data object");
  for (const key of ["tenantId", "clientId", "redirectUri"] as const) {
    if (typeof fields[key] !== "string" || !(fields[key] as string).trim()) {
      throw new AuthConfigError(`${key} is required (a non-empty string)`);
    }
  }
  if (fields.clientSecret !== undefined
    && (typeof fields.clientSecret !== "string" || !fields.clientSecret.trim())) {
    throw new AuthConfigError("clientSecret must be a non-empty string when present");
  }
  if (fields.allowMutableClaims !== undefined && typeof fields.allowMutableClaims !== "boolean") {
    throw new AuthConfigError("allowMutableClaims must be boolean when present");
  }
  const allowedTenantIds = optionalStringArray(fields.allowedTenantIds, "allowedTenantIds");
  const subjectAllowlist = optionalStringArray(fields.subjectAllowlist, "subjectAllowlist");
  const groupAuthorization = assertGroupAuthorizationMapping(
    fields.groupAuthorization as EntraConfig["groupAuthorization"],
    scopeCatalog,
  );
  return Object.freeze({
    tenantId: fields.tenantId,
    clientId: fields.clientId,
    clientSecret: fields.clientSecret as string | undefined,
    redirectUri: fields.redirectUri,
    allowedTenantIds,
    subjectAllowlist,
    allowMutableClaims: fields.allowMutableClaims === true,
    groupAuthorization,
  }) as Readonly<EntraConfig>;
}

function optionalStringArray(value: unknown, label: string): string[] | undefined {
  if (value === undefined) return undefined;
  const snapshot = snapshotOwnStringArray(value);
  if (snapshot === null) throw new AuthConfigError(`${label} must be a dense string array`);
  return Object.freeze([...snapshot]) as string[];
}
