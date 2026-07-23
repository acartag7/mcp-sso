import { snapshotOwnDataRecord, snapshotOwnStringArray } from "../own-property.ts";
import type { GenericOidcConfig } from "./generic-oidc-types.ts";
import type { GenericOidcManualEndpoints } from "./generic-oidc-discovery.ts";

export function snapshotGenericOidcConfig(value: unknown): Readonly<GenericOidcConfig> {
  const fields = snapshotOwnDataRecord(value);
  if (fields === null) throw new Error("generic_oidc_bad_config: config must be a data object");
  for (const key of ["issuer", "clientId", "redirectUri"] as const) {
    if (typeof fields[key] !== "string" || !(fields[key] as string).trim()) {
      throw new Error(`generic_oidc_bad_config: ${key} must be a non-empty string`);
    }
  }
  if (fields.clientSecret !== undefined
    && (typeof fields.clientSecret !== "string" || !fields.clientSecret.trim())) {
    throw new Error("generic_oidc_bad_config: clientSecret must be a non-empty string if set");
  }
  if (fields.scopes !== undefined && (typeof fields.scopes !== "string"
    || !fields.scopes.trim() || !fields.scopes.split(/\s+/).includes("openid"))) {
    throw new Error(
      "generic_oidc_bad_config: scopes must be a non-empty, space-separated list including 'openid' (omit for the default 'openid profile email')",
    );
  }
  if (fields.tokenEndpointAuthMethod !== undefined
    && fields.tokenEndpointAuthMethod !== "client_secret_post"
    && fields.tokenEndpointAuthMethod !== "client_secret_basic") {
    throw new Error("generic_oidc_bad_config: tokenEndpointAuthMethod is invalid");
  }
  for (const key of ["allowEmailAllowlist", "allowProviderWithoutPkce"] as const) {
    if (fields[key] !== undefined && typeof fields[key] !== "boolean") {
      throw new Error(`generic_oidc_bad_config: ${key} must be boolean when present`);
    }
  }
  const subjectAllowlist = fields.subjectAllowlist === undefined
    ? undefined : snapshotOwnStringArray(fields.subjectAllowlist);
  if (subjectAllowlist === null) {
    throw new Error("generic_oidc_bad_config: subjectAllowlist must be a dense string array");
  }
  const endpoints = snapshotEndpoints(fields.endpoints);
  return Object.freeze({
    issuer: fields.issuer,
    clientId: fields.clientId,
    clientSecret: fields.clientSecret as string | undefined,
    tokenEndpointAuthMethod: fields.tokenEndpointAuthMethod as GenericOidcConfig["tokenEndpointAuthMethod"],
    redirectUri: fields.redirectUri,
    endpoints,
    scopes: fields.scopes as string | undefined,
    subjectAllowlist: subjectAllowlist && Object.freeze([...subjectAllowlist]) as string[],
    allowEmailAllowlist: fields.allowEmailAllowlist === true,
    allowProviderWithoutPkce: fields.allowProviderWithoutPkce === true,
  }) as Readonly<GenericOidcConfig>;
}

function snapshotEndpoints(value: unknown): GenericOidcConfig["endpoints"] {
  if (value === "discover") return value;
  const fields = snapshotOwnDataRecord(value);
  if (fields === null) throw new Error("generic_oidc_bad_config: endpoints must be discover or a data object");
  for (const key of ["authorizationEndpoint", "tokenEndpoint", "jwksUri"] as const) {
    if (typeof fields[key] !== "string" || !fields[key]) {
      throw new Error(`generic_oidc_bad_config: endpoints.${key} is required`);
    }
  }
  return Object.freeze({
    authorizationEndpoint: fields.authorizationEndpoint,
    tokenEndpoint: fields.tokenEndpoint,
    jwksUri: fields.jwksUri,
  }) as GenericOidcManualEndpoints;
}
