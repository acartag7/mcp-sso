// RFC 8414 AS metadata + RFC 9728 Protected Resource Metadata builders
// (contracts §9.1, §9.7). Each PRM is resource-specific and carries no jwks_uri:
// in RFC 9728 that field is the resource server's own key set, not the AS's.

import type { JWK } from "jose";
import type { AnyBridgeConfig as BridgeConfig } from "./config.ts";
import { originOf } from "./config.ts";
import { publicJwk } from "./crypto.ts";
import { buildResourceCatalog, resolveResource, scopeUnion } from "./resource.ts";
import type { ResourceConfiguration } from "./resource.ts";

function catalog(config: BridgeConfig) {
  return buildResourceCatalog(
    config as ResourceConfiguration,
    { allowInsecureLocalhost: config.dev?.allowInsecureLocalhost === true },
  );
}

/** RFC 8414 authorization-server metadata. `scopes_supported` is emitted ONLY
 *  for a single-resource catalog (where it equals that resource's own set); with
 *  several resources it is omitted rather than published as a cross-resource
 *  union no single resource honours. Resource documents below are always
 *  resource-specific. */
export function authorizationServerMetadata(config: BridgeConfig): Record<string, unknown> {
  const built = catalog(config);
  const entries = built.entries;
  const ccEnabled = config.clientCredentials?.enabled === true;
  return {
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/oauth/authorize`,
    token_endpoint: `${config.issuer}/oauth/token`,
    jwks_uri: `${config.issuer}/oauth/jwks`,
    registration_endpoint: `${config.issuer}/oauth/register`,
    revocation_endpoint: `${config.issuer}/oauth/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ccEnabled
      ? ["authorization_code", "refresh_token", "client_credentials"]
      : ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ccEnabled
      ? ["none", "client_secret_basic", "client_secret_post"]
      : ["none"],
    // RFC 8414 makes `scopes_supported` OPTIONAL, and it is omitted when more
    // than one resource is configured. The AS-level value would have to be the
    // union across resources, and a client that reads its scope set from here
    // (rather than from the per-resource PRM) then builds a request no single
    // resource can satisfy — observed live: Codex CLI 0.146.0 requested the
    // full union against one resource and was rejected `invalid_scope`.
    // Omitting the field forces clients to the PRM, which carries the
    // authoritative per-resource catalog. A singleton catalog keeps the field:
    // there the union IS the resource's own set, so it is accurate.
    ...(entries.length === 1 ? { scopes_supported: scopeUnion(built) } : {}),
    authorization_response_iss_parameter_supported: true,
    ...(config.cimd?.enabled === true ? { client_id_metadata_document_supported: true } : {}),
  };
}

/** RFC 9728 metadata for exactly one configured resource. Omission is supported
 *  only when the catalog contains one entry. */
export function protectedResourceMetadata(config: BridgeConfig, resource?: string): Record<string, unknown> {
  const resolved = resolveResource(catalog(config), resource);
  return {
    resource: resolved.resource,
    authorization_servers: [config.issuer],
    scopes_supported: resolved.scopeCatalog,
  };
}

/** Root and canonical path-inserted PRM URLs for one resolved resource. */
export function protectedResourceMetadataUrls(config: BridgeConfig, resource?: string): { root: string; pathInserted: string } {
  const resolved = resolveResource(catalog(config), resource).resource;
  const root = `${originOf(resolved)}/.well-known/oauth-protected-resource`;
  const pathname = new URL(resolved).pathname;
  return { root, pathInserted: pathname === "/" ? root : `${root}${pathname}` };
}

/** JWKS document for /oauth/jwks. */
export function jwks(config: BridgeConfig): { keys: JWK[] } {
  return { keys: [publicJwk(config)] };
}
