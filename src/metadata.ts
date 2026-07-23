// RFC 8414 AS metadata + RFC 9728 Protected Resource Metadata builders
// (contracts §9.1). The PRM is served at BOTH the root and the path-inserted
// well-known path (fix #2). The PRM does NOT carry jwks_uri — in RFC 9728 that
// field is the resource server's own key set, not the AS's signing keys.

import type { JWK } from "jose";
import type { BridgeConfig } from "./config.ts";
import { assertBridgeConfig, originOf, pathAfterOrigin } from "./config.ts";
import { publicJwk } from "./crypto.ts";
import { ownBooleanTrue, ownDataValue } from "./own-property.ts";

/** RFC 8414 authorization-server metadata. Includes RC item (a): the iss flag.
 *  The `client_credentials` grant and its confidential-client auth methods are
 *  advertised ONLY when `config.clientCredentials.enabled` (contracts §17.2) — a
 *  disabled grant is never advertised, so discovery can't steer a client to a
 *  surface the bridge would reject with `unsupported_grant_type`. `"none"` is
 *  always advertised: the user grants use PKCE public clients. */
export function authorizationServerMetadata(config: BridgeConfig): Record<string, unknown> {
  assertBridgeConfig(config);
  const ccEnabled = ownBooleanTrue(ownDataValue(config, "clientCredentials"), "enabled");
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
    scopes_supported: config.scopeCatalog,
    authorization_response_iss_parameter_supported: true,
  };
}

/** RFC 9728 protected-resource metadata (identical JSON at both served paths). */
export function protectedResourceMetadata(config: BridgeConfig): Record<string, unknown> {
  assertBridgeConfig(config);
  return {
    resource: config.resource,
    authorization_servers: [config.issuer],
    scopes_supported: config.scopeCatalog,
  };
}

/** The two URLs at which the PRM is served (root + path-inserted). */
export function protectedResourceMetadataUrls(config: BridgeConfig): { root: string; pathInserted: string } {
  assertBridgeConfig(config);
  const origin = originOf(config.resource);
  const path = pathAfterOrigin(config.resource).replace(/^\/+|\/+$/g, "");
  const root = `${origin}/.well-known/oauth-protected-resource`;
  return { root, pathInserted: path ? `${root}/${path}` : root };
}

/** JWKS document for /oauth/jwks. */
export function jwks(config: BridgeConfig): { keys: JWK[] } {
  assertBridgeConfig(config);
  return { keys: [publicJwk(config)] };
}
