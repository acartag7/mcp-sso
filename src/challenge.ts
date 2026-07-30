// WWW-Authenticate challenge + error-redirect builders (contracts §8.2, §9.3,
// §9.7). Bearer challenges are pinned to one configured resource.

import type { AnyBridgeConfig as BridgeConfig } from "./config.ts";
import { originOf } from "./config.ts";
import { buildResourceCatalog, resolveResource } from "./resource.ts";
import type { ResourceConfiguration, ResolvedResource } from "./resource.ts";

export interface ChallengeOptions {
  /** Resource pin for the challenge PRM URL. Omission preserves singleton calls. */
  resource?: string;
  /** Retained for source compatibility. The selected resource catalog is emitted. */
  scope?: readonly string[];
  /** OAuth error code, e.g. "invalid_token" or "insufficient_scope". */
  error?: string;
  errorDescription?: string;
}

function resolvedResource(config: BridgeConfig, resource?: string): ResolvedResource {
  const catalog = buildResourceCatalog(
    config as ResourceConfiguration,
    { allowInsecureLocalhost: config.dev?.allowInsecureLocalhost === true },
  );
  return resolveResource(catalog, resource);
}

/** Internal adapter helper; callers pass a catalog-resolved canonical resource. */
export function pathInsertedProtectedResourceMetadataUrl(resource: string): string {
  const root = `${originOf(resource)}/.well-known/oauth-protected-resource`;
  const pathname = new URL(resource).pathname;
  return pathname === "/" ? root : `${root}${pathname}`;
}

/** The canonical PRM URL. A one-argument singleton call keeps the legacy root
 *  form; a resource-taking call emits the resource's path-inserted form. */
export function protectedResourceMetadataUrl(config: BridgeConfig, resource?: string): string {
  const resolved = resolvedResource(config, resource);
  if (resource === undefined) return `${originOf(resolved.resource)}/.well-known/oauth-protected-resource`;
  return pathInsertedProtectedResourceMetadataUrl(resolved.resource);
}

/** Build the exact `WWW-Authenticate` value for a 401/403. Scope is always the
 *  selected resource's catalog, never the authorization-server scope union. */
export function buildUnauthorizedChallenge(config: BridgeConfig, opts: ChallengeOptions = {}): string {
  const resolved = resolvedResource(config, opts.resource);
  const params = [
    `Bearer resource_metadata="${opts.resource === undefined
      ? `${originOf(resolved.resource)}/.well-known/oauth-protected-resource`
      : pathInsertedProtectedResourceMetadataUrl(resolved.resource)}"`,
    `scope="${resolved.scopeCatalog.join(" ")}"`,
  ];
  if (opts.error) {
    params.push(`error="${opts.error}"`);
    if (opts.errorDescription) params.push(`error_description="${escapeQuoted(opts.errorDescription)}"`);
  }
  return params.join(", ");
}

/** Build the `WWW-Authenticate: Basic` challenge for failed client authentication. */
export function buildBasicClientChallenge(config: BridgeConfig): string {
  return `Basic realm="${escapeQuoted(config.issuer)}", charset="UTF-8"`;
}

/** Build an RFC 6749 §4.1.2.1 error redirect. The redirect_uri is already
 *  validated by the caller. */
export function buildErrorRedirect(redirectUri: string, code: string, state?: string, description?: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set("error", code);
  if (state) url.searchParams.set("state", state);
  if (description) url.searchParams.set("error_description", description);
  url.hash = "";
  return url.href;
}

function escapeQuoted(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}
