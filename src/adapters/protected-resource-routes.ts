// Shared PRM route preflight for Fastify, Express, and Hono (contracts §9.7).
// The complete mount plan is resolved before an adapter touches its framework.

import { AuthConfigError, type AnyBridgeConfig as BridgeConfig } from "../config.ts";
import { pathInsertedProtectedResourceMetadataUrl } from "../challenge.ts";
import { buildResourceCatalog, resolveResource } from "../resource.ts";
import type { ResourceConfiguration, ResolvedResource } from "../resource.ts";

export interface ProtectedResourceRoute {
  readonly pathname: string;
  readonly resource: ResolvedResource;
}

export interface ProtectedResourceRoutePlan {
  readonly routes: readonly ProtectedResourceRoute[];
  readonly rootFallback?: ResolvedResource;
}

/** Select and preflight one adapter mount's finite resource subset. */
export function planProtectedResourceRoutes(
  config: BridgeConfig,
  protectedResources?: readonly string[],
): ProtectedResourceRoutePlan {
  const catalog = buildResourceCatalog(
    config as ResourceConfiguration,
    { allowInsecureLocalhost: config.dev?.allowInsecureLocalhost === true },
  );
  const selected = protectedResources === undefined
    ? [...catalog.entries]
    : resolveSubset(catalog, protectedResources);
  const routes = selected.map((resource) => ({
    resource,
    pathname: new URL(pathInsertedProtectedResourceMetadataUrl(resource.resource)).pathname,
  }));
  routes.forEach((route) => rejectRouteMetacharacters(route.pathname, route.resource.resource));
  rejectRouteCollisions(routes);
  const rootRoute = routes.find((route) => route.pathname === "/.well-known/oauth-protected-resource");
  const rootFallback = selected.length === 1 && rootRoute === undefined ? selected[0] : undefined;
  return Object.freeze({
    routes: Object.freeze(routes),
    ...(rootFallback === undefined ? {} : { rootFallback }),
  });
}

function resolveSubset(
  catalog: ReturnType<typeof buildResourceCatalog>,
  value: readonly string[],
): ResolvedResource[] {
  if (!Array.isArray(value)) {
    throw new AuthConfigError("protectedResources must be a non-empty array when provided");
  }
  const length = value.length;
  if (!Number.isInteger(length) || length <= 0) {
    throw new AuthConfigError("protectedResources must be a non-empty array when provided");
  }
  const snapshot = Array.from({ length }, (_, index) => value[index]);
  return snapshot.map((resource, index) => {
    if (typeof resource !== "string" || resource.length === 0) {
      throw new AuthConfigError(`protectedResources[${index}] must be a non-empty string`);
    }
    try { return resolveResource(catalog, resource); }
    catch { throw new AuthConfigError(`protectedResources[${index}] must match a configured resource: ${resource}`); }
  });
}

function rejectRouteCollisions(routes: readonly ProtectedResourceRoute[]): void {
  const seen = new Map<string, ProtectedResourceRoute>();
  for (const route of routes) {
    const identity = routeIdentity(route.pathname);
    const prior = seen.get(identity);
    if (prior !== undefined) {
      throw new AuthConfigError(
        `duplicate protected-resource route pathname "${identity}" for resources ` +
          `"${prior.resource.resource}" and "${route.resource.resource}"`,
      );
    }
    seen.set(identity, route);
  }
}

/** Routers decode percent escapes before dispatch; Express is case-insensitive by
 *  default. Compare that dispatch identity while preserving slash distinctions. */
function routeIdentity(pathname: string): string {
  let decoded: string;
  try { decoded = decodeURIComponent(pathname); }
  catch { throw new AuthConfigError(`protected-resource route pathname cannot be percent-decoded: ${pathname}`); }
  return decoded.replace(/[A-Z]/g, (char) => char.toLowerCase());
}

/** Reject router metacharacters in a computed route pathname.
 *
 *  Fastify, Express and Hono all read `:name` as a parameter and `*` as a
 *  wildcard, so a resource path containing them registers a MATCHING route
 *  rather than a literal one: a resource at `/mcp/:id` answers
 *  `/mcp/anything` and shadows a sibling resource, returning one resource's
 *  metadata for another's URL — and the pathname-collision check cannot see it,
 *  because the two literal strings differ.
 *
 *  This rejects rather than escapes: escaping differs per framework, and a
 *  resource identifier containing router syntax has no legitimate use here.
 *  Allowlist at the trust boundary — the check is on the COMPUTED pathname, so
 *  it cannot be sidestepped by percent-encoding that the URL parser resolves. */
function rejectRouteMetacharacters(pathname: string, resource: string): void {
  // ALLOWLIST, not a blocklist: a blocklist of router metacharacters was wrong
  // twice (it missed `!`, which the pinned Express/path-to-regexp reserves).
  //
  // The set is RFC 3986 `pchar` MINUS the characters the three routers actually
  // reserve. Unreserved (A-Z a-z 0-9 - . _ ~), the sub-delims that all three
  // register literally (; = & , @ $ '), plus `/` and percent-escapes. Verified
  // against Fastify, Express and Hono rather than assumed. Excluded: `: * ? { }
  // ( ) [ ] + !` — parameter, wildcard, group and optional syntax in at least
  // one router. Narrowing this further rejects resources the config accepts,
  // leaving a bridge that cannot serve its own contracted metadata route.
  const found = /[^A-Za-z0-9\-._~;=&,@$'/%]/.exec(pathname);
  if (found !== null) {
    throw new AuthConfigError(
      `resource "${resource}" produces the protected-resource route "${pathname}", which contains the ` +
        `character "${found[0]}", which is not safe to register as a literal route. ` +
        `Frameworks reserve their own metacharacters (Express rejects "!", all three read ":" and "*"), ` +
        `so only unreserved path characters, "/" and percent-escapes are accepted here.`,
    );
  }
}
