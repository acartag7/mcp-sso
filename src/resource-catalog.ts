// Resource catalog (contracts §5.1). Normalizes EITHER the singleton trio OR the
// `resources` array into ONE immutable internal catalog, and resolves a request
// resource against it. Every field is read exactly once from an own data
// property, so what boot validated is what the catalog publishes.

import { AuthConfigError } from "./config.ts";
import { OAuthError } from "./errors.ts";
import { isScopeToken } from "./scopes.ts";
import { canonicalResource, snapshotOwn } from "./resource.ts";
import type {
  CanonicalResourceOptions, ResolvedResource, ResourceCatalog, ResourceConfiguration, ResourceDefinition,
} from "./resource.ts";

/** Accepted own keys on a ResourceDefinition (contracts §5.1). An extra string-
 *  OR symbol-keyed own property is a boot error naming the key — a typo or secret
 *  parked on an input entry is neither ignored nor copied into the catalog.
 *  Mirrors KNOWN_CONFIG_KEYS in config.ts, including Reflect.ownKeys. */
const RESOURCE_DEF_KEYS: ReadonlySet<string> = new Set(["resource", "scopeCatalog", "defaultScopes"]);

type Loose = { resource?: unknown; scopeCatalog?: unknown; defaultScopes?: unknown; resources?: unknown; legacySingletonResource?: unknown };

/** Build the immutable catalog from EITHER the singleton trio OR `resources`.
 *  Rejects: both forms, neither form, an empty `resources` array, a partial trio,
 *  extra own keys on an entry, and duplicate canonical resources. Throws
 *  AuthConfigError (boot-time). */
export function buildResourceCatalog(input: ResourceConfiguration, options: CanonicalResourceOptions): ResourceCatalog {
  const allowInsecureLocalhost = options.allowInsecureLocalhost === true;
  if (typeof input !== "object" || input === null) {
    throw new AuthConfigError("resource configuration must be an object");
  }
  // Read every field ONCE from an own data property. Presence is decided by
  // OWNERSHIP, not by value: `{ resources: [...], resource: undefined }` declares
  // both branches and is ambiguous, so it fails closed rather than silently
  // selecting the multi-resource branch (contracts §5.1 mutual exclusion).
  const raw = snapshotOwn(input, ["resource", "scopeCatalog", "defaultScopes", "resources", "legacySingletonResource"]) as Loose;
  const hasResources = "resources" in raw;
  const hasSingleton = "resource" in raw || "scopeCatalog" in raw || "defaultScopes" in raw;
  if (hasResources && hasSingleton) {
    throw new AuthConfigError("provide either the singleton trio (resource/scopeCatalog/defaultScopes) or 'resources', not both");
  }
  if (!hasResources && !hasSingleton) {
    throw new AuthConfigError("configuration requires either the singleton resource trio or a non-empty 'resources' array");
  }
  if (hasResources) {
    if ("legacySingletonResource" in raw) {
      throw new AuthConfigError("legacySingletonResource is accepted only in the singleton form");
    }
    if (!Array.isArray(raw.resources)) {
      throw new AuthConfigError("resources must be a non-empty array");
    }
    // Capture length ONCE and read each index once, mirroring
    // snapshotRedirectAllowlist in config.ts: a Proxy that shifts `length`
    // between reads must not change the set that was validated.
    const length = raw.resources.length;
    if (!Number.isInteger(length) || length <= 0) {
      throw new AuthConfigError("resources must be a non-empty array");
    }
    const definitions = Array.from({ length }, (_, index) => (raw.resources as unknown[])[index]);
    const entries = definitions.map((def) => buildEntry(def, allowInsecureLocalhost));
    rejectDuplicateResources(entries);
    return freezeCatalog(entries, "multi", allowInsecureLocalhost, undefined);
  }
  if (!("resource" in raw) || !("scopeCatalog" in raw) || !("defaultScopes" in raw)) {
    throw new AuthConfigError("singleton form requires resource, scopeCatalog, and defaultScopes together");
  }
  const hasLegacy = "legacySingletonResource" in raw;
  if (hasLegacy && typeof raw.legacySingletonResource !== "string") {
    throw new AuthConfigError("legacySingletonResource must be a string");
  }
  const resource = canonicalResource(raw.resource, { allowInsecureLocalhost });
  const scopeCatalog = validateScopeCatalog(raw.scopeCatalog);
  const defaultScopes = validateDefaultScopes(raw.defaultScopes, scopeCatalog);
  let legacy: string | undefined;
  if (hasLegacy) {
    const legacyCanonical = canonicalResource(raw.legacySingletonResource, { allowInsecureLocalhost });
    if (legacyCanonical !== resource) {
      throw new AuthConfigError("legacySingletonResource must canonicalize exactly to resource");
    }
    legacy = legacyCanonical;
  }
  return freezeCatalog([makeEntry(resource, scopeCatalog, defaultScopes)], "singleton", allowInsecureLocalhost, legacy);
}

/** Rebuild the public resource branch from the exact immutable catalog that boot
 *  validated. The singleton trio stays source-compatible; the multi branch
 *  publishes only `resources`, including when it contains one entry. */
export function resourceConfigurationFromCatalog(catalog: ResourceCatalog): ResourceConfiguration {
  if (catalog.configurationKind === "multi") {
    return { resources: Object.freeze([...catalog.entries]) as unknown as ResourceDefinition[] };
  }
  const only = catalog.entries[0];
  if (only === undefined) throw new AuthConfigError("resource catalog must contain an entry");
  return {
    resource: only.resource,
    scopeCatalog: only.scopeCatalog as string[],
    defaultScopes: only.defaultScopes as string[],
    ...(catalog.legacySingletonResource === undefined
      ? {} : { legacySingletonResource: catalog.legacySingletonResource }),
  };
}

/** Deterministic scope union (sorted, de-duplicated) across all catalog entries. */
export function scopeUnion(catalog: ResourceCatalog): string[] {
  const set = new Set<string>();
  for (const entry of catalog.entries) for (const scope of entry.scopeCatalog) set.add(scope);
  return [...set].sort();
}

/** Exact resolver. An omitted request resolves ONLY when the catalog has one entry;
 *  a present request is canonicalized (same rules as the catalog) and matched
 *  exactly. A malformed/unknown request resource is `invalid_target` (request-time). */
export function resolveResource(catalog: ResourceCatalog, request: string | undefined): ResolvedResource {
  if (request === undefined) {
    const only = catalog.entries[0];
    if (catalog.entries.length !== 1 || only === undefined) {
      throw new OAuthError("invalid_target", "resource parameter is required when multiple resources are configured");
    }
    return only;
  }
  let canonical: string;
  try {
    canonical = canonicalResource(request, { allowInsecureLocalhost: catalog.allowInsecureLocalhost });
  } catch {
    throw new OAuthError("invalid_target", "unknown or malformed OAuth resource");
  }
  const entry = catalog.entries.find((e) => e.resource === canonical);
  if (entry === undefined) throw new OAuthError("invalid_target", "unknown OAuth resource");
  return entry;
}

function freezeCatalog(entries: ResolvedResource[], configurationKind: "singleton" | "multi", allowInsecureLocalhost: boolean, legacy: string | undefined): ResourceCatalog {
  return Object.freeze({
    entries: Object.freeze(entries) as readonly ResolvedResource[],
    configurationKind, allowInsecureLocalhost,
    legacySingletonResource: legacy,
    legacyBindingPermitted: legacy !== undefined,
  } as ResourceCatalog);
}


function makeEntry(resource: string, scopeCatalog: string[], defaultScopes: string[]): ResolvedResource {
  return Object.freeze({
    resource,
    scopeCatalog: Object.freeze(scopeCatalog) as readonly string[],
    defaultScopes: Object.freeze(defaultScopes) as readonly string[],
  }) as ResolvedResource;
}

function buildEntry(def: unknown, allowInsecureLocalhost: boolean): ResolvedResource {
  if (typeof def !== "object" || def === null) {
    throw new AuthConfigError("each resource entry must be an object");
  }
  for (const key of Reflect.ownKeys(def)) {
    if (typeof key === "symbol" || !RESOURCE_DEF_KEYS.has(key)) {
      throw new AuthConfigError(`unknown resource entry key "${String(key)}": only resource, scopeCatalog, defaultScopes are accepted (contracts §5.1)`);
    }
  }
  // Own data properties only, read once each. §5.1 requires the three OWN
  // properties: an entry inheriting them from a prototype has zero own keys and
  // would otherwise pass the unknown-key sweep above while supplying values that
  // sweep never inspected.
  const d = snapshotOwn(def, ["resource", "scopeCatalog", "defaultScopes"]);
  if (!("resource" in d) || !("scopeCatalog" in d) || !("defaultScopes" in d)) {
    throw new AuthConfigError("each resource entry requires resource, scopeCatalog, and defaultScopes as own properties");
  }
  const scopeCatalog = validateScopeCatalog(d.scopeCatalog);
  return makeEntry(
    canonicalResource(d.resource, { allowInsecureLocalhost }),
    scopeCatalog,
    validateDefaultScopes(d.defaultScopes, scopeCatalog),
  );
}

function rejectDuplicateResources(entries: readonly ResolvedResource[]): void {
  const seen = new Set<string>();
  for (const entry of entries) {
    if (seen.has(entry.resource)) throw new AuthConfigError(`duplicate canonical resource: ${entry.resource}`);
    seen.add(entry.resource);
  }
}

function validateScopeCatalog(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new AuthConfigError("scopeCatalog must be a non-empty array");
  }
  const seen = new Set<string>();
  for (const scope of value) {
    if (typeof scope !== "string" || !isScopeToken(scope)) {
      throw new AuthConfigError("scopeCatalog must contain only RFC 6749 scope tokens");
    }
    if (seen.has(scope)) throw new AuthConfigError("scopeCatalog must not contain duplicates");
    seen.add(scope);
  }
  return [...value] as string[];
}

function validateDefaultScopes(value: unknown, catalog: readonly string[]): string[] {
  if (!Array.isArray(value)) throw new AuthConfigError("defaultScopes must be an array");
  const allowed = new Set(catalog);
  const seen = new Set<string>();
  for (const scope of value) {
    if (typeof scope !== "string" || !allowed.has(scope)) {
      throw new AuthConfigError("defaultScopes must be a subset of scopeCatalog");
    }
    if (seen.has(scope)) throw new AuthConfigError("defaultScopes must not contain duplicates");
    seen.add(scope);
  }
  return [...value] as string[];
}
