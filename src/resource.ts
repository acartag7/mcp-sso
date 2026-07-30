// Resource authority (contracts §5.1). One canonical parser owns configuration
// and request equality; a small immutable catalog normalizes EITHER the singleton
// trio OR the `resources` array into one internal form. Production requires https;
// the loopback-only dev exception applies. Userinfo, query, and fragment are
// rejected — they cannot produce an unambiguous RFC 9728 PRM route.

import { AuthConfigError } from "./config.ts";

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export interface ResourceDefinition {
  resource: string;
  scopeCatalog: string[];
  defaultScopes: string[];
}

export interface ResolvedResource {
  readonly resource: string;
  readonly scopeCatalog: readonly string[];
  readonly defaultScopes: readonly string[];
}

export interface ResourceCatalog {
  readonly entries: readonly ResolvedResource[];
  readonly configurationKind: "singleton" | "multi";
  /** Boot decision under which entries were canonicalized; {@link resolveResource}
   *  reuses it so a request canonicalizes the SAME way as the catalog. */
  readonly allowInsecureLocalhost: boolean;
  readonly legacySingletonResource?: string;
  readonly legacyBindingPermitted: boolean;
}

export interface CanonicalResourceOptions {
  readonly allowInsecureLocalhost: boolean;
}

export type SingletonResourceConfiguration = {
  resource: string; scopeCatalog: string[]; defaultScopes: string[];
  legacySingletonResource?: string; resources?: never;
};
export type MultiResourceConfiguration = {
  resources: ResourceDefinition[]; resource?: never; scopeCatalog?: never;
  defaultScopes?: never; legacySingletonResource?: never;
};
export type ResourceConfiguration = SingletonResourceConfiguration | MultiResourceConfiguration;

/** Read each named field EXACTLY ONCE, from an OWN data property, into a plain
 *  snapshot. Everything downstream validates and publishes THAT snapshot, so a
 *  getter- or Proxy-backed input cannot return one value to validation and a
 *  different one to construction (the validate-vs-publish TOCTOU class, §5/§10.0).
 *  An accessor property is rejected rather than invoked: a config field that
 *  computes a value has no legitimate use here and cannot be read safely twice.
 *  Inherited fields are NOT read — §5.1 requires the three OWN properties. */
export function snapshotOwn(source: object, keys: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(source, key);
    if (descriptor === undefined) continue;
    if (!("value" in descriptor)) {
      throw new AuthConfigError(
        `resource configuration field "${key}" must be a plain data property, not a getter ` +
          `(an accessor can return a different value to validation than to construction — contracts §5.1)`,
      );
    }
    out[key] = descriptor.value;
  }
  return out;
}

/** The ONE canonical resource parser (contracts §5.1). Accepts a primitive
 *  non-empty absolute URL, rejects raw syntax WHATWG would silently rewrite, then
 *  parses with `new URL`. https required in production; http only on loopback under
 *  the dev exception. Userinfo/query/fragment rejected before AND after parsing.
 *  Origin-only → NO trailing slash; non-root path keeps its trailing-slash
 *  distinction. The raw value is never trimmed or repaired. Throws AuthConfigError. */
export function canonicalResource(value: unknown, options: CanonicalResourceOptions): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new AuthConfigError("resource must be a non-empty string");
  }
  const allowInsecureLocalhost = options.allowInsecureLocalhost === true;
  const prefix = allowInsecureLocalhost ? /^(https|http):\/\//i.exec(value) : /^https:\/\//i.exec(value);
  if (prefix === null) {
    throw new AuthConfigError(
      allowInsecureLocalhost
        ? "resource must start with 'https://' (or 'http://' under the loopback dev exception)"
        : "resource must start with 'https://' (use dev.allowInsecureLocalhost for local http)",
    );
  }
  const schemeLen = prefix[0].length;
  // Prefix pins the '://' two-slash delimiter; reject a third slash (empty authority).
  if (schemeLen >= value.length || value.charCodeAt(schemeLen) === 0x2f /* / */) {
    throw new AuthConfigError("resource must have a non-empty authority");
  }
  if (value.includes("\\")) throw new AuthConfigError("resource must not contain a backslash");
  if (/[\x00-\x20\x7f]/u.test(value)) throw new AuthConfigError("resource must not contain ASCII whitespace or control characters");
  if (/%(?![0-9a-f]{2})/iu.test(value)) throw new AuthConfigError("resource must not contain a malformed percent escape");
  if (value.includes("?") || value.includes("#")) throw new AuthConfigError("resource must not contain a '?' or '#' delimiter");
  const slash = value.indexOf("/", schemeLen);
  const authority = slash < 0 ? value.slice(schemeLen) : value.slice(schemeLen, slash);
  if (authority.includes("@")) throw new AuthConfigError("resource must not contain userinfo");
  if (authority.lastIndexOf(":") === authority.length - 1) {
    throw new AuthConfigError("resource must not contain an empty port delimiter");
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AuthConfigError("resource must be a parseable absolute URL");
  }
  // Defence in depth: raw checks above already reject these.
  if (url.username !== "" || url.password !== "") throw new AuthConfigError("resource must not contain userinfo");
  if (url.search !== "" || url.hash !== "") throw new AuthConfigError("resource must not contain a query or fragment");
  if (url.protocol === "http:") {
    if (!allowInsecureLocalhost) throw new AuthConfigError("resource must be https:// (use dev.allowInsecureLocalhost for local http)");
    if (!LOOPBACK_HOSTS.has(url.hostname)) throw new AuthConfigError("http:// resource is allowed only on loopback under dev.allowInsecureLocalhost");
  } else if (url.protocol !== "https:") {
    throw new AuthConfigError("resource scheme must be https (or loopback http)");
  }
  return url.pathname === "/" ? url.origin : `${url.origin}${url.pathname}`;
}

// The catalog builder and request resolver live in ./resource-catalog.ts (this
// file is at the 250-line ceiling). Re-exported so callers keep one import site.
export {
  buildResourceCatalog, resourceConfigurationFromCatalog, scopeUnion, resolveResource,
} from "./resource-catalog.ts";
