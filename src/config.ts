// BridgeConfig — validated, fail-closed configuration (contracts §5). There is
// intentionally NO local/unauthenticated bypass. https is required in production;
// `dev.allowInsecureLocalhost` permits http ONLY on loopback and is rejected at
// boot if either origin is not loopback.

import type { JWK } from "jose";
import type { ClientStore } from "./ports/client-store.ts";
import { cimdConfigProblem, type CimdOptions } from "./cimd/options.ts";
import { parseRedirectEntry, RedirectEntryError } from "./redirect-entry.ts";
import { scopeListProblem } from "./scopes.ts";
import { snapshotScopeHierarchy, type ScopeHierarchyPolicy } from "./scope-hierarchy.ts";
import {
  configOwnKeys, configValue, isArrayValue, isEcP256PrivateJwk, snapshotArray,
  snapshotClientCredentials, snapshotDcr, snapshotDev, snapshotJwk,
  snapshotStringArray,
} from "./config-snapshot.ts";

export type { CimdOptions } from "./cimd/options.ts";
export type { ScopeHierarchyPolicy, ScopeImplication } from "./scope-hierarchy.ts";

export type DcrMode = { mode: "stateless" } | { mode: "stored"; store: ClientStore };

export interface DevOptions {
  /** Permit http:// issuer+resource on loopback only (Phase 4 local example).
   *  Rejected at boot if either origin is not loopback. Never weakens a real host. */
  allowInsecureLocalhost: boolean;
}

/** Opt-in to the `client_credentials` grant surface (contracts §17.2). When
 *  enabled the bridge accepts machine-client provisioning and the
 *  `/oauth/token` client_credentials grant. Fail-closed boot rule: enabling
 *  requires `dcr.mode === "stored"` — machine clients are persisted into the
 *  ClientStore, so stateless DCR (which persists nothing) cannot support them. */
export interface ClientCredentialsOptions {
  enabled: boolean;
}

export interface BridgeConfig {
  issuer: string;
  resource: string;
  consentSigningSecret: string;
  signingPrivateJwk: JWK;
  signingKeyId?: string;
  redirectAllowlist: string[];
  scopeCatalog: string[];
  defaultScopes: string[];
  scopeHierarchy?: ScopeHierarchyPolicy;
  allowedOrigins: string[];
  dcr: DcrMode;
  dev?: DevOptions;
  clientCredentials?: ClientCredentialsOptions;
  cimd?: CimdOptions;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  consentTokenTtlSeconds: number;
  authorizationCodeTtlSeconds: number;
}

export class AuthConfigError extends Error {
  readonly code = "invalid_auth_config";
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Every accepted top-level `BridgeConfig` key, in lockstep with the interface
 *  above. `createBridgeConfig` rejects any other own property (string OR symbol)
 *  so a value — e.g. a backend credential — parked on the input can never ship
 *  on the public frozen `bridge.config` object (contracts §5). If you add a
 *  field to `BridgeConfig`, add it here too: a stale set (new field not yet
 *  listed) makes that field REJECTED at every caller — failing closed, the safe
 *  direction — until you add it. Exported so tests can assert "no key outside
 *  this set survives" against the source of truth. */
export const KNOWN_CONFIG_KEYS: ReadonlySet<string> = new Set([
  "issuer", "resource", "consentSigningSecret", "signingPrivateJwk",
  "signingKeyId", "redirectAllowlist", "scopeCatalog", "defaultScopes",
  "scopeHierarchy", "allowedOrigins", "dcr", "dev", "clientCredentials", "cimd",
  "accessTokenTtlSeconds", "refreshTokenTtlSeconds", "consentTokenTtlSeconds",
  "authorizationCodeTtlSeconds",
]);

/** Validate and freeze a BridgeConfig. Throws AuthConfigError on any problem —
 *  it never degrades to a silent default. The dev escape hatch, when accepted,
 *  emits an advisory warning (see below). The returned object is the only thing
 *  use-cases accept. */
export function createBridgeConfig(input: BridgeConfig): BridgeConfig {
  const makeError = (message: string): AuthConfigError => new AuthConfigError(message);
  if (typeof input !== "object" || input === null
    || isArrayValue(input, "BridgeConfig input", makeError)) {
    throw new AuthConfigError("BridgeConfig input must be an object");
  }
  // Fail-closed (contracts §5): reject unknown own keys FIRST. `Reflect.ownKeys`
  // covers string AND symbol keys, so a symbol-keyed secret cannot reach the
  // frozen public object. The error names the offending key so a JS/cast-TS
  // caller can fix the typo without guessing.
  for (const key of configOwnKeys(input, makeError)) {
    if (typeof key === "symbol" || !KNOWN_CONFIG_KEYS.has(key)) {
      throw new AuthConfigError(
        `unknown BridgeConfig key "${String(key)}": only the BridgeConfig fields are accepted (contracts §5). ` +
          `A value parked here — e.g. a backend API key — would ship on the public frozen bridge.config object ` +
          `passed to every adapter and renderer; keep secrets in your own closure, not in the config input.`,
      );
    }
  }
  // Snapshot each field with a SINGLE read, then validate + freeze from these
  // locals. A getter- or Proxy-backed `input` can return different values across
  // reads, so validate-then-`{...input}`-spread is a TOCTOU: validation saw the
  // https/known value while the spread stored a different one, and a Proxy
  // `ownKeys` trap could inject an unknown key via that spread. Pinning every
  // field to one read and building the output from named locals closes both
  // (contracts §5; the promise on KNOWN_CONFIG_KEYS above is then actually true).
  // Every mutable container is snapshotted below before validation publishes it.
  const issuer = configValue(input, "issuer", makeError);
  const resource = configValue(input, "resource", makeError);
  const consentSigningSecret = configValue(input, "consentSigningSecret", makeError);
  const rawSigningPrivateJwk = configValue(input, "signingPrivateJwk", makeError);
  const signingKeyId = configValue(input, "signingKeyId", makeError);
  const rawRedirectAllowlist = configValue(input, "redirectAllowlist", makeError);
  const redirectAllowlist = snapshotRedirectAllowlist(rawRedirectAllowlist, makeError);
  const rawScopeCatalog = configValue(input, "scopeCatalog", makeError);
  const rawDefaultScopes = configValue(input, "defaultScopes", makeError);
  const rawScopeHierarchy = configValue(input, "scopeHierarchy", makeError);
  const rawAllowedOrigins = configValue(input, "allowedOrigins", makeError);
  const rawDcr = configValue(input, "dcr", makeError);
  const rawDev = configValue(input, "dev", makeError);
  const rawClientCredentials = configValue(input, "clientCredentials", makeError);
  let cimd = configValue(input, "cimd", makeError);
  const accessTokenTtlSeconds = configValue(input, "accessTokenTtlSeconds", makeError);
  const refreshTokenTtlSeconds = configValue(input, "refreshTokenTtlSeconds", makeError);
  const consentTokenTtlSeconds = configValue(input, "consentTokenTtlSeconds", makeError);
  const authorizationCodeTtlSeconds = configValue(input, "authorizationCodeTtlSeconds", makeError);
  const dev = snapshotDev(rawDev, makeError);
  const allowInsecureLocalhost = dev?.allowInsecureLocalhost === true;
  validateUrl(allowInsecureLocalhost, "issuer", issuer);
  validateUrl(allowInsecureLocalhost, "resource", resource);
  if (typeof consentSigningSecret !== "string" || consentSigningSecret.trim().length < 32) {
    throw new AuthConfigError("consentSigningSecret must be at least 32 characters");
  }
  if (signingKeyId !== undefined && typeof signingKeyId !== "string") {
    throw new AuthConfigError("signingKeyId must be a string when present");
  }
  const signingPrivateJwk = snapshotJwk(rawSigningPrivateJwk, makeError);
  if (!isEcP256PrivateJwk(signingPrivateJwk)) {
    throw new AuthConfigError("signingPrivateJwk must be an EC P-256 key with d, x, y");
  }
  const scopeCatalog = snapshotStringArray("scopeCatalog", rawScopeCatalog, makeError);
  if (scopeCatalog.length === 0) {
    throw new AuthConfigError("scopeCatalog must be a non-empty array");
  }
  const scopeCatalogProblem = scopeListProblem(scopeCatalog);
  if (scopeCatalogProblem) throw new AuthConfigError(`scopeCatalog ${scopeCatalogProblem}`);
  const scopeHierarchy = snapshotScopeHierarchy(rawScopeHierarchy, resource, scopeCatalog, makeError);
  const defaultScopes = snapshotStringArray("defaultScopes", rawDefaultScopes, makeError);
  const defaultScopesProblem = scopeListProblem(defaultScopes);
  if (defaultScopesProblem) throw new AuthConfigError(`defaultScopes ${defaultScopesProblem}`);
  if (!defaultScopes.every((s) => scopeCatalog.includes(s))) {
    throw new AuthConfigError("defaultScopes must be a subset of scopeCatalog");
  }
  const allowedOrigins = snapshotStringArray("allowedOrigins", rawAllowedOrigins, makeError);
  validateTtl(accessTokenTtlSeconds, "accessTokenTtlSeconds");
  validateTtl(refreshTokenTtlSeconds, "refreshTokenTtlSeconds");
  validateTtl(consentTokenTtlSeconds, "consentTokenTtlSeconds");
  validateTtl(authorizationCodeTtlSeconds, "authorizationCodeTtlSeconds");
  const dcr = snapshotDcr(rawDcr, makeError);
  const clientCredentials = snapshotClientCredentials(rawClientCredentials, makeError);
  if (clientCredentials !== undefined) {
    // §17.2: machine clients are persisted into the ClientStore, so the grant
    // surface is meaningless (and dangerous to advertise) without stored DCR.
    if (clientCredentials.enabled && dcr.mode !== "stored") {
      throw new AuthConfigError("clientCredentials.enabled requires dcr.mode 'stored' (machine clients are provisioned into the ClientStore — §17.2)");
    }
  }
  if (cimd !== undefined) {
    // Snapshot-then-validate returns the frozen object it checked, so an
    // accessor-backed cap cannot pass validation and publish a different value.
    let checked: ReturnType<typeof cimdConfigProblem>;
    try {
      checked = cimdConfigProblem(cimd);
    } catch {
      throw new AuthConfigError("cimd could not be read");
    }
    if ("problem" in checked) throw new AuthConfigError(checked.problem);
    cimd = checked.value;
  }
  if (allowInsecureLocalhost) {
    // Defense-in-depth advisory (threat-model #16): the loopback-only check above
    // already passed; this surfaces that the dev escape hatch is ACTIVE, so an
    // operator who tunnels/exposes the loopback bridge gets a loud signal.
    console.warn(
      "[mcp-sso] dev.allowInsecureLocalhost is ON — http:// is permitted on loopback origins only. Do NOT use in production.",
    );
  }
  return Object.freeze({
    issuer, resource, consentSigningSecret, signingPrivateJwk, signingKeyId,
    redirectAllowlist, scopeCatalog, defaultScopes, scopeHierarchy, allowedOrigins, dcr, dev,
    clientCredentials, cimd, accessTokenTtlSeconds, refreshTokenTtlSeconds,
    consentTokenTtlSeconds, authorizationCodeTtlSeconds,
  });
}

function snapshotRedirectAllowlist(value: unknown, makeError: (message: string) => Error): string[] {
  const snapshot = snapshotArray("redirectAllowlist", value, makeError);
  for (const entry of snapshot) {
    try {
      parseRedirectEntry(entry, { allowOmittedRootSlash: true });
    } catch (error) {
      const message = error instanceof RedirectEntryError ? error.message : "redirect entry is invalid";
      throw new AuthConfigError(`redirectAllowlist ${message}`);
    }
  }
  return snapshot as string[];
}

function validateUrl(allowInsecureLocalhost: boolean, label: string, value: unknown): void {
  if (typeof value !== "string") throw new AuthConfigError(`${label} must be an absolute URL`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AuthConfigError(`${label} must be an absolute URL`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new AuthConfigError(`${label} must be https:// or http://`);
  }
  if (allowInsecureLocalhost) {
    if (!LOOPBACK_HOSTS.has(url.hostname)) {
      throw new AuthConfigError(`dev.allowInsecureLocalhost requires a loopback origin for ${label}`);
    }
    // loopback: http or https both permitted
  } else if (url.protocol !== "https:") {
    throw new AuthConfigError(`${label} must be https:// (use dev.allowInsecureLocalhost for local http)`);
  }
}

function validateTtl(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new AuthConfigError(`${label} must be a positive integer (seconds)`);
  }
}

/** Origin (scheme://host[:port]) of a URL. */
export function originOf(value: string): string {
  const u = new URL(value);
  return `${u.protocol}//${u.host}`;
}

/** Pathname of a URL (e.g. "/mcp" or "/"); used for the path-inserted PRM route. */
export function pathAfterOrigin(value: string): string {
  return new URL(value).pathname;
}
