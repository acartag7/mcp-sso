// BridgeConfig — validated, fail-closed configuration (contracts §5). There is
// intentionally NO local/unauthenticated bypass. https is required in production;
// `dev.allowInsecureLocalhost` permits http ONLY on loopback and is rejected at
// boot if either origin is not loopback.

import type { JWK } from "jose";
import type { ClientStore } from "./ports/client-store.ts";
import {
  isDataDescriptor, snapshotOwnDataArray, snapshotOwnDataRecord,
} from "./own-property.ts";
import { isScopeToken } from "./scopes.ts";
import type { BridgeConfig } from "./config-types.ts";

export type {
  BridgeConfig, ClientCredentialsOptions, DcrMode, DevOptions,
} from "./config-types.ts";

export class AuthConfigError extends Error {
  readonly code = "invalid_auth_config";
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const CONFIG_INSTANCES = new WeakSet<object>();

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
  "allowedOrigins", "dcr", "dev", "clientCredentials",
  "accessTokenTtlSeconds", "refreshTokenTtlSeconds", "consentTokenTtlSeconds",
  "authorizationCodeTtlSeconds",
]);

/** Validate and freeze a BridgeConfig. Throws AuthConfigError on any problem —
 *  it never degrades to a silent default. The dev escape hatch, when accepted,
 *  emits an advisory warning (see below). The returned object is the only thing
 *  use-cases accept. */
export function createBridgeConfig(input: BridgeConfig): BridgeConfig {
  // Snapshot own data properties ONCE. Required fields and security opt-ins may
  // not come from a prototype or accessor, and Proxy/descriptor failures reject
  // before any warning or other side effect.
  const snapshot = snapshotBridgeConfigInput(input);
  const fields = snapshot as Readonly<Record<string, unknown>>;
  const issuer = requiredString(fields.issuer, "issuer");
  const resource = requiredString(fields.resource, "resource");
  const consentSigningSecret = requiredString(fields.consentSigningSecret, "consentSigningSecret");
  const signingJwkSnapshot = snapshotOwnDataRecord(fields.signingPrivateJwk);
  if (signingJwkSnapshot === null) throw new AuthConfigError("signingPrivateJwk must be a data object");
  const signingPrivateJwk = signingJwkSnapshot as JWK;
  const signingKeyId = fields.signingKeyId === undefined
    ? undefined : requiredString(fields.signingKeyId, "signingKeyId");
  const redirectAllowlist = snapshotStringArray(fields.redirectAllowlist, "redirectAllowlist");
  const scopeCatalog = snapshotStringArray(fields.scopeCatalog, "scopeCatalog");
  const defaultScopes = snapshotStringArray(fields.defaultScopes, "defaultScopes");
  const allowedOrigins = snapshotStringArray(fields.allowedOrigins, "allowedOrigins");
  const dcrSnapshot = snapshotOwnDataRecord(fields.dcr);
  if (dcrSnapshot === null) throw new AuthConfigError("dcr must be a data object");
  const dcrMode = dcrSnapshot.mode;
  if (dcrMode !== "stateless" && dcrMode !== "stored") {
    throw new AuthConfigError("dcr.mode must be 'stateless' or 'stored'");
  }
  if (dcrMode === "stored" && !dcrSnapshot.store) {
    throw new AuthConfigError("dcr.mode 'stored' requires a ClientStore");
  }
  const dcr = dcrMode === "stored"
    ? Object.freeze({ mode: "stored" as const, store: dcrSnapshot.store as ClientStore })
    : Object.freeze({ mode: "stateless" as const });
  const devSnapshot = fields.dev === undefined ? undefined : snapshotOwnDataRecord(fields.dev);
  if (devSnapshot === null) throw new AuthConfigError("dev must be { allowInsecureLocalhost: boolean }");
  const allowInsecureLocalhostValue = devSnapshot?.allowInsecureLocalhost;
  if (devSnapshot !== undefined && typeof allowInsecureLocalhostValue !== "boolean") {
    throw new AuthConfigError("dev must be { allowInsecureLocalhost: boolean }");
  }
  const allowInsecureLocalhost = allowInsecureLocalhostValue === true;
  const dev = devSnapshot === undefined ? undefined
    : Object.freeze({ allowInsecureLocalhost });
  const credentialsSnapshot = fields.clientCredentials === undefined
    ? undefined : snapshotOwnDataRecord(fields.clientCredentials);
  if (credentialsSnapshot === null) throw new AuthConfigError("clientCredentials must be { enabled: boolean }");
  const clientCredentialsEnabled = credentialsSnapshot?.enabled;
  const clientCredentials = credentialsSnapshot === undefined ? undefined
    : Object.freeze({ enabled: clientCredentialsEnabled as boolean });
  const accessTokenTtlSeconds = fields.accessTokenTtlSeconds as number;
  const refreshTokenTtlSeconds = fields.refreshTokenTtlSeconds as number;
  const consentTokenTtlSeconds = fields.consentTokenTtlSeconds as number;
  const authorizationCodeTtlSeconds = fields.authorizationCodeTtlSeconds as number;

  validateUrl(allowInsecureLocalhost, "issuer", issuer);
  validateUrl(allowInsecureLocalhost, "resource", resource);
  if (consentSigningSecret.trim().length < 32) {
    throw new AuthConfigError("consentSigningSecret must be at least 32 characters");
  }
  validateSigningKey(signingPrivateJwk);
  if (scopeCatalog.length === 0 || !scopeCatalog.every(isScopeToken)) {
    throw new AuthConfigError("scopeCatalog must be a non-empty array of scope tokens");
  }
  if (!defaultScopes.every((s) => scopeCatalog.includes(s))) {
    throw new AuthConfigError("defaultScopes must be a subset of scopeCatalog");
  }
  validateTtl(accessTokenTtlSeconds, "accessTokenTtlSeconds");
  validateTtl(refreshTokenTtlSeconds, "refreshTokenTtlSeconds");
  validateTtl(consentTokenTtlSeconds, "consentTokenTtlSeconds");
  validateTtl(authorizationCodeTtlSeconds, "authorizationCodeTtlSeconds");
  if (clientCredentials !== undefined) {
    if (typeof clientCredentialsEnabled !== "boolean") {
      throw new AuthConfigError("clientCredentials must be { enabled: boolean }");
    }
    // §17.2: machine clients are persisted into the ClientStore, so the grant
    // surface is meaningless (and dangerous to advertise) without stored DCR.
    if (clientCredentialsEnabled && dcrMode !== "stored") {
      throw new AuthConfigError("clientCredentials.enabled requires dcr.mode 'stored' (machine clients are provisioned into the ClientStore — §17.2)");
    }
  }
  if (allowInsecureLocalhost) {
    // Defense-in-depth advisory (threat-model #16): the loopback-only check above
    // already passed; this surfaces that the dev escape hatch is ACTIVE, so an
    // operator who tunnels/exposes the loopback bridge gets a loud signal.
    console.warn(
      "[mcp-sso] dev.allowInsecureLocalhost is ON — http:// is permitted on loopback origins only. Do NOT use in production.",
    );
  }
  const config = Object.freeze({
    issuer, resource, consentSigningSecret, signingPrivateJwk, signingKeyId,
    redirectAllowlist, scopeCatalog, defaultScopes, allowedOrigins, dcr, dev,
    clientCredentials, accessTokenTtlSeconds, refreshTokenTtlSeconds,
    consentTokenTtlSeconds, authorizationCodeTtlSeconds,
  });
  CONFIG_INSTANCES.add(config);
  return config;
}

/** Runtime brand for validated configuration. Security helpers reject structural
 * lookalikes so every policy read comes from createBridgeConfig's snapshot. */
export function assertBridgeConfig(value: unknown): BridgeConfig {
  if (typeof value !== "object" || value === null || !CONFIG_INSTANCES.has(value)) {
    throw new AuthConfigError("BridgeConfig must be created by createBridgeConfig");
  }
  return value as BridgeConfig;
}

function snapshotBridgeConfigInput(input: unknown): Readonly<Record<string, unknown>> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new AuthConfigError("BridgeConfig must contain only own enumerable data properties");
  }
  let descriptors: Record<PropertyKey, PropertyDescriptor>;
  try {
    descriptors = Object.getOwnPropertyDescriptors(input) as Record<PropertyKey, PropertyDescriptor>;
  } catch {
    throw new AuthConfigError("BridgeConfig must contain only own enumerable data properties");
  }
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string" || !KNOWN_CONFIG_KEYS.has(key)) {
      throw new AuthConfigError(
        `unknown BridgeConfig key "${String(key)}": only the BridgeConfig fields are accepted (contracts §5). ` +
          `A value parked here — e.g. a backend API key — would ship on the public frozen bridge.config object ` +
          `passed to every adapter and renderer; keep secrets in your own closure, not in the config input.`,
      );
    }
    const descriptor = descriptors[key]!;
    if (!descriptor.enumerable || !isDataDescriptor(descriptor)) {
      throw new AuthConfigError("BridgeConfig must contain only own enumerable data properties");
    }
    snapshot[key] = descriptor.value;
  }
  return Object.freeze(snapshot);
}

function snapshotStringArray(value: unknown, label: string): string[] {
  const snapshot = snapshotOwnDataArray(value);
  if (snapshot === null || !snapshot.every((entry) => typeof entry === "string")) {
    throw new AuthConfigError(`${label} must be a dense string[]`);
  }
  return Object.freeze([...snapshot]) as string[];
}

function validateUrl(allowInsecureLocalhost: boolean, label: string, value: string): void {
  if (!(value.startsWith("https://")
    || (allowInsecureLocalhost && value.startsWith("http://")))) {
    throw new AuthConfigError(`${label} must use a literal http(s):// URL`);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AuthConfigError(`${label} must be an absolute URL`);
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new AuthConfigError(`${label} must not contain userinfo, query, or fragment components`);
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

function validateSigningKey(jwk: JWK): void {
  if (jwk.kty !== "EC" || jwk.crv !== "P-256"
    || typeof jwk.d !== "string" || jwk.d.length === 0
    || typeof jwk.x !== "string" || jwk.x.length === 0
    || typeof jwk.y !== "string" || jwk.y.length === 0) {
    throw new AuthConfigError("signingPrivateJwk must be an EC P-256 key with d, x, y");
  }
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new AuthConfigError(`${label} must be a non-empty string`);
  }
  return value;
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
