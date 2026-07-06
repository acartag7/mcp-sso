// BridgeConfig — validated, fail-closed configuration (contracts §5). There is
// intentionally NO local/unauthenticated bypass. https is required in production;
// `dev.allowInsecureLocalhost` permits http ONLY on loopback and is rejected at
// boot if either origin is not loopback.

import type { JWK } from "jose";
import type { ClientStore } from "./ports/client-store.ts";

export type DcrMode = { mode: "stateless" } | { mode: "stored"; store: ClientStore };

export interface DevOptions {
  /** Permit http:// issuer+resource on loopback only (Phase 4 local example).
   *  Rejected at boot if either origin is not loopback. Never weakens a real host. */
  allowInsecureLocalhost: boolean;
}

/** Opt-in to the `client_credentials` grant surface (contracts §17.2). When
 *  enabled the bridge accepts machine-client provisioning and (in S3b) the
 *  token grant. Fail-closed boot rule: enabling requires `dcr.mode === "stored"`
 *  — machine clients are persisted into the ClientStore, so stateless DCR
 *  (which persists nothing) cannot support them. */
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
  allowedOrigins: string[];
  dcr: DcrMode;
  dev?: DevOptions;
  clientCredentials?: ClientCredentialsOptions;
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
  "allowedOrigins", "dcr", "dev", "clientCredentials",
  "accessTokenTtlSeconds", "refreshTokenTtlSeconds", "consentTokenTtlSeconds",
  "authorizationCodeTtlSeconds",
]);

/** Validate and freeze a BridgeConfig. Throws AuthConfigError on any problem —
 *  it never degrades to a silent default. The dev escape hatch, when accepted,
 *  emits an advisory warning (see below). The returned object is the only thing
 *  use-cases accept. */
export function createBridgeConfig(input: BridgeConfig): BridgeConfig {
  // Fail-closed (contracts §5): reject unknown own keys FIRST. `Reflect.ownKeys`
  // covers string AND symbol keys — the latter would survive the `{ ...input }`
  // spread below, so a symbol-keyed secret would otherwise reach the frozen
  // public object. The error names the offending key so a JS/cast-TS caller can
  // fix the typo without guessing.
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key === "symbol" || !KNOWN_CONFIG_KEYS.has(key)) {
      throw new AuthConfigError(
        `unknown BridgeConfig key "${String(key)}": only the BridgeConfig fields are accepted (contracts §5). ` +
          `A value parked here — e.g. a backend API key — would ship on the public frozen bridge.config object ` +
          `passed to every adapter and renderer; keep secrets in your own closure, not in the config input.`,
      );
    }
  }
  validateUrl(input, "issuer", input.issuer);
  validateUrl(input, "resource", input.resource);
  if (input.consentSigningSecret.trim().length < 32) {
    throw new AuthConfigError("consentSigningSecret must be at least 32 characters");
  }
  validateSigningKey(input.signingPrivateJwk);
  if (!Array.isArray(input.scopeCatalog) || input.scopeCatalog.length === 0) {
    throw new AuthConfigError("scopeCatalog must be a non-empty array");
  }
  if (!input.defaultScopes.every((s) => input.scopeCatalog.includes(s))) {
    throw new AuthConfigError("defaultScopes must be a subset of scopeCatalog");
  }
  validateTtl(input.accessTokenTtlSeconds, "accessTokenTtlSeconds");
  validateTtl(input.refreshTokenTtlSeconds, "refreshTokenTtlSeconds");
  validateTtl(input.consentTokenTtlSeconds, "consentTokenTtlSeconds");
  validateTtl(input.authorizationCodeTtlSeconds, "authorizationCodeTtlSeconds");
  if (input.dcr.mode !== "stateless" && input.dcr.mode !== "stored") {
    throw new AuthConfigError("dcr.mode must be 'stateless' or 'stored'");
  }
  if (input.dcr.mode === "stored" && !input.dcr.store) {
    throw new AuthConfigError("dcr.mode 'stored' requires a ClientStore");
  }
  if (input.clientCredentials !== undefined) {
    if (typeof input.clientCredentials !== "object" || input.clientCredentials === null
      || typeof input.clientCredentials.enabled !== "boolean") {
      throw new AuthConfigError("clientCredentials must be { enabled: boolean }");
    }
    // §17.2: machine clients are persisted into the ClientStore, so the grant
    // surface is meaningless (and dangerous to advertise) without stored DCR.
    if (input.clientCredentials.enabled && input.dcr.mode !== "stored") {
      throw new AuthConfigError("clientCredentials.enabled requires dcr.mode 'stored' (machine clients are provisioned into the ClientStore — §17.2)");
    }
  }
  if (input.dev?.allowInsecureLocalhost === true) {
    // Defense-in-depth advisory (threat-model #16): the loopback-only check above
    // already passed; this surfaces that the dev escape hatch is ACTIVE, so an
    // operator who tunnels/exposes the loopback bridge gets a loud signal.
    console.warn(
      "[mcp-sso] dev.allowInsecureLocalhost is ON — http:// is permitted on loopback origins only. Do NOT use in production.",
    );
  }
  return Object.freeze({ ...input });
}

function validateUrl(input: BridgeConfig, label: string, value: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AuthConfigError(`${label} must be an absolute URL`);
  }
  if (input.dev?.allowInsecureLocalhost === true) {
    if (!LOOPBACK_HOSTS.has(url.hostname)) {
      throw new AuthConfigError(`dev.allowInsecureLocalhost requires a loopback origin for ${label}`);
    }
    // loopback: http or https both permitted
  } else if (url.protocol !== "https:") {
    throw new AuthConfigError(`${label} must be https:// (use dev.allowInsecureLocalhost for local http)`);
  }
}

function validateSigningKey(jwk: JWK): void {
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.d || !jwk.x || !jwk.y) {
    throw new AuthConfigError("signingPrivateJwk must be an EC P-256 key with d, x, y");
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
