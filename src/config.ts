// BridgeConfig — validated, fail-closed configuration (contracts §5). There is
// intentionally NO local/unauthenticated bypass. https is required in production;
// `dev.allowInsecureLocalhost` permits http ONLY on loopback and is rejected at
// boot if either origin is not loopback.

import type { JWK } from "jose";
import type { ClientStore } from "./ports/client-store.js";

export type DcrMode = { mode: "stateless" } | { mode: "stored"; store: ClientStore };

export interface DevOptions {
  /** Permit http:// issuer+resource on loopback only (Phase 4 local example).
   *  Rejected at boot if either origin is not loopback. Never weakens a real host. */
  allowInsecureLocalhost: boolean;
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
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  consentTokenTtlSeconds: number;
  authorizationCodeTtlSeconds: number;
}

export class AuthConfigError extends Error {
  readonly code = "invalid_auth_config";
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Validate and freeze a BridgeConfig. Throws AuthConfigError on any problem —
 *  never warns, never degrades. The returned object is the only thing use-cases
 *  accept. */
export function createBridgeConfig(input: BridgeConfig): BridgeConfig {
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
