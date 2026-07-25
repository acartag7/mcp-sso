// BridgeConfig — validated, fail-closed configuration (contracts §5). There is
// intentionally NO local/unauthenticated bypass. https is required in production;
// `dev.allowInsecureLocalhost` permits http ONLY on loopback and is rejected at
// boot if either origin is not loopback.

import type { JWK } from "jose";
import type { ClientStore } from "./ports/client-store.ts";
import { cimdConfigProblem, type CimdOptions } from "./cimd/options.ts";
import { redirectAllowlistProblem } from "./redirect-allowlist.ts";
import {
  checkedStringArray, isEcP256PrivateJwk, snapshotClientCredentials, snapshotDcr, snapshotJwk,
} from "./config-snapshot.ts";

export type { CimdOptions } from "./cimd/options.ts";

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
  "allowedOrigins", "dcr", "dev", "clientCredentials", "cimd",
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
  // Snapshot each field with a SINGLE read, then validate + freeze from these
  // locals. A getter- or Proxy-backed `input` can return different values across
  // reads, so validate-then-`{...input}`-spread is a TOCTOU: validation saw the
  // https/known value while the spread stored a different one, and a Proxy
  // `ownKeys` trap could inject an unknown key via that spread. Pinning every
  // field to one read and building the output from named locals closes both
  // (contracts §5; the promise on KNOWN_CONFIG_KEYS above is then actually true).
  // Nested blocks and arrays are then published as frozen one-level SNAPSHOTS
  // (below): `Object.freeze` is shallow, and these are read per request, so
  // publishing the caller's own objects would leave every validated security
  // setting mutable after boot (issue #100).
  const issuer = input.issuer;
  const resource = input.resource;
  const consentSigningSecret = input.consentSigningSecret;
  const rawSigningPrivateJwk = input.signingPrivateJwk;
  const signingKeyId = input.signingKeyId;
  const rawRedirectAllowlist = input.redirectAllowlist;
  const rawScopeCatalog = input.scopeCatalog;
  const rawDefaultScopes = input.defaultScopes;
  const rawAllowedOrigins = input.allowedOrigins;
  const rawDcr = input.dcr;
  // Read-once rule for every nested value below: these locals are what the
  // validation checks AND what the snapshots publish. Re-reading any of them at
  // snapshot time would let an accessor-backed block return the approved value
  // during validation and a different one afterwards — publishing what boot
  // never approved.
  const dcrMode = rawDcr.mode;
  const dcrStore = dcrMode === "stored" ? (rawDcr as { store?: ClientStore }).store : undefined;
  const rawDev = input.dev;
  const allowInsecureLocalhost = rawDev?.allowInsecureLocalhost === true;
  const dev = rawDev === undefined ? undefined : Object.freeze({ allowInsecureLocalhost });
  const rawClientCredentials = input.clientCredentials;
  const clientCredentialsEnabled = rawClientCredentials?.enabled;
  let cimd = input.cimd;
  const accessTokenTtlSeconds = input.accessTokenTtlSeconds;
  const refreshTokenTtlSeconds = input.refreshTokenTtlSeconds;
  const consentTokenTtlSeconds = input.consentTokenTtlSeconds;
  const authorizationCodeTtlSeconds = input.authorizationCodeTtlSeconds;

  validateUrl(allowInsecureLocalhost, "issuer", issuer);
  validateUrl(allowInsecureLocalhost, "resource", resource);
  if (consentSigningSecret.trim().length < 32) {
    throw new AuthConfigError("consentSigningSecret must be at least 32 characters");
  }
  // Snapshot BEFORE validating, then publish that copy (rationale in
  // config-snapshot.ts: read per use by signKey()/publicJwk(), and WeakMap-keyed
  // in crypto-keys.ts, so a shared reference is a live swap window).
  const signingPrivateJwk = snapshotJwk(rawSigningPrivateJwk);
  if (!isEcP256PrivateJwk(signingPrivateJwk)) {
    throw new AuthConfigError("signingPrivateJwk must be an EC P-256 key with d, x, y");
  }
  // Snapshot-then-validate, then publish the snapshot: the array that was
  // checked is the array requests read (§5 "Publication"; issue #100).
  const scopeCatalog = checkedStringArray("scopeCatalog", rawScopeCatalog, (m) => new AuthConfigError(m));
  if (scopeCatalog.length === 0) {
    throw new AuthConfigError("scopeCatalog must be a non-empty array");
  }
  const defaultScopes = checkedStringArray("defaultScopes", rawDefaultScopes, (m) => new AuthConfigError(m));
  if (!defaultScopes.every((s) => scopeCatalog.includes(s))) {
    throw new AuthConfigError("defaultScopes must be a subset of scopeCatalog");
  }
  const allowedOrigins = checkedStringArray("allowedOrigins", rawAllowedOrigins, (m) => new AuthConfigError(m));
  validateTtl(accessTokenTtlSeconds, "accessTokenTtlSeconds");
  validateTtl(refreshTokenTtlSeconds, "refreshTokenTtlSeconds");
  validateTtl(consentTokenTtlSeconds, "consentTokenTtlSeconds");
  validateTtl(authorizationCodeTtlSeconds, "authorizationCodeTtlSeconds");
  // §5/§10.1: every allowlist entry is validated here, on the same rules the
  // request-time matcher enforces. Snapshot-then-validate returns the frozen
  // copy it checked, so a later mutation of the caller's array cannot swap in an
  // entry boot never approved (issue #104).
  const checkedAllowlist = redirectAllowlistProblem(rawRedirectAllowlist);
  if ("problem" in checkedAllowlist) throw new AuthConfigError(checkedAllowlist.problem);
  const redirectAllowlist = checkedAllowlist.value as string[];
  if (dcrMode !== "stateless" && dcrMode !== "stored") {
    throw new AuthConfigError("dcr.mode must be 'stateless' or 'stored'");
  }
  if (dcrMode === "stored" && !dcrStore) {
    throw new AuthConfigError("dcr.mode 'stored' requires a ClientStore");
  }
  // Publish a frozen one-level copy, never the caller's block: `dcr.mode` and
  // `dcr.store` are read PER REQUEST (authorize/register/token/upstream-flow),
  // so a shared reference would let a post-boot swap redirect client lookups and
  // `save()` to another store, or change which registration path runs (#100).
  const dcr = snapshotDcr(dcrMode, dcrStore);
  if (rawClientCredentials !== undefined) {
    if (typeof rawClientCredentials !== "object" || rawClientCredentials === null
      || typeof clientCredentialsEnabled !== "boolean") {
      throw new AuthConfigError("clientCredentials must be { enabled: boolean }");
    }
    // §17.2: machine clients are persisted into the ClientStore, so the grant
    // surface is meaningless (and dangerous to advertise) without stored DCR.
    if (clientCredentialsEnabled && dcrMode !== "stored") {
      throw new AuthConfigError("clientCredentials.enabled requires dcr.mode 'stored' (machine clients are provisioned into the ClientStore — §17.2)");
    }
  }
  // Same rule: `enabled` is read per request at /oauth/token and in AS metadata,
  // so flipping it post-boot would switch on a deliberately disabled grant.
  const clientCredentials = rawClientCredentials === undefined
    ? undefined
    : snapshotClientCredentials(clientCredentialsEnabled as boolean);
  if (cimd !== undefined) {
    // Snapshot-then-validate returns the frozen object it checked, so an
    // accessor-backed cap cannot pass validation and publish a different value.
    const checked = cimdConfigProblem(cimd);
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
    redirectAllowlist, scopeCatalog, defaultScopes, allowedOrigins, dcr, dev,
    clientCredentials, cimd, accessTokenTtlSeconds, refreshTokenTtlSeconds,
    consentTokenTtlSeconds, authorizationCodeTtlSeconds,
  });
}

function validateUrl(allowInsecureLocalhost: boolean, label: string, value: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AuthConfigError(`${label} must be an absolute URL`);
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
