// WWW-Authenticate challenge + error-redirect builders (contracts §8.2, §9.3).
// Fix #1: the 401 challenge carries RFC 9728 `resource_metadata` + the supported
// `scope` (+ optional error), not a bare `Bearer` (the source bug).

import type { BridgeConfig } from "./config.ts";
import { assertBridgeConfig, originOf } from "./config.ts";
import { snapshotOwnDataRecord, snapshotOwnStringArray } from "./own-property.ts";
import { isScopeToken } from "./scopes.ts";

export interface ChallengeOptions {
  /** Catalog the client may request (space-joined into `scope`). */
  scope?: readonly string[];
  /** OAuth error code, e.g. "invalid_token" or "insufficient_scope". */
  error?: string;
  errorDescription?: string;
}

/** The PRM URL advertised in the challenge (resource origin, root form — the
 *  path-inserted form is also served, §9.1). */
export function protectedResourceMetadataUrl(config: BridgeConfig): string {
  assertBridgeConfig(config);
  return `${originOf(config.resource)}/.well-known/oauth-protected-resource`;
}

/** Build the exact `WWW-Authenticate` value for a 401. */
export function buildUnauthorizedChallenge(config: BridgeConfig, opts: ChallengeOptions = {}): string {
  assertBridgeConfig(config);
  const fields = snapshotOwnDataRecord(opts);
  if (fields === null) throw new TypeError("challenge options must be own data properties");
  const scope = fields.scope === undefined ? undefined : snapshotOwnStringArray(fields.scope);
  if (scope === null || (scope && !scope.every(isScopeToken))) {
    throw new TypeError("challenge scope must be a dense array of scope tokens");
  }
  if (fields.error !== undefined && (typeof fields.error !== "string"
    || !/^[A-Za-z0-9_]+$/.test(fields.error))) throw new TypeError("challenge error is malformed");
  if (fields.errorDescription !== undefined && (typeof fields.errorDescription !== "string"
    || /[\u0000-\u001f\u007f]/.test(fields.errorDescription))) {
    throw new TypeError("challenge errorDescription is malformed");
  }
  const params: string[] = [];
  params.push(`Bearer resource_metadata="${protectedResourceMetadataUrl(config)}"`);
  if (scope && scope.length > 0) params.push(`scope="${scope.join(" ")}"`);
  if (fields.error) {
    params.push(`error="${fields.error}"`);
    if (fields.errorDescription) params.push(`error_description="${escapeQuoted(fields.errorDescription as string)}"`);
  }
  return params.join(", ");
}

/** Build the `WWW-Authenticate: Basic` challenge for a failed client_credentials
 *  client authentication (contracts §17.2: "WWW-Authenticate: Basic when Basic
 *  was attempted"). Distinct from {@link buildUnauthorizedChallenge} (the Bearer
 *  challenge for the `/mcp` resource surface): the token endpoint challenges the
 *  *client*, not the bearer. Realm = the AS issuer (RFC 7617 realm is opaque;
 *  the issuer is a stable AS identifier). `charset="UTF-8"` per RFC 7617 §2.1. */
export function buildBasicClientChallenge(config: BridgeConfig): string {
  assertBridgeConfig(config);
  return `Basic realm="${escapeQuoted(config.issuer)}", charset="UTF-8"`;
}

/** Build an RFC 6749 §4.1.2.1 error redirect: redirect_uri?error=…&state=…
 *  (&error_description). The redirect_uri MUST already be §10-validated by the
 *  caller (the authorize use-case tags post-validation errors with it). */
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
