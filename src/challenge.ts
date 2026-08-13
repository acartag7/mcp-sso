// WWW-Authenticate challenge + error-redirect builders (contracts §8.2, §9.3).
// Fix #1: the 401 challenge carries RFC 9728 `resource_metadata` + the supported
// `scope` (+ optional error), not a bare `Bearer` (the source bug).

import type { BridgeConfig } from "./config.ts";
import { originOf } from "./config.ts";

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
  return `${originOf(config.resource)}/.well-known/oauth-protected-resource`;
}

/** Build the exact `WWW-Authenticate` value for a 401. */
export function buildUnauthorizedChallenge(config: BridgeConfig, opts: ChallengeOptions = {}): string {
  const params: string[] = [];
  params.push(`Bearer resource_metadata="${protectedResourceMetadataUrl(config)}"`);
  if (opts.scope && opts.scope.length > 0) params.push(`scope="${opts.scope.join(" ")}"`);
  if (opts.error) {
    params.push(`error="${opts.error}"`);
    if (opts.errorDescription) params.push(`error_description="${escapeQuoted(opts.errorDescription)}"`);
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
  return `Basic realm="${escapeQuoted(config.issuer)}", charset="UTF-8"`;
}

/** Build the legacy RFC 6749 §4.1.2.1 error redirect. This public signature is
 *  retained for source compatibility. It cannot add the RFC 9207 issuer and is
 *  therefore not used for library-owned authorization responses.
 *
 *  @deprecated Use {@link buildAuthorizationErrorRedirect} when constructing
 *  an authorization-server response. */
export function buildErrorRedirect(redirectUri: string, code: string, state?: string, description?: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set("error", code);
  if (state) url.searchParams.set("state", state);
  if (description) url.searchParams.set("error_description", description);
  url.hash = "";
  return url.href;
}

/** Build an RFC 6749 §4.1.2.1 + RFC 9207 error redirect. The redirect_uri MUST
 *  already be §10-validated by the caller (the authorize use-case tags
 *  post-validation errors with it). */
export function buildAuthorizationErrorRedirect(config: BridgeConfig, redirectUri: string, code: string, state?: string, description?: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set("error", code);
  url.searchParams.set("iss", config.issuer);
  setOrDelete(url.searchParams, "state", state);
  setOrDelete(url.searchParams, "error_description", description);
  url.hash = "";
  return url.href;
}

function setOrDelete(params: URLSearchParams, name: string, value: string | undefined): void {
  if (value === undefined) params.delete(name);
  else params.set(name, value);
}

function escapeQuoted(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}
