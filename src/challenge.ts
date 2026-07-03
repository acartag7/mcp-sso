// WWW-Authenticate challenge + error-redirect builders (contracts §8.2, §9.3).
// Fix #1: the 401 challenge carries RFC 9728 `resource_metadata` + the supported
// `scope` (+ optional error), not a bare `Bearer` (the source bug).

import type { BridgeConfig } from "./config.js";
import { originOf } from "./config.js";

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
