// Redirect-URI policy (contracts §10). Two policies by DCR mode:
//   §10.1 assertAllowedRedirectUri        — global allowlist (stateless mode + stored
//                                            registration-time validation)
//   §10.2 assertRedirectAllowedForClient  — per-applicationType (stored authorize-time)
// Shared rule: no allow-all ("*"), no unanchored prefix, userinfo rejected, hash
// stripped. Built-in MCP-client loopback defaults always apply (§10.1).

import type { ClientRegistration } from "./ports/client-store.ts";
import { OAuthError } from "./errors.ts";

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Built-in trusted redirect origins. Web origins match any callback path on
 *  that origin; loopback origins match any port (RFC 8252). A config allowlist
 *  ADDS to these; it cannot remove a default. */
export const DEFAULT_ALLOWED_REDIRECT_ORIGINS = Object.freeze([
  "https://claude.ai",
  "https://chatgpt.com",
  "http://localhost",
  "http://127.0.0.1",
]);

/** Validate a redirect_uri against the global allowlist (built-ins + config).
 *  Returns the normalized URI. Throws invalid_redirect_uri on rejection. */
export function assertAllowedRedirectUri(value: string, allowlist: string[]): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new OAuthError("invalid_redirect_uri", "redirect_uri is invalid");
  }
  if (url.username || url.password) {
    throw new OAuthError("invalid_redirect_uri", "redirect_uri must not contain userinfo");
  }
  url.hash = "";
  const normalized = url.href;
  const origin = `${url.protocol}//${url.host}`;
  const effective = [...DEFAULT_ALLOWED_REDIRECT_ORIGINS, ...allowlist];
  const ok = effective.some((entry) => {
    if (entry === "*") return false;
    if (entry === normalized) return true;
    let e: URL;
    try {
      e = new URL(entry);
    } catch {
      return false;
    }
    // RFC 8252 §7.3: a loopback ORIGIN entry (no port, no path, no query) matches the
    // same scheme+host on ANY port. Restricted to origin-only entries (no explicit
    // port, no path/query) so a port-scoped or path-specific entry is NOT widened.
    if (!e.port && !hasExplicitPort(entry) && (!e.pathname || e.pathname === "/") && !e.search
      && LOOPBACK_HOSTS.has(e.hostname) && e.protocol === url.protocol && e.hostname === url.hostname) {
      return true;
    }
    return (!e.pathname || e.pathname === "/") && !e.search && `${e.protocol}//${e.host}` === origin;
  });
  if (!ok) throw new OAuthError("invalid_redirect_uri", "redirect_uri is not allowed");
  return normalized;
}

/** Per-client policy (stored-DCR authorize-time, RC item (b)):
 *   native → RFC 8252 loopback on any port (http or https), scheme+host+path must
 *            match a registered loopback URI (port ignored);
 *   web    → https only, exact match against a registered redirect_uri. */
export function assertRedirectAllowedForClient(redirectUri: string, client: ClientRegistration): string {
  // §17.2: machine clients have no redirect (redirectUris is []) and are rejected
  // at /oauth/authorize (invalid_client). Guarded here too as defense-in-depth so
  // any path that resolves a redirect for a stored client fails closed loudly
  // (with the contract's error code) rather than falling through the native
  // branch. Also makes the function exhaustive over ApplicationType.
  if (client.applicationType === "machine") {
    throw new OAuthError("invalid_client", "Machine clients cannot use the authorization-code flow", 401);
  }
  let url: URL;
  try {
    url = new URL(redirectUri);
  } catch {
    throw new OAuthError("invalid_redirect_uri", "redirect_uri is invalid");
  }
  if (url.username || url.password) {
    throw new OAuthError("invalid_redirect_uri", "redirect_uri must not contain userinfo");
  }
  url.hash = "";
  const normalized = url.href;
  if (client.applicationType === "web") {
    if (url.protocol !== "https:" || !client.redirectUris.includes(normalized)) {
      throw new OAuthError("invalid_redirect_uri", "redirect_uri is not registered for this web client");
    }
    return normalized;
  }
  // native: loopback any-port (RFC 8252 §7.3)
  if ((url.protocol !== "http:" && url.protocol !== "https:") || !LOOPBACK_HOSTS.has(url.hostname)) {
    throw new OAuthError("invalid_redirect_uri", "native redirect_uri must be loopback");
  }
  const matches = client.redirectUris.some((registered) => {
    let r: URL;
    try {
      r = new URL(registered);
    } catch {
      return false;
    }
    return r.protocol === url.protocol && r.hostname === url.hostname && r.pathname === url.pathname && r.search === url.search;
  });
  if (!matches) throw new OAuthError("invalid_redirect_uri", "redirect_uri is not registered for this native client");
  return normalized;
}

/** Whether a raw allowlist entry carries an explicit `:port` before any
 *  path/query/fragment. `new URL` normalizes default ports away, so this reads the
 *  raw entry to keep a port-scoped loopback entry from being widened. Handles
 *  bracketed IPv6 (`http://[::1]:80`). */
function hasExplicitPort(entry: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\/(?:\[[^\]]*\]|[^\s:/?#]+):\d+(?=[/?#]|$)/i.test(entry);
}
