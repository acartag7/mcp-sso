// Redirect-URI policy (contracts §10). Every configured, registered, stored, and
// presented value first passes the one raw §10.0 grammar in redirect-entry.ts.

import type { AuthorizationClientRegistration } from "./client-registration.ts";
import type { ClientRegistration } from "./ports/client-store.ts";
import { OAuthError } from "./errors.ts";
import {
  isLoopbackRedirect, parseRedirectEntry, RedirectEntryError,
  type RedirectEntry,
} from "./redirect-entry.ts";

/** Built-in trusted hosted-client origins. Loopback trust is operator-owned:
 *  add the needed origin to redirectAllowlist explicitly. */
export const DEFAULT_ALLOWED_REDIRECT_ORIGINS = Object.freeze([
  "https://claude.ai",
  "https://chatgpt.com",
]);

/** Validate a redirect_uri against the global allowlist (built-ins + config).
 *  Returns the unchanged canonical URI. Throws invalid_redirect_uri on rejection. */
export function assertAllowedRedirectUri(value: unknown, allowlist: readonly unknown[]): string {
  const presented = oauthEntry(value);
  const entries = [...DEFAULT_ALLOWED_REDIRECT_ORIGINS, ...allowlist]
    .map((entry) => oauthEntry(entry, true));
  if (!entries.some((entry) => globalMatch(entry, presented))) {
    throw new OAuthError("invalid_redirect_uri", "redirect_uri is not allowed");
  }
  return presented.raw;
}

/** Per-client policy (stored-DCR authorize-time, RC item (b)). Every registered
 *  entry is re-validated on read so legacy/out-of-band records cannot bypass the
 *  grammar after a rolling upgrade. */
export function assertRedirectAllowedForClient(
  redirectUri: string,
  client: ClientRegistration | AuthorizationClientRegistration,
): string {
  if (client.applicationType === "machine") {
    throw new OAuthError("invalid_client", "Machine clients cannot use the authorization-code flow", 401);
  }
  const presented = oauthEntry(redirectUri);
  // Stored-state sibling of the DCR 1..16 write cap: a legacy/out-of-band record
  // can still hold more entries than the write path now admits. Cap BEFORE the
  // scan so an authorize cannot be forced into unbounded parse/allocation work.
  // Capture length once (same Proxy discipline as the write path).
  const length = client.redirectUris.length;
  if (!Number.isInteger(length) || length < 1 || length > 16) {
    throw new OAuthError("invalid_redirect_uri", "stored redirect_uris must contain 1..16 entries");
  }
  // Materialize every stored slot once (Array.from visits holes as undefined,
  // which oauthEntry rejects). Array.prototype.map skips sparse holes and would
  // authorize a valid sibling entry while never re-validating the hole.
  const registered = Array.from(
    { length },
    (_, index) => oauthEntry(client.redirectUris[index]),
  );
  if (client.applicationType === "web") {
    if (presented.url.protocol !== "https:"
      || !registered.every((entry) => entry.url.protocol === "https:")
      || !registered.some((entry) => entry.raw === presented.raw)) {
      throw new OAuthError("invalid_redirect_uri", "redirect_uri is not registered for this web client");
    }
    return presented.raw;
  }
  if (!isNativeEntry(presented) || !registered.every(isNativeEntry)) {
    throw new OAuthError("invalid_redirect_uri", "native redirect_uri must be loopback");
  }
  if (!registered.some((entry) => entry.raw === presented.raw || loopbackAnyPortMatch(entry, presented))) {
    throw new OAuthError("invalid_redirect_uri", "redirect_uri is not registered for this native client");
  }
  return presented.raw;
}

/** Validate one strict (non-config) entry and map its reason to OAuth. Used by
 *  signed/persisted redirect carriers that do not perform an allowlist match. */
export function assertOAuthRedirectEntry(value: unknown): string {
  return oauthEntry(value).raw;
}

/** Validate a stored registration's write-time type policy. */
export function assertRegistrationRedirectPolicy(value: unknown, applicationType: "native" | "web"): string {
  const entry = oauthEntry(value);
  if (applicationType === "web" && entry.url.protocol !== "https:") {
    throw new OAuthError("invalid_redirect_uri", `redirect entry ${JSON.stringify(entry.raw)} must use https for a web client`);
  }
  if (applicationType === "native" && !isNativeEntry(entry)) {
    throw new OAuthError("invalid_redirect_uri", `redirect entry ${JSON.stringify(entry.raw)} must be loopback for a native client`);
  }
  return entry.raw;
}

function globalMatch(entry: RedirectEntry, presented: RedirectEntry): boolean {
  if (entry.form === "exact-uri") return entry.raw === presented.raw;
  if (isLoopbackRedirect(entry) && !entry.hasExplicitPort
    && entry.url.protocol === presented.url.protocol
    && entry.url.hostname === presented.url.hostname) return true;
  return entry.url.origin === presented.url.origin;
}

function isNativeEntry(entry: RedirectEntry): boolean {
  return isLoopbackRedirect(entry)
    && (entry.url.protocol === "http:" || entry.url.protocol === "https:");
}

function loopbackAnyPortMatch(registered: RedirectEntry, presented: RedirectEntry): boolean {
  return registered.url.protocol === "http:" && presented.url.protocol === "http:"
    && registered.url.hostname === presented.url.hostname
    && registered.url.pathname === presented.url.pathname;
}

function oauthEntry(value: unknown, allowOmittedRootSlash = false): RedirectEntry {
  try {
    return parseRedirectEntry(value, { allowOmittedRootSlash });
  } catch (error) {
    const message = error instanceof RedirectEntryError ? error.message : "redirect entry is invalid";
    throw new OAuthError("invalid_redirect_uri", message);
  }
}
