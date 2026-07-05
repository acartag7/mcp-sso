// Scope contract (contracts §11). The catalog is caller-supplied (no hardcoded
// fetch:* scopes) and fail-closed: any requested scope not in the catalog is
// rejected with invalid_scope. `requireScope` drives the 403 step-up (§8.3).

import { OAuthError } from "./errors.ts";

export interface AuthorizedSubject {
  subject: string;
  clientId: string;
  scopes: string[];
}

/** Validate requested scopes against the configured catalog. Falls back to
 *  `defaults` when `scope` is absent/empty. De-dupes, preserves order. */
export function normalizeScopes(
  scope: string | string[] | undefined,
  catalog: readonly string[],
  defaults: readonly string[],
): string[] {
  const allowed = new Set(catalog);
  const raw = Array.isArray(scope) ? scope : (scope ?? defaults.join(" ")).split(/\s+/);
  const out: string[] = [];
  for (const value of raw.map((item) => item.trim()).filter(Boolean)) {
    if (!allowed.has(value)) {
      throw new OAuthError("invalid_scope", "Requested scope is not supported");
    }
    if (!out.includes(value)) out.push(value);
  }
  return out.length ? out : [...defaults];
}

/** Stable scope string: sorted, space-joined. Used for token `scope` claims. */
export function scopeString(scopes: readonly string[]): string {
  return [...scopes].sort().join(" ");
}

/** Validate an identity-port `allowedScopes` ceiling (contracts §17.4). Returns
 *  the value unchanged when it is `undefined` (no ceiling — v0.1 behavior) or a
 *  `string[]` (any array, including `[]` = "entitled to nothing"). Throws
 *  `access_denied` on a present-but-malformed value (non-array or non-string
 *  elements): a malformed security input must NEVER widen to full access
 *  (fail-closed house rule; threat-model row 22). Applied at BOTH the Bridge
 *  boundary (`resolveIdentity`) AND the exported core use-case (`prepare`) so a
 *  consumer calling `prepare` directly — or a custom adapter bypassing
 *  `resolveIdentity` — cannot skip it. */
export function assertAllowedScopesCeiling(value: unknown): string[] | undefined {
  if (value === undefined) return undefined;
  if (Array.isArray(value) && value.every((s) => typeof s === "string")) return value;
  throw new OAuthError("access_denied", "Identity port returned a malformed allowedScopes ceiling", 401);
}

/** 403 insufficient_scope step-up if the subject lacks `required`. */
export function requireScope(auth: AuthorizedSubject, required: string): void {
  if (!auth.scopes.includes(required)) {
    throw new OAuthError("insufficient_scope", `Missing required scope: ${required}`, 403);
  }
}
