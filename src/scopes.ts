// Scope contract (contracts §11). The catalog is caller-supplied (no hardcoded
// fetch:* scopes) and fail-closed: any requested scope not in the catalog is
// rejected with invalid_scope. `requireScope` drives the 403 step-up (§8.3).

import { OAuthError } from "./errors.js";

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

/** 403 insufficient_scope step-up if the subject lacks `required`. */
export function requireScope(auth: AuthorizedSubject, required: string): void {
  if (!auth.scopes.includes(required)) {
    throw new OAuthError("insufficient_scope", `Missing required scope: ${required}`, 403);
  }
}
