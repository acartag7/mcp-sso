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

/** RFC 6749 §3.3 `scope-token = 1*NQCHAR` — no space, no `"`, no `\`, no control
 *  chars. Each ceiling entry must be a single token so the space-joined
 *  `allowed_scopes` JWT claim round-trips losslessly through `split(/\s+/)`. */
const SCOPE_TOKEN_RE = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

/** Validate an identity-port `allowedScopes` ceiling (contracts §17.4). Returns
 *  the value unchanged when it is `undefined` (no ceiling — v0.1 behavior) or a
 *  `string[]` of single scope tokens (any array, including `[]` = "entitled to
 *  nothing"). Throws `access_denied` on a present-but-malformed value: a
 *  non-array, or any entry that is not a single RFC 6749 scope token (non-string,
 *  empty, or whitespace/control/quote-bearing). A whitespace-bearing entry would
 *  otherwise serialize into the space-delimited `allowed_scopes` claim and
 *  re-split into discrete scopes at `approve`, widening the ceiling there and
 *  letting a prior grant resurrect a scope the prepare-time ceiling never held
 *  (threat-model row 22; Codex P1). Applied at BOTH the Bridge boundary
 *  (`resolveIdentity`) AND the exported core use-case (`prepare`) so a consumer
 *  calling `prepare` directly — or a custom adapter bypassing `resolveIdentity` —
 *  cannot skip it. */
export function assertAllowedScopesCeiling(value: unknown): string[] | undefined {
  if (value === undefined) return undefined;
  if (Array.isArray(value) && value.every((s) => typeof s === "string" && SCOPE_TOKEN_RE.test(s))) return value;
  throw new OAuthError("access_denied", "Identity port returned a malformed allowedScopes ceiling", 401);
}

/** 403 insufficient_scope step-up if the subject lacks `required`. */
export function requireScope(auth: AuthorizedSubject, required: string): void {
  if (!auth.scopes.includes(required)) {
    throw new OAuthError("insufficient_scope", `Missing required scope: ${required}`, 403);
  }
}
