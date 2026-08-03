// Scope contract (contracts §11). The catalog is caller-supplied (no hardcoded
// fetch:* scopes) and fail-closed: any requested scope not in the catalog is
// rejected with invalid_scope. `requireScope` drives the 403 step-up (§8.3).

import { OAuthError } from "./errors.ts";

export type CredentialKind = "interactive" | "machine";

export interface AuthorizedSubject {
  subject: string;
  clientId: string;
  scopes: string[];
  credentialKind: CredentialKind;
}

export const MAX_SCOPE_ENTRIES = 128;
export const MAX_SCOPE_TOKEN_BYTES = 256;
export const MAX_SCOPE_CLAIM_BYTES = MAX_SCOPE_ENTRIES * MAX_SCOPE_TOKEN_BYTES + MAX_SCOPE_ENTRIES - 1;

/** Validate requested scopes against the configured catalog. Falls back to
 *  `defaults` when `scope` is absent/empty. De-dupes, preserves order. */
export function normalizeScopes(
  scope: string | string[] | undefined,
  catalog: readonly string[],
  defaults: readonly string[],
): string[] {
  const allowed = new Set(catalog);
  const raw = scopeItems(scope, defaults);
  const out: string[] = [];
  for (const item of raw) {
    if (typeof item !== "string") throw invalidScope();
    const value = item.trim();
    if (!value) continue;
    if (!isBoundedScopeToken(value)) throw invalidScope();
    if (!allowed.has(value)) {
      throw invalidScope();
    }
    if (!out.includes(value)) out.push(value);
  }
  if (out.length !== 0 || scope === undefined) return out;
  return normalizeScopes(undefined, catalog, defaults);
}

/** Validate stored grant scopes without applying request-time defaults. */
export function storedScopes(value: unknown, catalog: readonly string[]): string[] {
  if (scopeListProblem(value) || !Array.isArray(value) || !value.every((scope) => catalog.includes(scope))) {
    throw new OAuthError("invalid_grant", "Stored grant scopes are malformed");
  }
  return [...value] as string[];
}

/** Stable scope string: sorted, space-joined. Used for token `scope` claims. */
export function scopeString(scopes: readonly string[]): string {
  return [...scopes].sort().join(" ");
}

/** RFC 6749 §3.3 `scope-token = 1*NQCHAR` — no space, no `"`, no `\`, no control
 *  chars. Each ceiling entry must be a single token so the space-joined
 *  `allowed_scopes` JWT claim round-trips losslessly through `split(/\s+/)`. */
const SCOPE_TOKEN_RE = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

/** Test a single string against RFC 6749 §3.3 `scope-token` (1*NQCHAR).
 *  Exported so identity-port ceiling producers (e.g. Entra group→scope mapping,
 *  the S3 client_credentials per-client ceiling, the S5 device-consent ceiling)
 *  can validate deployer config at BOOT against the same shape the JWT
 *  round-trip requires — a malformed entry (whitespace/quote/control) would
 *  otherwise serialize into the space-joined `allowed_scopes` claim, re-split at
 *  `approve`, and widen the ceiling (threat-model row 22; Codex P1 on PR #8). */
export function isScopeToken(value: string): boolean {
  return SCOPE_TOKEN_RE.test(value);
}

/** True only for the RFC 6749 token shape that can fit a bounded scope claim. */
export function isBoundedScopeToken(value: string): boolean {
  return isScopeToken(value) && Buffer.byteLength(value, "utf8") <= MAX_SCOPE_TOKEN_BYTES;
}

/** Describe a malformed or oversized scope list without choosing its OAuth error channel. */
export function scopeListProblem(value: unknown): string | undefined {
  try {
    if (!Array.isArray(value)) return "must be an array";
    if (value.length > MAX_SCOPE_ENTRIES) return `must contain at most ${MAX_SCOPE_ENTRIES} entries`;
    let claimBytes = Math.max(0, value.length - 1);
    for (const scope of value) {
      if (typeof scope !== "string" || !isBoundedScopeToken(scope)) {
        return `entries must be RFC 6749 scope tokens of at most ${MAX_SCOPE_TOKEN_BYTES} UTF-8 bytes`;
      }
      claimBytes += Buffer.byteLength(scope, "utf8");
      if (claimBytes > MAX_SCOPE_CLAIM_BYTES) return "space-joined value is too large";
    }
    return undefined;
  } catch {
    return "could not be read";
  }
}

/** Validate an identity-port `allowedScopes` ceiling (contracts §17.4). Returns
 *  `undefined` unchanged (no ceiling — v0.1 behavior) or a fresh bounded
 *  `string[]` of single scope tokens (any array, including `[]` = "entitled to
 *  nothing"). Throws `access_denied` on a present-but-malformed value: a
 *  non-array, over-bound list, or any entry that is not a single RFC 6749 scope
 *  token (non-string, empty, or whitespace/control/quote-bearing). A whitespace-bearing entry would
 *  otherwise serialize into the space-delimited `allowed_scopes` claim and
 *  re-split into discrete scopes at `approve`, widening the ceiling there and
 *  letting a prior grant resurrect a scope the prepare-time ceiling never held
 *  (threat-model row 22; Codex P1). Applied at BOTH the Bridge boundary
 *  (`resolveIdentity`) AND the exported core use-case (`prepare`) so a consumer
 *  calling `prepare` directly — or a custom adapter bypassing `resolveIdentity` —
 *  cannot skip it. */
export function assertAllowedScopesCeiling(value: unknown): string[] | undefined {
  if (value === undefined) return undefined;
  if (scopeListProblem(value) === undefined && Array.isArray(value)) return [...value] as string[];
  throw new OAuthError("access_denied", "Identity port returned a malformed allowedScopes ceiling", 401);
}

/** §17.2 client_credentials scope resolution: the granted scope MUST be a subset
 *  of BOTH the client's `allowedScopes` ceiling (the cap fixed at provisioning)
 *  AND the live `scopeCatalog`. Omitted/empty ⇒ the full ceiling (RFC 6749 §3.3
 *  default). A scope outside the ceiling, OR no longer in the catalog, ⇒
 *  `invalid_scope`. The catalog check is the same fail-closed gate
 *  {@link normalizeScopes} applies to user grants: a scope removed from the
 *  catalog AFTER a machine client was provisioned is never minted (the persisted
 *  record is not re-validated at provisioning only), so drift surfaces as
 *  invalid_scope until the client is re-provisioned — the same discipline a
 *  drifted user refresh token imposes. De-dupes, preserves request order. */
export function resolveClientCredentialsScope(requested: string | undefined, ceiling: readonly string[], catalog: readonly string[]): string[] {
  if (scopeListProblem(ceiling)) {
    throw new OAuthError("invalid_scope", "Client allowedScopes are malformed");
  }
  const ceilingSet = new Set(ceiling);
  const catalogSet = new Set(catalog);
  if (requested !== undefined && (typeof requested !== "string" || Buffer.byteLength(requested, "utf8") > MAX_SCOPE_CLAIM_BYTES)) {
    throw invalidScope();
  }
  const requestedList = requested === undefined || requested.trim() === "" ? [...ceiling] : requested.split(/\s+/).filter(Boolean);
  if (requestedList.length > MAX_SCOPE_ENTRIES) throw invalidScope();
  const out: string[] = [];
  for (const token of requestedList) {
    if (!isBoundedScopeToken(token)) throw invalidScope();
    if (!ceilingSet.has(token)) throw new OAuthError("invalid_scope", "Requested scope exceeds the client's allowedScopes");
    if (!catalogSet.has(token)) throw new OAuthError("invalid_scope", "Requested scope is not in the current scopeCatalog");
    if (!out.includes(token)) out.push(token);
  }
  return out;
}

function scopeItems(scope: string | string[] | undefined, defaults: readonly string[]): readonly unknown[] {
  const raw = scope === undefined ? defaults : Array.isArray(scope)
    ? scope
    : typeof scope === "string" && Buffer.byteLength(scope, "utf8") <= MAX_SCOPE_CLAIM_BYTES
      ? scope.split(/\s+/)
      : null;
  if (!raw || raw.length > MAX_SCOPE_ENTRIES) throw invalidScope();
  return raw;
}

function invalidScope(): OAuthError {
  return new OAuthError("invalid_scope", "Requested scope is not supported");
}

/** 403 insufficient_scope step-up if the subject lacks `required`. */
export function requireScope(auth: AuthorizedSubject, required: string): void {
  if (!auth.scopes.includes(required)) {
    throw new OAuthError("insufficient_scope", `Missing required scope: ${required}`, 403);
  }
}
