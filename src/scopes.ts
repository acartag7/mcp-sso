// Scope contract (contracts §11). The catalog is caller-supplied (no hardcoded
// fetch:* scopes) and fail-closed: any requested scope not in the catalog is
// rejected with invalid_scope. `requireScope` drives the 403 step-up (§8.3).

import { OAuthError } from "./errors.ts";
import { snapshotOwnDataArray, snapshotOwnDataRecord, snapshotOwnStringArray } from "./own-property.ts";

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
  const catalogValues = snapshotOwnStringArray(catalog);
  const defaultValues = snapshotOwnStringArray(defaults);
  if (catalogValues === null || defaultValues === null) {
    throw new OAuthError("invalid_scope", "Scope policy is malformed");
  }
  const allowed = new Set(catalogValues);
  const arrayScope = Array.isArray(scope) ? snapshotOwnDataArray(scope) : undefined;
  if (arrayScope === null || (arrayScope && !arrayScope.every((item) => typeof item === "string"))) {
    throw new OAuthError("invalid_scope", "Requested scope is malformed");
  }
  const raw: readonly string[] = Array.isArray(scope)
    ? arrayScope as readonly string[]
    : (scope ?? defaultValues.join(" ")).split(/\s+/);
  const out: string[] = [];
  for (const value of raw.map((item) => item.trim()).filter(Boolean)) {
    if (!allowed.has(value)) {
      throw new OAuthError("invalid_scope", "Requested scope is not supported");
    }
    if (!out.includes(value)) out.push(value);
  }
  return out.length ? out : [...defaultValues];
}

/** Stable scope string: sorted, space-joined. Used for token `scope` claims. */
export function scopeString(scopes: readonly string[]): string {
  const values = snapshotOwnStringArray(scopes);
  if (values === null || !values.every(isScopeToken)) {
    throw new OAuthError("invalid_scope", "Scope list is malformed");
  }
  return [...values].sort().join(" ");
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
  return typeof value === "string" && SCOPE_TOKEN_RE.test(value);
}

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
  const snapshot = snapshotOwnDataArray(value);
  if (snapshot && snapshot.every((s) => typeof s === "string" && isScopeToken(s))) return [...snapshot] as string[];
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
  const ceilingValues = snapshotOwnStringArray(ceiling);
  const catalogValues = snapshotOwnStringArray(catalog);
  if (ceilingValues === null || catalogValues === null
    || !ceilingValues.every(isScopeToken) || !catalogValues.every(isScopeToken)) {
    throw new OAuthError("invalid_scope", "Scope policy is malformed");
  }
  const ceilingSet = new Set(ceilingValues);
  const catalogSet = new Set(catalogValues);
  const requestedList = requested === undefined || requested.trim() === "" ? [...ceilingValues] : requested.split(/\s+/).filter(Boolean);
  const out: string[] = [];
  for (const token of requestedList) {
    if (!ceilingSet.has(token)) throw new OAuthError("invalid_scope", "Requested scope exceeds the client's allowedScopes");
    if (!catalogSet.has(token)) throw new OAuthError("invalid_scope", "Requested scope is not in the current scopeCatalog");
    if (!out.includes(token)) out.push(token);
  }
  return out;
}

/** 403 insufficient_scope step-up if the subject lacks `required`. */
export function requireScope(auth: AuthorizedSubject, required: string): void {
  const fields = snapshotOwnDataRecord(auth);
  const scopes = fields && snapshotOwnStringArray(fields.scopes);
  if (typeof required !== "string" || !required || fields === null || scopes === null
    || !scopes.includes(required)) {
    throw new OAuthError("insufficient_scope", `Missing required scope: ${required}`, 403);
  }
}
