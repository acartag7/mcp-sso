// Entra group→scope authorization ceiling — the PRODUCER of the IdP-agnostic
// `allowedScopes` ceiling (contracts §17.4; the engine itself is shipped S2a in
// src/scopes.ts + src/authorize.ts). Pure, JWKS-free, and unit-testable: it
// takes a verified id_token payload (signature already checked by the caller)
// plus a deployer mapping and returns either a scope ceiling or a fail-closed
// reason. Kept in its own module so src/identity/entra.ts stays under the
// 250-line DDD-lite limit and so the logic is exercisable WITHOUT the JWKS
// fetch (addendum 12 pattern).
//
// Facts verified against Microsoft Learn 2026-07-04 (see contracts §17.4): JWT
// `groups` claims cap at 200 entries; beyond that the claim is OMITTED and
// `_claim_names`/`_claim_sources` (id_token) or `hasgroups` (access token)
// overage markers appear instead. Group OBJECT IDs (GUIDs) are the only
// universally available, immutable, collision-safe form — display names are a
// documented spoof vector (any user can create a duplicate-named group), so
// they are boot-rejected here. The `_claim_sources` endpoint URL is legacy
// Azure AD Graph and Microsoft says not to rely on it; it is NEVER dereferenced
// by this module — a URL inside a token is data, not instructions.

import { AuthConfigError } from "../config.ts";
import { isScopeToken } from "../scopes.ts";
import {
  ownBooleanTrue, snapshotOwnDataArray, snapshotOwnDataRecord, snapshotOwnStringArray,
} from "../own-property.ts";
import type { GroupAuthorization, GroupClaimSource } from "./entra-group-types.ts";

export type { GroupAuthorization, GroupClaimSource } from "./entra-group-types.ts";

/** RFC 4122 GUID shape (8-4-4-4-12 hex), any case. Entra group object IDs are
  *  standard GUIDs; no version-digit is enforced (any GUID version is legal). */
const GUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** Boot-validate a group-authorization mapping (contracts §17.4). Throws
  *  `AuthConfigError` (never degrades to a silent default) on: a falsy/non-object
  *  `groupAuthorization` (null/false/0/""/array/primitive — only `undefined` is
  *  the legitimate "absent" sentinel), a non-GUID mapping key (the display-name
  *  spoof vector), an empty/non-string scope value, a duplicate (case-insensitive)
  *  mapping key, or — when `scopeCatalog` is supplied — any mapped/base scope not
  *  in the catalog. The catalog subset check is the wiring-time gate: it runs
  *  where both the Entra mapping and the bridge `scopeCatalog` are known (the
  *  `createEntraIdentity` composition point), not inside `registerOAuthRoutes`
  *  (which sees only an opaque `IdentityPort` — the ceiling is IdP-agnostic by
  *  S2a design). A mapped scope absent from the catalog can never be granted
  *  anyway (the engine intersects
  *  against catalog-validated requested scopes), so this is a deployer footgun
  *  guard surfacing a misconfiguration loudly at boot. */
export function assertGroupAuthorizationMapping(
  groupAuth: GroupAuthorization | undefined,
  scopeCatalog?: readonly string[],
): GroupAuthorization | undefined {
  const catalog = scopeCatalog === undefined ? undefined : snapshotOwnStringArray(scopeCatalog);
  if (catalog === null) throw new AuthConfigError("scopeCatalog must be a dense string array");
  // Only the canonical "absent" sentinel (undefined) bypasses validation. A
  // falsy/malformed value reaching here from JS/JSON config (null, false, 0, "",
  // an array, a primitive) MUST be rejected — treating it as absent would run
  // the Entra port with NO allowedScopes ceiling and grant the full catalog, a
  // fail-open for the shipped Gate 2 control (Codex P2). null !== undefined.
  if (groupAuth === undefined) return undefined;
  if (groupAuth === null || typeof groupAuth !== "object" || Array.isArray(groupAuth)) {
    throw new AuthConfigError("groupAuthorization must be an object (or omitted) — a falsy/malformed value never degrades to a silent no-ceiling default");
  }
  const groupSnapshot = snapshotOwnDataRecord(groupAuth);
  if (groupSnapshot === null) {
    throw new AuthConfigError("groupAuthorization must contain only own enumerable data properties");
  }
  const mapping = snapshotOwnDataRecord(groupSnapshot.mapping);
  if (mapping === null) {
    throw new AuthConfigError("groupAuthorization.mapping must be a Record<GUID, string[]>");
  }
  const seenLower = new Set<string>();
  const mappingSnapshot = Object.create(null) as Record<string, string[]>;
  for (const [key, scopes] of Object.entries(mapping)) {
    if (!GUID_RE.test(key)) {
      throw new AuthConfigError(
        `groupAuthorization mapping key "${key}" is not a GUID (display names are rejected — spoof vector)`,
      );
    }
    const lower = key.toLowerCase();
    if (seenLower.has(lower)) {
      throw new AuthConfigError(`groupAuthorization duplicate (case-insensitive) mapping key "${key}"`);
    }
    seenLower.add(lower);
    const scopeSnapshot = snapshotOwnStringArray(scopes);
    if (scopeSnapshot === null || scopeSnapshot.length === 0) {
      throw new AuthConfigError(`groupAuthorization mapping for "${key}" must be a non-empty string[]`);
    }
    for (const scope of scopeSnapshot) {
      assertMappedScope(scope, key, catalog);
    }
    mappingSnapshot[key] = Object.freeze([...scopeSnapshot]) as string[];
  }
  // baseScopes MUST be undefined or a string[]. A string (e.g. "mcp:read" from a
  // JSON typo) is iterable, so `for...of` would silently walk its characters —
  // each a valid single-char scope token — and computeGroupScopes would build a
  // nonsensical char-by-char ceiling. Reject at boot (Codex P2).
  const baseScopes = groupSnapshot.baseScopes;
  let baseSnapshot: string[] | undefined;
  if (baseScopes !== undefined) {
    const values = snapshotOwnStringArray(baseScopes);
    if (values === null) {
      throw new AuthConfigError("groupAuthorization.baseScopes must be a string[] (or omitted) — a string is iterated char-by-char, producing a nonsensical ceiling");
    }
    for (const scope of values) {
      assertBaseScope(scope, catalog);
    }
    baseSnapshot = Object.freeze([...values]) as string[];
  }
  return Object.freeze({ mapping: Object.freeze(mappingSnapshot), baseScopes: baseSnapshot });
}

function assertMappedScope(scope: unknown, key: string, scopeCatalog: readonly string[] | undefined): void {
  if (typeof scope !== "string" || scope.length === 0) {
    throw new AuthConfigError(`groupAuthorization mapping for "${key}" has an empty or non-string scope`);
  }
  if (!isScopeToken(scope)) {
    // The un-swept sibling of the PR #8 round-trip class (threat-model row 22):
    // a whitespace/quote/control-bearing entry would serialize into the
    // space-joined allowed_scopes claim, re-split at approve, and widen the
    // ceiling. The runtime assertAllowedScopesCeiling backstops this, but a
    // boot AuthConfigError points the deployer at the typo immediately.
    throw new AuthConfigError(
      `groupAuthorization mapping for "${key}" has scope "${scope}" that is not a single RFC 6749 scope token (whitespace/quote/control chars break the allowed_scopes JWT round-trip)`,
    );
  }
  if (scopeCatalog && !scopeCatalog.includes(scope)) {
    throw new AuthConfigError(`groupAuthorization mapped scope "${scope}" (group "${key}") is not in scopeCatalog`);
  }
}

function assertBaseScope(scope: unknown, scopeCatalog: readonly string[] | undefined): void {
  if (typeof scope !== "string" || scope.length === 0) {
    throw new AuthConfigError("groupAuthorization.baseScopes has an empty or non-string entry");
  }
  if (!isScopeToken(scope)) {
    throw new AuthConfigError(
      `groupAuthorization baseScope "${scope}" is not a single RFC 6749 scope token (whitespace/quote/control chars break the allowed_scopes JWT round-trip)`,
    );
  }
  if (scopeCatalog && !scopeCatalog.includes(scope)) {
    throw new AuthConfigError(`groupAuthorization baseScope "${scope}" is not in scopeCatalog`);
  }
}

/** True when the payload carries an overage marker in place of the `groups`
  *  claim. Reads `_claim_names.groups` and `hasgroups` as DATA only; never
  *  touches `_claim_sources` (its endpoint URL is never dereferenced). */
export function hasOverageMarker(payload: GroupClaimSource): boolean {
  const payloadSnapshot = snapshotOwnDataRecord(payload);
  if (payloadSnapshot === null) return false;
  const claimNames = snapshotOwnDataRecord(payloadSnapshot._claim_names);
  if (claimNames !== null && Object.hasOwn(claimNames, "groups")) {
    return true;
  }
  return ownBooleanTrue(payloadSnapshot, "hasgroups");
}

/** Coerce the raw `groups` claim to a deduped list of string GUIDs. Non-array
  *  or non-string entries are dropped (treated as unmapped), never thrown — a
  *  malformed claim yields an empty set and flows to the no-groups branch. */
function normalizeGroups(raw: unknown): string[] {
  const values = snapshotOwnStringArray(raw);
  if (values === null) return [];
  const out: string[] = [];
  for (const entry of values) {
    if (entry && !out.includes(entry)) out.push(entry);
  }
  return out;
}

/** Compute a subject's scope ceiling = `baseScopes ∪ ⋃ mapping[g]` over every
  *  group GUID `g` in `groups` that has a mapping entry. Unmapped groups
  *  contribute nothing. Lookups are case-insensitive (Entra emits lowercase
  *  GUIDs; mapping keys are validated GUIDs of any case). Insertion order:
  *  baseScopes first, then matched groups in claim order. */
export function computeGroupScopes(groups: readonly string[] | undefined, groupAuth: GroupAuthorization): string[] {
  let safeGroupAuth: GroupAuthorization | undefined;
  try { safeGroupAuth = assertGroupAuthorizationMapping(groupAuth); } catch { return []; }
  if (safeGroupAuth === undefined) return [];
  const groupValues = groups === undefined ? undefined : snapshotOwnStringArray(groups);
  if (groupValues === null) return [];
  const ceiling = new Set<string>();
  for (const scope of safeGroupAuth.baseScopes ?? []) ceiling.add(scope);
  if (groupValues && groupValues.length > 0) {
    const lower = new Map<string, string[]>();
    for (const [key, scopes] of Object.entries(safeGroupAuth.mapping)) {
      lower.set(key.toLowerCase(), scopes);
    }
    for (const guid of groupValues) {
      const scopes = lower.get(guid.toLowerCase());
      if (scopes) for (const scope of scopes) ceiling.add(scope);
    }
  }
  return [...ceiling];
}

/** Resolve the ceiling for a verified id_token payload (contracts §17.4).
  *
  *  - `groups` absent + overage marker (`_claim_names.groups` or `hasgroups`)
  *    ⇒ `{ ok:false, reason:"entra_groups_overage" }`. Fail closed: the
  *    alternative (dereferencing `_claim_sources`) puts a legacy Azure AD Graph
  *    URL — attacker-influenceable inside a token — on the auth path.
  *  - No usable groups claim and no overage marker (claim not configured in the
  *    app manifest, or the user is in zero groups) ⇒ ceiling = `baseScopes`;
  *    if that is empty ⇒ `{ ok:false, reason:"entra_no_groups" }` (likely a
  *    `groupMembershipClaims` misconfiguration — documented).
  *  - Otherwise the ceiling is the union of `baseScopes` and every matched
  *    group's mapped scopes. */
export function resolveGroupCeiling(
  payload: GroupClaimSource,
  groupAuth: GroupAuthorization,
): { ok: true; allowedScopes: string[] } | { ok: false; reason: "entra_groups_overage" | "entra_no_groups" | "entra_no_mapped_groups" } {
  const payloadSnapshot = snapshotOwnDataRecord(payload);
  if (payloadSnapshot === null) return { ok: false, reason: "entra_no_groups" };
  if (payloadSnapshot.groups !== undefined) {
    const rawGroups = snapshotOwnDataArray(payloadSnapshot.groups);
    if (rawGroups === null || !rawGroups.every((group) => typeof group === "string")) {
      return { ok: false, reason: "entra_no_groups" };
    }
  }
  const groups = normalizeGroups(payloadSnapshot?.groups);
  const hasGroupsClaim = groups.length > 0;
  if (!hasGroupsClaim && hasOverageMarker(payloadSnapshot)) {
    return { ok: false, reason: "entra_groups_overage" };
  }
  // No groups ⇒ only baseScopes survive (computeGroupScopes unions baseScopes
  // with the matched set, which is empty here).
  const allowedScopes = computeGroupScopes(hasGroupsClaim ? groups : [], groupAuth);
  if (allowedScopes.length === 0) {
    // Distinguish "no groups claim at all" (likely a groupMembershipClaims
    // misconfiguration) from "groups present but none mapped" (a deployer
    // mapping gap). Both are entitled-to-nothing and fail closed; the distinct
    // reason points the operator at the right config knob (audit fidelity —
    // the product's wedge is auditable execution).
    return { ok: false, reason: hasGroupsClaim ? "entra_no_mapped_groups" : "entra_no_groups" };
  }
  return { ok: true, allowedScopes };
}
