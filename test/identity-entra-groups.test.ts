// Entra group→scope authorization ceiling — contracts §17.4 PRODUCER (S2b).
// Pure-logic + boot-validation tests for src/identity/entra-groups.ts plus the
// validateEntraIdToken integration (signature is checked elsewhere; these feed
// a payload straight to the pure claim validator — addendum 12, no JWKS fetch).
// The IdP-agnostic ENGINE (intersection at prepare/approve) is covered by
// authorize-ceiling.test.ts; here we prove the Entra mapping produces the
// correct ceiling and fails closed on overage / no-groups / malformed config.

import assert from "node:assert/strict";
import { test } from "node:test";
import { AuthConfigError } from "../src/config.ts";
import {
  type EntraConfig, validateEntraIdToken, createEntraIdentity, entraIssuer,
} from "../src/identity/entra.ts";
import {
  type GroupAuthorization, assertGroupAuthorizationMapping,
  computeGroupScopes, resolveGroupCeiling, hasOverageMarker,
} from "../src/identity/entra-groups.ts";

const TENANT = "11111111-2222-3333-4444-555555555555";
const CONFIG: EntraConfig = {
  tenantId: TENANT,
  clientId: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  redirectUri: "https://bridge.test/oauth/entra/callback",
};
const NOW = Math.floor(Date.parse("2026-07-03T12:00:00.000Z") / 1000);

// Valid Entra group object IDs (GUIDs).
const READERS = "11111111-1111-1111-1111-111111111111";
const WRITERS = "22222222-2222-2222-2222-222222222222";
const ADMINS = "33333333-3333-3333-3333-333333333333";
const UNMAPPED = "44444444-4444-4444-4444-444444444444";
// Letter-bearing GUID (a–f) so .toUpperCase() is a genuinely different string —
// needed to exercise case-insensitive matching/duplicate detection for real.
const EDITORS = "abcdef01-1111-2222-3333-444455556666";

function payload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { iss: entraIssuer(TENANT), aud: CONFIG.clientId, tid: TENANT, oid: "oid-abc", exp: NOW + 3600, iat: NOW, ...overrides };
}

function groupConfig(mapping: Record<string, string[]>, baseScopes: string[] = []): EntraConfig {
  return { ...CONFIG, groupAuthorization: { mapping, baseScopes } };
}

// --- resolveGroupCeiling: the claim → ceiling decision (pure) ---

test("resolveGroupCeiling: unions baseScopes + every matched group's scopes (no precedence)", () => {
  const r = resolveGroupCeiling(
    { groups: [READERS, ADMINS, UNMAPPED] },
    { mapping: { [READERS]: ["mcp:read"], [ADMINS]: ["mcp:admin", "mcp:read"] }, baseScopes: ["mcp:base"] },
  );
  assert.equal(r.ok, true);
  assert.deepEqual(r.ok && [...r.allowedScopes].sort(), ["mcp:admin", "mcp:base", "mcp:read"]);
});

test("resolveGroupCeiling: unmapped groups contribute nothing", () => {
  const r = resolveGroupCeiling(
    { groups: [UNMAPPED] },
    { mapping: { [READERS]: ["mcp:read"] }, baseScopes: ["mcp:read"] },
  );
  assert.deepEqual(r.ok && [...r.allowedScopes].sort(), ["mcp:read"]);
});

test("resolveGroupCeiling: no groups claim + non-empty baseScopes ⇒ ceiling = baseScopes", () => {
  const r = resolveGroupCeiling({}, { mapping: { [READERS]: ["mcp:write"] }, baseScopes: ["mcp:read"] });
  assert.deepEqual(r.ok && [...r.allowedScopes].sort(), ["mcp:read"]);
});

test("resolveGroupCeiling: no groups claim + empty baseScopes ⇒ entra_no_groups", () => {
  const r = resolveGroupCeiling({}, { mapping: { [READERS]: ["mcp:read"] }, baseScopes: [] });
  assert.equal(r.ok, false);
  assert.equal(!r.ok && r.reason, "entra_no_groups");
});

test("resolveGroupCeiling: groups present but all unmapped + empty baseScopes ⇒ entra_no_mapped_groups (distinct from no-claim)", () => {
  // A user in a group that has no mapping entry is NOT a groupMembershipClaims
  // misconfiguration — it's a deployer mapping gap. The distinct reason points
  // the operator at the right config knob (audit fidelity).
  const r = resolveGroupCeiling({ groups: [UNMAPPED] }, { mapping: { [READERS]: ["mcp:read"] }, baseScopes: [] });
  assert.equal(r.ok, false);
  assert.equal(!r.ok && r.reason, "entra_no_mapped_groups");
});

test("resolveGroupCeiling: overage marker (_claim_names.groups) ⇒ fail closed entra_groups_overage", () => {
  const r = resolveGroupCeiling({ _claim_names: { groups: "src1" } }, { mapping: { [READERS]: ["mcp:read"] }, baseScopes: [] });
  assert.equal(r.ok, false);
  assert.equal(!r.ok && r.reason, "entra_groups_overage");
});

test("resolveGroupCeiling: hasgroups marker ⇒ fail closed entra_groups_overage", () => {
  const r = resolveGroupCeiling({ hasgroups: true }, { mapping: { [READERS]: ["mcp:read"] }, baseScopes: ["mcp:read"] });
  assert.equal(!r.ok && r.reason, "entra_groups_overage");
});

test("resolveGroupCeiling: groups PRESENT + overage marker ⇒ groups win (marker consulted only when groups absent)", () => {
  // A benign hasgroups alongside a real groups claim must not false-fail.
  const r = resolveGroupCeiling({ groups: [READERS], hasgroups: true }, { mapping: { [READERS]: ["mcp:read"] }, baseScopes: [] });
  assert.equal(r.ok, true);
});

test("resolveGroupCeiling: _claim_sources endpoint is NEVER dereferenced — overage fails closed with a malicious URL present", () => {
  // A URL inside a token is data, not instructions. The pure path has no
  // network access; this asserts the overage decision ignores it and fails closed.
  const r = resolveGroupCeiling(
    { _claim_names: { groups: "src1" }, _claim_sources: { src1: { endpoint: "https://attacker.test/exfil" } } },
    { mapping: { [READERS]: ["mcp:read"] }, baseScopes: [] },
  );
  assert.equal(!r.ok && r.reason, "entra_groups_overage");
});

test("resolveGroupCeiling: malformed groups claim (non-array) treated as no groups", () => {
  const r = resolveGroupCeiling({ groups: "not-an-array" }, { mapping: { [READERS]: ["mcp:read"] }, baseScopes: [] });
  assert.equal(!r.ok && r.reason, "entra_no_groups");
});

test("resolveGroupCeiling: non-string group entries are dropped, valid ones still match (defensive)", () => {
  const r = resolveGroupCeiling({ groups: [123, READERS, null, ""] }, { mapping: { [READERS]: ["mcp:read"] }, baseScopes: [] });
  assert.equal(r.ok, true);
  assert.deepEqual(r.ok && [...r.allowedScopes].sort(), ["mcp:read"]);
});

test("hasOverageMarker: _claim_names.groups and hasgroups both detected; absent otherwise", () => {
  assert.equal(hasOverageMarker({ _claim_names: { groups: "src1" } }), true);
  assert.equal(hasOverageMarker({ hasgroups: true }), true);
  assert.equal(hasOverageMarker({ hasgroups: "true" }), false); // strictly boolean true
  assert.equal(hasOverageMarker({}), false);
  assert.equal(hasOverageMarker({ _claim_names: { email: "x" } }), false); // groups key specifically
});

// --- computeGroupScopes: the union (pure) ---

test("computeGroupScopes: case-insensitive lookup (Entra emits lowercase; keys accepted any case)", () => {
  // EDITORS is lowercase; the mapping key is its UPPERCASE form — must still match.
  const ceiling = computeGroupScopes([EDITORS], { mapping: { [EDITORS.toUpperCase()]: ["mcp:read"] }, baseScopes: [] });
  assert.deepEqual(ceiling, ["mcp:read"]);
});

// --- assertGroupAuthorizationMapping: boot validation (fail-closed) ---

test("assertGroupAuthorizationMapping: rejects non-GUID mapping key (display-name spoof vector)", () => {
  for (const bad of ["Finance Team", "readers", "12345", "not-a-guid", `${READERS}-extra`]) {
    assert.throws(() => assertGroupAuthorizationMapping({ mapping: { [bad]: ["mcp:read"] } }), AuthConfigError, `key "${bad}"`);
  }
});

test("assertGroupAuthorizationMapping: accepts an uppercase GUID key (case-insensitive validation)", () => {
  assert.doesNotThrow(() => assertGroupAuthorizationMapping({ mapping: { [EDITORS.toUpperCase()]: ["mcp:read"] } }));
});

test("assertGroupAuthorizationMapping: rejects duplicate case-insensitive keys (same GUID, different case)", () => {
  // EDITORS (lowercase) and EDITORS.toUpperCase() are distinct JS keys but the
  // same GUID — boot must reject the ambiguity (one canonical mapping per group).
  assert.throws(
    () => assertGroupAuthorizationMapping({ mapping: { [EDITORS]: ["mcp:read"], [EDITORS.toUpperCase()]: ["mcp:write"] } }),
    AuthConfigError,
  );
});

test("assertGroupAuthorizationMapping: rejects empty scope array", () => {
  assert.throws(() => assertGroupAuthorizationMapping({ mapping: { [READERS]: [] } }), AuthConfigError);
});

test("assertGroupAuthorizationMapping: rejects empty / non-string scope values", () => {
  assert.throws(() => assertGroupAuthorizationMapping({ mapping: { [READERS]: ["mcp:read", ""] } }), AuthConfigError);
  assert.throws(() => assertGroupAuthorizationMapping({ mapping: { [READERS]: ["mcp:read", 5 as unknown as string] } }), AuthConfigError);
});

test("assertGroupAuthorizationMapping: rejects empty / non-string baseScopes", () => {
  assert.throws(() => assertGroupAuthorizationMapping({ mapping: { [READERS]: ["mcp:read"] }, baseScopes: [""] }), AuthConfigError);
  assert.throws(() => assertGroupAuthorizationMapping({ mapping: { [READERS]: ["mcp:read"] }, baseScopes: [false as unknown as string] }), AuthConfigError);
});

test("assertGroupAuthorizationMapping: rejects a non-array baseScopes (string iterates char-by-char — Codex P2)", () => {
  // baseScopes: "mcp:read" is iterable; without an Array guard, for..of walks it
  // as ['m','c','p',':','r','e','a','d'] and each char is a valid single-token
  // scope, so boot would accept it and computeGroupScopes would build a nonsense
  // ceiling. Must throw regardless of whether scopeCatalog is supplied.
  assert.throws(() => assertGroupAuthorizationMapping({ mapping: { [READERS]: ["mcp:read"] }, baseScopes: "mcp:read" as unknown as string[] }), AuthConfigError);
  assert.throws(() => assertGroupAuthorizationMapping({ mapping: { [READERS]: ["mcp:read"] }, baseScopes: "mcp:read" as unknown as string[] }, ["mcp:read"]), AuthConfigError);
  // undefined baseScopes is the legitimate "omitted" path.
  assert.doesNotThrow(() => assertGroupAuthorizationMapping({ mapping: { [READERS]: ["mcp:read"] } }));
});

test("assertGroupAuthorizationMapping: rejects a non-token scope value (NQCHAR round-trip guard — PR #8 sibling)", () => {
  // A space-bearing mapping value like "mcp:read mcp:admin" would serialize into
  // the space-joined allowed_scopes claim and re-split at approve, widening the
  // ceiling (resurrection escalation — threat-model row 22). Boot must catch it
  // even WITHOUT a scopeCatalog (the deployer may omit it), so the misconfig is
  // loud at boot, not a runtime 401 locking out every user in the group.
  assert.throws(() => assertGroupAuthorizationMapping({ mapping: { [READERS]: ["mcp:read mcp:admin"] } }), AuthConfigError);
  assert.throws(() => assertGroupAuthorizationMapping({ mapping: { [READERS]: ["mcp:read"] }, baseScopes: ["mcp:write mcp:admin"] }), AuthConfigError);
  // quote/control chars are likewise rejected
  assert.throws(() => assertGroupAuthorizationMapping({ mapping: { [READERS]: ['"mcp:read"'] } }), AuthConfigError);
  assert.throws(() => assertGroupAuthorizationMapping({ mapping: { [READERS]: ["mcp:read\tadmin"] } }), AuthConfigError);
  // a single valid token is accepted (no catalog needed)
  assert.doesNotThrow(() => assertGroupAuthorizationMapping({ mapping: { [READERS]: ["mcp:read"] } }));
});

test("assertGroupAuthorizationMapping: rejects non-object mapping", () => {
  assert.throws(() => assertGroupAuthorizationMapping({ mapping: "nope" as unknown as Record<string, string[]> }), AuthConfigError);
  assert.throws(() => assertGroupAuthorizationMapping({ mapping: [] as unknown as Record<string, string[]> }), AuthConfigError);
});

test("assertGroupAuthorizationMapping: subset check rejects a mapped scope not in catalog", () => {
  assert.throws(
    () => assertGroupAuthorizationMapping({ mapping: { [READERS]: ["mcp:unknown"] } }, ["mcp:read", "mcp:write"]),
    AuthConfigError,
  );
});

test("assertGroupAuthorizationMapping: subset check rejects a baseScope not in catalog", () => {
  assert.throws(
    () => assertGroupAuthorizationMapping({ mapping: { [READERS]: ["mcp:read"] }, baseScopes: ["mcp:unknown"] }, ["mcp:read"]),
    AuthConfigError,
  );
});

test("assertGroupAuthorizationMapping: subset check accepts mapped + base ⊆ catalog", () => {
  assert.doesNotThrow(() =>
    assertGroupAuthorizationMapping({ mapping: { [READERS]: ["mcp:read"], [WRITERS]: ["mcp:write"] }, baseScopes: ["mcp:read"] }, ["mcp:read", "mcp:write", "mcp:admin"]),
  );
});

test("assertGroupAuthorizationMapping: undefined groupAuth is a no-op (v0.1 path)", () => {
  assert.doesNotThrow(() => assertGroupAuthorizationMapping(undefined, ["mcp:read"]));
});

test("assertGroupAuthorizationMapping: falsy/non-object groupAuth is REJECTED (only undefined bypasses — Codex P2)", () => {
  // A null/false/0/"" reaching here from JS/JSON config must NOT be treated as
  // "absent" — that would run the port with no ceiling and grant the full catalog
  // (fail-open for the Gate 2 control). Only undefined is the absent sentinel.
  for (const bad of [null, false, 0, "", "nope", 42, []]) {
    assert.throws(
      () => assertGroupAuthorizationMapping(bad as unknown as GroupAuthorization, ["mcp:read"]),
      AuthConfigError,
      `falsy/non-object value ${JSON.stringify(bad)} must be rejected`,
    );
  }
});

test("createEntraIdentity: boot-rejects a falsy groupAuthorization (null never degrades to no-ceiling)", () => {
  assert.throws(() => createEntraIdentity({ ...CONFIG, groupAuthorization: null as unknown as GroupAuthorization }), AuthConfigError);
  assert.throws(() => createEntraIdentity({ ...CONFIG, groupAuthorization: false as unknown as GroupAuthorization }), AuthConfigError);
  // undefined remains the legitimate "not configured" path (no ceiling, v0.1).
  assert.equal(typeof createEntraIdentity({ ...CONFIG, groupAuthorization: undefined }).verify, "function");
});

test("assertGroupAuthorizationMapping: empty mapping is allowed (everyone falls back to baseScopes)", () => {
  assert.doesNotThrow(() => assertGroupAuthorizationMapping({ mapping: {}, baseScopes: ["mcp:read"] }, ["mcp:read"]));
});

// --- createEntraIdentity: boot wiring (construction-time validation) ---

test("createEntraIdentity: boot-rejects a non-GUID mapping key", () => {
  assert.throws(() => createEntraIdentity({ ...CONFIG, groupAuthorization: { mapping: { Admins: ["mcp:read"] } } }), AuthConfigError);
});

test("createEntraIdentity: subset check runs when scopeCatalog is supplied at construction", () => {
  assert.throws(
    () => createEntraIdentity({ ...CONFIG, groupAuthorization: { mapping: { [READERS]: ["mcp:unknown"] } } }, { scopeCatalog: ["mcp:read"] }),
    AuthConfigError,
  );
  // and accepts when the mapping is within the catalog
  const entra = createEntraIdentity(
    { ...CONFIG, groupAuthorization: { mapping: { [READERS]: ["mcp:read"] } } },
    { scopeCatalog: ["mcp:read", "mcp:write"] },
  );
  assert.equal(typeof entra.verify, "function");
});

test("createEntraIdentity: subset check is skipped when scopeCatalog is omitted (guid/empty checks still run)", () => {
  // mcp:unknown is not in any catalog, but without one supplied the subset gate
  // is the deployer's to run elsewhere; GUID/empty validation still applies.
  const entra = createEntraIdentity({ ...CONFIG, groupAuthorization: { mapping: { [READERS]: ["mcp:unknown"] } } });
  assert.equal(typeof entra.verify, "function");
  // ...but a non-GUID key still fails regardless of catalog.
  assert.throws(() => createEntraIdentity({ ...CONFIG, groupAuthorization: { mapping: { Admins: ["mcp:read"] } } }), AuthConfigError);
});

// --- validateEntraIdToken: end-to-end claim extraction (no JWKS fetch) ---

test("validateEntraIdToken: groupAuthorization ceiling is the union of matched groups + baseScopes", () => {
  const cfg = groupConfig({ [READERS]: ["mcp:read"], [ADMINS]: ["mcp:admin"] }, []);
  const r = validateEntraIdToken(payload({ groups: [READERS, ADMINS, UNMAPPED] }) as never, cfg);
  assert.equal(r.ok, true);
  assert.deepEqual(r.ok && [...(r.identity.allowedScopes ?? [])].sort(), ["mcp:admin", "mcp:read"]);
});

test("validateEntraIdToken: ceiling carries in identity.allowedScopes (the S2a channel)", () => {
  const cfg = groupConfig({ [READERS]: ["mcp:read"] });
  const r = validateEntraIdToken(payload({ groups: [READERS] }) as never, cfg);
  assert.equal(r.ok && r.identity.subject, "oid-abc");
  assert.deepEqual(r.ok && r.identity.allowedScopes, ["mcp:read"]);
});

test("validateEntraIdToken: overage marker fails closed with entra_groups_overage", () => {
  const cfg = groupConfig({ [READERS]: ["mcp:read"] });
  const r = validateEntraIdToken(payload({ _claim_names: { groups: "src1" } }) as never, cfg);
  assert.equal(!r.ok && r.reason, "entra_groups_overage");
});

test("validateEntraIdToken: no groups + empty baseScopes fails closed with entra_no_groups", () => {
  const cfg = groupConfig({ [READERS]: ["mcp:read"] }, []);
  const r = validateEntraIdToken(payload({}) as never, cfg);
  assert.equal(!r.ok && r.reason, "entra_no_groups");
});

test("validateEntraIdToken: subjectAllowlist (mutable-claims behavior) is independent of groupAuthorization", () => {
  const cfg: EntraConfig = { ...CONFIG, subjectAllowlist: ["oid-abc"], groupAuthorization: { mapping: { [READERS]: ["mcp:read"] }, baseScopes: ["mcp:read"] } };
  assert.equal(validateEntraIdToken(payload({ groups: [READERS] }) as never, cfg).ok, true);
  // oid not in the allowlist → rejected before the ceiling is even consulted.
  assert.equal(validateEntraIdToken(payload({ oid: "other", groups: [READERS] }) as never, cfg).ok, false);
});

test("validateEntraIdToken: WITHOUT groupAuthorization, behavior is unchanged v0.1 (no ceiling, groups ignored)", () => {
  // groups present but no mapping configured → no allowedScopes on the identity.
  const r = validateEntraIdToken(payload({ groups: [READERS] }) as never, CONFIG);
  assert.equal(r.ok, true);
  assert.equal(r.ok && r.identity.allowedScopes, undefined);
});
