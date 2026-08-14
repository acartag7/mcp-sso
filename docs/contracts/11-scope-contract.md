# 11. Scope contract

- `scopeCatalog` (config, required) is the complete set this resource honors.
  Every scope list that can reach a grant, access token, or consent token —
  catalog, defaults, request, identity `allowedScopes` ceiling, stored grant,
  and machine-client ceiling — is limited to **128** entries. Each entry is one
  RFC 6749 `scope-token` no longer than **256 UTF-8 bytes**; the largest
  space-joined claim is therefore 32,895 bytes. Config rejects an invalid
  catalog/default list at boot; untrusted or persisted runtime lists fail closed
  with their operation's typed OAuth error. Runtime lists are copied from one
  length read and one selected-index read per entry before validation or reuse;
  their iterator is never used to validate one view and publish another.
- `normalizeScopes(scope?, catalog)` → validates each requested scope against the
  catalog (unknown or over-bound ⇒ `invalid_scope`), de-dupes, and falls back to
  `defaultScopes` when none requested. Returns the validated list.
- `scopeString(scopes)` → sorted, space-joined (stable token `scope` values).
- `scopeHierarchy` (optional config) is a bounded, immutable implication graph
  for the exact `BridgeConfig.resource`. Each `granted → implies` edge says a
  token carrying the broader `granted` scope satisfies the directly narrower
  scope; reachability is transitive. Boot admits at most 128 granted rows and
  4,096 direct edges, and rejects empty rows, duplicates, self-references,
  cycles, unknown catalog scopes, malformed or extra members, and a resource
  binding that is not byte-for-byte equal to `BridgeConfig.resource`. Omission
  or an empty graph means exact membership, never an inferred hierarchy.
- `requireScope(auth, required, hierarchy?)` → 403 `insufficient_scope`
  step-up (§8.3). The helper remains exact unless the caller explicitly passes a
  validated hierarchy. With one, an exact grant or a transitively implied grant
  succeeds. `RequestAuthorizer` passes its validated config policy; it does not
  infer relationships from scope names. The graph applies only at resource
  authorization: tokens continue to carry the scopes actually granted, so
  implication does not mint or accumulate additional scope strings.
- **Accumulation *(RC item (c)) — stored-DCR opaque clients only.*** Re-authorization
  unions the requested scopes with those derived from this `(subject, clientId)`'s
  active refresh-token records (§9.3) — **no grant store**. In stateless mode, and for
  every scheme-shaped (CIMD) client_id in any mode, there is no accumulation
  (`priorScopes = []`); CIMD accumulation is deferred (§17.1.6 decision 3). Consent UI shows the **delta** (new
  scopes only); rendering is an adapter concern (Phase 3), the core supplies the
  before/after sets.
