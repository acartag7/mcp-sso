# 11. Scope contract

- `scopeCatalog` (config, required) is the complete set this resource honors.
- `normalizeScopes(scope?, catalog)` → validates each requested scope against the
  catalog (unknown ⇒ `invalid_scope`), de-dupes, and falls back to
  `defaultScopes` when none requested. Returns the validated list.
- `scopeString(scopes)` → sorted, space-joined (stable token `scope` values).
- `requireScope(auth, required)` → 403 `insufficient_scope` step-up (§8.3).
- **Accumulation *(RC item (c)) — stored-DCR opaque clients only.*** Re-authorization
  unions the requested scopes with those derived from this `(subject, clientId)`'s
  active refresh-token records (§9.3) — **no grant store**. In stateless mode, and for
  every scheme-shaped (CIMD) client_id in any mode, there is no accumulation
  (`priorScopes = []`); CIMD accumulation is deferred (§17.1.6 decision 3). Consent UI shows the **delta** (new
  scopes only); rendering is an adapter concern (Phase 3), the core supplies the
  before/after sets.
