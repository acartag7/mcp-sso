# 11. Scope contract

- `scopeCatalog` (config, required) is the complete set this resource honors.
  Every scope list that can reach a grant, access token, or consent token —
  catalog, defaults, request, identity `allowedScopes` ceiling, stored grant,
  and machine-client ceiling — is limited to **128** entries. Each entry is one
  RFC 6749 `scope-token` no longer than **256 UTF-8 bytes**; the largest
  space-joined claim is therefore 32,895 bytes. Config rejects an invalid
  catalog/default list at boot; untrusted or persisted runtime lists fail closed
  with their operation's typed OAuth error.
- `normalizeScopes(scope?, catalog)` → validates each requested scope against the
  catalog (unknown or over-bound ⇒ `invalid_scope`), de-dupes, and falls back to
  `defaultScopes` when none requested. Returns the validated list.
- `scopeString(scopes)` → sorted, space-joined (stable token `scope` values).
- `requireScope(auth, required)` → exact-membership 403 `insufficient_scope`
  step-up (§8.3). **MCP 2026-07-28 gap:** the final text says servers `MUST`
  account for scope hierarchies where a broader scope implies narrower scopes.
  This flat helper has no hierarchy policy; resolving that requires a separate
  contract-first runtime change.
- **Accumulation *(RC item (c)) — stored-DCR opaque clients only.*** Re-authorization
  unions the requested scopes with those derived from this `(subject, clientId)`'s
  active refresh-token records (§9.3) — **no grant store**. In stateless mode, and for
  every scheme-shaped (CIMD) client_id in any mode, there is no accumulation
  (`priorScopes = []`); CIMD accumulation is deferred (§17.1.6 decision 3). Consent UI shows the **delta** (new
  scopes only); rendering is an adapter concern (Phase 3), the core supplies the
  before/after sets.
