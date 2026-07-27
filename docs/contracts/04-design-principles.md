# 4. Design principles

- **Proven core behind generic ports.** The verifier + bridge logic is
  battle-tested OAuth, extracted behind framework-free ports so any host or
  adapter can use it without coupling to a specific framework or database.
- **`StorePort` is the parity boundary.** The in-tree memory, sqlite, and mysql
  adapters (and **any further downstream SQL adapter**) must all satisfy the §12 invariants — that
  is exactly what fix #3 (documented rotation backfill) makes possible. Parity is
  asserted by the shared conformance suite, not by copying code.
- **Identity is pluggable.** The core never depends on a specific IdP; an
  `IdentityPort` (§6.5) resolves the verified subject. Concrete implementations
  (Cloudflare Access, Entra) shipped in Phase 3.
- **Fail-closed everywhere.** Ambiguous config, a missing identity, an unknown
  audience, or a replayed token is a hard failure, never a degraded default.

> The library defines only the surface described by this indexed contract set
> and the reference adapters.
> It does **not** name or depend on any particular database, host, or downstream
> consumer; a production deployment story belongs in the README, not here.

## 4.1 Dynamic-key and parsed-record composition boundary

> **CONTRACT ONLY — implementation is gated.** This is the bounded replacement
> for a rejected repo-wide own-property sweep. The frozen acceptance rows below
> land in their own PR before any implementation.

This contract applies only when an externally controlled value is used as a
property key, or when an untrusted parsed record is copied into another record.
It does not require generic own-property parsing for fixed, statically named
field reads.

- A dynamic lookup uses `Map`, a null-prototype record, or an `Object.hasOwn`
  guard. An inherited entry is absent and follows that boundary's existing
  missing/unmapped failure.
- A dynamic write cannot invoke an inherited setter. It uses `Map` or a
  null-prototype record. `__proto__` and `constructor` either remain inert data
  in that container or are excluded by an explicit projection before
  composition.
- An untrusted parsed record is never spread or assigned wholesale into an
  ordinary security-sensitive record. Code projects the named fields the
  boundary consumes; unknown fields remain ignored.
- No descriptor walk, accessor classifier, recursive snapshot, or general
  own-property DSL is part of this contract.

The first bounded gates are:

| Boundary | Required behavior | Existing failure behavior |
|---|---|---|
| Hono-owned header/query-name accumulation (§9.6) | Attacker-controlled keys are written to a null-prototype record; `__proto__`/`constructor` cannot change the normalized record's prototype | Missing or malformed OAuth fields retain the endpoint's existing `invalid_request` or field-specific rejection; no new error taxonomy |
| Entra group→scope lookup (§17.4) | A verified group GUID can select only an own mapping entry or equivalent `Map` entry; an inherited match contributes no scopes | With groups present, no own mapped group, and empty `baseScopes`: `entra_no_mapped_groups` |
| CIMD parsed document composition (§17.1.3) | The returned document is the named projection of `client_id`, `client_name`, and `redirect_uris`; the parsed source record is not exposed for a later spread/merge. Unknown `__proto__`/`constructor` members are ignored like other extensions | Malformed known members remain `document_invalid`; the unknown names alone do not reject an otherwise valid document |

The Entra implementation already uses `Object.entries` plus `Map`; that is the
compliant pattern and needs an acceptance pin, not a rewrite. Hono normalization
and removal of CIMD's unused `raw` record are implementation-pending. Before
either changes, a separate frozen-acceptance PR adds one polluted-prototype
negative row (plus its ordinary positive control) for each table row. The
implementation PR mutation-verifies each row independently.

Pre-existing host-level prototype pollution and deliberately hostile in-process
ports or adapters are outside the remote-attacker threat model: code already
executing in-process can replace the verifier itself. This residual is explicit
in threat-model row 34.
