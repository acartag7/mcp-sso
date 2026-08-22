# 4. Design principles

**What this protects and why.** The rules that shape every contract: fail closed, parse untrusted input once at the boundary, never let an attacker choose a property key, and keep the contract set ahead of the code. Each one exists because it closed a real defect class.

- **Proven core behind generic ports.** The verifier + bridge logic is battle-tested OAuth, extracted behind framework-free ports so any host or adapter can use it without coupling to a specific framework or database.
- **`StorePort` is the parity boundary.** The in-tree memory, sqlite, and mysql adapters, and any downstream SQL adapter, must satisfy the §12 invariants. During refresh-token rotation, each store copies `clientId`, `subject`, and `scopes` from the consumed row into the next row. §12 calls this behavior rotation backfill. The shared conformance suite checks parity; adapters do not copy one another's implementation.
- **Identity is pluggable.** The core never depends on a specific IdP. An `IdentityPort` (§6.5) resolves the verified subject. Cloudflare Access, Entra ID, Google, generic OIDC, and console pairing provide concrete implementations.
- **Fail-closed everywhere.** Ambiguous config, a missing identity, an unknown audience, or a replayed token is a hard failure, never a degraded default.

> The library defines only the surface described by this indexed contract set and the reference adapters. It does **not** name or depend on any particular database, host, or downstream consumer. A production deployment story belongs in the README, not here.

## 4.1 Dynamic-key and parsed-record composition boundary

> **CONTRACT ONLY, implementation is gated.** This is the bounded replacement for a rejected repo-wide own-property sweep. Add the frozen acceptance rows below before changing the implementation.

This contract applies only when an externally controlled value is used as a property key, or when an untrusted parsed record is copied into another record. It does not require generic own-property parsing for fixed, statically named field reads.

- A dynamic lookup uses `Map`, a null-prototype record, or an `Object.hasOwn` guard. An inherited entry is absent and follows that boundary's existing missing/unmapped failure.
- A dynamic write cannot invoke an inherited setter. It uses `Map` or a null-prototype record. `__proto__` and `constructor` either remain inert data in that container or are excluded by an explicit projection before composition.
- An untrusted parsed record is never spread or assigned wholesale into an ordinary security-sensitive record. Code projects the named fields the boundary consumes. Unknown fields remain ignored.
- No descriptor walk, accessor classifier, recursive snapshot, or general own-property DSL is part of this contract.

The first bounded gates are:

| Boundary | Required behavior | Existing failure behavior |
|---|---|---|
| Hono-owned header/query-name accumulation (§9.6) | Attacker-controlled keys are written to a null-prototype record. `__proto__`/`constructor` cannot change the normalized record's prototype | Missing or malformed OAuth fields retain the endpoint's existing `invalid_request` or field-specific rejection. No new error taxonomy |
| Entra group→scope lookup (§17.4) | A verified group GUID can select only an own mapping entry or equivalent `Map` entry. An inherited match contributes no scopes | With groups present, no own mapped group, and empty `baseScopes`: `entra_no_mapped_groups` |
| CIMD parsed document composition (§17.1.3) | The returned document is the named projection of `client_id`, `client_name`, and `redirect_uris`. The parsed source record is not exposed for a later spread/merge. Unknown `__proto__`/`constructor` members are ignored like other extensions | Malformed known members remain `document_invalid`. The unknown names alone do not reject an otherwise valid document |
| Identity result and claims-only verified attributes (§6.5, §17.11) | The shared identity-result snapshot admits only a non-blank subject of at most 2048 UTF-8 bytes. Identity completion also converts optional attributes into bounded, plain, deeply frozen JSON data before `onIdentity`. It does not spread or pass the port-owned graph | A malformed or over-bound subject fails at the shared identity boundary. A prototype, accessor, cycle, non-JSON value, or exceeded attribute bound is row-10 `exchange_failed`. Bridge completion keeps ignoring optional attributes |
| Claims-only host response (§17.11) | The completion boundary snapshots a plain response and header record into bounded strings before success or adapter work. Header names are compared case-insensitively before projection. Header-bound strings are ASCII with no outer whitespace, redirects are already encoded URI references, Unicode remains valid in an explicitly typed body, and no-content statuses carry no body | A prototype, accessor, duplicate header, unsafe value, invalid status/body combination, or exceeded bound is row-12I `completion_failed` |

The Entra implementation already uses `Object.entries` plus `Map`. That is the compliant pattern and needs an acceptance pin, not a rewrite. Hono normalization and removal of CIMD's unused `raw` record are implementation-pending. Before either changes, add one polluted-prototype negative row and its ordinary positive control for each table row. Mutation-verify each row independently when implementing it.

Pre-existing host-level intrinsic mutation and a deliberately hostile in-process port or adapter capability are outside the remote-attacker threat model: code already executing in-process can replace the verifier itself. Values returned by a port remain untrusted and receive the snapshot required by that port's contract. This residual is explicit in threat-model row 34.
