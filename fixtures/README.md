# Parity fixtures

Language-neutral, executable statements of the contract set in `docs/contracts/`. Read [§19 Parity-fixture protocol](../docs/contracts/19-parity-fixture-protocol.md) before adding or changing anything here.

## Layout

```
schema/fixture.schema.json   the shape every fixture must satisfy (JSON Schema 2020-12)
keys/                        corpus-only key material (generated for the corpus, never reused)
<NN>-<section-slug>/         one directory per numbered contract section
  <clause>-<slug>.json       one fixture, one contract clause
FREEZE-LOG.md                every change to a frozen fixture, with the contract change that required it
```

## Rules in one screen

- A fixture pins one contract clause and quotes the complete sentence that it tests, copied verbatim. Rewording the clause makes the quote stale and nothing detects that. Coverage is derived from the frozen fixtures themselves, so a clause with none is uncovered.
- Set `kind` to `fixture` for one real HTTP request or `boot` for exact startup acceptance or rejection. A clause covered by an executable suite uses a suite receipt in the contract section that cites it; no clause is exempt.
- Label each fixture `portable` or `host`. Portable fixtures count toward cross-implementation parity. Host fixtures cover the TypeScript reference envelope and do not count toward another implementation's parity claim.
- Keep a fixture `draft` until the reference implementation's runner passes it unchanged in CI. Freeze it only with a `receipt` naming the implementation, version, date, and that CI commit. Nothing but review holds frozen bytes afterwards, so review a fixture hunk as closely as a `src/` hunk.
- One HTTP fixture, one request. A flow is a declared chain whose pre-state is the previous fixture's expected post-state. A named capture can carry an emitted string into a later step without pinning nondeterministic ES256 bytes.
- Write every request body as exactly one of `json`, ordered `form` fields, or verbatim `text`. The runner supplies no encoding or Content-Type default.
- Do not duplicate a server-side scenario that the frozen official MCP conformance requirement set scores. The `2026-07-28` set scores no OAuth resource-server or authorization-server scenario, so it excludes none of the current corpus.
- A frozen fixture changes only with a contract change and a `FREEZE-LOG.md` entry.
- Put the complete fixture configuration in `given.config`. The runner materializes the signing key from `given.keys` and a stored DCR port from `given.state`. It supplies no configuration default.
- Nothing in a fixture may depend on the machine running it: clock, randomness, keys, state, and outbound HTTP are all supplied in `given`.
- Use `{ "absent": true }` when absence is the assertion. Omission means that the fixture does not assert that observation. Logical state uses the §19 `snake_case` record names. `then.state.mode` says `exact` or `contains`; record arrays compare as unordered sets by primary key.
- Write `matches` patterns in the RE2 subset defined by §19.2. Anchor the pattern when the whole string must match.
- No real credential, hostname, tenant, or key from any deployment. Sentinels only.
- A runner that skips a frozen fixture has failed.
- Fastify is the canonical TypeScript host. CI also runs portable HTTP fixtures through Express and Hono to catch adapter drift; those extra runs do not change parity evidence.

## Status

Seventeen frozen fixtures cover Authorization occurrence and bearer-field input classes of clause 8.4: sixteen portable fixtures and one host fixture. Each carries a receipt and freeze-log entry. The reference runner executes each portable fixture on Fastify, Express, and Hono, and the host fixture on Fastify. The frozen fixtures do not exercise every verifier input class. The suite receipt in §8 records the non-HTTP verifier and shipped-composition evidence separately, including the zero-element array that cannot be distinguished from an absent header over HTTP. No published corpus version contains this set yet. See §19.11.

Token-admission work adds 70 draft fixtures: 64 portable and six host, naming §7.2 and §8.1. They cover signature, issuer, audience-mismatch, expiry, subject, and credential-marker input classes. Drafts are not evidence. The receipts in §7 and §8 record direct clock, verifier-result, and header-boundary observations separately. Exact audience-shape coverage remains incomplete; no complete first-slice or published corpus claim follows from these drafts.
