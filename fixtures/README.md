# Parity fixtures

Language-neutral, executable statements of the contract set in `docs/contracts/`. Read [§19 Parity-fixture protocol](../docs/contracts/19-parity-fixture-protocol.md) before adding or changing anything here.

## Layout

```
schema/fixture.schema.json   the shape every fixture must satisfy (JSON Schema 2020-12)
keys/                        corpus-only key material (generated for the corpus, never reused)
<NN>-<section-slug>/         one directory per numbered contract section
  <clause>-<slug>.json       one fixture, one contract clause
MANIFEST.json                corpus version, hash of every frozen fixture, clause coverage map
CATALOGUE.md                 generated human index: id, clause, what you get, receipt
FREEZE-LOG.md                every change to a frozen fixture, with the contract change that required it
```

## Rules in one screen

- A fixture pins **one** contract clause and quotes it. Reword the clause, and the quote goes stale on purpose.
- Label each fixture `portable` or `host`. Portable fixtures count toward cross-implementation parity. Host fixtures cover the TypeScript reference envelope and do not count toward another implementation's parity claim.
- Keep a fixture `draft` until the reference implementation's runner passes it unchanged. Freeze it only with a `receipt` that names the implementation, version, commit, and date.
- One fixture, one request. A flow is a chain of fixtures whose pre-state is the previous one's expected post-state.
- Do not duplicate a server-side scenario that the frozen official MCP conformance requirement set scores. The `2026-07-28` set scores no OAuth resource-server or authorization-server scenario, so it excludes none of the current corpus.
- A frozen fixture changes only with a contract change and a `FREEZE-LOG.md` entry.
- Put the complete fixture configuration in `given.config`. The runner materializes the signing key from `given.keys` and a stored DCR port from `given.state`. It supplies no configuration default.
- Nothing in a fixture may depend on the machine running it: clock, randomness, keys, state, and outbound HTTP are all supplied in `given`.
- Use `{ "absent": true }` when absence is the assertion. Omission means that the fixture does not assert that observation. `then.state.allowExtraRows` is always `false`.
- Write `matches` patterns in the RE2 subset defined by §19.2. Anchor the pattern when the whole string must match.
- No real credential, hostname, tenant, or key from any deployment. Sentinels only.
- A runner that skips a frozen fixture has failed.

## Status

Bootstrap. One `draft` host fixture, no runner, no official-suite receipt yet. See §19.11.
