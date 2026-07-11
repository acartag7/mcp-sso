# Dependency Ledger

> Every external dependency pinned by this repo, with its version, publish date,
> and the **15-day supply-chain check**. Re-verify before any install/bump and
> before every publish. Companion to `docs/contracts.md` §15 and
> `docs/threat-model.md` ("Implementation gates").
>
> **Today:** 2026-07-06. **15-day cutoff:** a pin is acceptable only if published
> on or before **2026-06-21** (≥15 days old).

## The 15-day rule and `minimumReleaseAge`

pnpm's `minimumReleaseAge` is measured in **minutes**. `pnpm-workspace.yaml` sets
`minimumReleaseAge: 21600`, and **21600 minutes = exactly 15 days**. So the
install-time floor and this ledger's manual curation rule are the **same standard**,
enforced at two layers:

- **install-time** — pnpm refuses any version younger than 15 days (applies to
  transitive deps too); and
- **pin-time** — every direct pin below is chosen ≥15 days old and recorded here.

This is the supply-chain posture: compromised/typosquat packages are usually
yanked within hours-to-days; a 15-day buffer dramatically reduces exposure. Never
weaken the rule to paper over a fresh-publish install problem.

## Runtime dependencies (shipped to consumers)

| Package | Version | Published | Age | 15-day check | Notes |
|---|---|---|---|---|---|
| [`jose`](https://github.com/panva/jose) | `6.2.3` | 2026-04-27 | 68d | ✅ | **The only runtime dep.** JOSE/JWT/JWKS primitives (ES256/HS256 sign+verify, `importJWK`, `createRemoteJWKSet`). Pure JS, no native, no postinstall. |

There is exactly one runtime dependency by design (`docs/contracts.md` §15). Every
other capability is a built-in (`node:crypto`, `node:sqlite`, `node:test`) or an
optional peer that a consumer opts into.

## Development dependencies (not shipped)

| Package | Version | Published | Age | 15-day check | Purpose |
|---|---|---|---|---|---|
| [`typescript`](https://www.typescriptlang.org/) | `6.0.3` | 2026-04-16 | 79d | ✅ | Type-checking + the publish `tsc` build. (7.0.1-rc skipped — RC.) |
| [`@types/node`](https://www.npmjs.com/package/@types/node) | `24.13.2` | 2026-06-10 | 24d | ✅ | Node 24 typings; matches the `engines.node >=24` target. |
| [`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/modelcontextprotocol) | `1.29.0` | 2026-03-30 | 96d | ✅ | The official MCP SDK — used in tests/the Phase 4 example (the end-to-end verify client) AND as a runtime dep of every server scaffolded by `npx mcp-sso init` (§15), pinned there at this same version. Not a runtime dep of the mcp-sso package itself (jose-only). |
| [`fastify`](https://fastify.dev/) | `5.8.5` | 2026-04-14 | 81d | ✅ | Reference framework adapter — dev/test + optional peer. (Latest `5.9.0` is 5d — rejected.) |
| [`express`](https://expressjs.com/) | `5.2.1` | 2025-12-01 | 215d | ✅ | Framework adapter — dev/test + optional peer. |
| [`hono`](https://hono.dev/) | `4.12.26` | 2026-06-18 | 16d | ✅ | Framework adapter — dev/test + optional peer. (Latest `4.12.27` is 10d — rejected.) |
| [`@types/express`](https://www.npmjs.com/package/@types/express) | `5.0.6` | 2025-12-01 | 215d | ✅ | Express typings (dev only). |
| [`mysql2`](https://github.com/sidorares/node-mysql2) | `3.22.5` | 2026-06-06 | 28d | ✅ | The `/store/mysql` `StorePort` adapter — dev/test + optional peer. Newest eligible version as of 2026-07-04 (cutoff 2026-06-19); it is also the latest stable. |
| [`ioredis`](https://github.com/redis/ioredis) | `5.11.1` | 2026-06-04 | 30d | ✅ | The `/rate-limit/redis` `RateLimitPort` adapter — dev/test + optional peer. Newest eligible (cutoff 2026-06-19) AND the latest stable. (Official `redis@6.1.0` is 3d old — rejected; `redis@6.0.0` is eligible but a minor behind, so `ioredis` was chosen.) |

Dev tooling with **no added dependency**: the test runner is `node:test` (built
in), assertions `node:assert/strict` (built in), the SQLite store uses `node:sqlite`
(built in). No bundler, no test framework, no postinstall — ever.

## Optional peer dependencies (not shipped to consumers)

`fastify`, `express`, `hono`, `mysql2`, and `ioredis` are declared as **optional
`peerDependencies`** — a consumer installs only the adapter(s) it uses. They are
also installed as **devDependencies** (above) for adapter testing. `jose` remains
the sole runtime dep.

| Package | Peer range | Notes |
|---|---|---|
| `fastify` | `>=5` | `/fastify` adapter (reference). |
| `express` | `>=5` | `/express` adapter. |
| `hono` | `>=4` | `/hono` adapter. |
| `mysql2` | `>=3` | `/store/mysql` `StorePort` adapter (v0.1.2 Phase 5). Pooled; see contracts §12.3 async-tx hygiene. |
| `ioredis` | `>=5` | `/rate-limit/redis` `RateLimitPort` adapter (v0.1.2 Phase 5). Fixed-window Lua script; see contracts §17.10. |

## Engines & package manager

| Tool | Pin | Published | Notes |
|---|---|---|---|
| Node.js | `>=24` (dev on 24.x; 24.3.0 verified locally) | 24 line since 2025 | Native TS execution (`.ts` imports) + `node:sqlite` + `node:test`. The published artifact is `tsc`-compiled ESM. |
| pnpm | `10.34.4` via corepack `packageManager` | 2026-06-18 (16d ✅) | The mature 10.x line; the last patch. (pnpm `11.8.0`, also 16d old, is the newer alternative if a 10.x blocker appears.) |

## CI / GitHub Actions (SHA-pinned)

GitHub Actions are pinned **by commit SHA**, not tag, so a compromised tag cannot
retroactively point at malicious code. The exact SHAs are resolved when the
workflow is written (Phase 2 scaffold) and recorded here. Intended actions (all
pinned to a SHA whose tag is ≥15 days old at pin time):

- `actions/checkout` — shallow checkout.
- `actions/setup-node` — Node 24 + cache.
- `pnpm/action-setup` — pnpm via corepack (matches `packageManager`).
- `acartag7/engineering-os/process-guard` — the Engineering OS artifact-chain
  guard (freeze-hash / mixed-diff / stage-artifact) in `.github/workflows/ci.yml`.
  Pinned to `b483fa418ffa8122588fdfa87c36f40f6908c06f` (published 2026-07-09).
  **First-party — documented exception to the 15-day floor (see below).**
- npm publish step runs `npm publish --provenance` under the GitHub Actions OIDC
  token (**no `NPM_TOKEN` with publish rights, no local publishes**).

### CI service containers (image tags)

The `verify` job runs the `/store/mysql` and `/rate-limit/redis` integration tests
against `mysql:8.4` and `redis:7-alpine` service containers (pinned by **tag**, not
digest). This is a deliberate, narrower trust boundary than the SHA-pinned Actions
above: a service image is a *test fixture*, not a build input that executes in the
published artifact. A tag rebuild that changed `sql_mode` defaults, the default
authentication plugin, or timezone handling would be caught loudly rather than
silently — `migrateMysqlStore` **fail-closed asserts** `STRICT_TRANS_TABLES` in
`sql_mode` and `utf8mb4_bin` table collation at boot, so image drift that matters for
correctness turns the CI red, not green-with-wrong-results. (If a future change makes
these assertions insufficient, promote both images to `@sha256:<digest>` pins recorded
here with the same 15-day check.)

## Verification & change protocol

1. **Before any install/bump:** `npm view <pkg> time --json` (or the registry API)
   to confirm the candidate version's publish date; reject anything <15 days old.
   Re-confirm every row above is still the chosen version.
2. **Before publish:** this ledger is rechecked; `pnpm audit --prod` must be clean,
   or any finding is documented here with why no eligible patched version can be
   selected under the 15-day gate.
3. **`--provenance` only.** The published artifact is reproducible from the tagged
   commit on GitHub Actions; no local `npm publish`.
4. Update this file whenever a pin changes — version, publish date, and the 15-day
   check must always reflect reality.

**Documented exception (2026-07-04):** `mcp-sso@0.0.0` was published with a local
`npm publish --no-provenance` to bootstrap the package name on the registry —
npm's Trusted Publisher (OIDC) can only be configured for a package that already
exists, so the very first publish couldn't itself go through OIDC. This was a
one-time, explicitly-owner-approved exception to rule 3, not a new precedent: it
carries no provenance attestation and is not the v0.1.0 release artifact. Every
publish from `v0.1.0` onward goes through GitHub Actions via OIDC Trusted
Publishing (`.github/workflows/publish.yml`), with `--provenance` intact.

**Documented exception (2026-07-09):** the `acartag7/engineering-os/process-guard`
action is pinned to `b483fa418ffa8122588fdfa87c36f40f6908c06f`, a same-day `main`
commit published 2026-07-09 — younger than the 15-day floor. This is a deliberate,
owner-approved exception. The action is **first-party**: same owner (`acartag7`)
as this repo, authored and controlled by the repo owner. The age floor exists to
blunt *third-party* supply-chain risk — a compromised upstream release is usually
caught and yanked within days — and mitigates nothing for self-owned code. The pin
is still immutable by commit SHA (a moved tag can't repoint it) and changes only
via deliberate batched SHA-bump sweeps per the engineering-os versioning policy. No
tag/release is used because none exists and a SHA pin is stricter regardless.

## Consuming this package under a `minimumReleaseAge` floor

A consumer that sets `minimumReleaseAge: 21600` (15 days) — the same standard this
repo uses — will refuse to install a freshly-published `mcp-sso`. That is
correct behavior, not a bug. Consumers have two sound options:

- **own-package exclusion:** `minimumReleaseAgeExclude: ["mcp-sso"]`, or
- **exact-pin + provenance check:** pin the exact version and verify its
  provenance/Sigstore attestation before trusting it.

The wrong response is to weaken or remove the 15-day rule globally.
