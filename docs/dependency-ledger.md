# Dependency Ledger

> Every external dependency pinned by this repo, with its version, publish date,
> and the **15-day supply-chain check**. Re-verify before any install/bump and
> before every publish. Companion to
> [`docs/contracts/15-package-and-export-map.md`](contracts/15-package-and-export-map.md)
> and
> `docs/threat-model.md` ("Implementation gates").
>
> The enforcing check computes the cutoff from the current UTC date. At this
> recheck (**2026-08-15**), an ordinary pin is acceptable only if published on
> or before **2026-07-31** (≥15 days old). A published-advisory exception must
> satisfy the separate two-rule policy below.

## The 15-day rule and `minimumReleaseAge`

pnpm's `minimumReleaseAge` is measured in **minutes**. `pnpm-workspace.yaml` sets
`minimumReleaseAge: 21600`, and **21600 minutes = exactly 15 days**. So the
install-time floor and this ledger's manual curation rule are the **same standard**,
enforced at two layers. The dependency-policy gate requires the workspace value
to equal this ledger's machine-readable `minimumAgeDays * 1440`; it also treats
`package.json#packageManager` as the single pnpm version source and rejects a
workflow-level `pnpm/action-setup` version override.

- **install-time** — pnpm refuses any unexcluded version younger than 15 days
  (including transitive deps); and
- **pin-time** — every ordinary direct pin below is chosen ≥15 days old and
  recorded here.

This is the supply-chain posture: compromised/typosquat packages are usually
yanked within hours-to-days; a 15-day buffer dramatically reduces exposure. Never
weaken the rule to paper over a fresh-publish install problem.

## Two-rule cooldown policy

1. **Ordinary updates wait.** A package or third-party Action release must be at
   least `minimumAgeDays` old. The global `minimumReleaseAge` and this ledger
   remain the same floor; an exception never lowers either value.
2. **Published-advisory fixes do not wait.** When a published GHSA or CVE
   affects a package this repository resolves — directly pinned **or**
   transitive in the lockfile — adopt the minimum version that fixes all
   recorded advisories after inspecting the release. Add that exact package to
   `minimumReleaseAgeExclude` and add one matching `advisoryExceptions` record.

Each advisory-exception record contains:

- `kind` — `"direct"` or `"transitive"`;
- `package` — the exact npm package name;
- `advisoryIds` — one or more published `GHSA-…` or `CVE-…` identifiers;
- `adoptedVersion` — the exact version selected as the minimum fixing version;
- `adoptedAt` — the UTC calendar date on which the exception was adopted; and
- `justification` — why the cooldown was skipped and what release was inspected.

A `direct` record must name a package pinned in `package.json` with a ledger
row, and `adoptedVersion` must equal both. A `transitive` record must name a
package that is **not** directly pinned and has no ledger row, and the
lockfile must resolve **exactly one** version of it, equal to
`adoptedVersion` — a second resolved version means some path still executes
an affected build, so it rejects. When a later update re-resolves the
package, pins it directly, or drops it from the tree, update the record or
remove the exclusion + record pair together; the gate fails closed on the
drift, the same lifecycle as a `direct` record surviving a pin change.

The dependency-policy gate requires a one-to-one match between exception
records and `minimumReleaseAgeExclude`, binds every `direct` exception to the
current direct pin and ledger version, binds every `transitive` exception to
a single matching lockfile resolution, and remotely confirms that every recorded
advisory exists, names the recorded npm package, and reports stable first
patched versions whose latest value is the adopted version. An unrecorded exclusion, a record without an
exclusion, a future pin or lockfile change that leaves stale exception evidence, or an
unknown field fails closed. The package-specific exclusion does not exempt any
other dependency and does not weaken the global 15-day floor. The upstream
advisory evidence itself is confirmed by the `--verify-remote` runs in CI and
pre-publish; the local `check:deps` run enforces record shape and binding
only.

## Runtime dependencies (shipped to consumers)

| Package | Version | Published | 15-day check | Notes |
|---|---|---|---|---|
| [`jose`](https://github.com/panva/jose) | `6.2.3` | 2026-04-27 | ✅ | **The only runtime dep.** JOSE/JWT/JWKS primitives (ES256/HS256 sign+verify, `importJWK`, `createRemoteJWKSet`). Pure JS, no native, no postinstall. |

There is exactly one runtime dependency by design
([§15](contracts/15-package-and-export-map.md)). Every
other capability is a built-in (`node:crypto`, `node:sqlite`, `node:test`) or an
optional peer that a consumer opts into.

## Development dependencies (not shipped)

| Package | Version | Published | 15-day check | Purpose |
|---|---|---|---|---|
| [`typescript`](https://www.typescriptlang.org/) | `6.0.3` | 2026-04-16 | ✅ | Type-checking + the publish `tsc` build. |
| [`@types/node`](https://www.npmjs.com/package/@types/node) | `24.13.2` | 2026-06-10 | ✅ | Node 24 typings; matches the `engines.node >=24` target. |
| [`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/modelcontextprotocol) | `1.29.0` | 2026-03-30 | ✅ | The official MCP SDK — used in tests/the Phase 4 example (the end-to-end verify client) AND as a runtime dep of every server scaffolded by `npx mcp-sso init` (§15), pinned there at this same version. Not a runtime dep of the mcp-sso package itself (jose-only). |
| [`@fastify/rate-limit`](https://github.com/fastify/fastify-rate-limit) | `11.2.0` | 2026-07-29 | ✅ | Real fail-closed `/mcp` middleware for the Fastify examples, generated starter, and isolated helper subpath. Also an optional peer; not loaded by the root/core entry. |
| [`fastify`](https://fastify.dev/) | `5.8.5` | 2026-04-14 | ✅ | Reference framework adapter — dev/test + optional peer. |
| [`express`](https://expressjs.com/) | `5.2.1` | 2025-12-01 | ✅ | Framework adapter — dev/test + optional peer. |
| [`hono`](https://hono.dev/) | `4.12.34` | 2026-08-03 | Advisory exception | Framework adapter — dev/test + optional peer; the minimum version fixing the recorded published advisories. |
| [`@types/express`](https://www.npmjs.com/package/@types/express) | `5.0.6` | 2025-12-01 | ✅ | Express typings (dev only). |
| [`mysql2`](https://github.com/sidorares/node-mysql2) | `3.22.5` | 2026-06-06 | ✅ | The `/store/mysql` `StorePort` adapter — dev/test + optional peer. |
| [`ioredis`](https://github.com/redis/ioredis) | `5.11.1` | 2026-06-04 | ✅ | The `/rate-limit/redis` `RateLimitPort` adapter — dev/test + optional peer. |

Dev tooling with **no added dependency**: the test runner is `node:test` (built
in), assertions `node:assert/strict` (built in), the SQLite store uses `node:sqlite`
(built in). No bundler, no test framework, no postinstall — ever.

## Transitive advisory sweep (2026-08-15)

An OSV/Dependabot scan flagged 8 published advisories. Every one sits in a
**dev-tree transitive dependency** (reachable only from `devDependencies`
roots: `fastify`, `@modelcontextprotocol/sdk`); `package.json#dependencies`
still contains exactly `jose`, so none of these packages ships in the
published artifact. Resolution:

| Transitive package (via) | Was | Now | Advisories | Path |
|---|---|---|---|---|
| `find-my-way` (`fastify`) | 9.6.0 | 9.7.0 | GHSA-c96f-x56v-gq3h | ✅ ordinary — 9.7.0 published 2026-07-21 |
| `ip-address` (SDK → `express-rate-limit`) | 10.2.0 | 10.3.1 | GHSA-mwp4-54f8-5fhr, GHSA-4xrf-jv44-h6hh, GHSA-22jq-vg5j-6vgg | ✅ ordinary — 10.3.1 published 2026-07-25 |
| `@hono/node-server` (SDK) | 1.19.14 | 1.19.17 | GHSA-frvp-7c67-39w9 | ✅ ordinary — 1.19.17 published 2026-07-27 (≥ the 1.19.15 minimum fix, newest within the SDK's `^1.19.9` and past the floor) |
| `fast-uri` (`ajv`/`fast-json-stringify` under `fastify` + SDK) | 3.1.2 | 3.1.5 | GHSA-4c8g-83qw-93j6, GHSA-v2hh-gcrm-f6hx, GHSA-7p8r-x3mc-p8w7 | ✅ ordinary — 3.1.5 published 2026-07-31 |

`fast-uri@3.1.5` is the **minimum version fixing all three** of its
advisories (`3.1.3` fixes one, `3.1.4` two, so a partial bump would
leave `pnpm audit` red while reading as "fixed"). It was published
2026-07-31T09:16:56.212Z and crossed the 15-day floor at
**2026-08-15T09:16:56.212Z**. The exact workspace override keeps every dev-tree
path on that minimum complete fix. It does not add a published dependency: the
package still has `jose` as its sole runtime dependency.

## Optional peer dependencies (not shipped to consumers)

`@fastify/rate-limit`, `fastify`, `express`, `hono`, `mysql2`, and `ioredis` are declared as **optional
`peerDependencies`** — a consumer installs only the adapter(s) it uses. They are
also installed as **devDependencies** (above) for adapter testing. `jose` remains
the sole runtime dep.

| Package | Peer range | Notes |
|---|---|---|
| `@fastify/rate-limit` | `>=11.2.0 <12` | `/fastify/protected-resource-rate-limit`; mandatory finite `/mcp` admission in the shipped Fastify composition roots. |
| `fastify` | `>=5` | `/fastify` adapter (reference). |
| `express` | `>=5` | `/express` adapter. |
| `hono` | `>=4.12.34 <5` | `/hono` adapter; lower bound is the tested advisory-fixed `bodyLimit` implementation, upper bound excludes an unverified major. |
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
- `actions/setup-node` — Node 24 with the pnpm cache enabled on ephemeral
  GitHub-hosted CI runners. The reviewed v7 major migrates the action's internal
  bundle to ESM, retains the existing workflow inputs and Node 24 action runtime,
  adds cache-key outputs that this repository does not consume, and stops
  exporting a dummy `NODE_AUTH_TOKEN` when none was supplied. The latter is
  compatible with this repository's tokenless OIDC trusted-publishing job.
- `pnpm/action-setup` — pnpm via corepack (matches `packageManager`).
- `actions/upload-artifact` / `actions/download-artifact` — transfer the single
  packed tarball from the read-only build job into the dry-run or isolated OIDC
  publish job. Download rejects an artifact-archive digest mismatch; the
  workflow additionally verifies the tarball's own SHA-256 file.
- `acartag7/engineering-os/process-guard` — the Engineering OS artifact-chain
  guard (freeze-hash / mixed-diff / stage-artifact) in `.github/workflows/ci.yml`.
  Pinned to `c697b412abf034be7a22a53f567ec10eecc776e0` (published 2026-07-19).
  **First-party — documented exception to the 15-day floor (see below).**
- npm publish step runs `npm publish --provenance` under the GitHub Actions OIDC
  token (**no `NPM_TOKEN` with publish rights, no local publishes**).

The 15-day Action quarantine uses the upstream release's `published_at`.
Immutable workflow SHAs stop a later tag move from changing executed code, and
the live tag-to-SHA check rejects that move until a deliberate pin+ledger change
is reviewed here. Git commit timestamps are not treated as a second quarantine
clock because their creator controls them.

The following block is the machine-readable source used by `check:deps`. The
human tables above explain purpose and trade-offs; the check binds the exact
versions, SHAs, tags, and publication dates to the repository files and to the
upstream registries.

<!-- dependency-policy:start -->
```json
{
  "minimumAgeDays": 15,
  "advisoryExceptions": [
    {
      "kind": "direct",
      "package": "hono",
      "advisoryIds": [
        "GHSA-54fx-42gc-7vw4",
        "GHSA-79qm-7rj5-m7r9",
        "GHSA-8j4g-w8fx-2239",
        "GHSA-f23p-vx2j-j53r"
      ],
      "adoptedVersion": "4.12.34",
      "adoptedAt": "2026-08-10",
      "justification": "Inspected Hono v4.12.34 release; it is the minimum published fix for these advisories."
    }
  ],
  "transitivePins": {
    "fast-uri": {
      "version": "3.1.5",
      "published": "2026-07-31T09:16:56.212Z",
      "advisoryIds": ["GHSA-4c8g-83qw-93j6", "GHSA-v2hh-gcrm-f6hx", "GHSA-7p8r-x3mc-p8w7"]
    }
  },
  "packages": {
    "@fastify/rate-limit": { "version": "11.2.0", "published": "2026-07-29T14:38:39.112Z" },
    "@modelcontextprotocol/sdk": { "version": "1.29.0", "published": "2026-03-30T16:50:42.718Z" },
    "@types/express": { "version": "5.0.6", "published": "2025-12-01T20:35:51.488Z" },
    "@types/node": { "version": "24.13.2", "published": "2026-06-10T22:15:29.361Z" },
    "express": { "version": "5.2.1", "published": "2025-12-01T20:49:43.268Z" },
    "fastify": { "version": "5.8.5", "published": "2026-04-14T12:07:12.232Z" },
    "hono": { "version": "4.12.34", "published": "2026-08-03T02:36:40.543Z" },
    "ioredis": { "version": "5.11.1", "published": "2026-06-04T10:14:59.752Z" },
    "jose": { "version": "6.2.3", "published": "2026-04-27T15:23:35.019Z" },
    "mysql2": { "version": "3.22.5", "published": "2026-06-06T08:10:39.646Z" },
    "pnpm": { "version": "10.34.4", "published": "2026-06-18T22:30:33.318Z" },
    "typescript": { "version": "6.0.3", "published": "2026-04-16T23:38:27.905Z" }
  },
  "actions": {
    "actions/checkout": {
      "sha": "3d3c42e5aac5ba805825da76410c181273ba90b1",
      "tag": "v7.0.1",
      "published": "2026-07-20T15:10:05Z"
    },
    "actions/setup-node": {
      "sha": "820762786026740c76f36085b0efc47a31fe5020",
      "tag": "v7.0.0",
      "published": "2026-07-14T02:46:05Z"
    },
    "pnpm/action-setup": {
      "sha": "0ebf47130e4866e96fce0953f49152a61190b271",
      "tag": "v6.0.9",
      "published": "2026-06-15T12:06:03Z"
    },
    "github/codeql-action": {
      "sha": "8aad20d150bbac5944a9f9d289da16a4b0d87c1e",
      "tag": "v4.36.2",
      "published": "2026-06-04T14:27:19Z"
    },
    "ossf/scorecard-action": {
      "sha": "2d1146689b8cda280b9bc96326124645441f03bc",
      "tag": "v2.4.4",
      "published": "2026-07-23T21:12:46Z"
    },
    "actions/upload-artifact": {
      "sha": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
      "tag": "v7.0.1",
      "published": "2026-04-10T17:31:14Z"
    },
    "actions/download-artifact": {
      "sha": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
      "tag": "v8.0.1",
      "published": "2026-03-11T15:44:25Z"
    },
    "acartag7/engineering-os": {
      "sha": "c697b412abf034be7a22a53f567ec10eecc776e0",
      "published": "2026-07-19T02:55:07Z",
      "firstPartyException": true
    }
  }
}
```
<!-- dependency-policy:end -->

### CI integration containers (image tags)

The `verify` job runs the `/store/mysql` and `/rate-limit/redis` integration tests
against `mysql:8.4` and `redis:7-alpine` GitHub Actions services (pinned by
**tag**, not digest). The ephemeral `ubuntu-latest` runner waits for both service
health checks and exposes their fixed loopback ports only for the duration of
the job. This is a deliberate, narrower trust boundary than the SHA-pinned
Actions above: a service image is a *test fixture*, not a build input that
executes in the published artifact. A tag rebuild that changed `sql_mode`
defaults, the default authentication plugin, or timezone handling would be
caught loudly rather than silently — `migrateMysqlStore` **fail-closed asserts**
`STRICT_TRANS_TABLES` in `sql_mode` and `utf8mb4_bin` table collation at boot,
so image drift that matters for correctness turns the CI red, not
green-with-wrong-results. (If a future change makes these assertions
insufficient, promote both images to `@sha256:<digest>` pins recorded here with
the same 15-day check.)

CI verification, `process-guard`, and CodeQL use ephemeral GitHub-hosted
`ubuntu-latest` runners. CI and CodeQL subscribe to pull requests targeting
`main` and to `main` pushes; CodeQL also runs weekly. The CI verify job runs on
both events, while `process-guard` runs on pull requests where a base branch is
available for its merge-base checks. Pull-request checks attach natively to the
PR, so the self-hosted-era `workflow_dispatch` and required-status attestation
machinery is removed. CI retains read-only workflow
permissions and disables checkout credential persistence. CodeQL installs the
frozen dependency graph before analysis for richer JavaScript/TypeScript module
resolution.

Release publishing remains separately isolated in `publish.yml` on
GitHub-hosted `ubuntu-latest` behind the tag-only `publish` environment and the
no-checkout OIDC publishing job.

## Verification & change protocol

1. **Before any install/bump:** `npm view <pkg> time --json` (or the registry API)
   to confirm the candidate version's publish date; reject anything <15 days old
   unless a published GHSA/CVE qualifies for the verified per-package exception
   above. Re-confirm every row above is still the chosen version.
2. **Before publish:** this ledger is rechecked; `pnpm audit --prod` must be clean,
   or any finding is documented here with why no eligible patched version can be
   selected under the 15-day gate.
3. **`--provenance` only.** The published artifact is reproducible from the tagged
   commit on GitHub Actions; no local `npm publish`.
4. Update this file whenever a pin changes — version, publish date, and the 15-day
   check must always reflect reality.
5. Before a real tag, query the `publish` GitHub Environment and verify required
   reviewer approval, admin bypass disabled, and a custom `v*.*.*` tag-only
   deployment policy. The workflow's tag event/version check is the first gate;
   the environment policy is the independently configured second gate.

**Documented exception (2026-07-04):** `mcp-sso@0.0.0` was published with a local
`npm publish --no-provenance` to bootstrap the package name on the registry —
npm's Trusted Publisher (OIDC) can only be configured for a package that already
exists, so the very first publish couldn't itself go through OIDC. This was a
one-time, explicitly-owner-approved exception to rule 3, not a new precedent: it
carries no provenance attestation and is not the v0.1.0 release artifact. Every
publish from `v0.1.0` onward goes through GitHub Actions via OIDC Trusted
Publishing (`.github/workflows/publish.yml`), with `--provenance` intact.

**Documented exception (2026-07-19):** the `acartag7/engineering-os/process-guard`
action is pinned to `c697b412abf034be7a22a53f567ec10eecc776e0`, a `main` commit
published 2026-07-19 — younger than the 15-day floor. This is a deliberate,
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
