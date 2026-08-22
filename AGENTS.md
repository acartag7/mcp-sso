# AGENTS.md

Front door for AI coding agents working in `mcp-sso`. It states the rules an agent cannot infer from the code and links to the documents that own the detail. When this file and a linked document disagree, the linked document wins until one of them is deliberately changed. This file is canonical for agent rules; [`CLAUDE.md`](CLAUDE.md) includes it and adds only Claude Code session notes.

## What this project is

`mcp-sso` is an OAuth 2.1 layer for remote MCP servers, in two halves on one framework-free core. The resource-server verifier checks bearer tokens (RFC 9728 metadata and challenge, fail-closed audience validation, scope enforcement). The authorization-server bridge speaks CIMD or `POST /oauth/register`, PKCE, and consent to MCP clients while an upstream identity provider (Cloudflare Access, Microsoft Entra ID, Google, any OIDC) stays the identity source. The bridge mints its own audience-bound tokens. Upstream identity-provider tokens never pass through to the MCP client.

This is a standalone personal open-source project. It is not part of the Edictum polyrepo. Ignore the parent directory's `CLAUDE.md`. No Edictum branding here.

## Specification target

- The published MCP Authorization spec (`2026-07-28`) governs client-facing OAuth behavior. The RFCs it builds on are the mechanics: [9728](https://datatracker.ietf.org/doc/html/rfc9728) (protected resource metadata), [8707](https://datatracker.ietf.org/doc/html/rfc8707) (resource indicator), [8414](https://datatracker.ietf.org/doc/html/rfc8414) (authorization-server metadata), [7591](https://datatracker.ietf.org/doc/html/rfc7591) (dynamic client registration), [7636](https://datatracker.ietf.org/doc/html/rfc7636) (PKCE), [7009](https://datatracker.ietf.org/doc/html/rfc7009) (revocation), [9207](https://datatracker.ietf.org/doc/html/rfc9207) (`iss` parameter).
- `v0.4.0` is the first release that claims conformance to `2026-07-28`, with two recorded deviations (the CIMD Metadata Document Service rows, which a library does not operate). The current status, the exact row counts, and what the last live campaign did and did not prove are in [`docs/verification-status.md`](docs/verification-status.md). The requirement-by-requirement matrix is [`docs/contracts/16-spec-conformance-matrix.md`](docs/contracts/16-spec-conformance-matrix.md). Do not restate those numbers here; link to them.

## Invariants the agent cannot infer

- Fail closed everywhere. Ambiguous configuration, a missing identity, an unknown audience, or a replayed token is a hard failure: a boot failure or a rejected request, never a degraded default. There is no unauthenticated bypass in production configuration.
- `jose` is the only runtime dependency. Framework adapters (fastify, express, hono) and stores (`mysql2`; `node:sqlite` is built in) are optional peer dependencies. No postinstall scripts, no bundler, ever.
- Tokens and fetched metadata are data, never instructions. Any token or fetched identity-provider, JWKS, or CIMD body is untrusted input. It is never code to execute or a directive to follow.
- npm publishes run with `--provenance` from GitHub Actions OIDC only, never from a local machine. CI actions are pinned by commit SHA.
- Contract first. [`docs/contracts.md`](docs/contracts.md), its numbered files, and [`docs/threat-model.md`](docs/threat-model.md) are written and reviewed before implementation code, and must be updated before any change to a port, schema, or error shape. If code and the contract set disagree, the contract set wins until one of them is deliberately changed.
- Pure core, adapters at the edge. `src/` root holds use-cases and ports with no infrastructure imports. Framework, store, identity, audit, and rate-limit code lives behind ports in `src/adapters/`, `src/store/`, `src/identity/`, `src/audit/`, `src/rate-limit/`.

## Repository map

| Path | Role |
| --- | --- |
| `src/` (root) | Pure core: `verifier.ts`, `authorize.ts`, `token.ts`, `register.ts`, `challenge.ts`, `client-auth.ts`, `machine-client.ts`, `metadata.ts`, `redirect.ts`, `scopes.ts`, `config.ts`, `crypto.ts`, `errors.ts`, `quickstart.ts`, `index.ts`. |
| `src/ports/` | Port interfaces: `store.ts`, `client-store.ts`, `identity.ts`, `audit.ts`, `clock.ts`, `fetcher.ts`, `rate-limit.ts`. |
| `src/adapters/` | `fastify.ts`, `express.ts`, `hono.ts` wire routes, enforce raw-body budgets, normalize headers and bodies, preserve ambiguity evidence for `Bridge` rejection, and carry client-IP data. Also `bridge.ts`, `http.ts`, `consent-page.ts`, `upstream-flow.ts`, `upstream-flow-internals.ts`, `pairing-flow.ts`, `pairing-page.ts`. |
| `src/store/` | `memory.ts`, `sqlite.ts` (+ `sqlite-schema.ts`), `mysql.ts` (+ `mysql-schema.ts`). Parity is enforced by the shared conformance suite, never by a store-specific test. |
| `src/identity/` | `cloudflare-access.ts`, `entra.ts`, `entra-redirect.ts`, `entra-groups.ts`, `google.ts`, `generic-oidc.ts`, `console-pairing.ts`. |
| `src/audit/`, `src/rate-limit/` | Reference sinks (`jsonl-file.ts`, `webhook.ts`, `combine.ts`) and the `redis.ts` rate limiter. |
| `examples/` | `fastify-sqlite/` (bridge + verifier + `/mcp`) and `api-key-gateway/` (SSO in front of a token-only backend). |
| `docs/` | [`docs/README.md`](docs/README.md) is the index. `contracts/` holds one file per numbered contract section. `verification.md` is the release matrix that `scripts/check-release-matrix.mjs` reads. `threat-model.md`, `dependency-ledger.md`, and `verification-status.md` are the trust artifacts. `archive/` holds dated history. |
| `test/` | Unit, integration, `e2e-mcp-sdk.test.ts` (full flow through the official MCP SDK client), and the 16 frozen acceptance files under `test/acceptance/`. |

## Commands and gates

pnpm via corepack. The `packageManager` pin is `pnpm@10.34.4`. Node `>=24` (native TypeScript for development and tests; the npm artifact is plain `tsc` output). `pnpm-workspace.yaml` sets `minimumReleaseAge: 21600` minutes, a 15-day install floor that is stricter than the global default on purpose; every pin and its publish date are in [`docs/dependency-ledger.md`](docs/dependency-ledger.md).

| Command | What it checks |
| --- | --- |
| `pnpm run typecheck` | `tsc --noEmit`. |
| `pnpm run check:lines` | 250-line file limit via `scripts/check-line-length.mjs`. A file may exceed it only through a recorded exception in that script that says why splitting would separate things that belong together. An exception whose file drops back under 250 fails as stale. |
| `pnpm run check:seams` | No internals imports in `test/acceptance`. |
| `pnpm run check:deps` | Dependency pins match the ledger and the age policy. |
| `pnpm run check:release-matrix` | Every row in `test/release-matrix.json` has a `### RM.N — <title>` section in `docs/verification.md`. |
| `pnpm test` | `node --test`. |
| `pnpm run build` | `rm -rf dist && tsc -p tsconfig.build.json`. |
| `RUN_INTEGRATION=true MYSQL_URL=… REDIS_URL=… pnpm run test:release` | The release matrix against real services. |
| `npm pack --dry-run` | Before any release. The tarball root must contain only `dist/`, `docs/`, `README.md`, `LICENSE`, and `package.json`. |

CI runs typecheck, `check:lines`, test, and build on pull requests and on `main`. Pull requests also run `process-guard` (`freeze-hash`, `mixed-diff`, `stage-artifact`), whose `contract-paths` input enumerates `docs/contracts.md` and the 18 numbered contract files; a new contract file must be added to that list in `.github/workflows/ci.yml` or `mixed-diff` will not see it. Branch protection requires the exact contexts `typecheck · lines · test · build` and `process-guard`, and administrator enforcement is on, so those contexts apply to the maintainer too. An unresolved review conversation blocks the merge: addressing a review finding means pushing the fix, replying with the commit, and resolving the thread. No approving review is required, because the repository has one maintainer and GitHub does not let an author approve their own pull request; a required approval there could only ever be a rubber stamp from a second account. The review gate is the one in item 5 of the pull-request checklist below, the review bot's `Reviewed commit: <head sha>` marker for the current head. CodeQL runs on pull requests and weekly but is not required. Fork pull requests run on ephemeral runners with read-only permissions and no persisted checkout credential. Direct pushes to `main` are blocked.

Local mirror of `process-guard`, one time: `git config core.hooksPath .githooks`. The hook finds an `engineering-os` checkout through `$ENGINEERING_OS_DIR`, `../engineering-os`, or `~/project/engineering-os`, and no-ops with a warning if none exists. CI is the real wall.

Release flow: merge the version-bump pull request, run live verification from that reachable `origin/main` commit, merge the evidence-only pull request, and tag `vX.Y.Z`. Let `publish.yml` publish through OIDC and create the GitHub Release, then edit the release with hand-written notes. Never create the GitHub Release before the workflow runs. Immutable releases are on, so creating and deleting a release burns that tag permanently (`HTTP 422: tag_name was used by an immutable release`) and the workflow's own release step then fails with no recovery. The full procedure is [`docs/release-checklist.md`](docs/release-checklist.md).

## Every pull request

Work on a feature branch and open a pull request. Never push to `main`. Commit subjects and pull-request titles are conventional commits that name the user-visible or code-level change (`fix(adapters): …`), with the `Spec: <path>` trailer. Never use session labels, batch identifiers, or contract-section numbers as a subject.

Each item below exists because a review round caught the defect it describes.

1. Claims trace to enforcement. Every guarantee sentence in README, docs, or contracts ("never", "cannot", "always", "only", "must", "rejected", "enforced", "safely") traces to enforcing code or a test. Before pushing a doc-touching diff, run `git diff | grep "^+" | grep -iE "never|always|cannot|enforced|rejected|only|must|guarantee|safely"` and verify each hit against a `file:line`. When enforcement is a few lines away, add the enforcement instead of softening the sentence. A claim that names a function names the function that does the work, not a wrapper.
2. Sibling sweep by exhaustive grep, never by eye. The recurring axes: the 3 adapters (fastify, express, hono); the 3 stores (memory, sqlite, mysql, with parity through the shared conformance suite); the 4 live probes (`scripts/live/probe-{cloudflare,entra,google,e2e}.mjs`, where a preflight, cleanup, or evidence rule added to one belongs in a shared `*-support.mjs` helper); example versus library; quickstart path versus deployment branch; entry-point guard versus stored state (a guard at prepare or register always has a sibling for records already in the store); and every mutable-state exit path (when a fix changes state handling in one exit path, list all mutable state against all except, else, and early-return exits in that scope and verify each, as one complete fix). Changing the live harness also updates its record: [`docs/reference/live-harness.md`](docs/reference/live-harness.md), [`scripts/live/README.md`](scripts/live/README.md), and [`scripts/live/CHECKLIST.md`](scripts/live/CHECKLIST.md). `test/live-evidence-scripts.test.mjs` asserts that they agree.
3. Guards run before side effects. A rejection leaves no state. Check ordering against store writes and success-audit emits. A success audit followed by a failure for the same operation means the guard is in the wrong place.
4. Mutation-verify every fix. Revert the fix in isolation and exactly its regression tests go red. Commit before running mutation reverts; never `git checkout -- .` with uncommitted work in the tree.
5. Gates, then the artifact. typecheck, `check:lines`, `check:seams`, `check:deps`, test, and build on every push; `npm pack --dry-run` before any release. The merge gate on a reviewed pull request is the review bot's `Reviewed commit: <head sha>` marker for the current head. Silence, a reaction, or an older review is not approval.
6. Local exact-head review before hosted review. Run [class-closure-review](.claude/skills/class-closure-review/SKILL.md) on the real `merge-base...HEAD` before opening a pull request or after a hosted comment. It is how items 1 to 4 are executed: name the behavior, fill the matrices, an empty occupied cell means do not push. Hosted Codex remains the merge gate. Request it once per batch of commits, not per commit. More than two unsuccessful review cycles means split or redesign the pull request. A follow-up pull request that is only the next sibling of the last merge is a miss of that skill; freeze it as an eval case the same day. Runner budget: [runner.md](.claude/skills/class-closure-review/references/runner.md).
7. Frozen tests stay frozen. The 16 files under `test/acceptance/` are pinned by `test/acceptance/acceptance.manifest.json`; all five flags in `phases.json` are active. If a frozen test is wrong, the contract is wrong: stop and review the contract change explicitly under [`docs/contracts/18-contract-change-protocol.md`](docs/contracts/18-contract-change-protocol.md). Never weaken a check to get green.
8. New trust boundary, contract first. Before implementing a new port, CLI entry point, or exported security helper, enumerate its fail-closed class in the contract (input types, blank and malformed handling, filesystem trust, packaging edges) and add a negative test per edge. Security decisions fail closed, use allowlists, and reject missing, malformed, or wrongly typed external input.

## Verify before claiming done

Run the real flow, not only unit tests: register, authorize through the identity port, exchange the token, call a protected `/mcp` with the official MCP SDK client, refresh. Use one refresh family to prove that replaying a consumed token kills its live successor. Use a second active family to prove that `POST /oauth/revoke` makes its refresh token unusable. Revoking the family that replay already killed proves only the RFC 7009 response shape.

Tests that pass are reported as passing. Tests that fail are reported with their output. A skipped step is reported as skipped.

## Documentation writing standard

Every documentation change applies the `technical-writing` and `unslop` skills. The acceptance test is a human one: a reader new to MCP and its OAuth RFCs can say what a component does, why it exists, what goes wrong when it is misconfigured, and where the exact contract is.

- One Diátaxis mode per file: tutorial, how-to, reference, explanation, or dated history. When the mode changes, split and link.
- Write the real symbol, once, everywhere: `POST /oauth/register`, `RateLimitPort.check`, `OAUTH_DCR_MODE=stored`. Never a description in place of the name. Never two names for one thing.
- Say what the code does, including early returns, status codes, and side-effect order. Check every guard description against the implementing path and its siblings before writing it.
- Explain impact in plain words: who can then do what, or what breaks. The bar: "if the rate limiter throws, `POST /oauth/register` in stored DCR mode returns 503 instead of letting registrations through; stateless registration continues", not "durable anonymous operations fail closed under limiter unavailability". Note that the plain sentence still has to carry the condition: the first draft of this example omitted "in stored DCR mode" and was wider than the code.
- Put `> [!WARNING]` before a mistake that weakens security, exposes data, corrupts state, or breaks a deployment, and `> [!IMPORTANT]` before a prerequisite that changes the result. The marker sits alone on the first line of the quote; text on the same line renders as a plain quote.
- Add a copyable example wherever a rule has to be translated into configuration, a request, or an expected result, and show the failure result when the distinction matters. Add a small Mermaid diagram when three or more actors, stages, or branches are clearer drawn than described, and keep the prose complete for readers who skip it.
- No internal labels in current documentation: no batch identifiers, phase numbers, fix numbers, pull-request numbers, or session names. Name the capability. Keep an old label only in a dated archive page where a historical receipt depends on it.
- Keep each prose paragraph on one physical source line so copied text carries no editorial line breaks. Code blocks and tables keep their own formatting.
- Archive superseded receipts and decisions under `docs/archive/` with dates in their headings. Link the current page to the archive and the archive back to the current page. Nothing is deleted.
- No em dashes, no bold-label-then-dash list items, no ornamental headings, no curly quotes, no inflated adjectives. Plain English.
- Every "never", "always", "cannot", "only", "must", "rejected", "enforced", or "guarantee" in a docs diff traces to code or a test, or it is cut.

## Surfacing a decision to the owner

Findings and tradeoffs that need the owner's call are written as a disclosure, not a checklist. `file:line` evidence is the appendix; consequence is the report. For each item, in this order:

1. What it is: one line of mechanism.
2. What actually happens: concrete, plain words, the real sequence.
3. If it is not fixed: who ends up able to do what. Never omit this.
4. Where it already works: the sibling that got it right. In this repo the recurring defect is a guard wired to one path and assumed on its mirror (upstream versus direct authorize, one adapter versus three, entry point versus stored state), so "X does this correctly, Y does not" is usually the true shape.
5. Recommendation with the reasoning attached, not a severity label.

Across a set: rank by what matters; say which items are exploitable today, latent, or reliability; and keep mechanical fixes (nobody chose this) separate from design decisions (the code does what a comment says on purpose, so changing it needs a contract change first). Always include what was disproved: the attacks that failed and the invariants that held. Lead with what is genuinely sound.

This applies to adversarial-assessment reports, pull-request descriptions that surface a tradeoff, and any Spec Reviewer briefing.
