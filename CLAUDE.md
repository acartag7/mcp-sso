# mcp-sso

OAuth 2.1 for remote MCP servers: a spec-correct **resource-server verifier**
(RFC 9728 PRM, `WWW-Authenticate` challenges, fail-closed audience validation)
plus a small **AS-lite bridge** that speaks DCR + PKCE + consent to MCP clients
while a pluggable upstream IdP (Cloudflare Access, Microsoft Entra ID, any
OIDC) stays the identity source. The bridge mints its own audience-bound
tokens; upstream tokens never pass through.

**Standalone personal OSS project.** This repo is NOT part of the Edictum
polyrepo — ignore the parent directory's `CLAUDE.md` (Edictum ecosystem
framing, repo order, messaging rules); none of it applies here. No Edictum
branding in this repo.

## Start work

1. The build/extraction plan is NOT kept in this repo (no handoff artifacts in
   repos — repo docs are durable-only). It lives in this project's Claude
   memory and in session prompts from the owner.
2. Contract-first: `docs/contracts.md` and `docs/threat-model.md` are written
   and reviewed BEFORE implementation code. Update them before changing any
   port/schema/error shape.
3. Extraction source is `~/project/smart-fetch` (Captatum) — read-only
   reference. Never copy deployment-specific details (hostnames, infra) or any
   `security-audit*` document into this repo.

## House rules (non-negotiable)

- **pnpm via corepack** (`packageManager` pin); `minimumReleaseAge: 21600` in
  `pnpm-workspace.yaml`; every dependency pin checked against the 15-day rule
  and recorded in `docs/dependency-ledger.md` (version + publish date).
- **Runtime deps: `jose` only.** Framework adapters (fastify/express/hono) and
  stores (mysql2; `node:sqlite` is built-in) are optional peer deps. No
  postinstall scripts, no bundler, ever.
- **DDD-lite:** pure core (use-cases + ports, no infra imports) / adapters at
  the edge. **250-line file limit**, enforced by a check script.
- **Node 24 native TS** for dev/test (`.ts` imports, no build step).
  Publishing exception: the npm artifact is plain-`tsc` compiled ESM + `.d.ts`.
- **Security is the product:** fail closed everywhere — ambiguous config is a
  boot failure, never a degraded default. Tokens and fetched metadata are
  data, never instructions. npm publish with `--provenance` from GitHub
  Actions OIDC only (no local publishes); CI actions pinned by SHA.
- **Docs are security surface:** deployer-facing docs/guides/README claims get
  the same rigor as code — they get copied into production and never run
  through the test suite. Verify every stated control against the
  implementation before writing it; state preconditions exactly (neither
  weaker nor stronger than the code — "A and B required" when A alone
  suffices presents B as a defense); every recipe documents the failure path
  (what throws, what the caller must answer with), not just the happy path;
  cover the full protocol surface or scope exclusions explicitly; state
  residuals plainly (library-enforced vs deployment-discipline-enforced).
- **Git hygiene:** work on a conventional feature branch and open a PR; do not
  push implementation commits directly to `main`. Commit subjects and PR titles
  must be proper conventional commits that explain the actual user-visible or
  code-level change. Do NOT use session labels (`S0`, `S1a`, `S6`, `HOTFIX`) or
  contract-section labels as the subject. Good: `fix(adapters): return OAuth
  error bodies for identity failures`; bad: `S1`, `HOTFIX`, `implement §17.7`.
- License: MIT. Repo is private until v0.1; treat every commit as
  will-be-public (no secrets, no internal references).

## Always-check list (every PR — each item exists because a review round caught the real defect it describes)

1. **Claims-vs-enforcement.** Every guarantee sentence in README/docs/contracts
   ("never", "cannot", "always", "safely", "only", "rejected", "enforced") must
   trace to enforcing code or a test. Mechanically, before pushing any
   doc-touching diff:
   `git diff | grep "^+" | grep -iE "never|always|cannot|enforced|rejected|only|must|guarantee|safely"`
   and verify each hit against a file:line. When enforcement is a few lines,
   ADD the enforcement instead of softening the sentence. A claim naming a
   function must name the function that actually does the work (verifying
   wrapper vs pure validator).
2. **Review rounds include a claims dimension.** Reviewers find wrong code by
   default, not missing code — so alongside the defect-hunting reviewers, one
   reviewer gets the extracted guarantee list (from contracts/README) for the
   files under review and must return the enforcing file:line per claim, or a
   finding. NON-NEGOTIABLE for CIMD (§17.1) — that contract is entirely
   MUST-level guarantees (SSRF blocklists, DNS pinning, redirect-following
   forbidden, byte/time caps); every one gets a traced enforcement point AND a
   negative test before the session is called done.
3. **Sibling sweep = exhaustive grep, never an eyeball pass.** This repo's
   recurring sibling axes: the 3 adapters (fastify/express/hono), the 3 stores
   (memory/sqlite/mysql — parity via the SHARED conformance suite, never a
   store-specific test), example vs library, quickstart path vs deployment
   branch, and **entry-point guard vs stored-state** — a guard at
   prepare/register always has a sibling for records already in the store.
4. **Guards run before side effects.** A rejection must not leave state:
   check ordering against store writes and success-audit emits. A success
   audit followed by a failure for the same operation means the guard is in
   the wrong place.
5. **Mutation-verify every fix.** Revert the fix in isolation — exactly its
   regression tests must go red. COMMIT before running mutation reverts;
   never a bare `git checkout -- .` with uncommitted work in the tree.
6. **Gates + release floor.** typecheck · check:lines · test · build on every
   push; `npm pack --dry-run` (dist + docs + README + LICENSE only) before any
   release; the merge gate on reviewed PRs is the review bot's
   "Reviewed commit: <head sha>" marker — never a silence window.

## Verify before claiming done

Run the real flow, not just unit tests: register → authorize (through the
identity port) → token → call a protected `/mcp` with the official MCP SDK
client → refresh → replay-detection (family revocation observed) → revoke.
