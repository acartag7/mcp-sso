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
- **Git hygiene:** work on a conventional feature branch and open a PR; do not
  push implementation commits directly to `main`. Commit subjects and PR titles
  must be proper conventional commits that explain the actual user-visible or
  code-level change. Do NOT use session labels (`S0`, `S1a`, `S6`, `HOTFIX`) or
  contract-section labels as the subject. Good: `fix(adapters): return OAuth
  error bodies for identity failures`; bad: `S1`, `HOTFIX`, `implement §17.7`.
- License: MIT. Repo is private until v0.1; treat every commit as
  will-be-public (no secrets, no internal references).

## Verify before claiming done

Run the real flow, not just unit tests: register → authorize (through the
identity port) → token → call a protected `/mcp` with the official MCP SDK
client → refresh → replay-detection (family revocation observed) → revoke.
