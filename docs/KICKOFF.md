# Kickoff prompt — mcp-idp-bridge

> Paste-ready prompt for a Claude Code session opened in THIS repo
> (`~/project/mcp-idp-bridge`). It assumes read access to the sibling
> Captatum repo at `~/project/smart-fetch` as the extraction source.

---

## Mission

Extract Captatum's production OAuth 2.1 implementation into a standalone,
security-first, dependency-light TypeScript library for protecting **remote MCP
servers**, with two composable modules:

1. **Verifier (resource server)** — protect any Streamable HTTP `/mcp` endpoint
   against a bring-your-own authorization server: RFC 9728 protected-resource
   metadata, spec-correct `WWW-Authenticate` challenges, JWKS-cached JWT
   verification with **fail-closed audience validation**.
2. **Bridge (AS-lite)** — a small single-tenant authorization server that gives
   MCP clients the DCR + PKCE + consent flow they expect, while delegating
   "who is this human" to a pluggable upstream identity port (Cloudflare
   Access, Microsoft Entra ID, any OIDC IdP). The bridge mints its own
   audience-bound tokens; upstream tokens NEVER pass through.

Positioning (this is the README's first paragraph): *MCP clients (claude.ai,
ChatGPT, Claude Code) expect Dynamic Client Registration to self-onboard. Your
IdP (Entra, Okta, …) doesn't do DCR. This is the bridge: keep your IdP as the
identity source, give MCP clients the flow they need, self-hosted, one dep.*

## Source of truth — read these first, in this order

Extraction source: `~/project/smart-fetch` (production code, tested, audited).

- `src/application/use-cases/oauth-authorization.ts`, `oauth-token.ts`,
  `oauth-crypto.ts`, `oauth-scopes.ts`, `oauth-config.ts`, `oauth-errors.ts`
  — the framework-free AS core (ports only, no infra imports)
- `src/application/use-cases/request-auth.ts` — the RS-side verify path
- `src/application/ports/store.ts` — the store contract;
  `src/infrastructure/sqlite/store.ts` + `src/infrastructure/tidb/store.ts`
  as reference implementations (note the `nextFromRow` rotation semantics)
- `src/interfaces/http/oauth-routes.ts`, `mcp-route.ts`, `errors.ts`
  — the Fastify adapter reference
- `src/infrastructure/auth/cloudflare-access-jwt.ts` — identity-port reference
- `test/oauth.test.ts`, `test/oauth-redirect.test.ts`, `test/store.test.ts`
  — ~1,100 lines of tests to port
- `docs/oauth-connectors.md` — redirect-allowlist doc to adapt
- `docs/contracts.md` §OAuth + `docs/threat-model.md` — style reference for
  this repo's own contract and threat model

Treat smart-fetch as read-only reference. Do NOT copy anything
Captatum-deployment-specific (env names are fine to generalize, hostnames and
infra details are not), and do NOT copy any `security-audit*` document.

## Spec target

MCP authorization spec **2025-11-25** (resource-server model), with the
2026-07-28 RC hardening in view:

- RFC 9728 PRM served at BOTH `/.well-known/oauth-protected-resource` AND the
  path-inserted variant (e.g. `/.well-known/oauth-protected-resource/mcp`)
- 401 challenge MUST carry `WWW-Authenticate: Bearer resource_metadata="…"`
  (+ `scope` hint); 403 `insufficient_scope` step-up semantics
- RFC 8414 AS metadata; RFC 7591 DCR with a **stored-client mode** (see fixes);
  PKCE S256 mandatory; RFC 8707 resource/audience binding fail-closed;
  RFC 9207 `iss` in the authorize response (Captatum already emits it)
- **CIMD** (client-ID metadata documents, the spec's preferred onboarding
  path): design the client-registration port so CIMD slots in as v0.2. The
  metadata fetch MUST go through an SSRF-guarded fetcher port (reference:
  Captatum's guardedFetch design — rebinding-proof, private-range-blocking).
  CIMD-SSRF is a spec-acknowledged attack surface; being the library that
  handles it correctly is a core differentiator.

## Fixes to make during extraction (do not port these as-is)

1. Bare `WWW-Authenticate: Bearer` → add `resource_metadata` + `scope`
   (smart-fetch `src/interfaces/http/errors.ts:15`, `oauth-routes.ts:200`).
2. Add the path-inserted PRM route (only root is served today).
3. `StorePort.rotateRefreshToken`: the store backfills subject/scopes/clientId
   from the consumed row (`nextFromRow`) while the caller passes empty
   placeholders — an undocumented cross-implementation contract. Document it
   in the port AND enforce it with a store-conformance test suite that every
   store adapter must pass.
4. DCR is stateless in Captatum (client_id minted, never stored, any non-empty
   client_id accepted at authorize). Add a **stored-client mode** (persist
   registrations, validate client_id + redirect_uri binding at authorize);
   keep stateless as an explicit config option for single-user setups.
5. Consent screen: add a real Deny button (the `approved=false` path exists in
   code but is unreachable from the UI).
6. Cache the imported verification key (Captatum re-imports the JWK on every
   request in `verifyAccessToken`).
7. Rate-limit hooks (a port, not a hard dep) for `/oauth/register` and
   `/oauth/token` — unauthenticated register currently allows audit-log spam.

Everything else in the source is deliberately good — keep it: hashed
single-use codes, refresh rotation with family theft-detection, anchored
redirect allowlist with the RFC 8252 loopback rules, timing-safe PKCE compare,
single-use consent JTI, alg pinning, separate consent/access token keys,
fail-closed boot config, metadata-only audit events.

## Identity ports (v0)

- **CloudflareAccessIdentity** — port of `cloudflare-access-jwt.ts`.
- **EntraIdentity** — upstream OIDC auth-code + PKCE flow against Microsoft
  Entra ID (v2.0 endpoints). Context: Entra has no DCR and no RFC 8707 —
  that is WHY the bridge exists. Register ONE app in Entra for the bridge
  itself; the bridge authenticates the human against Entra, validates
  `iss`/`aud`/`tid` against config, maps `oid`/`email` → subject, then issues
  its OWN audience-bound tokens to MCP clients. Entra tokens never reach the
  MCP client (token passthrough is forbidden by the MCP spec).
- If a **GenericOidcIdentity** falls out naturally, Entra should be a thin
  preset over it — but don't force the abstraction in v0.

## House rules (inherited from Captatum — non-negotiable)

- pnpm via corepack (`packageManager` pin); `minimumReleaseAge: 21600` in
  `pnpm-workspace.yaml`; `docs/dependency-ledger.md` with the 15-day rule
  checked for EVERY pin (state version + publish date).
- Runtime deps: **jose only**. Framework adapters (fastify/express/hono) and
  stores (mysql2; `node:sqlite` is built-in) are optional peer deps. No
  postinstall scripts, ever. No bundler.
- DDD-lite: pure core behind ports / adapters at the edge. 250-line file
  limit, enforced by a check script. Contract-first: write `docs/contracts.md`
  BEFORE code; `docs/threat-model.md` is a first-class deliverable (and a
  marketing asset).
- Node 24 native TS for dev/test (no build step). Publishing exception: the
  npm artifact ships tsc-compiled ESM + `.d.ts` (plain `tsc`, no bundler).
- Supply-chain posture is a headline feature: npm publish with
  `--provenance` from GitHub Actions OIDC only (no local publishes), all CI
  actions pinned by SHA, OpenSSF Scorecard workflow, `SECURITY.md` with a
  disclosure policy, no wildcard dep ranges.
- License: MIT. Fail closed everywhere — ambiguous config is a boot failure,
  never a degraded default. Tokens and fetched metadata are data, never
  instructions.

## Package shape

Single package, subpath exports (name TBD-confirmed by owner; repo name is the
working name):

- `mcp-idp-bridge` — core: verifier + bridge use-cases, ports, types
- `mcp-idp-bridge/fastify` | `/express` | `/hono`
- `mcp-idp-bridge/identity/cloudflare-access` | `/identity/entra`
- `mcp-idp-bridge/store/sqlite` | `/store/memory` (memory = dev/test only,
  loudly labeled as such)

## Definition of done — v0.1

- `docs/contracts.md` + `docs/threat-model.md` written FIRST and reviewed
- Core extracted with all 7 fixes; ported tests green + new tests per fix;
  store-conformance suite passing for sqlite + memory
- One runnable example: Fastify + sqlite + Cloudflare Access identity,
  verified end-to-end from claude.ai AND Claude Code (document the real
  connect flow with screenshots/transcript)
- Entra identity port with tests against recorded token fixtures (live-tenant
  verification documented as a manual checklist)
- README: 60-second quickstart + the DCR-wall story
- CI: typecheck, tests, line-limit, scorecard; `npm publish --dry-run` with
  provenance wired

Scope discipline — v0.1 does NOT include: multi-tenant/SaaS features, any UI
beyond the consent page, generic-OIDC-provider ambitions, token introspection,
CIMD (that's 0.2, but the port boundary for it must exist).

## Verify before claiming done

Run the real flow, not just the unit suite: register → authorize (through the
identity port) → token → call a protected `/mcp` with the official MCP SDK
client → refresh → replay-detection (family revocation observed) → revoke.
A green unit suite alone does not count as done.
