# Verification plan — integration tests & pre-release gates

How mcp-sso proves a release actually works.

Three tiers:

- **Tier 1 — CI tests.** Loopback servers and injected fakes only; no public network, no real provider accounts. This is the definition of "implemented".
- **Tier 2 — packed-artifact gate.** Proves the npm package shape works, not just the source tree.
- **Tier 3 — manual live verification.** Real IdPs, real MCP clients, production dogfood evidence.

The contracts these tests enforce live in
[§17](contracts/17-v0-2-feature-contracts.md); the
threat rows they close are 13 and 17-25 in [`docs/threat-model.md`](threat-model.md).

Baseline (v0.1): `test/e2e-mcp-sdk.test.ts` drives register → authorize → token →
protected `/mcp` with the official MCP SDK client → refresh → replay/family
revocation → revoke. The shared store-conformance suite covers memory, sqlite,
and mysql.
Everything below extends that baseline; nothing replaces it.

## Rules

A feature is done when its real-flow Tier-1 row is covered — not when its unit
tests pass.

Tier-1 tests must be deterministic:

- Native TypeScript on Node's built-in test runner, matching the current suite.
- Loopback servers, adapter injection, fake resolvers, or fake transports. No
  public DNS, public HTTP, provider uptime, tunnels, or manual browser state.
- Injected `ClockPort` or explicit test clocks for expiry. Avoid real sleeps
  except for sub-deadline transport tests that cannot be modeled otherwise.
- Every new store-record invariant goes into the shared store-conformance suite,
  so memory/sqlite/mysql prove identical behavior.
- Keep the baseline official MCP SDK flow green after every session.

Tier-3 live checks are still required for provider/client claims. Live checks
never replace CI security tests.

## Harness helpers

The current shared helpers are:

| Helper | Purpose |
|---|---|
| `test/lib/adapter-flow.ts` | Shared authorize/token flow assertions for Fastify, Express, and Hono. |
| `test/lib/adapter-header-flow.ts` | Shared raw-header and duplicate-header assertions across adapters. |
| `test/lib/store-conformance.ts` | Single source for StorePort invariants across memory, sqlite, and mysql. |

Other integration and release checks live in their named `test/*.test.ts` or
`scripts/*.mjs` entrypoints; this document does not promise helper files that do
not exist.

## Tier 1 — CI tests

### T1.HF — adapter identity-rejection parity

Run before S2.

| # | Scenario | Assert |
|---|---|---|
| HF.1 | `IdentityPort` returns `{ ok: false }` on authorize | All adapters return HTTP 401 with RFC-shaped `{ error: "access_denied", error_description: ... }`. |
| HF.2 | `IdentityPort` throws `OAuthError("access_denied", 401)` | Same HTTP 401 body on Fastify, Express, and Hono. |
| HF.3 | Non-OAuth error thrown inside a handler | 500 with a top-level string error body, never a framework-specific envelope. |

### T1.S0a — MySQL store and Redis/Valkey limiter

| # | Scenario | Assert |
|---|---|---|
| S0a.1 | Shared StorePort conformance against MySQL | Same suite passes for memory, sqlite, and mysql. |
| S0a.2 | MySQL async transaction failure | Original error propagates; rollback/release cleanup errors are swallowed; connection is released. |
| S0a.3 | Timestamp ordering through MySQL | 3-ms UTC timestamps preserve lexicographic ordering. |
| S0a.4 | Two Redis limiter instances share a key/window | Second instance observes the first's increments. |
| S0a.5 | Redis unavailable | Limiter fails open; auth flow continues. |

### T1.S1a — audit sinks

| # | Scenario | Assert |
|---|---|---|
| S1a.1 | Full authorize→token→refresh flow with JSONL audit | One valid JSON object per line; expected event sequence. (`test/audit-flow.test.ts`) |
| S1a.2 | No-secrets sweep over audit output | No raw auth code, access token, refresh token, consent token, client secret, private key, or pairing code appears. Asserted on the live-flow JSONL file and on synthetic per-event-name serialization through both sinks. |
| S1a.3 | `combineAudit(throwingSink, fileSink)` during a flow | Flow succeeds; file sink still writes; failure surfaces only as diagnostic output. (`test/audit-flow.test.ts`) |
| S1a.4 | `WebhookAudit` POST via injected transport stub | Body is the exact event JSON with merged headers; `redirect:"manual"`; a never-settling stub times out via `AbortSignal.timeout`; the sink never rejects and is at-most-once. |
| S1a.5 | `WebhookAudit("http://...")` and userinfo URLs | Constructor rejects non-https config and URLs carrying `user:pass@` userinfo. |
| S1a.6 | New v0.2 event names | Every new event name has a dedicated pure serialization test across both sinks. |
| S1a.7 | Sink stderr never leaks secrets | An IO/transport error carrying a Bearer token, a long opaque run, a known header value, or a credential-bearing query string (`?access_token=…`) is redacted before reaching stderr; benign diagnostics are preserved. (`test/audit-util.test.ts` + jsonl/webhook stderr-capture tests) |

Notes:

- **S1a.4 transport seam.** The webhook is https-only by construction, so a
  plain-http loopback server is rejected at build time and a self-signed
  loopback cert would need an out-of-dep undici dispatcher. The test drives the
  `fetchImpl` DI seam (the codebase's pattern, cf. Redis stubs) as the transport.
- **S1a.5 why userinfo is blocked.** Credentials belong in `headers`. A fetch
  error would otherwise echo the URL into stderr.

### T1.S1b — quickstart secrets and console pairing

| # | Scenario | Assert |
|---|---|---|
| S1b.1 | First boot with empty quickstart dir | Directory `0700`, secrets file `0600`, `.gitignore` with `*`, valid signing JWK and consent secret. |
| S1b.2 | Token survives restart | Mint token, close app, boot from same dir, old token still validates. |
| S1b.3 | POSIX secrets file is `0644` | Boot fails closed with `AuthConfigError` and chmod remediation. |
| S1b.4 | Corrupt or partial secrets file | Boot fails closed; no ephemeral fallback. |
| S1b.5 | Console pairing happy path | Code generated lazily, accepted once, authorize→token→`/mcp` succeeds. |
| S1b.6 | Pairing wrong attempts | Five wrong attempts invalidate the code independent of `RateLimitPort`. |
| S1b.7 | Pairing replay/expiry | Used or expired code cannot authorize. |
| S1b.8 | Example no longer uses dev stub | `examples/fastify-sqlite` boots zero-config and completes the protected MCP flow. (`test/e2e-pairing.test.ts`) |
| S1b.9 | Pairing code never in audit | The 12-char code (canonical and `XXXX-XXXX-XXXX`) appears in no `oauth.pairing.attempt` event; `reason` is always a short enum. (`test/identity-console-pairing.test.ts`) |
| S1b.10 | Rate-limit deny ≠ throw | A denying `RateLimitPort` blocks without bumping the attempt cap; a throwing limiter fails open. (`test/identity-console-pairing.test.ts`) |
| S1b.11 | Audit JSONL on a live pairing flow | `audit.jsonl` carries `oauth.pairing.attempt` plus the v0.1 authorize/token events; no raw pairing code, auth code, or access token. (`test/e2e-pairing.test.ts`) |

Notes:

- **S1b.10 deny-vs-throw.** The correct code still succeeds after a flood of
  denials — the deny path does not consume the attempt slot.

### T1.S2a — core `allowedScopes` ceiling

| # | Scenario | Assert |
|---|---|---|
| S2a.1 | Identity has no `allowedScopes` | Existing authorize/token/refresh behavior unchanged. |
| S2a.2 | Identity has `allowedScopes` subset | Token scopes are the intersection of requested/default/prior scopes and the ceiling. |
| S2a.3 | Empty intersection | `access_denied` over the redirect channel, after redirect validation. |
| S2a.4 | Consent-token tampering | `approve` uses `allowed_scopes` from the verified consent token, never caller input. |
| S2a.5 | Prior grants | Existing grants cannot resurrect scopes outside the current ceiling. |
| S2a.6 | Adapter plumbing | Fastify, Express, and Hono all pass the identity object through the bridge. |

### T1.S2b — Entra group mapping

| # | Scenario | Assert |
|---|---|---|
| S2b.1 | Boot config has display-name key | Boot rejects non-GUID mapping keys. |
| S2b.2 | Mapped groups plus base scopes | Returned `allowedScopes` is the contract-required union. |
| S2b.3 | Groups map to no scopes and no base | Fail closed with the Entra no-groups/no-scopes reason. |
| S2b.4 | Overage marker present | Fail closed; `_claim_sources` is never dereferenced. |
| S2b.5 | Existing Entra config without group auth | Behavior unchanged. |
| S2b.6 | Full authorize flow | Entra-derived ceiling enforced by the S2a core flow. |

### T1.S3a — machine client provisioning

| # | Scenario | Assert |
|---|---|---|
| S3a.1 | Enable with non-stored DCR | Boot fails with `AuthConfigError`. |
| S3a.2 | Provision machine client | Returns `mcc_...` id and `mcs_...` secret once; store holds only a SHA-256 hash. |
| S3a.3 | Rotate secret | New secret works; old secret gets a bounded grace expiry; max two active secrets. |
| S3a.4 | Provision with invalid scope | Rejected before store write. |
| S3a.5 | Machine-shaped DCR request | `/oauth/register` returns `invalid_client_metadata`. |
| S3a.6 | Audit events | Provision/rotate events contain no secret and no hash. |

### T1.S3b — `client_credentials` grant

| # | Scenario | Assert |
|---|---|---|
| S3b.1 | `client_secret_basic` valid | Token response succeeds; protected `/mcp` accepts the access token. |
| S3b.2 | `client_secret_post` valid | Same success path. |
| S3b.3 | Wrong or expired secret | `invalid_client` 401; Basic attempt includes `WWW-Authenticate: Basic`. |
| S3b.4 | Omitted scope | Token gets the full allowed set. |
| S3b.5 | Requested scope outside allowed set | `invalid_scope`; no token minted. |
| S3b.6 | Resource mismatch | Token request fails. |
| S3b.7 | Response shape | No `refresh_token` member exists at all. |
| S3b.8 | User grant regression | Authorization-code and refresh flows unchanged. |

### T1.GG — stored-DCR grant-generation cutover (0.3.2)

| # | Scenario | Assert |
|---|---|---|
| GG.1 | Current-generation code and refresh family across reopen/restart | Exchange and refresh still succeed. |
| GG.2 | Old binary writes a null/missing-generation code after cutover | Current binary burns it and returns `invalid_grant`, for both an unknown and an existing stored client ID. |
| GG.3 | Old binary writes a null/missing-generation refresh family, or a successor inside an existing current family, after cutover | Current binary returns `invalid_grant` before consuming it or creating a successor. |
| GG.4 | Rotation caller substitutes generation | All three stores preserve the family generation from durable state. |
| GG.5 | Legacy/non-current active refresh rows exist, including inside a current family | `findGrantedScopes` excludes their scopes. |
| GG.6 | Store lacks the generation capability in stored-DCR mode | Construction fails closed with `AuthConfigError`; stateless-DCR operation remains unchanged. CIMD alongside stored DCR uses the same cutover generation without enabling accumulation. |

### T1.S4a — Generic OIDC and Google preset

| # | Scenario | Assert |
|---|---|---|
| S4a.1 | Generic discovery issuer mismatch | Boot fails. |
| S4a.2 | Discovery endpoint non-https or redirects | Boot fails. |
| S4a.3 | Valid generic id_token claims | Pure validator accepts only exact issuer, expected audience, nonce, time window, and pinned alg. |
| S4a.4 | Multi-audience token | Rejected. |
| S4a.5 | Missing PKCE support | Boot fails unless an explicit loud override is set. |
| S4a.6 | Email allowlist with unverified email | Rejected. |
| S4a.7 | Google preset config | Issuer pinned to `https://accounts.google.com`; the `hd` claim (not email domain) controls hosted-domain matching. |

Google live sign-in is Tier 3, not CI.

### T1.S4b — GitHub identity port

| # | Scenario | Assert |
|---|---|---|
| S4b.1 | OAuth URL construction | Hardcoded GitHub authorize endpoint, state, PKCE S256, `user:email` scope. |
| S4b.2 | Token exchange request | Sends `Accept: application/json` and the client secret. |
| S4b.3 | User mapping | Subject is the numeric id string; login is not identity unless the mutable-claims opt-in is set. |
| S4b.4 | Email mapping | Primary verified email only; absence allowed. |
| S4b.5 | Allowlist reject | Fails closed before bridge token issuance. |

Real GitHub OAuth sign-in is Tier 3. CI uses pure mapping tests and a stubbed
transport only if the implementation exposes one without weakening the
production contract.

### T1.S5a — device-flow store and authorization endpoint

| # | Scenario | Assert |
|---|---|---|
| S5a.1 | Store conformance extension | Device-code invariants pass for memory, sqlite, and mysql if shipped. |
| S5a.2 | Request device authorization | Response has `device_code`, `user_code`, verification URIs, `expires_in`, `interval`. |
| S5a.3 | Stored record | Raw device code and user code are hashed, not stored. |
| S5a.4 | Poll before approval | Returns `authorization_pending`. |
| S5a.5 | Too-fast poll | Returns `slow_down`; persists interval +5. |
| S5a.6 | Expired code | Not found/consumed; sweep removes expired rows. |
| S5a.7 | Wrong-code attempt cap | Five wrong submissions per IP invalidate the path independently of the external limiter. |

### T1.S5b — device verification, approval, and token grant

| # | Scenario | Assert |
|---|---|---|
| S5b.1 | Browser enters code and approves | Polling succeeds; protected `/mcp` works with the issued access token. |
| S5b.2 | Browser denies | Token polling returns terminal `access_denied`. |
| S5b.3 | Approval replay | Device consent token and approved device code are single-use. |
| S5b.4 | `allowedScopes` ceiling | Approved scopes intersected with the S2a ceiling. |
| S5b.5 | Expired token path | Polling returns terminal `expired_token`. |
| S5b.6 | Refresh token issued | Device flow is a user grant: refresh/replay/revoke semantics match baseline. |

### T1.S6a — CIMD security primitives

The CIMD enforcement contract is
[§17.1](contracts/17-v0-2-feature-contracts.md#171-cimd--client-id-metadata-documents-the-ssrf-enforcement-contract);
the
security target is [`threat-model.md` row 13](threat-model.md). These rows are
its enforcement evidence.

| # | Scenario | Assert |
|---|---|---|
| S6a.1 | URL admission table | Rejects: non-https, malformed https, root path, query, fragment, userinfo, CRLF, controls, dot segments, localhost, trailing dot, denied ports, and IP literals — including dword, octal, and hex forms. |
| S6a.2 | IP blocklist table | At least one rejection for every enumerated IPv4/IPv6 CIDR; public allow cases pass. |
| S6a.3 | IPv4-embedding IPv6 | IPv4-mapped, NAT64, 6to4, and Teredo-style prefixes blocked wholesale. |
| S6a.4 | Guarded fetch all-records DNS | Any blocked A or AAAA record rejects the whole fetch. |
| S6a.5 | Pinned connect | Transport receives the validated IP; Host/SNI stay the original hostname. |
| S6a.6 | Redirect, cap, timeout | Redirects are not followed; explicit no-redirect evidence (`redirected === false` / hop count 0) asserted, never URL comparison alone; over-cap body rejects (not truncates); deadline aborts. |
| S6a.7 | Guard cannot be bypassed | Injected low-level transport sits below admission/DNS/IP/cap/timeout checks. |
| S6a.8 | Document validator | Exact `client_id` equality, required fields, auth method, forbidden secrets, private/symmetric key material in `jwks` rejected, redirect URI hygiene, grant/response constraints. |

### T1.S6b — CIMD integration and SSRF regression

| # | Scenario | Assert |
|---|---|---|
| S6b.1 | Boot config | **No whole `cimd.fetcher` config knob** (removed — §17.1.6 decision 5): the core constructs the default guarded fetcher from the `cimd` caps + `allowLoopback` derived solely from `dev.allowInsecureLocalhost`; only the below-guard `cimdTransport`/`cimdResolver` seams (never a whole `GuardedFetcher`, never a `BridgeConfig` field) inject in tests. |
| S6b.2 | Happy path | URL-shaped `client_id` fetches the doc, validates; authorize→token→`/mcp` succeeds. |
| S6b.3 | Generic client error | Every CIMD failure returns identical client-facing error text. |
| S6b.4 | Audit detail | `oauth.cimd.fetch` records the specific reason without leaking the document body or secrets. |
| S6b.5 | Redirect URI match | Exact match required; loopback any-port exception honored. |
| S6b.6 | Scope accumulation (CIMD deferred) | CIMD ids do NOT accumulate: a genuine CIMD authorization reports `priorScopes = []` and mints only the requested (ceiling-bounded) scopes in BOTH DCR modes; seed an active legacy URL-keyed refresh row with a broader scope and prove it is never unioned. Control: an opaque stored-DCR client still accumulates. (§17.1.6 decision 3.) |
| S6b.7 | Metadata flag | `client_id_metadata_document_supported` appears only when enabled. |
| S6b.8 | Cache (freshness) | Cache HIT reuses the doc (no fetch). Freshness = `min(valid max-age, cacheTtlCapSeconds) − Age − elapsed`; **`max-age`<60 / `no-store` / `no-cache` / absent, duplicate, or quoted `Cache-Control`/`max-age` ⇒ NON-cacheable (re-fetch), never clamped up** (§17.1.6 decision 4); bounded LRU eviction; no error/invalid-doc cache; the SAME cache serves direct-mode `prepare` AND upstream-redirect authorize; single-flight keyed by the raw `client_id`; global in-flight cap (`overloaded` at the cap). |
| S6b.9 | SSRF negative suite | Encoded dot segments, IP-literal tricks, blocked DNS records, rebinding, redirect-to-blocked-host, over-cap body, slow endpoint, mismatched `client_id`, and `client_secret` doc all fail with identical client-facing text. |
| S6b.10 | Upstream-redirect CIMD | Doc resolved + validated ONCE at authorize, carried in the signed `cimd` flow claim, consumed at callback with **NO re-fetch**: inject a fetcher whose `fetch()` THROWS at callback and prove the CIMD flow still completes (carry-forward). Three-way dispatch: `HTTPS://` / `http://` / `ftp://`, and lowercase-`https://` while `cimd` is disabled ⇒ direct `invalid_client` (never a stateless fallback, never an IdP hop). Callback claim/mode/redirect matrix (row 5a) rejects a mismatch as `flow_cookie_invalid`; approve-time scheme gate rejects a legacy URL-shaped stateless token as `invalid_consent`. |

A happy path alone does not close S6b. The negative SSRF suite is the security
evidence.

### T1.S7a — examples

| # | Scenario | Assert |
|---|---|---|
| S7a.1 | Fastify example | Boots and completes authorize→token→protected `/mcp`. |
| S7a.2 | Express example | Same flow. |
| S7a.3 | Hono example | Same flow. |
| S7a.4 | API-key gateway example | Backend key read once at boot, injected only server-to-backend, never in client-visible traffic, token claims, or audit logs. |

## Tier 2 — packed-artifact release gate

Run after the source-tree gates, before tagging.

| # | Scenario | Assert |
|---|---|---|
| T2.1 | Source-tree gates | `pnpm run typecheck`, `pnpm run check:lines`, `pnpm run check:seams`, `pnpm test`, `pnpm run build` all green from a clean tree. |
| T2.2 | `npm pack --dry-run` | Tarball contains `dist`, README, LICENSE, and intended docs only. |
| T2.3 | Install packed artifact in a temp project | Public exports import successfully without source files. |
| T2.4 | Minimal metadata smoke from the installed package | Config + metadata endpoint works from the installed package. |
| T2.5 | Optional peer behavior | Importing core does not require fastify/express/hono/mysql/redis unless that adapter is imported. |
| T2.6 | Dependency ledger | Every new dependency or optional peer has version, publish date, and age recorded. |

**2026-07-28 receipt.** T2.1-T2.6 passed from clean commit
`e71a2bbaf6902f98502a788a8d1e4bfc604b9bbc`: 866 tests passed with zero
skipped; the tarball contained only `dist/`, `docs/`, `README.md`, `LICENSE`,
and `package.json`; a temporary install without optional peers imported the
eight peer-free public entry points, all 13 public entry points imported after
their declared optional peers were installed, and the installed root package
produced authorization-server and protected-resource metadata.

**v0.3.1 prepublication candidate input (2026-07-28).** Exact merged
implementation commit `d9b4f089dc46cf832ac598c5fce2401b095a2654`
passed typecheck, line, acceptance-seam, and dependency-policy checks; 886 local
tests and 910 hosted integration tests passed with zero skipped, followed by a
clean build and `npm pack --dry-run`. The 200-file dry-run artifact had only
`dist/`, `docs/`, `README.md`, `LICENSE`, and `package.json` at its root. That
input still declares package version 0.3.0 because the version bump is a
separate release commit. It is not evidence of a `v0.3.1` tag or npm
publication; the final versioned head, hosted CI and review, publish dry-run,
and installed-artifact smoke remain release gates.

**v0.3.2 prepublication candidate input (2026-07-28).** Exact merged
implementation commit `526ad2a2f1167ba7d905cb05cd3c44ce3a2c1d99`
contains the stored-DCR grant-generation cutover. Version candidate
`6b87d804084d899aa29942ae1348f9983ac79619` passed typecheck, line,
acceptance-seam, dependency-policy, process-guard, and CodeQL checks; 899 local
tests and 926 hosted tests with real MySQL and Redis passed with zero skipped,
followed by a clean build. Its 204-file dry-run artifact declared version
0.3.2 and contained only `dist/`, `docs/`, `README.md`, `LICENSE`, and
`package.json`. The documentation-status correction after that candidate must
pass the same exact-head gates and review before merge. This receipt is not
evidence of a `v0.3.2` tag or npm publication; the final versioned head,
publish workflow, and installed registry-artifact smoke remain release gates.

### Release-authority gate

Before tagging, verify the `publish` GitHub Environment through the repository
API: the owner is a required reviewer, admin bypass is disabled, and the only
custom deployment branch policy is a tag pattern `v*.*.*`. A
`workflow_dispatch` run must execute the artifact dry-run and must not enter the
OIDC publish or GitHub Release jobs. For the real release, the tag must equal
`v${package.version}`; the build job produces one tarball and SHA-256 file, the
OIDC job publishes that exact digest-verified tarball without checkout,
dependency installation, or repository scripts, and the no-OIDC release job
runs only after publication succeeds.

## Tier 3 — manual live verification

Tier 3 proves provider/client compatibility. It must never be the only proof for
a security property.

| Area | Live target | Evidence to record |
|---|---|---|
| Captatum dogfood | Deployed Captatum using mcp-sso | Date, mcp-sso commit/package, Captatum commit, client rows, caveats. |
| Entra groups | Real tenant, mapped groups, overage/guest caveats | Date, sanitized tenant setup notes, pass/fail of mapped/no-map/overage paths. |
| Google identity | Real Google OAuth app | Stable subject observed; allowed/rejected allowlist cases; hosted-domain behavior if configured. |
| GitHub identity | Real GitHub OAuth app | Numeric id subject, verified primary email behavior, allowlist reject. |
| Device flow | Real terminal + browser | Request code, approve/deny, poll success/failure, protected `/mcp`. |
| CIMD | Owner-controlled HTTPS metadata URL | The clean-main rerun exercised guarded-fetcher deny legs. Claude Code 2.1.220 then completed CIMD authorization and protected calls through exact runtime commit `af2a61f` with Cloudflare Access, Entra, and Google. |
| MCP clients | curl, official MCP SDK, Claude Code, claude.ai, ChatGPT where available | Date, client version if known, exact caveat if any row is partial. |

README conformance rows can be upgraded only after the relevant Tier-3 evidence
exists.

### Tier 3 requirements

Live checks need operator-owned accounts and deployable URLs. Never put these
values in git. Record only dates, commits, provider/client versions, and
sanitized setup notes.

| Area | Needed before the run |
|---|---|
| Common | Node 24, corepack/pnpm, clean tree, current package commit, HTTPS issuer URL, redirect URL registered with the provider/client, audit log location, scratch browser profile or private window. |
| Release smoke | Temp dir outside the repo, packed tarball path, npm network access only when testing the published package, command transcript for import/metadata smoke. |
| Captatum dogfood | `~/project/smart-fetch` access, deploy credentials, target environment, production-like DB path, Cloudflare Access test identity, rollback plan, exact MCP clients to exercise. |
| Entra groups | Azure tenant, app registration, client secret, redirect URI, test users, group GUIDs for mapped and unmapped cases, scope mapping, owner-run plan for the overage case. |
| Google identity | Google Cloud project, OAuth consent screen, OAuth client id/secret, redirect URI, test account, allowlist values, optional Workspace hosted-domain account for `hd` testing. |
| GitHub identity | GitHub OAuth App, client id/secret, callback URL, test account with verified primary email, numeric user id for allowlist, mutable-login allowlist case if enabled. |
| Device flow | Terminal client session, browser session, identity source for the approving user, short TTL config for expiry checks, screenshots or transcript of approve/deny/poll. |
| CIMD | Owner-controlled HTTPS metadata-document URL, valid document, redirect URI under owner control, cache-control variants, confirmation the deployment uses the guarded fetcher. Negative SSRF proof stays Tier 1. |
| MCP clients | curl command, official MCP SDK version, Claude Code version, claude.ai test window, ChatGPT connector setup if available, per-client caveat field. |

Minimum evidence per live row:

1. Date and timezone.
2. mcp-sso commit or npm version.
3. Provider/client name and version when visible.
4. Sanitized config shape — never secrets.
5. Pass/fail for each scenario named in the Tier-3 row.
6. Exact caveat if any step was skipped, simulated, or only partially verified.
7. Protocol-accurate step names: a CIMD flow starts with an HTTPS `client_id`
   at authorize and does not call `/oauth/register`; only a DCR flow includes
   registration.

## Spec-release re-verification (completed 2026-08-02)

MANUAL maintainer receipt — not automated and not CI-enforced. Checked against:

- official stable release/tag
  [`2026-07-28`](https://github.com/modelcontextprotocol/modelcontextprotocol/releases/tag/2026-07-28),
  commit `5f5440bb26a62e2cf3440b92da5a667efa03b267`;
- dated [Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization),
  [Client Registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration),
  and [Key Changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
  pages; and
- the tagged source files under
  `docs/specification/2026-07-28/basic/authorization/` in the official
  `modelcontextprotocol/modelcontextprotocol` repository.

- [x] **(a) DCR deprecation wording.** Final text retains DCR as an optional
  `MAY` mechanism, marks it Deprecated, directs new implementations to CIMD,
  and retains DCR for backwards compatibility with authorization servers that
  do not support CIMD. The v0.3.2 shape — CIMD preferred, DCR retained for
  compatibility — is accurate.
- [x] **(b) CIMD normative level + draft revision.** Final text keeps CIMD at
  `SHOULD` and cites `draft-ietf-oauth-client-id-metadata-document-00`. The
  implementation was built against later hardening and proves the explicitly
  checked MCP-page requirements through capability advertisement in
  `src/metadata.ts`, exact document binding in `src/cimd/document.ts`, redirect
  binding through `src/cimd/registration.ts`, and the frozen
  `test/acceptance/cimd/` suites. The complete 44-statement draft `-00` mapping
  is now in [§16.1](contracts/16-spec-conformance-matrix.md#161-cimd-draft--00-requirement-matrix):
  no runtime mismatch was confirmed, but four test-evidence rows remain open.
- [x] **(c) RFC 9207 `iss` + `application_type`.** Final text keeps
  authorization-server inclusion of `iss` at `SHOULD`, including error
  responses, with a signposted future `MUST`; a server that includes it `MUST`
  advertise `authorization_response_iss_parameter_supported: true`. MCP clients
  still `MUST` send an appropriate DCR `application_type`. v0.3.2 validates
  `"native"`/`"web"`, defaults omission to OIDC's `"web"`, and enforces stored
  per-type redirect policy. It advertises RFC 9207 support and emits `iss` on
  successful code responses, but `buildErrorRedirect` omits `iss` from
  redirected errors.
- [x] **(d) Record the outcome.** `docs/contracts.md`, normative references, the
  §9 bridge contract, §16 matrix, §17 CIMD citation, this receipt, and the
  contributor-facing status were updated.

**Verdict:** final checked, but MCP Authorization 2026-07-28 conformance remains
pending on three known items:

1. **RFC 9207 error responses.** `src/challenge.ts` builds
   `error`/`state`/`error_description` redirects without `iss`;
   `src/authorize.ts`, `src/adapters/http.ts`, and
   `src/adapters/upstream-flow-internals.ts` use that builder. Successful
   responses add `iss` in `src/authorize-internals.ts`, while AS metadata
   advertises support in `src/metadata.ts`.
2. **Scope hierarchies.** The final Authorization text says servers `MUST`
   account for hierarchies where a broader scope implies narrower scopes.
   `src/scopes.ts` `requireScope` currently performs exact array membership and
   has no hierarchy policy or proof.
3. **CIMD draft evidence.** The final artifact normatively references CIMD draft
   `-00`. The complete §16.1 mapping found no runtime mismatch for the implemented
   public-client profile, but four rows still lack complete hostile or shipped-route
   test evidence: symmetric client-auth declarations, adapter route parity,
   post-authorization no-re-fetch, and inert document-contained URLs.

These are separate contract/runtime follow-ups. The conformance target must not
move from 2025-11-25 until all three are resolved and the resulting implementation
passes the full release gates.

## Done rules

Per build session:

1. Add or update the Tier-1 rows for that session.
2. Keep the baseline official MCP SDK flow green.
3. Run `pnpm run typecheck`, `pnpm run check:lines`, `pnpm run check:seams`,
   `pnpm test`, `pnpm run build`.
4. Push and confirm GitHub CI green.
5. Update roadmap memory with the commit SHA and any Tier-3 live status.

For the v0.3 release:

1. All Tier-1 rows for shipped features pass in CI.
2. Tier 2 packed-artifact gate passes.
3. Required Tier-3 rows for public README claims have dated evidence.
4. The finalized MCP Authorization spec re-read against
   [§16](contracts/16-spec-conformance-matrix.md) and
   [§17](contracts/17-v0-2-feature-contracts.md)
   before any v1.0 language is used.

## Status

The v0.3 feature rows already implemented on `main` are backed by the current
automated suite; rows for unshipped GitHub identity and device flow remain
future plans, not release claims. A 2026-07-26/27 patched, uncommitted checkout
based on `ee8994a` produced CIMD and refresh-replay observations, but its exact
dirty tree was not archived and those observations do not qualify as verified
rows under the minimum evidence contract. On
2026-07-28, an autonomous clean-main rerun at `e71a2bb` completed three
metadata/tokenless-challenge probes and DCR registrations, Cloudflare Access
path gating, public-CIMD resolution to authorization redirects on the Entra-
and Google-configured gateways, and the CIMD literal-IP, DNS-rebinding,
DNS-failure, non-200, content-type, size, and timeout deny legs.
The durable sanitized receipt is in
[`docs/live-verification.md`](live-verification.md#clean-main-rerun-receipt-2026-07-28).
At exact runtime commit `af2a61f`, Claude Code 2.1.220 then completed CIMD
authorization and protected `status` calls with Cloudflare Access, Entra, and
Google. A corrected refresh harness required and observed 200 responses for
A→B→C rotation, HTTP 400 `invalid_grant` for replayed A, and HTTP 400
`invalid_grant` for current C after family revocation. Retained client results
and all three audit logs contained zero backend-key matches.

The packed-artifact pre-tag smoke passed at exact clean-main commit `e71a2bb`.
The published `mcp-sso@0.3.0` artifact repeated the eight peer-free and all-13
with-peers import smokes, produced both metadata documents, and carried verified
registry signatures and attestations. The implementation was reviewed against `2026-07-28-RC`, and the official
stable artifact was manually checked on 2026-08-02. The release still targets
MCP Authorization 2025-11-25 because the completed receipt above records open
RFC 9207 error-response and scope-hierarchy runtime requirements plus four CIMD
draft test-evidence requirements.
Historical Codex CLI success remains recorded, but installed Codex CLI 0.144.1
showed an RFC 9207 `iss` callback regression on 2026-07-28; current
compatibility awaits upstream resolution and retest.
