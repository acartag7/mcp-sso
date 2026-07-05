# Verification plan — integration tests & pre-release gates

How mcp-sso proves a release actually works.

There are three verification tiers:

- **Tier 1:** automated tests in CI. Loopback or injected fakes only; no public
  network and no real provider accounts.
- **Tier 2:** packed-artifact release gate. Proves the npm package shape works,
  not just the source tree.
- **Tier 3:** manual live verification. Real IdPs, real MCP clients, and
  production dogfood evidence.

Baseline already exists in v0.1: `test/e2e-mcp-sdk.test.ts` drives register ->
authorize -> token -> protected `/mcp` with the official MCP SDK client ->
refresh -> replay/family revocation -> revoke. The store-conformance suite runs
against memory and sqlite. Everything below extends that baseline; nothing
replaces it.

Contracts: `docs/contracts.md` §17. Threat rows: `docs/threat-model.md` rows
13 and 17-25.

## Rules

Tier-1 tests are the definition of "implemented" for a feature. A feature may
have pure/unit tests too, but it is not done until the real flow row for that
feature is covered.

Tier-1 tests must be deterministic:

- Use Node's built-in test runner and native TypeScript, matching the current
  suite.
- Use loopback servers, adapter injection, fake resolvers, or fake transports.
- Do not depend on public DNS, public HTTP, provider uptime, tunnels, or manual
  browser state.
- Use injected `ClockPort` or explicit test clocks for expiry; avoid real sleeps
  except for sub-deadline transport tests that cannot be modeled otherwise.
- Add every new store record invariant to the shared store-conformance suite, so
  memory/sqlite/mysql prove identical behavior.
- Keep the existing official MCP SDK flow green after every session.

Tier-3 live checks are still required for provider/client claims, but live checks
do not replace CI security tests.

## Harness Pieces

The harness should grow a few shared helpers instead of one-off tests in every
feature file.

| Helper | Purpose |
|---|---|
| `test/lib/oauth-flow.ts` | Drive register/authorize/approve/token/refresh/revoke against an adapter client. |
| `test/lib/mcp-sdk-flow.ts` | Call protected `/mcp` with the official MCP SDK client and a bridge token. |
| `test/lib/adapter-matrix.ts` | Run the same assertions against Fastify, Express, and Hono. |
| `test/lib/store-conformance.ts` | Stay the single source for StorePort invariants; extend it for device-code records. |
| `test/lib/fake-clock.ts` | Deterministic expiry and TTL checks. |
| `test/lib/audit-capture.ts` | Capture audit events and assert no secrets appear. |
| `test/lib/provider-stubs.ts` | Loopback OIDC/GitHub-style token/userinfo stubs where contracts allow local endpoints. |
| `test/lib/cimd-network.ts` | Fake resolver plus guarded low-level transport for SSRF, rebinding, redirect, cap, and timeout cases. |
| `test/lib/package-smoke.ts` | Shared logic for the packed npm artifact smoke test. |

The existing `test/lib/adapter-flow.ts` can either be extended or replaced by
the first three helpers.

## Tier 1 — CI Tests

### T1.HF — adapter identity-rejection parity

Run before S2.

| # | Scenario | Assert |
|---|---|---|
| HF.1 | IdentityPort returns `{ ok: false }` on authorize | All adapters return HTTP 401 with RFC-shaped `{ error: "access_denied", error_description: ... }`. |
| HF.2 | IdentityPort throws `OAuthError("access_denied", 401)` | Same HTTP 401 body on Fastify, Express, and Hono. |
| HF.3 | Non-OAuth error thrown inside a handler | 500 with top-level string error body, never a framework-specific envelope. |

### T1.S0a — MySQL store and Redis/Valkey limiter

| # | Scenario | Assert |
|---|---|---|
| S0a.1 | Shared StorePort conformance against MySQL | Same suite passes for memory, sqlite, and mysql. |
| S0a.2 | MySQL async transaction failure | Original error propagates; rollback/release cleanup errors are swallowed; connection is released. |
| S0a.3 | Timestamp ordering through MySQL | 3-ms UTC timestamps preserve lexicographic ordering. |
| S0a.4 | Two Redis limiter instances share a key/window | Second instance observes the first instance's increments. |
| S0a.5 | Redis unavailable | Limiter fails open and auth flow continues. |

### T1.S1a — audit sinks

| # | Scenario | Assert |
|---|---|---|
| S1a.1 | Full authorize->token->refresh flow with JSONL audit | File has one valid JSON object per line and expected event sequence. (`test/audit-flow.test.ts`) |
| S1a.2 | No-secrets sweep over audit output | No raw auth code, access token, refresh token, consent token, client secret, private key, or pairing code appears. (asserted on the live-flow JSONL file AND on synthetic per-event-name serialization through both sinks) |
| S1a.3 | `combineAudit(throwingSink, fileSink)` during a flow | Flow succeeds; file sink still writes; failure is surfaced only as diagnostic output. (`test/audit-flow.test.ts`) |
| S1a.4 | `WebhookAudit` POST behavior via injected transport stub | Body is the exact event JSON with merged headers; `redirect:"manual"`; a never-settling stub times out via `AbortSignal.timeout`; the sink never rejects and is at-most-once. (The https-only design rejects a plain-http loopback server at construction, and trusting a self-signed loopback cert would need an out-of-dep undici dispatcher; the `fetchImpl` DI seam — the codebase's pattern, cf. Redis stubs — is the test transport.) |
| S1a.5 | `WebhookAudit("http://...")` and userinfo URLs | Constructor rejects non-https config AND URLs containing `user:pass@` userinfo (credentials belong in `headers`; a fetch error would otherwise echo the URL into stderr). |
| S1a.6 | New v0.2 event names | Every new event name has a dedicated pure serialization test across both sinks. |
| S1a.7 | Sink stderr never leaks secrets | An IO/transport error whose message carries a Bearer token, a long opaque run, a known header value, or a credential-bearing URL query string (`?access_token=…`) is redacted before reaching stderr; benign diagnostics are preserved. (`test/audit-util.test.ts` + jsonl/webhook stderr-capture tests) |

### T1.S1b — quickstart secrets and console pairing

| # | Scenario | Assert |
|---|---|---|
| S1b.1 | First boot with empty quickstart dir | Directory `0700`, secrets file `0600`, `.gitignore` with `*`, valid signing JWK and consent secret. |
| S1b.2 | Token survives restart | Mint token, close app, boot from same dir, verify old token still validates. |
| S1b.3 | POSIX secrets file is `0644` | Boot fails closed with `AuthConfigError` and chmod remediation. |
| S1b.4 | Corrupt or partial secrets file | Boot fails closed; no ephemeral fallback. |
| S1b.5 | Console pairing happy path | Code is generated lazily, accepted once, authorize->token->`/mcp` succeeds. |
| S1b.6 | Pairing wrong attempts | Five wrong attempts invalidate the code independent of `RateLimitPort`. |
| S1b.7 | Pairing replay/expiry | Used or expired code cannot authorize. |
| S1b.8 | Example no longer uses dev stub | `examples/fastify-sqlite` boots zero-config and completes the protected MCP flow. (`test/e2e-pairing.test.ts`) |
| S1b.9 | Pairing code never in audit | The 12-char code (canonical and `XXXX-XXXX-XXXX`) appears in NO `oauth.pairing.attempt` event; `reason` is always a short enum. (`test/identity-console-pairing.test.ts`) |
| S1b.10 | Rate-limit deny ≠ throw | A denying `RateLimitPort` blocks without bumping the attempt cap (the correct code still succeeds after a flood of denials); a throwing limiter fails open. (`test/identity-console-pairing.test.ts`) |
| S1b.11 | Audit JSONL on a live pairing flow | `audit.jsonl` carries `oauth.pairing.attempt` + the v0.1 authorize/token events and no raw pairing code / auth code / access token. (`test/e2e-pairing.test.ts`) |

### T1.S2a — core `allowedScopes` ceiling

| # | Scenario | Assert |
|---|---|---|
| S2a.1 | Identity has no `allowedScopes` | Existing authorize/token/refresh behavior is unchanged. |
| S2a.2 | Identity has `allowedScopes` subset | Token scopes are intersection of requested/default/prior scopes and ceiling. |
| S2a.3 | Empty intersection | `access_denied` over the redirect channel after redirect validation. |
| S2a.4 | Consent-token tampering | `approve` uses `allowed_scopes` from verified consent token, never caller input. |
| S2a.5 | Prior grants | Existing grants cannot resurrect scopes outside the current ceiling. |
| S2a.6 | Adapter plumbing | Fastify, Express, and Hono all pass identity object through the bridge. |

### T1.S2b — Entra group mapping

| # | Scenario | Assert |
|---|---|---|
| S2b.1 | Boot config has display-name key | Boot rejects non-GUID mapping key. |
| S2b.2 | Mapped groups plus base scopes | Returned `allowedScopes` is the union required by contract. |
| S2b.3 | Groups map to no scopes and no base | Fail closed with Entra no-groups/no-scopes reason. |
| S2b.4 | Overage marker present | Fail closed; `_claim_sources` is never dereferenced. |
| S2b.5 | Existing Entra config without group auth | Behavior remains unchanged. |
| S2b.6 | Full authorize flow | Entra-derived ceiling is enforced by S2a core flow. |

### T1.S3a — machine client provisioning

| # | Scenario | Assert |
|---|---|---|
| S3a.1 | Enable with non-stored DCR | Boot fails with `AuthConfigError`. |
| S3a.2 | Provision machine client | Returns `mcc_...` id and `mcs_...` secret once; store contains only SHA-256 hash. |
| S3a.3 | Rotate secret | New secret works; old secret gets bounded grace expiry; max two active secrets. |
| S3a.4 | Provision with invalid scope | Rejected before store write. |
| S3a.5 | Machine-shaped DCR request | `/oauth/register` returns `invalid_client_metadata`. |
| S3a.6 | Audit events | Provision/rotate events contain no secret and no hash. |

### T1.S3b — `client_credentials` grant

| # | Scenario | Assert |
|---|---|---|
| S3b.1 | `client_secret_basic` valid | Token response succeeds and protected `/mcp` accepts the access token. |
| S3b.2 | `client_secret_post` valid | Same success path. |
| S3b.3 | Wrong or expired secret | `invalid_client` 401; Basic attempt includes `WWW-Authenticate: Basic`. |
| S3b.4 | Omitted scope | Token gets the full allowed set. |
| S3b.5 | Requested scope outside allowed set | `invalid_scope`; no token minted. |
| S3b.6 | Resource mismatch | Token request fails. |
| S3b.7 | Response shape | No `refresh_token` member exists at all. |
| S3b.8 | User grant regression | Authorization-code and refresh flows remain unchanged. |

### T1.S4a — Generic OIDC and Google preset

| # | Scenario | Assert |
|---|---|---|
| S4a.1 | Generic discovery issuer mismatch | Boot fails. |
| S4a.2 | Discovery endpoint is non-https or redirects | Boot fails. |
| S4a.3 | Valid generic id_token claims | Pure validator accepts only exact issuer, expected audience, nonce, time window, and pinned alg. |
| S4a.4 | Multi-audience token | Rejected. |
| S4a.5 | Missing PKCE support | Boot fails unless explicit loud override is set. |
| S4a.6 | Email allowlist with unverified email | Rejected. |
| S4a.7 | Google preset config | Issuer pinned to `https://accounts.google.com`; `hd` claim, not email domain, controls hosted-domain matching. |

Google live sign-in is Tier 3, not CI.

### T1.S4b — GitHub identity port

| # | Scenario | Assert |
|---|---|---|
| S4b.1 | OAuth URL construction | Hardcoded GitHub authorize endpoint, state, PKCE S256, and `user:email` scope. |
| S4b.2 | Token exchange request | Sends `Accept: application/json` and client secret. |
| S4b.3 | User mapping | Subject is numeric id string; login is not identity unless mutable-claims opt-in is set. |
| S4b.4 | Email mapping | Uses primary verified email only; absence is allowed. |
| S4b.5 | Allowlist reject | Fails closed before bridge token issuance. |

Real GitHub OAuth sign-in is Tier 3. CI should use pure mapping tests and
stubbed transport only if the implementation exposes one without weakening the
production contract.

### T1.S5a — device-flow store and authorization endpoint

| # | Scenario | Assert |
|---|---|---|
| S5a.1 | Store conformance extension | Device-code invariants pass for memory, sqlite, and mysql if shipped. |
| S5a.2 | Request device authorization | Response has `device_code`, `user_code`, verification URIs, `expires_in`, and interval. |
| S5a.3 | Stored record | Raw device code and user code are hashed, not stored. |
| S5a.4 | Poll before approval | Returns `authorization_pending`. |
| S5a.5 | Too-fast poll | Returns `slow_down` and persists interval +5. |
| S5a.6 | Expired code | Not found/consumed; sweep removes expired rows. |
| S5a.7 | Wrong-code attempt cap | Five wrong submissions per IP invalidate the path independently of external limiter. |

### T1.S5b — device verification, approval, and token grant

| # | Scenario | Assert |
|---|---|---|
| S5b.1 | Browser enters code and approves | Polling succeeds and protected `/mcp` works with the issued access token. |
| S5b.2 | Browser denies | Token polling returns terminal `access_denied`. |
| S5b.3 | Approval replay | Device consent token and approved device code are single-use. |
| S5b.4 | `allowedScopes` ceiling | Approved scopes are intersected with the S2a ceiling. |
| S5b.5 | Expired token path | Polling returns terminal `expired_token`. |
| S5b.6 | Refresh token issued | Device flow is a user grant, so refresh/replay/revoke semantics match baseline. |

### T1.S6a — CIMD security primitives

| # | Scenario | Assert |
|---|---|---|
| S6a.1 | URL admission table | Reject non-https, malformed https, root path, query, fragment, userinfo, CRLF, controls, dot segments, localhost, trailing dot, denied ports, and IP literals including dword/octal/hex forms. |
| S6a.2 | IP blocklist table | At least one rejection for every enumerated IPv4/IPv6 CIDR; public allow cases pass. |
| S6a.3 | IPv4-embedding IPv6 | IPv4-mapped, NAT64, 6to4, Teredo-style prefixes are blocked wholesale. |
| S6a.4 | Guarded fetch all-records DNS | Any blocked A or AAAA record rejects the whole fetch. |
| S6a.5 | Pinned connect | Transport receives the validated IP while Host/SNI stay original hostname. |
| S6a.6 | Redirect, cap, timeout | Redirects are not followed; over-cap body rejects not truncates; deadline aborts. |
| S6a.7 | Guard cannot be bypassed | Injected low-level transport sits below admission/DNS/IP/cap/timeout checks. |
| S6a.8 | Document validator | Exact `client_id` equality, required fields, auth method, forbidden secrets, redirect URI hygiene, grant/response constraints. |

### T1.S6b — CIMD integration and SSRF regression

| # | Scenario | Assert |
|---|---|---|
| S6b.1 | Boot config | Branded fetcher accepted; unbranded fetcher rejected; default guarded fetcher constructed. |
| S6b.2 | Happy path | URL-shaped `client_id` fetches doc, validates, authorize->token->`/mcp` succeeds. |
| S6b.3 | Generic client error | Every CIMD failure returns identical client-facing error text. |
| S6b.4 | Audit detail | `oauth.cimd.fetch` records specific reason without leaking document body or secrets. |
| S6b.5 | Redirect URI match | Exact match required; loopback any-port exception honored. |
| S6b.6 | Scope accumulation | CIMD ids accumulate scopes in stateless and stored DCR modes. |
| S6b.7 | Metadata flag | `client_id_metadata_document_supported` appears only when enabled. |
| S6b.8 | Cache | Cache hit, RFC 9111 clamp, no error cache, no invalid-doc cache, single-flight per URL, global in-flight cap. |
| S6b.9 | SSRF negative suite | Encoded dot segments, IP-literal tricks, blocked DNS records, rebinding, redirect-to-blocked-host, over-cap body, slow endpoint, mismatched `client_id`, and `client_secret` doc all fail with identical client-facing text. |

S6b is not done if it only has a happy path. The negative SSRF suite is the
security evidence.

### T1.S7a — examples

| # | Scenario | Assert |
|---|---|---|
| S7a.1 | Fastify example | Boots and completes authorize->token->protected `/mcp`. |
| S7a.2 | Express example | Same flow. |
| S7a.3 | Hono example | Same flow. |
| S7a.4 | API-key gateway example | Backend key is read once at boot, injected only server-to-backend, and never appears in client-visible traffic, token claims, or audit logs. |

## Tier 2 — Packed-Artifact Release Gate

Run after the normal source-tree gates and before tagging a release.

| # | Scenario | Assert |
|---|---|---|
| T2.1 | `pnpm run typecheck`, `pnpm run check:lines`, `pnpm test`, `pnpm run build` | All green from a clean working tree. |
| T2.2 | `npm pack --dry-run` | Tarball contains `dist`, README, LICENSE, and intended docs only. |
| T2.3 | Install packed artifact in temp project | Public exports import successfully without source files. |
| T2.4 | Minimal metadata smoke from installed package | Config + metadata endpoint works from installed package. |
| T2.5 | Optional peer behavior | Importing core package does not require fastify/express/hono/mysql/redis unless that adapter is imported. |
| T2.6 | Dependency ledger | Every new dependency or optional peer has version, publish date, and age recorded. |

## Tier 3 — Manual Live Verification

Tier 3 proves provider/client compatibility. It must never be the only proof for
a security property.

| Area | Live target | Evidence to record |
|---|---|---|
| Captatum dogfood | Deployed Captatum using mcp-sso | Date, mcp-sso commit/package, Captatum commit, client rows, caveats. |
| Entra groups | Real tenant, mapped groups, overage/guest caveats | Date, tenant setup notes without secrets, pass/fail of mapped/no-map/overage paths. |
| Google identity | Real Google OAuth app | Stable subject observed; allowed/rejected allowlist cases; hosted-domain behavior if configured. |
| GitHub identity | Real GitHub OAuth app | Numeric id subject, verified primary email behavior, allowlist reject. |
| Device flow | Real terminal + browser | Request code, approve/deny, poll success/failure, protected `/mcp`. |
| CIMD | Owner-controlled HTTPS metadata URL | Valid doc happy path plus proof that public deployment uses guarded fetcher. |
| MCP clients | curl, official MCP SDK, Claude Code, claude.ai, ChatGPT where available | Date, client version if known, exact caveat if any row is partial. |

README conformance rows can be upgraded only after the relevant Tier-3 evidence
exists.

## Tier 3 Requirements

Live checks need operator-owned accounts and deployable URLs. Do not put these
values in git. Record only dates, commits, provider/client versions when known,
and sanitized setup notes.

| Area | Needed before the run |
|---|---|
| Common | Node 24, corepack/pnpm, clean working tree, current package commit, HTTPS issuer URL, redirect URL registered with the provider/client, audit log location, and a scratch browser profile or private window. |
| Release smoke | Temp directory outside the repo, packed tarball path, network access to npm only when testing the published package, and a command transcript for import/metadata smoke. |
| Captatum dogfood | Access to `~/project/smart-fetch`, deploy credentials, target environment, production-like DB path, Cloudflare Access test identity, rollback plan, and the exact MCP clients to exercise. |
| Entra groups | Azure tenant, app registration, client secret, redirect URI, test users, group GUIDs for mapped and unmapped cases, scope mapping, and an owner-run plan for the overage case. |
| Google identity | Google Cloud project, OAuth consent screen, OAuth client id/secret, redirect URI, test account, allowlist values, and optional Workspace hosted-domain account for `hd` testing. |
| GitHub identity | GitHub OAuth App, client id/secret, callback URL, test account with verified primary email, numeric user id for allowlist, and mutable-login allowlist case if enabled. |
| Device flow | A terminal client session, browser session, identity source for the approving user, short TTL configuration for expiry checks, and screenshots or transcript of approve/deny/poll paths. |
| CIMD | Owner-controlled HTTPS metadata-document URL, valid document, redirect URI under owner control, cache-control variants, and confirmation that deployment uses the guarded fetcher. Negative SSRF proof remains Tier 1. |
| MCP clients | curl command, official MCP SDK version, Claude Code version, claude.ai test window, ChatGPT connector setup if available, and a per-client caveat field. |

Minimum evidence bundle for each live row:

1. Date and timezone.
2. mcp-sso commit or npm version.
3. Provider/client name and version when visible.
4. Sanitized config shape, never secrets.
5. Pass/fail result for each scenario named in the Tier-3 row.
6. Exact caveat if any step was skipped, simulated, or only partially verified.

## Done Rules

For a build session:

1. Add or update the Tier-1 rows for that session.
2. Keep the baseline official MCP SDK flow green.
3. Run `pnpm run typecheck`, `pnpm run check:lines`, `pnpm test`, and
   `pnpm run build`.
4. Push and confirm GitHub CI green.
5. Update roadmap memory with the commit SHA and any Tier-3 live status.

For v0.2 release:

1. All Tier-1 rows for shipped features pass in CI.
2. Tier 2 packed-artifact gate passes.
3. Required Tier-3 rows for public README claims have dated evidence.
4. The finalized MCP Authorization spec has been re-read against
   `docs/contracts.md` §16 and §17 before any v1.0 language is used.

## Current Status

This file is the intended harness design. The v0.1 baseline exists today. Most
v0.2 rows are not implemented yet; each implementation session is responsible
for turning its rows into executable tests before the feature is called done.
