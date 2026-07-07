# Threat Model

> Security reasoning for `mcp-sso`. `docs/contracts.md` is the contract
> surface; **this file is the attacker-driven reasoning about why those controls
> hold and what they do not cover.** Update this document before any change to
> auth, token issuance/verification, redirect policy, the store, identity
> handling, egress, or the build/publish pipeline.
>
> Status: **v0.1 shipped + v0.2 contracts locked 2026-07-04** (threats 17–25
> below cover the locked-but-unimplemented contracts in `contracts.md` §17;
> threats 29-33, added 2026-07-06, cover the shipped §17.11 upstream
> redirect-leg orchestrator). Companion to `docs/contracts.md`.

## Assets

- **Signing keys** — the HS256 consent secret and the ES256 access-token private
  key. Compromise = minting arbitrary tokens.
- **OAuth state in the store** — auth-code hashes, refresh-token family/tokens,
  consent JTIs; *(v0.2)* device-code records and machine-client secret hashes.
  Integrity and single-use semantics are load-bearing.
- **Subject identities** — emails / OIDs resolved from the upstream IdP.
- **Audit events** — the evidence trail (metadata-only).
- **The protected resource** — the MCP server behind `/mcp`.
- ***(v0.2)* Machine-client secrets** (`mcs_…`, stored as SHA-256 only) —
  each is standing M2M access until rotated.
- ***(v0.2)* Pairing / user codes** — short-lived human-entered codes whose
  compromise window is bounded by TTL + attempt caps.
- ***(v0.2)* Quickstart secret file** (`.mcp-sso/secrets.json`) — plaintext
  signing material on disk, guarded by file permissions.
- ***(v0.2)* The group→scope mapping config** — its integrity decides
  privilege tiers (GUID-keyed by contract).
- ***(v0.2, §17.11)* The upstream flow cookie** — signed bearer of one
  in-flight redirect flow (upstream state/nonce/PKCE verifier + the
  round-tripped client params); single-use, TTL default 600 s (≤ 3600 s),
  browser-held.

## Trust boundaries

- The **bridge is the security boundary**. MCP clients (claude.ai, Claude Code,
  ChatGPT, third parties) are OUTSIDE trust; every request is authenticated and
  authorized independently. Session IDs are never auth.
- The **upstream IdP is a trusted identity source** — but its credentials/tokens
  are **data, never commands**, and are never forwarded to MCP clients (token
  passthrough is forbidden by the MCP spec). The bridge mints its own
  audience-bound tokens.
- The **store is within the bridge boundary**: `MemoryStore` is the process;
  `SqliteStore` is a local file (no network). The pooled `MysqlStore` (`/store/mysql`,
  v0.1.2) extends the boundary to the DB network — TLS, credentials, and DB access
  control are the deployer's/host's responsibility, validated by the store-conformance
  suite. The library's own control on that path is **§12.3 async-transaction hygiene**:
  a `beginTransaction` failure cannot leak a pooled connection (begun-guard + `release`
  in `finally` on every path), so a begin/commit/rollback error cannot exhaust the pool
  into an auth outage. `rotateRefreshToken` takes a `SELECT ... FOR UPDATE` row lock so
  concurrent rotations of one token cannot double-spend the successor.
- **Fetched metadata is UNTRUSTED DATA.** v0.1 does no outbound fetching. v0.2
  CIMD (Client ID Metadata Documents) fetches client-supplied URLs — an
  attacker-controlled input driving a server-side fetch. That path MUST go
  through the SSRF-guarded `FetcherPort` under the full contracts §17.1
  control set; the fetched document is registration *data* (validated,
  escaped, never executed), and URLs inside tokens or documents are data,
  never instructions (e.g. Entra's `_claim_sources` endpoint is never
  dereferenced — §17.4).
- ***(v0.2)* The server console is a trust boundary** (console pairing,
  §17.5): whoever reads the process stderr is treated as the operator. Log
  aggregation pipelines EXTEND this boundary — the port's deployment envelope
  is single-operator hosts with operator-private console output, and that
  envelope is a documented non-goal boundary, not a hardening gap to fix.
- ***(v0.2)* Deployer configuration is trusted** — the OIDC discovery issuer
  (§17.6) and the webhook audit URL (§17.7) are deliberately NOT behind the
  SSRF guard: they are static, reviewed config (enterprise IdPs/SIEMs
  legitimately live on private networks). Only *client-supplied* URLs get the
  §17.1 treatment.

## Required controls (the "why" behind contracts §5–§14)

- **Fail-closed everywhere** (contracts §5, §9.3): ambiguous config, a missing or
  rejected identity, an unknown audience, or a replayed token is a hard failure —
  never a degraded default, never a placeholder subject. There is intentionally no
  unauthenticated/local-bypass flavor.
- **Algorithm pinning + key separation** (§7): consent HS256, access ES256; verifiers
  pin the algorithm set, so a `none`-alg or key-confusion token is rejected; the
  consent secret never validates an access token and vice-versa.
- **Audience fail-closed** (§7.2, RFC 8707): a token's `aud` MUST equal the
  configured `resource`; a token minted for resource A never validates for B.
- **Hashed, single-use credentials** (§7.3, §7.4, §12): auth codes and refresh
  tokens are stored only as SHA-256 digests; codes and consent JTIs are single-use.
- **Refresh rotation + family replay detection** (§7.4, §12.2.3): rotation marks the
  current token consumed; reuse of a consumed token revokes the entire family;
  RFC 6749 §6 client binding revokes the family on a client_id mismatch.
- **Rotation backfill** (§12.2.4, fix #3): the next token's
  `subject`/`clientId`/`scopes` are authoritative-copied from the consumed row, not
  from the (untrusted, wire-supplied) request — so a stolen refresh token cannot
  poison the successor. Defense-in-depth at the store layer.
- **PKCE S256, timing-safe** (§7.5): malformed verifiers rejected outright;
  constant-time compare.
- **Redirect-URI policy** (§10): anchored allowlist (no allow-all `*`, no unanchored
  prefix, userinfo rejected); RFC 8252 loopback any-port only for origin entries;
  stored-DCR per-`application_type` policy (native ⇒ loopback, web ⇒ https exact).
- **Error-redirect safety** (§9.3, RFC 6749 §4.1.2.1): a redirect (success or
  error) is ever issued ONLY to a `redirect_uri` that already passed §10
  validation. Pre-validation failures (bad client_id/redirect_uri, no identity) are
  direct 4xx — they NEVER redirect, because the destination is untrusted.
- **CSRF on approve** (§9.3): the `origin` check lives in the core use-case; a
  missing/foreign origin is rejected (direct 403). The single-use consent JTI is
  the primary replay defense.
- **Metadata-only audit** (§13): no token values, no `Authorization`/`Set-Cookie`,
  no request bodies; redirect URIs canonicalized to host. The test suite asserts
  serialized audit output contains no raw codes/refresh/access tokens.
- **Supply chain** (§15): `jose` is the only runtime dep; every pin is ≥15 days old
  and recorded in `docs/dependency-ledger.md`; CI actions are SHA-pinned; npm
  publish is `--provenance` from GitHub Actions OIDC only — **no local publishes**;
  no postinstall scripts, no bundler.
- **Dev escape hatch is loopback-only** (§5): `dev.allowInsecureLocalhost` is
  rejected at boot unless both origins are loopback, and it warns loudly. It can
  never weaken a real (non-loopback) deployment.

## Threats (attacker-driven)

| # | Threat | STRIDE | Primary control(s) | Residual risk |
|---|---|---|---|---|
| 1 | Steal/replay an access token | Spoofing / Elevation | Short TTL; audience fail-closed; alg pin; `cache-control: no-store` on token responses | A stolen access token is valid until `exp` (no introspection/revocation of live access tokens in v0.1) — accepted given short TTL |
| 2 | Steal/replay a refresh token | Spoofing / Elevation | Rotation marks consumed; replay ⇒ family revoked; RFC 6749 §6 client binding; rotation backfill blocks poisoning | None beyond the race window (reuse revokes immediately) |
| 3 | Forge a token (key compromise / `none`-alg) | Spoofing | ES256/HS256 alg pin; key separation; key strength boot checks | A compromised signing key = total break; mitigated by supply-chain + ops hygiene |
| 4 | CSRF an `approve` to mint a code | Tampering | Core `origin` check (fail-closed); single-use consent JTI (primary). The consent token travels as a hidden form field — **the consent surface sets no cookie**; the optional `mcp_idp_consent` cookie read in `handleApprove` is a deployer seam, and cookie attributes (HttpOnly/Secure/SameSite) are the deployer's responsibility if used. *(The §17.11 upstream redirect flow sets its own, separate signed flow cookie with library-defined attributes — rows 29–33; it never touches the consent surface.)* | None meaningful |
| 5 | Open-redirect / redirect_uri abuse | Spoofing / Elevation | Anchored allowlist (§10); error redirects target only validated redirect_uris | None (a redirect can only go to a §10-validated URI) |
| 6 | Token substitution across resources | Elevation | Audience fail-closed (§7.2) | None |
| 7 | PRM/metadata substitution (client-side) | Spoofing | https-only (TLS); RFC 9728 §3.3 client validates `resource` matches; bridge emits `resource`=config | MITM on non-TLS — excluded by https-only (loopback dev aside) |
| 8 | DCR flooding / audit spam | DoS | Stateless registrations are cheap + audit is metadata-only; **`RateLimitPort` hook exists (fix #7)** | The hook defaults to no-op — `/oauth/register` + `/oauth/token` can be hammered unless a deployer injects a real limiter or fronts the bridge with a rate-limiting proxy |
| 9 | Stored-mode client spoofing (claim another's redirect) | Spoofing / Elevation | Registration validates each `redirect_uri` via the global allowlist (§10.1); `application_type` per-type policy blocks a web client widening via native | None (only already-trusted URIs registerable) |
| 10 | Scope escalation | Elevation | `normalizeScopes` vs catalog (unknown ⇒ reject); server-authoritative prior-scopes (derived, not client-claimed); consent shows the delta; `requireScope` at the RS | None |
| 11 | Consent replay | Tampering | Single-use consent JTI, atomic `consumeConsentJti` | None |
| 12 | Identity spoofing | Spoofing | `IdentityPort` verifies upstream credential; no/failed identity ⇒ 401 fail-closed; no passthrough | Depends on the concrete identity port (Cloudflare Access, Entra) correctly validating iss/aud/tid — a new/custom `IdentityPort` implementation must do the same. **Header-driven mode (`identityHeader`) nonce residual:** a raw Entra id_token delivered by a fronting proxy is verified for signature/iss/aud/tid/exp but NOT replay-bound — mcp-sso never minted the OIDC nonce, and `validateEntraIdToken` checks `nonce` only when an expected value is set. Replay protection is the fronting proxy's job: header mode is safe only behind a proxy that itself ran the nonce-bound code exchange (Cloudflare Access's signed assertion is the model), never behind one that merely relays tokens. The §17.11 redirect orchestrator does not carry this residual (it mints and validates its own nonce, row 31) |
| 13 | SSRF via CIMD (v0.2) | SSRF | Full §17.1 contract: URL admission (https-only, no userinfo/fragment/query/dot-segments/IP-literals/CRLF), complete IANA IPv4+IPv6 special-purpose blocklists (binary compare; embedding prefixes blocked wholesale), all-records DNS validation + pinned connect (no re-resolve), redirects refused (draft -01 MUST NOT), 200-only, 5 KiB cap, 5 s deadline, single generic client-facing error | Timing side-channel could still leak coarse network facts (fetch duration); accepted — response content/error shape leak nothing |
| 14 | Secrets in logs/audit | Info disclosure | Metadata-only audit; tests assert no raw secrets leak | None |
| 15 | Compromised dependency / build | Supply chain | jose-only runtime; ≥15-day pins; SHA-pinned CI; provenance publish; no postinstall/bundler | A zero-day in jose itself — minimized by single-dep + pin + age |
| 16 | Dev flag used to weaken a real host | Misconfiguration | `allowInsecureLocalhost` rejected unless loopback + loud warning | Someone tunnels a loopback dev instance out — dev-only, documented |
| 17 | *(v0.2)* CIMD client impersonation via lookalike/localhost redirect (the MCP-documented attack: legit metadata URL + attacker's loopback redirect) | Spoofing | Exact `client_id` echo-match; redirect exact-match against the doc; consent page MUST show client_id host + redirect host, warns on loopback-only redirects; `client_name` labeled unverified | Real and spec-acknowledged: user judgment on lookalike domains / loopback approval remains the last line — CIMD cannot fully close this by design |
| 18 | *(v0.2, shipped S3a provisioning/rotation + S3b grant)* Machine-client secret theft / misuse | Spoofing / Elevation | Out-of-band provisioning only (open DCR can NEVER mint a secret-bearing client — §17.2: `token_endpoint_auth_method`≠`none` / `grant_types`∋`client_credentials` ⇒ `invalid_client_metadata`; machine clients rejected at `/oauth/authorize`); 256-bit secrets (`mcs_`+base64url(32)), SHA-256-only storage, shown once; **token-endpoint client auth composes `verifyMachineClientSecret` (uniform-work + fail-closed: wrong secret / unknown client / poisoned record all ⇒ `invalid_client`, no client-existence or active-count oracle)**; scopes capped by per-client `allowedScopes` (fixed ⊆ catalog at provisioning); the grant validates the resolved scope against BOTH the ceiling and the LIVE `scopeCatalog` (`invalid_scope` on any over-ceiling or post-narrowing-drift entry — a scope removed from the catalog after provisioning is never minted, matching the user-grant `normalizeScopes` fail-closed gate); no refresh tokens; rotation with bounded grace (≤2 active secrets) | A stolen secret is valid until rotated — there is no theft *signal* (unlike refresh replay); bounded by rotation practice + audit of `oauth.token.client_credentials` |
| 19 | *(v0.2)* Device-flow `user_code` brute force | Spoofing | 34.5-bit code + 600 s TTL + built-in in-process 5-attempts-per-IP cap + `RateLimitPort` hook ≈ RFC 8628 §5.1's 2⁻³² budget | In-process cap is per-instance; multi-instance deployments need the distributed limiter (§17.10) for the full budget |
| 20 | *(v0.2)* Device-flow remote phishing (attacker delivers THEIR user_code to the victim) | Spoofing | Consent page echoes the user_code + "you are authorizing a device — confirm it is yours" (§5.4); short TTL limits emailed-code viability | Real-time phishing remains viable per the RFC itself; accepted with the UI mitigations, documented |
| 21 | *(v0.2, shipped S1b)* Pairing-code exposure (console scrollback, shipped logs) | Info disclosure / Spoofing | TTL 600 s, single-use, 5-attempt invalidation, session binding, ~52-bit code, in-process limiter | Shared log pipelines are OUTSIDE the deployment envelope (single-operator only) — a documented non-goal, not a mitigated risk |
| 22 | *(v0.2, shipped S2b)* Group-authorization bypass (spoofed/mutable group names, overage truncation, stale grants) | Elevation | GUID-only mapping keys (display names boot-rejected; duplicate case-insensitive keys rejected); overage ⇒ fail-closed `entra_groups_overage`; `_claim_sources` URL never dereferenced; ceiling intersected at `prepare` AND `approve` (prior grants cannot resurrect removed-group scopes) | Refresh tokens outlive group removal until family expiry/revocation (no identity at refresh) — bounded by `refreshTokenTtlSeconds`, documented. Guest/B2B group-claim behavior UNVERIFIED in Microsoft's docs — on the live-tenant checklist |
| 23 | *(v0.2, shipped S1b)* Quickstart secret-file theft | Info disclosure | `0700` dir + `0600` file + `O_EXCL` create; group/other-readable file is a BOOT FAILURE; `.gitignore` written into the dir | Any process running as the same OS user can read it — the OS user account is the boundary; production uses env/secret managers |
| 24 | *(v0.2, shipped S1a)* Audit-sink loss or injection | Repudiation / Tampering | JSONL sink: JSON encoding escapes newlines (no log injection); fan-out isolation (`combineAudit`); webhook https-only (raw prefix check), redirects not followed, at-most-once; all sinks fail-open (`writeAuthEvent` never rejects) | Audit writes are fail-open by design (evidence, not a gate): sink outage = lost events; webhook is at-most-once — hard-evidence deployments use file + shipper |
| 25 | *(v0.2)* CIMD fetch abuse as DoS/amplification (attacker makes the AS fetch repeatedly) | DoS | Single-flight per URL, global in-flight cap, `RateLimitPort` on authorize, 5 KiB/5 s caps; error responses not cached (spec MUST NOT) but rate-limited | Sustained distributed abuse degrades to rate-limiter quality — same §8-class residual as DCR flooding |
| 26 | *(v0.2, shipped S1b)* FIFO/special-file boot/audit hang | DoS | `open(O_NOFOLLOW \| O_NONBLOCK)` + `fstat().isFile()` on quickstart reads (`secrets.json`, `.gitignore`) and the JSONL audit sink's append open — a FIFO at the path returns immediately instead of blocking until a writer appears; non-regular files are rejected. `openSqliteStore` opens O_RDWR (no block) and fails closed (SQLITE_IOERR) on a FIFO | None — the parity rule (§17.8) keeps every state-file open non-blocking |
| 27 | *(v0.2, shipped S1b)* Non-loopback pairing binding (envelope breach) | Spoofing / Elevation | `defaultListenHost` binds console pairing to `127.0.0.1` by default (the trust envelope is "whoever reads the process's stderr IS the operator"); Cloudflare/proxy binds `0.0.0.0`; `HOST` overrides + a loud stderr warning if pairing is bound off-loopback | An operator who sets `HOST=0.0.0.0` or tunnels the loopback listener publicly exposes the pairing surface + the attempt budget — bounded by maxAttempts/TTL, but the envelope is breached; documented, not mitigated |
| 28 | *(v0.2, shipped S1b)* State-dir trust-bar divergence across code paths | Elevation / Info disclosure | The §17.8 parity rule: every path that creates/reads the state dir (quickstart, the example CF branch `ensureStateDir`, the sqlite store, the audit sink) meets the full bar — `assertRealDir`, `ensureGitignore`, `0600`/`0700`, `O_NOFOLLOW`+`O_NONBLOCK` reads — and a control fixed in one path is swept into every sibling (global CLAUDE.md "sweep for sibling instances") | Recurrence is process-disciplined (the sweep rule), not mechanistically enforced — a future code path added without the sweep could diverge; caught by review + the dedicated integration round |
| 29 | *(v0.2, §17.11 shipped)* Upstream login-CSRF / session fixation — an attacker delivers *their* callback URL (or initiates a flow) into a victim's browser so the victim consents on the attacker's upstream identity | Spoofing / Tampering | 256-bit upstream `state` bound to the initiating browser via the signed `HttpOnly`/`SameSite=Lax` flow cookie; timing-safe state compare, mismatch ⇒ direct 400 (never redirect); consent page delivered ONLY as the direct response to the cookie-bearing callback (the §17.11 same-browser binding) | None meaningful — the callback is inert in any browser that did not initiate the flow |
| 30 | *(v0.2, §17.11 shipped)* Callback replay (reused callback URL, stolen scrollback/history) | Spoofing / Tampering | Single-use flow `jti` (`upf_…`) consumed via the conformance-tested consent-JTI registry BEFORE any IdP-error handling or code exchange; the IdP's own code single-use is the second layer; cookie cleared on every callback completion | Per-process memory store detects replay per instance only — multi-replica deployments need the shared (mysql) store, same class as consent JTIs; bounded by the flow TTL (default 600 s, deployer-configurable ≤ 3600 s — §17.11) |
| 31 | *(v0.2, §17.11 shipped)* Upstream authorization-code injection/substitution (a stolen or attacker-obtained code redeemed inside another flow) | Spoofing / Elevation | Mandatory upstream PKCE S256 — the verifier lives only in the victim flow's cookie, so a foreign code fails the exchange; OIDC `nonce` binds the id_token to the same flow; both values are orchestrator-generated CSPRNG 256-bit | Providers with no id_token (the future §17.6 GitHub port) lack the nonce layer — state + upstream PKCE remain; documented per-port, never silent |
| 32 | *(v0.2, §17.11 shipped)* Attacker-influenced IdP callback params abused for open redirect / error-echo injection | Spoofing / Info disclosure | Upstream `error`/`error_description` are mapped to a fixed enum with fixed description strings and NEVER echoed; redirects go only to the §10-validated `redirect_uri` inside the *signed* flow context; `state`/`code`/id_tokens never logged — audit carries enum reasons only | None (row 5's invariant extends: a redirect only ever targets a §10-validated URI) |
| 33 | *(v0.2, §17.11 shipped)* Flow-cookie theft or tampering (the cookie carries the upstream PKCE verifier + round-tripped client params) | Tampering / Info disclosure | HS256 signature (consent secret, `aud`-pinned `mcp-sso/upstream-flow` — cannot be replayed as a consent token or vice-versa); tampering ⇒ signature failure ⇒ direct 400; `HttpOnly` + `Secure`/`__Host-` on https; flow TTL default 600 s (a deployer may raise it to at most 3600 s, widening this window — §17.11); single-use jti; upstream tokens never enter the cookie | A full browser/endpoint compromise exposes only the in-flight flow (bounded by TTL + single-use); the cookie is signed, not encrypted — the browser's owner can read their own flow params, which is by design |

## Implementation gates

- No change to auth, tokens, redirect policy, the store, identity, egress, or the
  publish pipeline without updating **this document and `docs/contracts.md`**.
- No dependency install or bump without a `docs/dependency-ledger.md` recheck
  (version + publish date, ≥15 days, the 15-day gate).
- The **store-conformance suite must be green** (memory + sqlite + mysql) before any
  correctness claim; a further downstream SQL adapter must pass the same suite.
- The **end-to-end verify gate** (Phase 4) — register → authorize (identity port)
  → token → protected `/mcp` call → refresh → replay-detection (family revoked) →
  revoke, driven by the **official MCP SDK client** — must pass before v0.1 ships.
  Green unit tests alone are not "done."
- **No local publishes.** npm publish is `--provenance` from GitHub Actions OIDC
  only. The repo is private until v0.1; treat every commit as will-be-public (no
  secrets, no internal hostnames).
- Never weaken a fail-closed control to make a test pass — the control wins; change
  the test and document why.

## Known residual risks (explicit)

- **No live access-token revocation in v0.1.** Refresh revokes the family (so future
  refreshes fail), but an already-minted access token remains valid until its short
  `exp`. Token introspection is out of v0.1 scope. Accepted: short TTL bounds exposure.
- **The rate-limit hook (`RateLimitPort`, fix #7) ships in v0.1, but defaults to
  a no-op that allows everything.** Unless a deployer injects a real limiter (a
  per-IP token bucket, etc.) at the composition root, the unauthenticated
  DCR/token endpoints can be flooded (audit is metadata-only, but DoS is
  possible). A reference distributed limiter ships at `/rate-limit/redis`
  (v0.1.2, §17.10): a Redis/Valkey fixed-window counter closes the multi-instance
  gap (threat #19) where a per-process limiter is bypassed by spreading requests
  across instances. Deployers who don't wire a real `RateLimitPort` should front
  the bridge with a rate-limiting proxy instead.
- **Single-node store is not HA** (memory is process-local; sqlite is one file).
  Documented; the pooled `MysqlStore` (`/store/mysql`, v0.1.2) is the scale path to a
  shared DB. Under concurrent `/oauth/token` load a fixed-size pool can be saturated —
  provisioning `mysql2` `connectionLimit` is the deployer's job (the default is 10; size
  it to peak token-refresh arrival rate × per-request latency, plus headroom for refresh
  bursts AND the periodic `sweepExpired`); the error surfaces as a 500 (NOT fail-open —
  fail-open applies only to `RateLimitPort` per §6.7), and wiring the Redis
  `RateLimitPort` is the in-band DoS mitigation.
  Performance posture: both adapters are correctness-first on low-QPS OAuth-state
  paths; the hot path (the rate-limit check on `/oauth/register` + `/oauth/token`) uses
  Redis `EVALSHA`, so once the script is cached only its hash crosses the wire (the
  post-restart / `SCRIPT FLUSH` path re-sends the body once via `EVAL`); the MySQL
  adapter uses the text protocol and per-transaction `READ COMMITTED` (see contracts
  §12.3 for the two accepted trade-offs).
- **CIMD (v0.2) adds an outbound-fetch SSRF surface.** The `FetcherPort` boundary is
  in place to gate it; the v0.2 implementation must enforce the full contracts
  §17.1 control set before it ships (that section is now the normative list —
  this line no longer paraphrases it).
- ***(v0.2, accepted by contract)* Group membership changes lag on refresh.**
  Removing a user from a mapped Entra group does not shrink scopes on an
  existing refresh-token family; the ceiling re-applies at the next full
  authorize. Bounded by `refreshTokenTtlSeconds` and family revocation.
- ***(v0.2, accepted by contract)* Machine-secret theft has no built-in
  theft signal.** Refresh-token replay reveals theft (family revocation);
  a copied `client_credentials` secret does not. Rotation cadence and audit
  review are the compensating controls.
- ***(v0.2, accepted by contract)* Console pairing is single-operator
  only.** Codes printed to stderr enter any log pipeline attached to it;
  that deployment shape is excluded by the documented envelope rather than
  mitigated.
- ***(v0.2, accepted by contract)* Audit sinks are fail-open.** An auth flow
  never fails because evidence could not be written; deployments that need
  guaranteed evidence must layer a reliable transport under the file sink.
- ***(v0.2, accepted by contract)* In-process attempt limiters are
  per-instance.** The pairing and device-flow attempt caps hold per process;
  horizontally scaled deployments need the §17.10 distributed limiter to keep
  the full brute-force budget.
- ***(v0.2, accepted by contract — §17.11)* Upstream-flow replay detection is
  store-scoped, and abandoned flows are invisible.** The flow cookie's
  single-use `jti` is consumed through the store: with the per-process memory
  store behind multiple replicas, a callback replay is detected per instance
  only (the shared mysql store closes this — same class as consent JTIs). An
  initiated-but-abandoned flow leaves no server-side trace (the cookie simply
  expires) — accepted as the cost of the stateless-cookie decision; the
  `upstream:<ip>` rate-limit key bounds flow-initiation abuse, and every
  callback outcome is audited (`oauth.upstream.callback`).
