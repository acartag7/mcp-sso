# Threat Model

> Security reasoning for `mcp-sso`. [Contracts](./contracts.md) is the control
> surface; **this file is the attacker-driven reasoning about why those controls
> hold and what they do not cover.**
>
> Update this file before any change to auth, tokens, redirect policy, the
> store, identity, egress, or the publish pipeline.
>
> Status: **v0.2 shipped (through v0.2.3).** Threats 17–25 cover the
> [§17](./contracts.md#17-v02-feature-contracts-locked-2026-07-04) feature
> contracts — most shipped in v0.2; CIMD (§17.1), device flow (§17.3), and the
> GitHub identity port (§17.6) remain contract-locked, implementation pending.
> Threats 29–33 cover the shipped [§17.11](./contracts.md#1711-upstream-redirect-leg-orchestrator-locked-2026-07-06)
> upstream redirect-leg orchestrator. Threat 34 records the contract-only,
> implementation-pending dynamic-key boundary in
> [§4.1](./contracts.md#41-dynamic-key-and-parsed-record-composition-boundary).

## Assets

- **Signing keys** — the HS256 consent secret and the ES256 access-token private
  key. Compromise = minting arbitrary tokens.
- **OAuth state in the store** — auth-code hashes, refresh-token families/tokens,
  consent JTIs. v0.2 adds device-code records and machine-client secret hashes.
  Integrity and single-use semantics are load-bearing.
- **Subject identities** — emails / OIDs resolved from the upstream IdP.
- **Audit events** — the evidence trail (metadata-only).
- **The protected resource** — the MCP server behind `/mcp`.
- **Machine-client secrets** (`mcs_…`, v0.2) — stored as SHA-256 only; standing
  M2M access until rotated.
- **Pairing / user codes** (v0.2) — short-lived human-entered codes; compromise
  window bounded by TTL + attempt caps.
- **Quickstart secret file** (`.mcp-sso/secrets.json`, v0.2) — plaintext signing
  material on disk, guarded by file permissions.
- **Group→scope mapping config** (v0.2) — its integrity decides privilege tiers
  (GUID-keyed by contract).
- **Upstream flow cookie** (§17.11, v0.2) — signed bearer of one in-flight
  redirect flow (upstream state/nonce/PKCE verifier + round-tripped client
  params); single-use, TTL default 600 s (≤ 3600 s), browser-held.

## Trust boundaries

- **The bridge is the security boundary.** Every MCP client (claude.ai, Claude
  Code, ChatGPT, third parties) is outside trust — each request is authenticated
  and authorized independently. Session IDs are never auth.
- **The upstream IdP is a trusted identity source.** Its credentials/tokens are **data,
  never commands**, and are never forwarded to MCP clients (token passthrough is
  forbidden by the MCP spec). The bridge mints its own audience-bound tokens.
- **The store is within the bridge boundary.** `MemoryStore` is the process;
  `SqliteStore` is a local file (no network); the pooled `MysqlStore`
  (`/store/mysql`, v0.1.2) extends the boundary to the DB network. TLS, DB
  credentials, and DB access control are the deployer's/host's responsibility,
  validated by the [store-conformance suite](./contracts.md#12-store-conformance-contract).
  The library's control on that path is
  [§12.3 transaction hygiene](./contracts.md#123-reference-adapters):
  - A `beginTransaction` failure cannot leak a pooled connection (begun-guard +
    `release` in `finally` on every path), so a begin/commit/rollback error
    cannot exhaust the pool into an auth outage.
  - `rotateRefreshToken` takes a `SELECT ... FOR UPDATE` row lock, so concurrent
    rotations of one token cannot double-spend the successor.
- **Fetched metadata is untrusted data.** v0.1 does no outbound fetching. v0.2
  CIMD (Client ID Metadata Documents) fetches client-supplied URLs —
  attacker-controlled input driving a server-side fetch.
  - That path MUST go through the SSRF-guarded `FetcherPort` under the full
    [§17.1](./contracts.md#171-cimd--client-id-metadata-documents-the-ssrf-enforcement-contract)
    control set. The fetched document is registration data: validated, escaped,
    never executed.
  - URLs inside tokens or documents are data, never instructions. Entra's
    `_claim_sources` endpoint is never dereferenced
    ([§17.4](./contracts.md#174-entra-group-based-authorization-gate-2-becomes-a-scope-ceiling)).
- **The server console is a trust boundary** (v0.2 console pairing,
  [§17.5](./contracts.md#175-console-pairing-identity-zero-idp-setup)): whoever
  reads the process stderr is treated as the operator. Log aggregation
  pipelines extend this boundary. The deployment envelope is single-operator
  hosts with operator-private console output — a documented non-goal boundary,
  not a hardening gap to fix.
- **Deployer configuration is trusted.** The OIDC discovery issuer
  ([§17.6](./contracts.md#176-genericoidcidentity--google-preset--dedicated-github-port))
  and the webhook audit URL
  ([§17.7](./contracts.md#177-audit-reference-sinks--event-coverage)) are
  deliberately NOT behind the SSRF guard: they are static, reviewed config
  (enterprise IdPs/SIEMs legitimately live on private networks). Only
  client-supplied URLs get the §17.1 treatment.

## Required controls

The why behind [contracts §5–§14](./contracts.md). Each control is a guarantee.

- **Fail-closed everywhere** ([§5](./contracts.md#5-configuration-contract),
  [§9.3](./contracts.md#93-authorize--consent)): ambiguous config, a
  missing/rejected identity, an unknown audience, or a replayed token is a hard
  failure — never a degraded default, never a placeholder subject. There is
  intentionally no unauthenticated/local-bypass flavor.
- **Algorithm pinning + key separation** ([§7](./contracts.md#7-crypto--token-contracts)):
  consent HS256, access ES256. Verifiers pin the algorithm set, so a `none`-alg
  or key-confusion token is rejected. The consent secret never validates an
  access token and vice-versa.
- **Audience fail-closed** ([§7.2](./contracts.md#72-access-token-es256-audience-bound-fail-closed),
  RFC 8707): a token's `aud` MUST equal the configured `resource`; a token
  minted for resource A never validates for B.
- **Hashed, single-use credentials** ([§7.3](./contracts.md#73-authorization-code-hashed-single-use),
  [§7.4](./contracts.md#74-refresh-token-family-rotation-replay-detection),
  [§12](./contracts.md#12-store-conformance-contract)): auth codes and refresh
  tokens are stored only as SHA-256 digests; codes and consent JTIs are
  single-use.
- **Refresh rotation + family replay detection** ([§7.4](./contracts.md#74-refresh-token-family-rotation-replay-detection),
  [§12.2](./contracts.md#122-invariants-the-suite-asserts)): rotation marks the
  current token consumed; reuse of a consumed token revokes the entire family.
  RFC 6749 §6 client binding revokes the family on a `client_id` mismatch.
- **Rotation backfill** ([§12.2](./contracts.md#122-invariants-the-suite-asserts),
  fix #3): the next token's `subject`/`clientId`/`scopes` are
  authoritative-copied from the consumed row, not from the (untrusted,
  wire-supplied) request. A stolen refresh token cannot poison the successor.
  Defense-in-depth at the store layer.
- **PKCE S256, timing-safe** ([§7.5](./contracts.md#75-pkce-s256-timing-safe)):
  malformed verifiers rejected outright; constant-time compare.
- **Redirect-URI policy** ([§10](./contracts.md#10-redirect-uri-policy)):
  anchored allowlist — no allow-all `*`, no unanchored prefix, userinfo
  rejected. RFC 8252 loopback any-port only for origin entries. Stored-DCR
  per-`application_type` policy: native ⇒ loopback, web ⇒ https exact.
- **Error-redirect safety** ([§9.3](./contracts.md#93-authorize--consent),
  RFC 6749 §4.1.2.1): a redirect (success or error) is issued ONLY to a
  `redirect_uri` that already passed §10 validation. Pre-validation failures
  (bad `client_id`/`redirect_uri`, no identity) are direct 4xx — they NEVER
  redirect, because the destination is untrusted.
- **CSRF on approve** ([§9.3](./contracts.md#93-authorize--consent)): the
  `origin` check lives in the core use-case; a missing/foreign origin is
  rejected (direct 403). The single-use consent JTI is the primary replay
  defense.
- **Metadata-only audit** ([§13](./contracts.md#13-audit-contract)): no token
  values, no `Authorization`/`Set-Cookie`, no request bodies; redirect URIs
  canonicalized to host. The test suite asserts serialized audit output contains
  no raw codes/refresh/access tokens.
- **Supply chain** ([§15](./contracts.md#15-package--export-map)): `jose` is the
  only runtime dep. Every pin is ≥15 days old and recorded in
  `docs/dependency-ledger.md`. CI actions are SHA-pinned. npm publish is
  `--provenance` from GitHub Actions OIDC only — **no local publishes**. No
  postinstall scripts, no bundler.
- **Dev escape hatch is loopback-only** ([§5](./contracts.md#5-configuration-contract)):
  `dev.allowInsecureLocalhost` is rejected at boot unless both origins are
  loopback, and it warns loudly. It can never weaken a real (non-loopback)
  deployment.

## Threats (attacker-driven)

| # | Threat | STRIDE | Primary control(s) | Residual risk |
|---|---|---|---|---|
| 1 | Steal/replay an access token | Spoofing / Elevation | Short TTL; audience fail-closed; alg pin; `cache-control: no-store` on token responses | A stolen access token is valid until `exp` — no introspection/revocation of live access tokens in v0.1. Accepted given short TTL |
| 2 | Steal/replay a refresh token | Spoofing / Elevation | Rotation marks consumed; replay ⇒ family revoked; RFC 6749 §6 client binding; rotation backfill blocks poisoning | None beyond the race window (reuse revokes immediately) |
| 3 | Forge a token (key compromise / `none`-alg) | Spoofing | ES256/HS256 alg pin; key separation; key-strength boot checks | A compromised signing key = total break; mitigated by supply-chain + ops hygiene |
| 4 | CSRF an `approve` to mint a code | Tampering | Core `origin` check (fail-closed); single-use consent JTI (primary replay defense). The consent surface sets **no cookie**; the optional `mcp_idp_consent` cookie is a deployer seam whose attributes the deployer owns. The §17.11 flow cookie is separate and never touches the consent surface (rows 29–33) | None meaningful |
| 5 | Open-redirect / `redirect_uri` abuse | Spoofing / Elevation | Anchored allowlist ([§10](./contracts.md#10-redirect-uri-policy)); error redirects target only validated `redirect_uri`s | None (a redirect can only go to a §10-validated URI) |
| 6 | Token substitution across resources | Elevation | Audience fail-closed ([§7.2](./contracts.md#72-access-token-es256-audience-bound-fail-closed)) | None |
| 7 | PRM/metadata substitution (client-side) | Spoofing | https-only (TLS); RFC 9728 §3.3 client validates `resource` matches; bridge emits `resource`=config | MITM on non-TLS — excluded by https-only (loopback dev aside) |
| 8 | DCR flooding / audit spam | DoS | Stateless registrations are cheap; audit is metadata-only; `RateLimitPort` hook exists (fix #7) | The hook defaults to no-op — `/oauth/register` + `/oauth/token` can be hammered unless a deployer injects a real limiter or fronts the bridge with a rate-limiting proxy |
| 9 | Stored-mode client spoofing (claim another's redirect) | Spoofing / Elevation | Registration validates each `redirect_uri` via the global allowlist ([§10.1](./contracts.md#101-global-allowlist-stateless-dcr-mode--assertallowedredirecturi)); `application_type` per-type policy blocks a web client widening via native | None (only already-trusted URIs registerable) |
| 10 | Scope escalation | Elevation | `normalizeScopes` vs catalog (unknown ⇒ reject); server-authoritative prior-scopes (derived, not client-claimed); consent shows the delta; `requireScope` at the RS | None |
| 11 | Consent replay | Tampering | Single-use consent JTI; atomic `consumeConsentJti` | None |
| 12 | Identity spoofing | Spoofing | `IdentityPort` verifies the upstream credential; no/failed identity ⇒ 401 fail-closed; no passthrough | Depends on the concrete port validating iss/aud/tid. Header mode (`identityHeader`) carries a nonce residual — [see below](#row-12--header-mode-nonce-residual). The §17.11 redirect orchestrator does not (it mints its own nonce, row 31) |
| 13 | SSRF via CIMD (v0.2) | SSRF | Full [§17.1](./contracts.md#171-cimd--client-id-metadata-documents-the-ssrf-enforcement-contract) contract: URL admission (https-only, no userinfo/fragment/query/dot-segments/IP-literals/CRLF), complete IANA IPv4+IPv6 blocklists (binary compare; embedding prefixes blocked wholesale), all-records DNS validation + pinned connect (no re-resolve), redirects refused (draft -01 MUST NOT), 200-only, 5 KiB cap, 5 s deadline, single generic client-facing error | Timing side-channel could leak coarse network facts (fetch duration); accepted — response content/error shape leak nothing |
| 14 | Secrets in logs/audit | Info disclosure | Metadata-only audit; tests assert no raw secrets leak | None |
| 15 | Compromised dependency / build | Supply chain | jose-only runtime; ≥15-day pins; SHA-pinned CI; provenance publish; no postinstall/bundler | A zero-day in jose itself — minimized by single-dep + pin + age |
| 16 | Dev flag used to weaken a real host | Misconfiguration | `allowInsecureLocalhost` rejected unless loopback + loud warning | Someone tunnels a loopback dev instance out — dev-only, documented |
| 17 | (v0.2) CIMD client impersonation via lookalike/localhost redirect (the MCP-documented attack: legit metadata URL + attacker's loopback redirect) | Spoofing | Exact `client_id` echo-match; redirect exact-match against the doc; consent page MUST show `client_id` host + redirect host, warns on loopback-only redirects; `client_name` labeled unverified | Real and spec-acknowledged: user judgment on lookalike domains / loopback approval remains the last line — CIMD cannot fully close this by design |
| 18 | (v0.2) Machine-client secret theft / misuse | Spoofing / Elevation | Out-of-band provisioning only; 256-bit secrets (`mcs_`+base64url(32)); SHA-256-only storage; shown once; `verifyMachineClientSecret` uniform-work + fail-closed; scopes capped by per-client `allowedScopes` ⊆ catalog; no refresh tokens; rotation with bounded grace (≤2 active secrets). [Enforcement detail below](#row-18--machine-client-secret-enforcement) | A stolen secret is valid until rotated — there is no theft *signal* (unlike refresh replay); bounded by rotation practice + audit of `oauth.token.client_credentials` |
| 19 | (v0.2) Device-flow `user_code` brute force | Spoofing | 34.5-bit code + 600 s TTL + built-in in-process 5-attempts-per-IP cap + `RateLimitPort` hook ≈ RFC 8628 §5.1's 2⁻³² budget | In-process cap is per-instance; multi-instance deployments need the distributed limiter ([§17.10](./contracts.md#1710-distributed-ratelimitport-redisvalkey--shipped-v012)) for the full budget |
| 20 | (v0.2) Device-flow remote phishing (attacker delivers THEIR `user_code` to the victim) | Spoofing | Consent page echoes the `user_code` + "you are authorizing a device — confirm it is yours" (RFC 8628 §5.4 remote-phishing mitigation); short TTL limits emailed-code viability | Real-time phishing remains viable per the RFC itself; accepted with the UI mitigations, documented |
| 21 | (v0.2) Pairing-code exposure (console scrollback, shipped logs) | Info disclosure / Spoofing | TTL 600 s, single-use, 5-attempt invalidation, session binding, ~52-bit code, in-process limiter | Shared log pipelines are OUTSIDE the deployment envelope (single-operator only) — a documented non-goal, not a mitigated risk |
| 22 | (v0.2) Group-authorization bypass (spoofed/mutable group names, overage truncation, stale grants) | Elevation | GUID-only mapping keys; overage ⇒ fail-closed `entra_groups_overage`; `_claim_sources` URL never dereferenced; ceiling intersected at `prepare` AND `approve`. [Enforcement detail below](#row-22--group-authorization-enforcement) | Refresh tokens outlive group removal until family expiry/revocation (no identity at refresh) — bounded by `refreshTokenTtlSeconds`, documented. Guest/B2B group-claim behavior UNVERIFIED in Microsoft's docs — on the live-tenant checklist |
| 23 | (v0.2) Quickstart secret-file theft | Info disclosure | `0700` dir + `0600` file + `O_EXCL` create; group/other-readable file is a BOOT FAILURE; `.gitignore` written into the dir | Any process running as the same OS user can read it — the OS user account is the boundary; production uses env/secret managers |
| 24 | (v0.2) Audit-sink loss or injection | Repudiation / Tampering | JSONL sink: JSON encoding escapes newlines (no log injection); fan-out isolation (`combineAudit`); webhook https-only (raw prefix check), redirects not followed, at-most-once; all sinks fail-open (`writeAuthEvent` never rejects) | Audit writes are fail-open by design (evidence, not a gate): sink outage = lost events; webhook is at-most-once — hard-evidence deployments use file + shipper |
| 25 | (v0.2) CIMD fetch abuse as DoS/amplification (attacker makes the AS fetch repeatedly) | DoS | Single-flight keyed by the raw presented `client_id` string, global in-flight cap, `RateLimitPort` on authorize, 5 KiB/5 s caps; error responses not cached (spec MUST NOT) but rate-limited | Sustained distributed abuse degrades to rate-limiter quality — same §8-class residual as DCR flooding |
| 26 | (v0.2) FIFO/special-file boot/audit hang | DoS | `open(O_NOFOLLOW \| O_NONBLOCK)` + `fstat().isFile()` on quickstart reads (`secrets.json`, `.gitignore`) and the JSONL audit sink's append open — a FIFO at the path returns immediately instead of blocking until a writer appears; non-regular files are rejected. `openSqliteStore` opens `O_RDWR` (no block) and fails closed (`SQLITE_IOERR`) on a FIFO | None — the parity rule ([§17.8](./contracts.md#178-quickstart-secret-persistence-auto-keygen)) keeps every state-file open non-blocking |
| 27 | (v0.2) Non-loopback pairing binding (envelope breach) | Spoofing / Elevation | `defaultListenHost` binds console pairing to `127.0.0.1` by default (the trust envelope is "whoever reads the process's stderr IS the operator"); Cloudflare/proxy binds `0.0.0.0`; `HOST` overrides + a loud stderr warning if pairing is bound off-loopback | An operator who sets `HOST=0.0.0.0` or tunnels the loopback listener publicly exposes the pairing surface + the attempt budget — bounded by maxAttempts/TTL, but the envelope is breached; documented, not mitigated |
| 28 | (v0.2) State-dir trust-bar divergence across code paths | Elevation / Info disclosure | The [§17.8](./contracts.md#178-quickstart-secret-persistence-auto-keygen) parity rule: every state-dir path meets the full bar (`assertRealDir`, `ensureGitignore`, `0600`/`0700`, `O_NOFOLLOW`+`O_NONBLOCK` reads); a control fixed in one path is swept into every sibling. [Detail below](#row-28--state-dir-parity) | Recurrence is process-disciplined (the sweep rule), not mechanistically enforced — a future code path added without the sweep could diverge; caught by review + the dedicated integration round |
| 29 | (v0.2) Upstream login-CSRF / session fixation — an attacker delivers *their* callback URL (or initiates a flow) into a victim's browser so the victim consents on the attacker's upstream identity | Spoofing / Tampering | 256-bit upstream `state` bound to the initiating browser via the signed `HttpOnly`/`SameSite=Lax` flow cookie; timing-safe state compare; mismatch ⇒ direct 400 (never redirect); consent page delivered ONLY as the direct response to the cookie-bearing callback (the §17.11 same-browser binding) | None meaningful — the callback is inert in any browser that did not initiate the flow |
| 30 | (v0.2) Callback replay (reused callback URL, stolen scrollback/history) | Spoofing / Tampering | Single-use flow `jti` (`upf_…`) consumed via the conformance-tested consent-JTI registry BEFORE any IdP-error handling or code exchange; the IdP's own code single-use is the second layer; cookie cleared on every callback completion | Per-process memory store detects replay per instance only — multi-replica deployments need the shared (mysql) store, same class as consent JTIs; bounded by the flow TTL (default 600 s, deployer-configurable ≤ 3600 s, [§17.11](./contracts.md#1711-upstream-redirect-leg-orchestrator-locked-2026-07-06)) |
| 31 | (v0.2) Upstream authorization-code injection/substitution (a stolen or attacker-obtained code redeemed inside another flow) | Spoofing / Elevation | Mandatory upstream PKCE S256 — the verifier lives only in the victim flow's cookie, so a foreign code fails the exchange; OIDC `nonce` binds the id_token to the same flow; both values are orchestrator-generated CSPRNG 256-bit | Providers with no id_token (the future §17.6 GitHub port) lack the nonce layer — state + upstream PKCE remain; documented per-port, never silent |
| 32 | (v0.2) Attacker-influenced IdP callback params abused for open redirect / error-echo injection | Spoofing / Info disclosure | Upstream `error`/`error_description` are mapped to a fixed enum with fixed description strings and NEVER echoed; redirects go only to the §10-validated `redirect_uri` inside the *signed* flow context; `state`/`code`/id_tokens never logged — audit carries enum reasons only | None (row 5's invariant extends: a redirect only ever targets a §10-validated URI) |
| 33 | (v0.2) Flow-cookie theft or tampering (the cookie carries the upstream PKCE verifier + round-tripped client params) | Tampering / Info disclosure | HS256 signature (consent secret, `aud`-pinned `mcp-sso/upstream-flow` — cannot be replayed as a consent token or vice-versa); tampering ⇒ signature failure ⇒ direct 400; `HttpOnly` + `Secure`/`__Host-` on https; flow TTL default 600 s (a deployer may raise it to at most 3600 s, widening this window — [§17.11](./contracts.md#1711-upstream-redirect-leg-orchestrator-locked-2026-07-06)); single-use jti; upstream tokens never enter the cookie | A full browser/endpoint compromise exposes only the in-flight flow (bounded by TTL + single-use); the cookie is signed, not encrypted — the browser's owner can read their own flow params, which is by design |
| 34 | Prototype-chain confusion at attacker-controlled dynamic-key or parsed-record composition sites | Tampering / Elevation | Contract locked in [§4.1](./contracts.md#41-dynamic-key-and-parsed-record-composition-boundary): dynamic lookups use `Map`, null-prototype records, or `Object.hasOwn`; dynamic writes cannot invoke inherited setters; parsed records are explicitly projected rather than spread wholesale. Initial gates are Entra group mapping, adapter-owned request normalization, and CIMD document projection. Acceptance and implementation are separate follow-up PRs | Host-level prototype pollution and hostile in-process ports/adapters are OUT OF SCOPE: code already executing in-process can replace the verifier. Fixed named-field reads are not claimed to withstand arbitrary intrinsic mutation |

### Row 12 — header-mode nonce residual

A new/custom `IdentityPort` MUST validate `iss`/`aud`/`tid` the way Cloudflare
Access and Entra do. Header mode (`identityHeader`) is the residual.

A raw Entra id_token delivered by a fronting proxy is verified by the port's
verify wrapper — but mcp-sso never minted the OIDC nonce, so it is NOT
replay-bound:

- **The verify wrapper** (`verifyEntraIdToken` / `createEntraIdentity().verify`)
  runs jose `jwtVerify`: it enforces the RS256 signature and expiry, then the
  `iss`/`aud`/`tid` claim checks. It checks `nonce` only when an expected value
  is set.
- **The pure `validateEntraIdToken`** is claim validation only — no signature
  check, `exp` presence only. It MUST never be a custom port's sole gate.
- **Replay protection is the fronting proxy's job.** Header mode is safe only
  behind a proxy that itself ran the nonce-bound code exchange (Cloudflare
  Access's signed assertion is the model) — never behind one that merely relays
  tokens.

The §17.11 redirect orchestrator does NOT carry this residual: it mints and
validates its own nonce (row 31).

**Generic-OIDC / Google `at_hash` residual (same class).** The §17.6 generic +
Google ports validate `at_hash` when it is present **in the code flow** (the
access_token just exchanged is available to hash it against). In header mode — a
raw id_token verified standalone with no access_token — `at_hash`, if present, is
**skipped, not rejected**: there is no access_token to bind it to, exactly as
there is no nonce to bind to. The redirect flow (the primary path for these
ports) always has the access_token and always validates `at_hash` when present;
the residual is header-mode-only and is owned by the fronting proxy, like the
nonce residual above.

### Row 18 — machine-client secret enforcement

- **Out-of-band provisioning only.** Open DCR can NEVER mint a secret-bearing
  client. Per [§17.2](./contracts.md#172-client_credentials-grant-mcp-extension-iomodelcontextprotocoloauth-client-credentials):
  a request with `token_endpoint_auth_method ≠ "none"` or a `grant_types`
  containing `client_credentials` is rejected with `invalid_client_metadata`.
  Machine clients are also rejected at `/oauth/authorize`.
- **256-bit secrets.** `mcs_` + base64url(32). Stored as SHA-256 only. Shown
  once.
- **Uniform-work + fail-closed verify.** `verifyMachineClientSecret` composes
  into token-endpoint client auth: wrong secret, unknown client, and poisoned
  record all map to `invalid_client`. There is no client-existence or
  active-count oracle.
- **Scope caps.** Scopes are capped by per-client `allowedScopes`, fixed ⊆
  catalog at provisioning. The grant validates the resolved scope against BOTH
  the ceiling AND the live `scopeCatalog`: `invalid_scope` on any over-ceiling
  or post-narrowing-drift entry. A scope removed from the catalog after
  provisioning is never minted (matching the user-grant `normalizeScopes`
  fail-closed gate).
- **No refresh tokens.** Rotation has bounded grace (≤ 2 active secrets).

### Row 22 — group-authorization enforcement

- **GUID-only mapping keys.** Display names are boot-rejected; duplicate
  case-insensitive keys are rejected.
- **Overage ⇒ fail-closed.** Overage yields `entra_groups_overage` (no
  truncation-driven privilege leak).
- **`_claim_sources` URL never dereferenced** ([§17.4](./contracts.md#174-entra-group-based-authorization-gate-2-becomes-a-scope-ceiling)).
- **Ceiling intersected twice** — at `prepare` AND `approve`. Prior grants
  cannot resurrect removed-group scopes.

### Row 28 — state-dir parity

The [§17.8](./contracts.md#178-quickstart-secret-persistence-auto-keygen)
parity rule: every path that creates/reads the state dir — quickstart, the
example CF branch `ensureStateDir`, the sqlite store, the audit sink — meets the
full bar: `assertRealDir`, `ensureGitignore`, `0600`/`0700`, `O_NOFOLLOW` +
`O_NONBLOCK` reads. A control fixed in one path is swept into every sibling
(the global "sweep for sibling instances" rule).

Recurrence is process-disciplined, not mechanistically enforced — a future code
path added without the sweep could diverge; caught by review + the dedicated
integration round.

## Implementation gates

- No change to auth, tokens, redirect policy, the store, identity, egress, or
  the publish pipeline without updating **this file and
  [contracts](./contracts.md)**.
- No dependency install or bump without a `docs/dependency-ledger.md` recheck
  (version + publish date, ≥15 days — the 15-day gate).
- The [store-conformance suite](./contracts.md#12-store-conformance-contract)
  MUST be green (memory + sqlite + mysql) before any correctness claim; any
  further downstream SQL adapter must pass the same suite.
- The end-to-end verify gate — register → authorize (identity port) → token →
  protected `/mcp` call → refresh → replay-detection (family revoked) → revoke,
  driven by the **official MCP SDK client** — must pass before a release. Green
  unit tests alone are not "done."
- **No local publishes.** npm publish is `--provenance` from GitHub Actions
  OIDC only. Treat every commit as will-be-public (no secrets, no internal
  hostnames).
- Never weaken a fail-closed control to make a test pass — the control wins;
  change the test and document why.

## Known residual risks (deployment-facing)

The terse residual lives in each table row above. These expand the ones a
deployer acts on.

- **No live access-token revocation in v0.1.** Refresh revokes the family (so
  future refreshes fail), but an already-minted access token remains valid until
  its short `exp`. Token introspection is out of v0.1 scope. Accepted: short
  TTL bounds exposure (row 1).
- **The rate-limit hook (`RateLimitPort`, fix #7) defaults to a no-op that
  allows everything.** Without a real limiter at the composition root, the
  unauthenticated DCR/token endpoints can be flooded (DoS, though audit is
  metadata-only). A reference distributed limiter ships at `/rate-limit/redis`
  (v0.1.2, [§17.10](./contracts.md#1710-distributed-ratelimitport-redisvalkey--shipped-v012)):
  a Redis/Valkey fixed-window counter closes the multi-instance gap (threat #19)
  where a per-process limiter is bypassed by spreading requests across
  instances. Deployers who don't wire a real `RateLimitPort` should front the
  bridge with a rate-limiting proxy instead.
- **Single-node store is not HA** (memory is process-local; sqlite is one file).
  The pooled `MysqlStore` (`/store/mysql`, v0.1.2) is the scale path to a shared
  DB. Under concurrent `/oauth/token` load a fixed-size pool can be saturated:
  - Pool sizing is the deployer's job. Provision `mysql2` `connectionLimit`
    (default 10) for peak token-refresh arrival rate × per-request latency, plus
    headroom for refresh bursts AND the periodic `sweepExpired`.
  - Saturation surfaces as a 500 (NOT fail-open — fail-open applies only to
    `RateLimitPort` per [§6.7](./contracts.md#67-ratelimitport-fix-7)); wiring
    the Redis `RateLimitPort` is the in-band DoS mitigation.
  - Performance posture: the hot path (the rate-limit check on `/oauth/register`
    + `/oauth/token`) uses Redis `EVALSHA`, so once the script is cached only its
    hash crosses the wire (the post-restart / `SCRIPT FLUSH` path re-sends the
    body once via `EVAL`). The MySQL adapter uses the text protocol and
    per-transaction `READ COMMITTED`
    ([§12.3](./contracts.md#123-reference-adapters) for the two accepted
    trade-offs).
- **CIMD (v0.2) adds an outbound-fetch SSRF surface.** The `FetcherPort`
  boundary gates it; the v0.2 implementation must enforce the full
  [§17.1](./contracts.md#171-cimd--client-id-metadata-documents-the-ssrf-enforcement-contract)
  control set before it ships (row 13).
- **Upstream-flow replay detection is store-scoped, and abandoned flows are
  invisible.** The flow cookie's single-use `jti` is consumed through the store:
  behind multiple replicas with the per-process memory store, a callback replay
  is detected per instance only (the shared mysql store closes this — same class
  as consent JTIs). An initiated-but-abandoned flow leaves no server-side trace
  (the cookie simply expires) — accepted as the cost of the stateless-cookie
  decision. The `upstream:<ip>` rate-limit key bounds flow-initiation abuse, and
  every callback outcome is audited (`oauth.upstream.callback`). Bounded by the
  flow TTL (default 600 s, ≤ 3600 s, [§17.11](./contracts.md#1711-upstream-redirect-leg-orchestrator-locked-2026-07-06)).
- **Audit sinks are fail-open by design** (evidence, not a gate —
  [§13](./contracts.md#13-audit-contract)): an auth flow never fails because
  evidence could not be written, so sink outage = lost events, and the webhook is
  at-most-once. Deployments that need guaranteed evidence MUST layer a reliable
  transport (e.g. file + shipper) under the file sink.
- **In-process attempt limiters are per-instance.** The pairing and device-flow
  attempt caps hold per process; horizontally scaled deployments need the
  [§17.10](./contracts.md#1710-distributed-ratelimitport-redisvalkey--shipped-v012)
  distributed limiter to keep the full brute-force budget.

Further accepted-by-contract residuals — group-removal lag on refresh (row 22),
machine-secret theft has no signal (row 18), and console pairing is
single-operator only (rows 21, 27) — are stated in full in their table rows.
