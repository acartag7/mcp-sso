# Threat Model

> Security reasoning for `mcp-sso`. [Contracts](./contracts.md) is the control
> surface; **this file is the attacker-driven reasoning about why those controls
> hold and what they do not cover.**
>
> Update this file before any change to auth, tokens, redirect policy, the
> store, identity, egress, or the publish pipeline.
>
> Status: **v0.3.2.** This release carries the v0.3.1 threat controls forward
> and adds the stored-DCR grant-generation rollback defense in row 40. It also
> retains post-rotation compensation in row 2, the atomic, auditable
> machine-client lifecycle in row 18, and the public redirect-policy helper
> exposing the existing §10 enforcement.
> Threats 17–25 cover the
> [§17](./contracts/17-v0-2-feature-contracts.md#17-v02-feature-contracts-locked-2026-07-04) feature
> contracts — most shipped in v0.2; CIMD (§17.1) ships in v0.3.0
> (S6a/S6b, frozen suites active), with
> live verification across Cloudflare Access, Entra, and Google. Claude Code
> 2.1.220 repeated all three CIMD happy paths and protected calls at exact
> runtime commit `af2a61f` on 2026-07-28; the Entra deny/ceiling sweep remains
> pending. Device flow (§17.3) and the
> GitHub identity port (§17.6) remain contract-locked, implementation pending.
> Threats 29–33 cover the shipped [§17.11](./contracts/17-v0-2-feature-contracts.md#1711-upstream-redirect-leg-orchestrator-locked-2026-07-06)
> upstream redirect-leg orchestrator, including the per-flow audience binding
> in rows 33 and 37 (shipped with the §17.11 flow-instance amendment; frozen
> suite `flow-instance-binding` active). Threat 34 records the contract-only,
> implementation-pending dynamic-key boundary in
> [§4.1](./contracts/04-design-principles.md#41-dynamic-key-and-parsed-record-composition-boundary).
> Threat 35 covers the CIMD × upstream-redirect flow
> ([§17.1.6](./contracts/17-v0-2-feature-contracts.md#1716-s6b-flow-integration-amendments-decisions-16-2026-07-23)),
> implemented on `main`, including rule 20's shared entry grammar. Threat 39
> covers the 0.3.0 invalid-clock JWT hardening.
> Refresh theft detection through `OAuthTokenUseCase` and
> `StorePort.rotateRefreshToken` was repeated at exact runtime commit `af2a61f`
> on 2026-07-28: refresh A→B→C succeeded, replayed A returned HTTP 400
> `invalid_grant`, and current C then returned HTTP 400 `invalid_grant`.

## Assets

- **Signing keys** — the HS256 consent secret and the ES256 access-token private
  key. Compromise = minting arbitrary tokens.
- **OAuth state in the store** — auth-code hashes, refresh-token families/tokens,
  consent JTIs, and machine-client secret hashes. Device-code records are
  contract-only (§17.3) and do not ship.
  Integrity and single-use semantics are load-bearing.
- **Subject identities** — emails / OIDs resolved from the upstream IdP.
- **Audit events** — the evidence trail (metadata-only).
- **The protected resource** — the MCP server behind `/mcp`.
- **Machine-client secrets** (`mcs_…`, v0.2) — stored as SHA-256 only; standing
  M2M access until rotated.
- **Pairing codes** (v0.2) — shipped, short-lived human-entered codes whose
  compromise window is bounded by TTL + attempt caps. Device-flow user codes
  are contract-only and do not ship.
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
  validated by the [store-conformance suite](./contracts/12-store-conformance-contract.md#12-store-conformance-contract).
  The library's control on that path is
  [§12.3 transaction hygiene](./contracts/12-store-conformance-contract.md#123-reference-adapters):
  - A `beginTransaction` failure cannot leak a pooled connection (begun-guard +
    `release` in `finally` on every path), so a begin/commit/rollback error
    cannot exhaust the pool into an auth outage.
  - `rotateRefreshToken` takes a `SELECT ... FOR UPDATE` row lock, so concurrent
    rotations of one token cannot double-spend the successor.
  - A library-opened persistent SQLite file enters the boundary only through
    [§12.4](./contracts/12-store-conformance-contract.md#124-persistent-sqlite-filesystem-admission):
    trusted-directory admission, descriptor validation, and post-open identity
    comparison all run before library migrations or SQL reads. A caller-supplied
    `DatabaseSync` passed to `new SqliteStore(...)` is already inside the
    caller's trust boundary and carries no library filesystem guarantee.
- **Fetched metadata is untrusted data.** v0.1 does no outbound fetching. v0.2
  CIMD (Client ID Metadata Documents) fetches client-supplied URLs —
  attacker-controlled input driving a server-side fetch.
  - That path MUST go through the SSRF-guarded `FetcherPort` under the full
    [§17.1](./contracts/17-v0-2-feature-contracts.md#171-cimd--client-id-metadata-documents-the-ssrf-enforcement-contract)
    control set. The fetched document is registration data: validated, escaped,
    never executed.
  - URLs inside tokens or documents are data, never instructions. Entra's
    `_claim_sources` endpoint is never dereferenced
    ([§17.4](./contracts/17-v0-2-feature-contracts.md#174-entra-group-based-authorization-gate-2-becomes-a-scope-ceiling)).
- **The server console is a trust boundary** (v0.2 console pairing,
  [§17.5](./contracts/17-v0-2-feature-contracts.md#175-console-pairing-identity-zero-idp-setup)): whoever
  reads the process stderr is treated as the operator. Log aggregation
  pipelines extend this boundary. The deployment envelope is single-operator
  hosts with operator-private console output — a documented non-goal boundary,
  not a hardening gap to fix.
- **Deployer configuration is trusted.** The OIDC discovery issuer
  ([§17.6](./contracts/17-v0-2-feature-contracts.md#176-genericoidcidentity--google-preset--dedicated-github-port))
  and the webhook audit URL
  ([§17.7](./contracts/17-v0-2-feature-contracts.md#177-audit-reference-sinks--event-coverage)) are
  deliberately NOT behind the SSRF guard: they are static, reviewed config
  (enterprise IdPs/SIEMs legitimately live on private networks). Only
  client-supplied URLs get the §17.1 treatment.

## Required controls

The why behind [contracts §5–§14](./contracts.md). Each control is a guarantee.

- **Fail-closed everywhere** ([§5](./contracts/05-configuration-contract.md#5-configuration-contract),
  [§9.3](./contracts/09-as-lite-bridge-contract.md#93-authorize--consent)): ambiguous config, a
  missing/rejected identity, an unknown audience, or a replayed token is a hard
  failure — never a degraded default, never a placeholder subject. There is
  intentionally no unauthenticated/local-bypass flavor.
- **Algorithm pinning + key separation** ([§7](./contracts/07-crypto-and-token-contracts.md#7-crypto--token-contracts)):
  consent HS256, access ES256. Verifiers pin the algorithm set, so a `none`-alg
  or key-confusion token is rejected. The consent secret never validates an
  access token and vice-versa.
- **Audience fail-closed** ([§7.2](./contracts/07-crypto-and-token-contracts.md#72-access-token-es256-audience-bound-fail-closed),
  RFC 8707): a token's `aud` MUST equal the configured `resource`; a token
  minted for resource A never validates for B.
- **Finite JWT operation clocks**
  ([§6.1](./contracts/06-ports.md#61-clockport)): the access and consent
  production paths reuse one canonical four-digit UTC `ClockPort` snapshot for
  JWT expiry and audit timestamps. Approval also proves its two TTL-derived
  store timestamps remain canonical. Invalid snapshots preserve the
  typed `invalid_token` / `invalid_consent` failure without fabricating an
  audit time.
- **Hashed, single-use credentials** ([§7.3](./contracts/07-crypto-and-token-contracts.md#73-authorization-code-hashed-single-use),
  [§7.4](./contracts/07-crypto-and-token-contracts.md#74-refresh-token-family-rotation-replay-detection),
  [§12](./contracts/12-store-conformance-contract.md#12-store-conformance-contract)): auth codes and refresh
  tokens are stored only as SHA-256 digests; codes and consent JTIs are
  single-use.
- **Refresh rotation + family replay detection** ([§7.4](./contracts/07-crypto-and-token-contracts.md#74-refresh-token-family-rotation-replay-detection),
  [§12.2](./contracts/12-store-conformance-contract.md#122-invariants-the-suite-asserts)): rotation marks the
  current token consumed; reuse of a consumed token revokes the entire family.
  RFC 6749 §6 client binding revokes the family on a `client_id` mismatch.
- **Rotation backfill** ([§12.2](./contracts/12-store-conformance-contract.md#122-invariants-the-suite-asserts),
  fix #3): the next token's `subject`/`clientId`/`scopes` are
  authoritative-copied from the consumed row, not from the (untrusted,
  wire-supplied) request. A stolen refresh token cannot poison the successor.
  Defense-in-depth at the store layer.
- **PKCE S256, timing-safe** ([§7.5](./contracts/07-crypto-and-token-contracts.md#75-pkce-s256-timing-safe)):
  malformed verifiers rejected outright; constant-time compare.
- **Redirect-URI policy** ([§10](./contracts/10-redirect-uri-policy.md#10-redirect-uri-policy)):
  anchored allowlist — no allow-all `*`, no unanchored prefix, userinfo
  rejected. RFC 8252 loopback any-port only for origin entries. Stored-DCR
  per-`application_type` policy: native ⇒ loopback, web ⇒ https exact.
- **Error-redirect safety** ([§9.3](./contracts/09-as-lite-bridge-contract.md#93-authorize--consent),
  RFC 6749 §4.1.2.1): a redirect (success or error) is issued ONLY to a
  `redirect_uri` that already passed §10 validation. Pre-validation failures
  (bad `client_id`/`redirect_uri`, no identity) are direct 4xx — they NEVER
  redirect, because the destination is untrusted.
- **CSRF on approve** ([§9.3](./contracts/09-as-lite-bridge-contract.md#93-authorize--consent)): the
  `origin` check lives in the core use-case; a missing/foreign origin is
  rejected (direct 403). The single-use consent JTI is the primary replay
  defense.
- **Metadata-only audit** ([§13](./contracts/13-audit-contract.md#13-audit-contract)): no token
  values, no `Authorization`/`Set-Cookie`, no request bodies; redirect URIs
  canonicalized to host. The test suite asserts serialized audit output contains
  no raw codes/refresh/access tokens.
- **Supply chain** ([§15](./contracts/15-package-and-export-map.md#15-package--export-map)): `jose` is the
  only runtime dep. Every pin is ≥15 days old and recorded in
  `docs/dependency-ledger.md`. CI actions are SHA-pinned. `check:deps` rejects
  drift between the ledger, direct package pins, and
  workflow Action pins, and verifies third-party Action tag/date evidence
  upstream. npm publish is `--provenance` from GitHub Actions OIDC only — **no
  local publishes**. No postinstall scripts, no bundler.
- **Dev escape hatch is loopback-only** ([§5](./contracts/05-configuration-contract.md#5-configuration-contract)):
  `dev.allowInsecureLocalhost` is rejected at boot unless both origins are
  loopback, and it warns loudly. It can never weaken a real (non-loopback)
  deployment.

## Threats (attacker-driven)

| # | Threat | STRIDE | Primary control(s) | Residual risk |
|---|---|---|---|---|
| 1 | Steal/replay an access token | Spoofing / Elevation | Short TTL; audience fail-closed; alg pin; `cache-control: no-store` on token responses | A stolen access token is valid until `exp` — no introspection/revocation of live access tokens in v0.1. Accepted given short TTL |
| 2 | Steal/replay a refresh token | Spoofing / Elevation | Rotation marks consumed; replay ⇒ family revoked; RFC 6749 §6 client binding; durable exact resource binding is checked before all rotation/replay mutation; rotation backfill blocks poisoning; every failure after a successful rotation compensates by revoking the whole family before the error escapes | A wrong-resource request to a conforming store commits no mutation, so its legitimate family remains usable at its bound resource. A custom store that ignores the added predicate is nonconforming; the use-case still refuses to sign or success-audit its returned mismatched record, but the store boundary determines whether it already mutated state. Rotation remains before ordinary response preparation so replay detection cannot be skipped. A malformed row, signing failure, or other post-rotation preparation error leaves no active unreturned successor while the store is available. If the compensating store call itself fails, the endpoint still returns no token but external storage availability determines whether revocation was durably recorded (§7.4) |
| 3 | Forge a token (key compromise / `none`-alg) | Spoofing | ES256/HS256 alg pin; key separation; key-strength boot checks | A compromised signing key = total break; mitigated by supply-chain + ops hygiene |
| 4 | CSRF an `approve` to mint a code | Tampering | Core `origin` check (fail-closed); Fastify/Express `headersFromDistinct` preserves raw occurrences and Fetch/Hono `readHeader` rejects comma-coalesced `Origin`; `headerString` never selects an array-valued/case-duplicated normalized value; single-use consent JTI (primary replay defense). The consent surface sets **no cookie**; the optional `mcp_idp_consent` cookie is a deployer seam whose attributes the deployer owns. The §17.11 flow cookie is separate and never touches the consent surface (rows 29–33) | A trusted upstream that selects one duplicate before forwarding erases the occurrence evidence; configure it to reject duplicates instead. Once a request reaches the adapter with multiple occurrences preserved or coalesced, it fails closed |
| 5 | Open-redirect / `redirect_uri` abuse | Spoofing / Elevation | **Mode-appropriate validation** ([§10](./contracts/10-redirect-uri-policy.md#10-redirect-uri-policy) anchored allowlist for opaque ids; the CIMD document exact/loopback-any-port match for CIMD ids — [§17.1.6](./contracts/17-v0-2-feature-contracts.md#1716-s6b-flow-integration-amendments-decisions-16-2026-07-23) decision 1); error redirects target only the validated `redirect_uri`. Entry grammar: [row 5/9 note](#rows-59--the-redirect-entry-grammar) | **PENDING (D00-4.5.2, [§16.1](./contracts/16-spec-conformance-matrix.md#161-cimd-draft--00-requirement-matrix)):** a redirect can only go to a URI the shared matcher accepted, which for a CIMD loopback entry is **not** limited to URIs the document registered: the port is currently allowed to vary without RFC 9700's native-app precondition. A document declaring `application_type: "web"` still matches a different loopback port, so another local process that binds a different port on the same registered host and path can receive the code. Bounded by the document still having to register that host and path. Closed by the follow-up runtime PR |
| 6 | Authorization-code or refresh-token substitution across resources | Elevation | Authorization-code approval requires the verified consent token's resource string to equal the exact bridge configuration before redirect or state mutation. Code redemption predicates reference-store consumption on the stored resource and independently rechecks the returned record. Refresh-family predicates atomically check the exact family and token resources before mutation; the token use case rechecks before signing or success audit | A custom StorePort that ignores a predicate may burn the legitimate code or violate refresh atomicity, but the use-case check still prevents wrong-audience token issuance and success audit; such a store is nonconforming under §12. Built-in stores preserve a correctly bound refresh family on a wrong-resource attempt; legacy refresh rows fail closed |
| 7 | PRM/metadata substitution (client-side) | Spoofing | https-only (TLS); RFC 9728 §3.3 client validates `resource` matches; bridge emits `resource`=config | MITM on non-TLS — excluded by https-only (loopback dev aside) |
| 8 | DCR / identity-verification / token/revocation flooding and audit spam | DoS | Stateless registrations are cheap; `Bridge.resolveIdentity` applies `authorize:<ip>` before direct `IdentityPort.verify`; register, token, and revoke have their own keys; after an adapter's request-body boundary, `Bridge.handleRevoke` applies `revoke:<ip>` before Bridge body normalization, token hashing, store access, revocation, or audit; audit is metadata-only; `RateLimitPort` hook exists (fix #7) | The hook defaults to no-op — `/oauth/register`, direct header-identity `/oauth/authorize`, `/oauth/token`, and `/oauth/revoke` can be hammered unless a deployer injects a real limiter or fronts the bridge with a rate-limiting proxy. Adapter body caps are a separate control; malformed or over-cap revocation input can reject before the limiter. |
| 9 | Stored-mode client spoofing (claim another's redirect) | Spoofing / Elevation | Registration validates each `redirect_uri` via the global allowlist ([§10.1](./contracts/10-redirect-uri-policy.md#101-global-allowlist-stateless-dcr-mode--assertallowedredirecturi)); `application_type` per-type policy blocks a web client widening via native. Entry grammar: [row 5/9 note](#rows-59--the-redirect-entry-grammar) | None (only already-trusted URIs registerable) |
| 10 | Scope escalation or token/form expansion through a scope list | Elevation / DoS | Every scope carrier that reaches a grant or token has the same 128-entry, 256-byte-token cap; `normalizeScopes` checks the catalog (unknown ⇒ reject); server-authoritative prior-scopes are derived, not client-claimed; approve validates both those stored scopes and the signed consent claims before consuming its JTI or writing a code; consent shows the delta; `requireScope` runs at the RS | Scope hierarchy remains the documented final-spec gap; this flat contract does not imply hierarchy semantics |
| 11 | Consent replay | Tampering | Single-use consent JTI; atomic `consumeConsentJti` | None |
| 12 | Identity spoofing | Spoofing | `IdentityPort` verifies the upstream credential; no/failed identity ⇒ 401 fail-closed; no passthrough | Depends on the concrete port validating iss/aud/tid. Header mode (`identityHeader`) carries a nonce residual — [see below](#row-12--header-mode-nonce-residual). The §17.11 redirect orchestrator does not (it mints its own nonce, row 31) |
| 13 | SSRF via CIMD (v0.2) | SSRF | `createGuardedFetcher` enforces the [§17.1](./contracts/17-v0-2-feature-contracts.md#171-cimd--client-id-metadata-documents-the-ssrf-enforcement-contract) network boundary: URL admission (https-only, no userinfo/fragment/query/dot-segments/IP-literals/CRLF), complete IANA IPv4+IPv6 blocklists (binary compare; embedding prefixes blocked wholesale), all-records DNS validation + pinned connect (no re-resolve), redirects refused (draft -01 MUST NOT), 200-only, 5 KiB cap, and 5 s deadline. `CimdResolver.resolve` catches resolution failures and `mapCimdError` collapses them to one generic client-facing `invalid_client` | Timing side-channel could leak coarse network facts (fetch duration); accepted — response content/error shape leak nothing |
| 14 | Secrets in logs/audit | Info disclosure | Metadata-only audit; tests assert no raw secrets leak | None |
| 15 | Compromised dependency / build | Supply chain | jose-only runtime; ≥15-day pins; SHA-pinned CI; provenance publish; no postinstall/bundler | A zero-day in jose itself — minimized by single-dep + pin + age |
| 16 | Dev flag used to weaken a real host | Misconfiguration | `allowInsecureLocalhost` rejected unless loopback + loud warning | Someone tunnels a loopback dev instance out — dev-only, documented |
| 17 | (v0.2) CIMD client impersonation via lookalike/localhost redirect (the MCP-documented attack: legit metadata URL + attacker's loopback redirect) | Spoofing | Exact `client_id` echo-match; redirect exact-match against the doc **except that the loopback port is currently allowed to vary — see the pending qualification opposite**; the consent page presents the client-ID and redirect hosts first as the decision anchors, warns on loopback-only redirects, and renders `client_name` second as self-reported, unverified text. **The page is frame-blocked (row 36)** — without that, the user judgment this row depends on can be bypassed by an overlay rather than deceived | Real and spec-acknowledged: user judgment on lookalike domains / loopback approval remains the last line — CIMD cannot fully close this by design. **PENDING (D00-4.5.2, [§16.1](./contracts/16-spec-conformance-matrix.md#161-cimd-draft--00-requirement-matrix)) — a second, non-judgment residual:** the match is not port-exact for loopback, and RFC 9700's native-app precondition is not evaluated, so a document declaring `application_type: "web"` still matches any port on its registered loopback host and path. A different local process bound to that path on another port can therefore receive the code, which **no amount of user care at the consent page can detect** — the host and path shown are the legitimate ones. Bounded by the attacker needing local process execution and the document still having to register that host and path. Closed by the follow-up runtime PR |
| 18 | (v0.2) Machine-client secret theft / misuse | Spoofing / Elevation | Out-of-band provisioning only; 256-bit secrets (`mcs_`+base64url(32)); SHA-256-only storage; shown once; stored rows parsed and key-bound by `parseMachineClientRegistration`; versioned create/CAS/disable commits each mutation with durable audit; concurrent rotation has one winner; disabled tombstones contain no hashes; `verifyMachineClientSecret` uses two digest comparisons and fails closed; scopes capped by per-client `allowedScopes` ⊆ catalog; no refresh tokens; rotation grace preserves the published 24-hour default and is hard-capped at 24 hours (≤2 active secrets); deployments can request a shorter overlap. [Enforcement detail below](#row-18--machine-client-secret-enforcement) | A stolen secret is valid until rotated or disabled — there is no theft *signal* (unlike refresh replay); already-issued access tokens remain valid until their ordinary expiry |
| 19 | (contract-only) Device-flow `user_code` brute force | Spoofing | No device endpoint ships. §17.3 requires a 34.5-bit code, 600 s TTL, built-in in-process attempt cap, and `RateLimitPort` hook before this surface can be implemented | Not an active runtime threat; the specified per-instance residual applies only to a future implementation |
| 20 | (contract-only) Device-flow remote phishing (attacker delivers THEIR `user_code` to the victim) | Spoofing | No device consent page ships. §17.3 requires the future page to echo the code and warn the user to confirm the device | Not an active runtime threat; real-time phishing remains a future RFC 8628 residual |
| 21 | (v0.2) Pairing-code exposure (console scrollback, shipped logs) | Info disclosure / Spoofing | TTL 600 s, single-use, 5-attempt invalidation, session binding, ~52-bit code, in-process limiter | Shared log pipelines are OUTSIDE the deployment envelope (single-operator only) — a documented non-goal, not a mitigated risk |
| 22 | (v0.2) Group-authorization bypass (spoofed/mutable group names, overage truncation, stale grants) | Elevation | `createEntraRedirectIdentity` verifies the identity and `resolveGroupCeiling` applies GUID-only mappings; overage ⇒ fail-closed `entra_groups_overage`; `_claim_sources` URL never dereferenced; ceiling intersected at `prepare` AND `approve`. [Enforcement detail below](#row-22--group-authorization-enforcement) | Refresh tokens outlive group removal until family expiry/revocation (no identity at refresh) — bounded by `refreshTokenTtlSeconds`, documented. A real guest/B2B membership was observed on an unarchived patched checkout; clean-main and tenant-specific claim emission remain prerequisites for a current live claim |
| 23 | (v0.2) Quickstart secret-file theft | Info disclosure | `0700` dir + `0600` file + `O_EXCL` create; group/other-readable file is a BOOT FAILURE; `.gitignore` written into the dir | Any process running as the same OS user can read it — the OS user account is the boundary; production uses env/secret managers |
| 24 | (v0.2) Audit-sink loss, injection, or local path redirection | Repudiation / Tampering | JSONL sink: JSON encoding escapes newlines (no log injection); on hosts with `O_NOFOLLOW`, each append opens the final component with `O_NOFOLLOW | O_NONBLOCK`, validates `fstat().isFile()` on that descriptor, then writes through that descriptor. Calls to one sink instance are serialized across that complete operation, so a short write cannot splice that instance's records. A symlink (including a dangling or swapped one), FIFO, socket, device, or directory cannot receive an event. `combineAudit` isolates fan-out; webhook is https-only (raw prefix check), redirects not followed, at-most-once; reference sinks fail open. `OAuthTokenUseCase` routes token/revocation events through `writeTokenAudit`, so even a nonconforming custom sink cannot replace those OAuth outcomes | Audit writes are fail-open by design (evidence, not a gate): sink outage = lost events; webhook is at-most-once — hard-evidence deployments use file + shipper. A Node host without `O_NOFOLLOW` drops JSONL events rather than using a raceable fallback. `O_NOFOLLOW` cannot distinguish a hard-linked regular file: an attacker who can write the parent and create a hard link to a service-writable victim can still redirect evidence. This release does not add a link-count policy because that needs a separate contract decision; deployers must protect the parent and use host hard-link protections. Separate sink instances/processes have no interprocess file lock, so deployments requiring cross-process JSONL framing must designate one writer or coordinate it externally. Other use-cases still rely on the `AuditPort` contract and the shipped fail-open sinks |
| 25 | (v0.2) CIMD fetch abuse as DoS/amplification (attacker makes the AS fetch repeatedly) | DoS | Single-flight keyed by the raw presented `client_id` string, global in-flight cap, **bounded (LRU) validated-success cache** (§17.1.6 decision 4 — repeated same-id fetches collapse to one per freshness window **for cacheable responses only**, in direct AND upstream-redirect mode), optional `RateLimitPort`, guarded-fetch timeout and response-size cap, cache TTL cap, and deployment egress policy | Sequential abuse — across distinct valid ids, or one id whose client-controlled response is non-cacheable: `no-store`, `no-cache`, `private`, absent/malformed freshness metadata, `Vary: *`, old/skewed `Date`, or a short/zero selected `max-age`/`s-maxage`. Those controls bound but do not eliminate repeated fetches; a mandatory origin-independent budget is a §18 option (row 35). |
| 26 | (v0.2) FIFO/special-file boot/audit hang | DoS | `open(O_NOFOLLOW \| O_NONBLOCK)` + `fstat().isFile()` on quickstart reads (`secrets.json`, `.gitignore`) and, where the native no-follow flag exists, the JSONL audit sink's append open — a FIFO at the path returns immediately instead of blocking until a writer appears; non-regular files are rejected. A host without that flag drops the audit event before opening. `openSqliteStore` rejects a non-regular final path before SQLite; its nonblocking descriptor open and `fstat` repeat that defense if the name changes after preflight ([§12.4](./contracts/12-store-conformance-contract.md#124-persistent-sqlite-filesystem-admission)) | Root/same-account replacement remains row 42's explicit filesystem-boundary residual |
| 27 | (v0.2) Non-loopback pairing binding (envelope breach) | Spoofing / Elevation | `defaultListenHost` binds console pairing to `127.0.0.1` by default (the trust envelope is "whoever reads the process's stderr IS the operator"); Cloudflare/proxy binds `0.0.0.0`; `HOST` overrides + a loud stderr warning if pairing is bound off-loopback | An operator who sets `HOST=0.0.0.0` or tunnels the loopback listener publicly exposes the pairing surface + the attempt budget — bounded by maxAttempts/TTL, but the envelope is breached; documented, not mitigated |
| 28 | (v0.2) State-dir trust-bar divergence across code paths | Elevation / Info disclosure | The [§17.8](./contracts/17-v0-2-feature-contracts.md#178-quickstart-secret-persistence-auto-keygen) parity rule requires every state path to meet its applicable trust bar. Quickstart and `ensureStateDir` own directory/`.gitignore` setup; `openSqliteStore` deliberately does not and instead requires the already-existing §12.4 private directory plus descriptor admission. A control fixed in one path is swept into every sibling that touches the same resource. The JSONL sink is not state-dir storage: its narrower final-target/descriptor protection and parent-directory hard-link residual are row 24, not an `assertRealDir` claim. [Detail below](#row-28--state-dir-parity) | Recurrence is process-disciplined (the sweep rule), not mechanistically enforced — a future code path added without the sweep could diverge; caught by review + the dedicated integration round |
| 29 | (v0.2) Upstream login-CSRF / session fixation — an attacker delivers *their* callback URL (or initiates a flow) into a victim's browser so the victim consents on the attacker's upstream identity | Spoofing / Tampering | 256-bit upstream `state` bound to the initiating browser via the signed `HttpOnly`/`SameSite=Lax` flow cookie; timing-safe state compare; mismatch ⇒ direct 400 (never redirect); consent page delivered ONLY as the direct response to the cookie-bearing callback (the §17.11 same-browser binding) | None meaningful — the callback is inert in any browser that did not initiate the flow |
| 30 | (v0.2) Callback replay (reused callback URL, stolen scrollback/history) | Spoofing / Tampering | Single-use flow `jti` (`upf_…`) consumed via the conformance-tested consent-JTI registry BEFORE any IdP-error handling or code exchange; the IdP's own code single-use is the second layer; cookie cleared on every callback completion | Per-process memory store detects replay per instance only — multi-replica deployments need the shared (mysql) store, same class as consent JTIs; bounded by the flow TTL (default 600 s, deployer-configurable ≤ 3600 s, [§17.11](./contracts/17-v0-2-feature-contracts.md#1711-upstream-redirect-leg-orchestrator-locked-2026-07-06)) |
| 31 | (v0.2) Upstream authorization-code injection/substitution (a stolen or attacker-obtained code redeemed inside another flow) | Spoofing / Elevation | Mandatory upstream PKCE S256 — the verifier lives only in the victim flow's cookie, so a foreign code fails the exchange; OIDC `nonce` binds the id_token to the same flow; both values are orchestrator-generated CSPRNG 256-bit | Providers with no id_token (the future §17.6 GitHub port) lack the nonce layer — state + upstream PKCE remain; documented per-port, never silent |
| 32 | (v0.2) Attacker-influenced IdP callback params abused for open redirect / error-echo injection | Spoofing / Info disclosure | Upstream `error`/`error_description` are mapped to a fixed enum with fixed description strings and NEVER echoed; redirects go only to the mode-appropriately validated `redirect_uri` (§10 or the CIMD document match, [§17.1.6](./contracts/17-v0-2-feature-contracts.md#1716-s6b-flow-integration-amendments-decisions-16-2026-07-23)) inside the *signed* flow context; `state`/`code`/id_tokens never logged — audit carries enum reasons only | Row 5's invariant extends, in its **pending-qualified** form (D00-4.5.2): a redirect only ever targets a URI the shared matcher accepted. For an opaque client that is a §10-validated URI; for a CIMD client it is a document-registered URI **or**, on a loopback entry, one sharing its registered host and path with a different port — which is not a URI the document registered. No other residual |
| 33 | (v0.2) Flow-cookie theft or tampering (the cookie carries the upstream PKCE verifier + round-tripped client params) | Tampering / Info disclosure | HS256 signature (consent secret, `aud`-pinned `mcp-sso/upstream-flow` — cannot be replayed as a consent token or vice-versa; the audience is PER FLOW — `+ callbackPath`, §17.11 — so a token cannot be replayed across flow instances either, see row 37); tampering ⇒ signature failure ⇒ direct 400; `HttpOnly` + `Secure`/`__Host-` on https; flow TTL default 600 s (a deployer may raise it to at most 3600 s, widening this window — [§17.11](./contracts/17-v0-2-feature-contracts.md#1711-upstream-redirect-leg-orchestrator-locked-2026-07-06)); single-use jti; upstream tokens never enter the cookie | A full browser/endpoint compromise exposes only the in-flight flow (bounded by TTL + single-use); the cookie is signed, not encrypted — the browser's owner can read their own flow params, which is by design |
| 34 | Prototype-chain confusion at attacker-controlled dynamic-key or parsed-record composition sites | Tampering / Elevation | Contract locked in [§4.1](./contracts/04-design-principles.md#41-dynamic-key-and-parsed-record-composition-boundary): dynamic lookups use `Map`, null-prototype records, or `Object.hasOwn`; dynamic writes cannot invoke inherited setters; parsed records are explicitly projected rather than spread wholesale. Initial gates are Entra group mapping, adapter-owned request normalization, and CIMD document projection. Acceptance and implementation are separate follow-up PRs | Host-level prototype pollution and hostile in-process ports/adapters are OUT OF SCOPE: code already executing in-process can replace the verifier. Fixed named-field reads are not claimed to withstand arbitrary intrinsic mutation |
| 35 | (v0.2) CIMD client in **upstream-redirect** mode — document swap between authorize and callback (approve-then-swap), unauthenticated pre-identity outbound fetch, registration substitution | Tampering / SSRF / DoS | [§17.1.6](./contracts/17-v0-2-feature-contracts.md#1716-s6b-flow-integration-amendments-decisions-16-2026-07-23) decision 1: the CIMD document is resolved and validated at authorize through the shared success cache (1a — at most one guarded fetch on a miss, zero on a hit); its validated named projection is carried forward in the HS256-signed single-use flow cookie (1c) and consumed at callback with NO re-fetch (1d) — the consented registration is cryptographically the validated one (approve-then-swap CLOSED). The registration handed to `bridge.handleAuthorize` is orchestrator-resolved trusted state (same category as `subject`/`allowedScopes`), not a new deployer trust input; no capability/brand system. All CIMD resolution failures collapse to one generic `invalid_client` (decision 2, closing the SSRF content/reachability oracle) | Residuals (documented, not eliminated): CIMD resolution at authorize precedes identity, so an unauthenticated caller triggers guarded outbound fetches. The bound is **precise, not hand-waved**: the SSRF guard limits *reach* (admission + blocklist ⇒ only an external, public, attacker-chosen host — never internal); the validated-success cache (bounded, LRU) collapses repeated requests for the *same* `client_id` to at most one fetch per freshness window **for cacheable responses only** (a non-cacheable/`no-store`/`max-age`<60 response re-fetches each time); single-flight + `maxInFlight` bound only *concurrent* fetches, and — per **§17.1.6 decision 7** — `maxWaitersPerFetch` (default 256) bounds the callers that may *park on* one in-flight fetch, so total concurrent waiting resolutions are bounded above by `maxInFlight × (maxWaitersPerFetch + 1)` (default 2056 — the `+1` per entry is the initiating resolution). Without that second cap a single slow attacker-hosted document held an unbounded number of waiters (measured: 10 000 same-id requests ⇒ 1 fetch, ~15.4 MB retained) — CWE-770 on an unauthenticated path. **Sequential requests across many distinct valid `client_id`s remain bounded only by the optional `cimd:<ip>` `RateLimitPort`** — the same residual class as row 25 / DCR flooding (row 8). A *mandatory* built-in request budget independent of the optional limiter is a deliberate **§18 option, not built in v0.2** (it would change the optional-rate-limit architecture; the SSRF-reach bound + optional limiter are judged sufficient for v0.2). Other residuals: a leaked `consentSigningSecret` enables registration substitution (same secret/trust as row 33); redirect-mode effective document size is cookie-bound (a large-but-valid doc fails closed as `invalid_client`); resolution timing is a coarse side channel (row 13 class). Enforcement + acceptance ship in the S6b PRs (frozen suite `s6b-cimd-flow` active). Claude Code 2.1.220 completed CIMD authorization and protected calls through exact runtime commit `af2a61f` with Cloudflare Access, Entra, and Google on 2026-07-28 |
| 36 | Clickjacking of the consent / pairing page (framed + overlaid Approve) | Spoofing / Elevation | Both HTML responses send `frame-ancestors 'none'` **and** `x-frame-options: DENY` (CSP3 does NOT fall back to `default-src` for `frame-ancestors`, so `default-src 'none'` alone does not frame-block). Their form policies intentionally differ under the **0.3.0 amendment**: consent omits `form-action` because Chromium applies it across the POST's redirect chain and `'self'` blocks the validated client callback; pairing retains `form-action 'self'` because its submission terminates same-origin. Consent's form action is a fixed literal, all interpolation is escaped, scripts remain blocked, and `assertApproveOrigin` plus signed consent state still gate the resulting 302. Their referrer policies also differ: consent sends `same-origin` so its same-origin Approve POST retains the exact Origin value required by `assertApproveOrigin`, while suppressing the authorize query on cross-origin navigation; pairing sends `no-referrer`. Applies to `CONSENT_HEADERS` (`adapters/bridge.ts`) and `PAIRING_HEADERS` (`adapters/pairing-flow.ts`); all three adapters relay response headers verbatim. **The two pages carry different risk and the headers are not claimed to do the same work on both:** the CONSENT page is the real target (it holds the Approve control this row is about); the PAIRING page's only control is `Continue` and its code is TYPED IN by the operator (printed to stderr, never in the markup), so framing it yields UI redress on a form that still requires a code readable only from the server console — defense-in-depth, not a header-mirror requirement | Row 17 makes the user's judgment at this page the last line of defence, and CIMD needs no registration to reach it — so framing would nullify that mitigation with a single click. `SameSite` does not help (the consent token is a hidden form field, and the POST originates from the mcp-sso document, so `assertApproveOrigin` passes). Omitting consent `form-action` loses CSP-level form-destination containment if a future defect injects markup; current fixed escaped markup, script blocking, the Origin gate, and signed validated redirect state bound that residual. A deployer proxy that strips or rewrites the frame headers reopens clickjacking — outside the library's control, same class as row 12 |
| 37 | (v0.2) Cross-flow upstream-callback substitution in a multi-IdP deployment (a cookie minted by one `createUpstreamRedirectFlow` redeemed at another's callback) | Spoofing / Elevation | **Shipped** (`signFlowToken`/`verifyFlowToken` take a required `callbackPath`; frozen suite `flow-instance-binding` active). The flow JWT's `aud` is bound to the flow instance — `"mcp-sso/upstream-flow" + callbackPath` (§17.11 "flow-instance binding"). `callbackPath` is already unique per mounted flow and boot-validated by `assertCallbackPath` into a canonical literal. A non-matching cookie fails `jwtVerify` at **row 3** (`flow_cookie_invalid`) — before jti consumption and before any token exchange — so the wrong IdP is never contacted | Before the binding, every flow built from one signing secret accepted every other flow's cookies: the user picks one IdP and a different one authenticates them (an authentication-provider **confused deputy**), and because CIMD resolution runs pre-identity the initiating request is unauthenticated. MEDIUM not HIGH — the shipped adapters mount a single flow, which is unaffected — but the exported factory permits the multi-flow topology. Residual: a leaked `consentSigningSecret` still forges any flow token (row 33's trust assumption); binding narrows scope, it does not replace the secret's role |
| 38 | Duplicate or differently normalized `Origin` fields weaken a reference `/mcp` DNS-rebinding gate | Spoofing | The runnable Fastify examples reconstruct headers with `headersFromDistinct` and decide with `readHeader`; the generated server checks `request.raw.headersDistinct.origin` inline. Both admit absent `Origin`, allowlist exactly one comma-free occurrence, and return 403 on ambiguity before parsing or bearer authorization | This is low-severity parser hardening, not a demonstrated normal-config authentication bypass. A custom `/mcp` mount owns its Origin gate, and a trusted proxy that already selected one occurrence erased the evidence; either must apply the same reject-on-ambiguity rule |
| 39 | A broken custom `ClockPort` supplies a non-finite, fractional, or non-canonical UTC value, disabling access/consent JWT expiry, breaking approval store timestamps, or replacing the intended OAuth failure during audit formatting | Spoofing / Elevation | `finiteClockSnapshot` validates one underlying read against the canonical four-digit UTC range. `verifyAccessToken` / `verifyConsentToken` reject before `jwtVerify`; `RequestAuthorizer.authorize` / `OAuthAuthorizationUseCase.approve` reuse a fixed snapshot through verification and timestamped work. Approval also validates its larger TTL-derived future offset before token processing, preserving `invalid_token` / `invalid_consent` | This is hardening, not a normal remote clock-control path: exploitation requires a faulty/custom trusted port plus an expired but otherwise valid signed token. The clock remains trusted; a plausible but stale canonical value is not detectable. Invalid snapshots become a fail-closed authentication outage and emit no timestamped event because no honest `occurredAt` exists |
| 40 | Stored-DCR cutover is followed by a rollback, pre-resource migration, or resource change; an old binary writes a new authorization code, refresh family, or successor, then the current binary accepts or accumulates it because the client ID still exists | Tampering / Elevation | **0.3.2:** `OAuthAuthorizationUseCase.approve` stamps library generation `1`; nullable SQL columns make old-binary inserts explicitly legacy; `consumeAuthCode` and `rotateRefreshToken` check generation inside their atomic operation; `OAuthTokenUseCase` rechecks returned records; `findGrantedScopes` filters both family/token generations and their exact resource; `assertStoredDcrGenerationStore` refuses stored mode without both capabilities | Realistic rolling/rollback or shared-store resource-change class demonstrated by a current→old→current application sequence. It requires write access through an older trusted binary or a deployment sharing its store across resources, not a remote attacker choosing a field. Existing access JWTs are stateless and remain valid only until their normal expiry; browser-held pre-cutover consent/flow state is a separate deployment cutover concern and is not claimed fixed by this row |
| 41 | An unauthenticated caller exhausts Hono or Express memory/CPU by making an OAuth POST parser materialize an oversized JSON, URL-encoded, or multipart body before Bridge admission control, or a server-generated consent form exceeds the approval route's cap | DoS | The Hono adapter applies the tested `hono/body-limit` middleware with a fixed 256 KiB cap before all four built-in OAuth POST handlers. The returned Express OAuth router installs its JSON and URL-encoded parsers with the same 256 KiB limit. The core bounds the other recognized DCR array, `grant_types`, to 32 entries × 256 UTF-8 bytes, so a compact, fully JSON-escaped registration with 16 maximum redirects is 245,939 bytes and reaches both adapters. Every scope carrier that can enter a consent token is bounded to 128 entries × 256 UTF-8 bytes and is snapshotted before reuse; the signer refuses output over 192 KiB, leaving form-encoding headroom under the approval cap. RFC 7591-required unknown metadata and arbitrary JSON whitespace remain subject to the raw adapter cap. A grammar precheck rejects malformed, duplicate/coalesced, conflicting, unsafe, or oversized `Content-Length`; valid declared lengths are removed from the Hono middleware-visible request so actual bytes are still stream-counted. Missing-length and transfer-encoded streams therefore cannot bypass Hono's cap. HTTP 413 is fixed and precedes parser, Bridge, limiter, store, and success-audit work. Hono stream/framing failures return a fixed direct 400 without raw-throwable logging or downstream work. Caller-owned Hono POST authorize routes, including console pairing with `skipAuthorize`, reuse the exported `honoOAuthBodyLimit` before parsing. Own-property raw-Request extensions survive reconstruction | The Hono middleware buffers a legitimate body up to 256 KiB and may read one host-sized crossing chunk without retaining or parsing it; it stops pulling but does not guarantee transport cancellation. Upload draining/timeouts and any lower limit belong to the host or reverse proxy. Prototype-only/subclass/private Request context is not copied; `clientIp` needing it must use stable Hono Context/environment data. Fastify's shipped/default parser cap remains a composition-owned sibling control. An Express application that mounts a lower parser before the OAuth router owns that lower limit. |
| 42 | A `file:` URI bypasses SQLite `0600` enforcement, or an attacker preseeds/replaces OAuth state before a custom persistent database path is opened | Tampering / Elevation / Info disclosure | `openSqliteStore` accepts only exact `:memory:` or an ordinary path; rejects non-string/blank/NUL/`file:` input; requires an existing effective-user-owned private immediate directory; opens the final path exclusively/no-follow/nonblocking where supported; validates regular-file type, UID, exact `0600`, and single link; holds the descriptor across `DatabaseSync` open; compares device/inode before any library migration/SQL read; and closes both handles on failure. SQLite sidecars inherit the private-directory boundary. [§12.4](./contracts/12-store-conformance-contract.md#124-persistent-sqlite-filesystem-admission) | Root or another process running as the same OS account remains inside the filesystem trust boundary and can race or read state. Node exposes no caller-owned descriptor constructor for `DatabaseSync`, so the private-directory rule closes the lower-privileged replacement window rather than claiming a race-free same-account open. Windows has no Node `O_NOFOLLOW`/POSIX UID-mode enforcement; deployers must use a private ACL-controlled directory. The direct `SqliteStore(DatabaseSync)` constructor is caller-owned and outside this admission guarantee. |

### Rows 5/9 — the redirect-entry grammar

[§10.0](./contracts/10-redirect-uri-policy.md#100-the-redirect-entry-grammar-one-definition-every-consumer)
defines one closed entry grammar for every consumer, checked on the raw string.

It closes a measured **parser differential**: the §10.1 allowlist, the CIMD
matcher, and the CIMD document validator gave different verdicts on `*`,
`javascript:`, empty userinfo, a bare `?`, case-folded and percent-encoded
hosts, `:443`, and dot segments.

For stored DCR (row 9) the two guards land together: registration
**REJECTS** a non-canonical `redirect_uri` and stores accepted input
byte-for-byte, while §10.2 re-validates each
registered URI **at read**, covering records written before the grammar existed
or populated out-of-band. The read guard generalizes: **every carrier that
outlives the check that admitted it re-validates on read** — the stored client
record, the CIMD registration and the opaque params in the flow cookie, the
consent token, and the authorization-code record (contracts §10.0's nine-consumer
list). A signature or a store hit proves *we issued this*, never *this is still
valid*, so a rolling upgrade cannot be a window in which pre-upgrade state
authorizes what the new grammar forbids.

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
  client. Per [§17.2](./contracts/17-v0-2-feature-contracts.md#172-client_credentials-grant-mcp-extension-iomodelcontextprotocoloauth-client-credentials):
  a request with `token_endpoint_auth_method ≠ "none"` or a `grant_types`
  containing `client_credentials` is rejected with `invalid_client_metadata`.
  Machine clients are also rejected at `/oauth/authorize`.
- **256-bit secrets.** `mcs_` + base64url(32). Stored as SHA-256 only. Shown
  once.
- **Fixed comparison count + fail-closed verify.**
  `verifyMachineClientSecret` composes into token-endpoint client auth: wrong
  secret, unknown client, and poisoned record all map to `invalid_client`, and
  the library performs two digest comparisons on every non-empty-secret path.
  This removes an active-slot comparison-count signal; it does not equalize
  lookup latency implemented by a custom `ClientStore`.
- **Stored-row binding.** `parseMachineClientRegistration` checks the complete
  persisted machine shape and requires the embedded `clientId` to equal the
  requested lookup key. It preserves the stored resource string without
  canonicalization, and authentication plus each lifecycle operation requires
  exact equality with its configured resource. A resource-less legacy row,
  blank/malformed resource, or cross-resource row is rejected before accepting
  a secret, creating a secret, mutating a record, or signing a token; token
  callers receive the same `invalid_client` result as an invalid secret. Its
  clock-relative active-secret cap permits expired history for rotation cleanup
  but rejects more than two active slots. Provisioning and rotation also reject TTL/grace
  values whose derived expiry is not a safe integer before secret generation,
  mutation, or a success audit.
- **Atomic lifecycle.** `MachineClientStore.createMachineClient` and
  `compareAndSwapMachineClient` commit the versioned row and metadata-only
  lifecycle audit in one transaction or neither. Same-version rotations have
  one CAS winner, and a conflict returns no secret. Disable atomically replaces
  the active row with a hash-free tombstone. Only resource-bearing unversioned
  rows normalize to active version 0 and move to version 1 on first mutation;
  resource-less legacy rows and partial lifecycle markers fail closed.
- **Scope caps.** Scopes are capped by per-client `allowedScopes`, fixed ⊆
  catalog at provisioning. The grant validates the resolved scope against BOTH
  the ceiling AND the live `scopeCatalog`: `invalid_scope` on any over-ceiling
  or post-narrowing-drift entry. A scope removed from the catalog after
  provisioning is never minted (matching the user-grant `normalizeScopes`
  fail-closed gate).
- **No refresh tokens.** Rotation has at most two active secrets. The published
  24-hour default is also the hard maximum; deployments can explicitly request
  a shorter overlap.

### Row 22 — group-authorization enforcement

- **GUID-only mapping keys.** Display names are boot-rejected; duplicate
  case-insensitive keys are rejected.
- **Overage ⇒ fail-closed.** Overage yields `entra_groups_overage` (no
  truncation-driven privilege leak).
- **`_claim_sources` URL never dereferenced** ([§17.4](./contracts/17-v0-2-feature-contracts.md#174-entra-group-based-authorization-gate-2-becomes-a-scope-ceiling)).
- **Ceiling intersected twice** — at `prepare` AND `approve`. Prior grants
  cannot resurrect removed-group scopes.

### Row 28 — state-dir parity

The [§17.8](./contracts/17-v0-2-feature-contracts.md#178-quickstart-secret-persistence-auto-keygen)
parity rule: every path that creates/reads the state dir — quickstart, the
example CF branch `ensureStateDir`, and the sqlite store — meets its applicable
bar. Quickstart and `ensureStateDir` own creation plus `.gitignore`; SQLite's
§12.4 boundary requires that directory to exist already, then independently
checks its provenance/mode and admits the database descriptor before use. A
control fixed in one path is swept into every sibling that touches the same
resource (the global "sweep for sibling instances" rule).

`JsonlFileAudit` is deliberately not included in that state-dir claim. It opens
an operator-configured final file path per event and has row 24's
`O_NOFOLLOW`/descriptor-regular-file control, but it neither owns nor validates
the parent directory and does not reject hard-linked regular files. That
deployment contract is explicit so a future state-dir hardening change is not
mistakenly assumed to cover arbitrary audit destinations.

Recurrence is process-disciplined, not mechanistically enforced — a future code
path added without the sweep could diverge; caught by review + the dedicated
integration round.

### Row 42 — persistent SQLite state admission

The database file and its journal/WAL sidecars form one state boundary. File
mode alone is insufficient: an attacker-writable immediate directory permits a
preseed before boot and a replacement between a path check and SQLite's own
open. An ancestor owned by another non-root account is also attacker-controlled
because its owner can chmod it before replacing the next entry. `openSqliteStore`
therefore admits the directory and an already-open file descriptor before
constructing `DatabaseSync`, then compares the path identity before library
migrations or SQL reads. It never repairs an untrusted existing object.

The remaining same-account/root race is explicit. Node's SQLite API takes a
path, not the verified descriptor, and Windows Node lacks POSIX no-follow and
UID/mode primitives. The contract does not turn those platform facts into a
false guarantee.

## Implementation gates

- No change to auth, tokens, redirect policy, the store, identity, egress, or
  the publish pipeline without updating **this file and
  [contracts](./contracts.md)**.
- No dependency install or bump without a `docs/dependency-ledger.md` recheck
  (version + publish date, ≥15 days — the 15-day gate).
- The [store-conformance suite](./contracts/12-store-conformance-contract.md#12-store-conformance-contract)
  MUST be green (memory + sqlite + mysql) before any correctness claim; any
  further downstream SQL adapter must pass the same suite.
- The end-to-end verify gate — register → authorize (identity port) → token →
  protected `/mcp` call → refresh → replay-detection (family revoked) → revoke,
  driven by the **official MCP SDK client** — must pass before a release. Green
  unit tests alone are not "done."
- **No local publishes.** npm publish is `--provenance` from GitHub Actions
  OIDC only. The workflow's read-only job builds and packs once; manual dispatch
  can only dry-run that digest-bound artifact. Only a version-matching
  `v*.*.*` tag enters the no-checkout/no-install OIDC publish job, and GitHub
  Release creation runs afterward in a separate no-OIDC `contents: write` job.
  Before tagging, the `publish` Environment must be configured as the
  independent release-tag + owner-approval gate with admin bypass disabled.
  Treat every commit as will-be-public (no secrets, no internal hostnames).
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
  unauthenticated DCR, direct header-identity authorize, token, and revocation
  endpoints can be flooded (DoS, though audit is metadata-only). Direct identity
  verification uses `authorize:<ip>` before `IdentityPort.verify`; after an
  adapter's request-body boundary, revocation uses `revoke:<ip>` before Bridge
  body normalization, token hashing, store access, revocation, or audit. The
  revocation limiter does not replace the adapter body caps: malformed or over-cap
  input can return 400/413 before it reaches Bridge. Upstream redirect, pairing,
  and CIMD retain their separate documented budgets. A reference distributed
  limiter ships at `/rate-limit/redis`
  (v0.1.2, [§17.10](./contracts/17-v0-2-feature-contracts.md#1710-distributed-ratelimitport-redisvalkey--shipped-v012)):
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
    `RateLimitPort` per [§6.7](./contracts/06-ports.md#67-ratelimitport-fix-7)); wiring
    the Redis `RateLimitPort` is the in-band DoS mitigation.
  - Performance posture: the hot path (the rate-limit check on `/oauth/register`,
    direct header-identity `/oauth/authorize`, `/oauth/token`, and `/oauth/revoke`)
    uses Redis
    `EVALSHA`, so once the script is cached only its
    hash crosses the wire (the post-restart / `SCRIPT FLUSH` path re-sends the
    body once via `EVAL`). The MySQL adapter uses the text protocol and
    per-transaction `READ COMMITTED`
    ([§12.3](./contracts/12-store-conformance-contract.md#123-reference-adapters) for the two accepted
    trade-offs).
- **CIMD (v0.2) adds an outbound-fetch SSRF surface.** `createGuardedFetcher`
  enforces the network
  [§17.1](./contracts/17-v0-2-feature-contracts.md#171-cimd--client-id-metadata-documents-the-ssrf-enforcement-contract)
  control set; `CimdResolver.resolve` and `mapCimdError` provide the anti-oracle
  boundary (row 13).
- **Upstream-flow replay detection is store-scoped, and abandoned flows are
  invisible.** The flow cookie's single-use `jti` is consumed through the store:
  behind multiple replicas with the per-process memory store, a callback replay
  is detected per instance only (the shared mysql store closes this — same class
  as consent JTIs). An initiated-but-abandoned flow leaves no server-side trace
  (the cookie simply expires) — accepted as the cost of the stateless-cookie
  decision. The `upstream:<ip>` rate-limit key bounds flow-initiation abuse, and
  every callback outcome is audited (`oauth.upstream.callback`). Bounded by the
  flow TTL (default 600 s, ≤ 3600 s, [§17.11](./contracts/17-v0-2-feature-contracts.md#1711-upstream-redirect-leg-orchestrator-locked-2026-07-06)).
- **Audit sinks are fail-open by design** (evidence, not a gate —
  [§13](./contracts/13-audit-contract.md#13-audit-contract)): an auth flow never fails because
  evidence could not be written, so sink outage = lost events, and the webhook is
  at-most-once. Deployments that need guaranteed evidence MUST layer a reliable
  transport (e.g. file + shipper) under the file sink.
- **The shipped pairing attempt limiter is per-instance.** Horizontally scaled
  pairing deployments need the
  [§17.10](./contracts/17-v0-2-feature-contracts.md#1710-distributed-ratelimitport-redisvalkey--shipped-v012)
  distributed limiter to keep the full brute-force budget. The contract-only
  device flow specifies the same residual for any future implementation; no
  device limiter or endpoint ships today.

Further accepted-by-contract residuals — group-removal lag on refresh (row 22),
machine-secret theft has no signal (row 18), and console pairing is
single-operator only (rows 21, 27) — are stated in full in their table rows.
