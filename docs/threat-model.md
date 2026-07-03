# Threat Model

> Security reasoning for `mcp-idp-bridge`. `docs/contracts.md` is the contract
> surface; **this file is the attacker-driven reasoning about why those controls
> hold and what they do not cover.** Update this document before any change to
> auth, token issuance/verification, redirect policy, the store, identity
> handling, egress, or the build/publish pipeline.
>
> Status: **v0.1** (private). Companion to `docs/contracts.md`.

## Assets

- **Signing keys** — the HS256 consent secret and the ES256 access-token private
  key. Compromise = minting arbitrary tokens.
- **OAuth state in the store** — auth-code hashes, refresh-token family/tokens,
  consent JTIs. Integrity and single-use semantics are load-bearing.
- **Subject identities** — emails / OIDs resolved from the upstream IdP.
- **Audit events** — the evidence trail (metadata-only).
- **The protected resource** — the MCP server behind `/mcp`.

## Trust boundaries

- The **bridge is the security boundary**. MCP clients (claude.ai, Claude Code,
  ChatGPT, third parties) are OUTSIDE trust; every request is authenticated and
  authorized independently. Session IDs are never auth.
- The **upstream IdP is a trusted identity source** — but its credentials/tokens
  are **data, never commands**, and are never forwarded to MCP clients (token
  passthrough is forbidden by the MCP spec). The bridge mints its own
  audience-bound tokens.
- The **store is within the bridge boundary**: `MemoryStore` is the process;
  `SqliteStore` is a local file (no network). A downstream SQL adapter (e.g. a
  MySQL-compatible one) extends the boundary to the DB network — that is the
  deployer's/host's responsibility, validated by the store-conformance suite.
- **Fetched metadata is UNTRUSTED DATA.** v0.1 does no outbound fetching. v0.2
  CIMD (Client-issued Metadata Discovery) will fetch PRM/AS-metadata from
  client-supplied URLs — that path MUST go through the SSRF-guarded `FetcherPort`
  (§6.6); its boundary exists now so v0.2 cannot add a raw `fetch`.

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
| 4 | CSRF an `approve` to mint a code | Tampering | Core `origin` check (fail-closed); single-use consent JTI; HttpOnly+Secure+SameSite=Lax consent cookie | None meaningful |
| 5 | Open-redirect / redirect_uri abuse | Spoofing / Elevation | Anchored allowlist (§10); error redirects target only validated redirect_uris | None (a redirect can only go to a §10-validated URI) |
| 6 | Token substitution across resources | Elevation | Audience fail-closed (§7.2) | None |
| 7 | PRM/metadata substitution (client-side) | Spoofing | https-only (TLS); RFC 9728 §3.3 client validates `resource` matches; bridge emits `resource`=config | MITM on non-TLS — excluded by https-only (loopback dev aside) |
| 8 | DCR flooding / audit spam | DoS | Stateless registrations are cheap + audit is metadata-only; **rate-limit hook ports (fix #7) are Phase 3** | Until fix #7, `/oauth/register` + `/oauth/token` can be hammered — DoS possible; noted for deployers |
| 9 | Stored-mode client spoofing (claim another's redirect) | Spoofing / Elevation | Registration validates each `redirect_uri` via the global allowlist (§10.1); `application_type` per-type policy blocks a web client widening via native | None (only already-trusted URIs registerable) |
| 10 | Scope escalation | Elevation | `normalizeScopes` vs catalog (unknown ⇒ reject); server-authoritative prior-scopes (derived, not client-claimed); consent shows the delta; `requireScope` at the RS | None |
| 11 | Consent replay | Tampering | Single-use consent JTI, atomic `consumeConsentJti` | None |
| 12 | Identity spoofing | Spoofing | `IdentityPort` verifies upstream credential; no/failed identity ⇒ 401 fail-closed; no passthrough | Depends on the IdP impl (Phase 3) correctly validating iss/aud/tid |
| 13 | SSRF via CIMD (v0.2) | SSRF | `FetcherPort` boundary; v0.1 fetches nothing | The v0.2 impl must enforce scheme allow-list, resolved-IP private-range check, connect-to-IP, per-hop re-validation, byte cap, timeout |
| 14 | Secrets in logs/audit | Info disclosure | Metadata-only audit; tests assert no raw secrets leak | None |
| 15 | Compromised dependency / build | Supply chain | jose-only runtime; ≥15-day pins; SHA-pinned CI; provenance publish; no postinstall/bundler | A zero-day in jose itself — minimized by single-dep + pin + age |
| 16 | Dev flag used to weaken a real host | Misconfiguration | `allowInsecureLocalhost` rejected unless loopback + loud warning | Someone tunnels a loopback dev instance out — dev-only, documented |

## Implementation gates

- No change to auth, tokens, redirect policy, the store, identity, egress, or the
  publish pipeline without updating **this document and `docs/contracts.md`**.
- No dependency install or bump without a `docs/dependency-ledger.md` recheck
  (version + publish date, ≥15 days, the 15-day gate).
- The **store-conformance suite must be green** (memory + sqlite) before any
  correctness claim; a downstream SQL adapter must pass the same suite.
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
- **Rate limiting is Phase 3 (fix #7).** Until then the unauthenticated DCR/token
  endpoints can be flooded (audit is metadata-only, but DoS is possible). Deployers
  should front the bridge with a rate-limiting proxy in the interim.
- **Single-node store is not HA** (memory is process-local; sqlite is one file).
  Documented; a SQL adapter is the scale path.
- **CIMD (v0.2) adds an outbound-fetch SSRF surface.** The `FetcherPort` boundary is
  in place to gate it; the v0.2 implementation must enforce the full SSRF control
  set before it ships.
