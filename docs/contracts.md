# Contracts

> **Contract-first.** This document is the source of truth for every port, schema,
> endpoint, token claim, and error shape in `mcp-sso`. It is written and
> reviewed **before** implementation code, and it MUST be updated before any change
> to a port, schema, or error shape. `docs/threat-model.md` reasons about this
> surface; `docs/dependency-ledger.md` records the pins. If code and this document
> disagree, this document wins until one of them is deliberately changed.
>
> Status: **v0.1 shipped** (`mcp-sso@0.1.1` on npm) + **v0.2 contracts locked
> 2026-07-04 (§17, pre-implementation)**. Spec conformance target: **MCP
> Authorization 2025-11-25** (the stable spec clients implement), with the
> **2026-07-28 RC** hardening items built in now because all are
> backward-compatible additions.

## Contents

1. [Purpose & scope](#1-purpose--scope)
2. [The two roles](#2-the-two-roles)
3. [Normative references](#3-normative-references)
4. [Design principles](#4-design-principles)
5. [Configuration contract](#5-configuration-contract)
6. [Ports](#6-ports)
7. [Crypto & token contracts](#7-crypto--token-contracts)
8. [Resource-server verifier contract](#8-resource-server-verifier-contract)
9. [AS-lite bridge contract](#9-as-lite-bridge-contract)
10. [Redirect-URI policy](#10-redirect-uri-policy)
11. [Scope contract](#11-scope-contract)
12. [Store-conformance contract](#12-store-conformance-contract)
13. [Audit contract](#13-audit-contract)
14. [Error catalog](#14-error-catalog)
15. [Package & export map](#15-package--export-map)
16. [Spec-conformance matrix](#16-spec-conformance-matrix)
17. [v0.2 feature contracts (locked 2026-07-04)](#17-v02-feature-contracts-locked-2026-07-04)
18. [Contract-change protocol](#18-contract-change-protocol)

---

## 1. Purpose & scope

`mcp-sso` is a spec-correct **OAuth 2.1 layer for remote MCP servers** with
two halves, in one framework-free core:

- a **resource-server verifier** — RFC 9728 Protected Resource Metadata (PRM),
  `WWW-Authenticate` challenges, fail-closed audience validation, scope step-up; and
- a small **AS-lite bridge** — RFC 7591 Dynamic Client Registration (DCR),
  authorization-code + PKCE S256, consent, refresh rotation with replay detection,
  revocation, JWKS, and RFC 8414/9728 metadata.

The bridge mints its **own audience-bound tokens**. An upstream identity provider
(Cloudflare Access, Microsoft Entra ID, any OIDC) stays the identity source behind
a pluggable `IdentityPort`; **upstream identity credentials never pass through to
MCP clients and are never forwarded** (token passthrough is forbidden by the MCP
spec).

**v0.1 includes:** the framework-free verifier + bridge core, the store port with
memory + sqlite + mysql reference adapters and a shared conformance suite, and the
identity-port boundary.

**v0.1 does NOT include:** multi-tenant/SaaS, UI beyond the consent page,
generic-OIDC-provider ambitions (`GenericOidcIdentity` — Cloudflare Access and
Entra are the only concrete identity ports today), token introspection, or the
CIMD implementation (its port boundary is defined now; impl is v0.2). Framework
adapters (`/fastify` `/express` `/hono`), the Cloudflare Access/Entra identity
ports, and a runnable example were originally Phase 3/4 scope and have since
shipped — see §16 for the current conformance matrix and `docs/threat-model.md`
for the boundary.

**v0.2 contracts are locked in §17** (CIMD, `client_credentials`, device flow,
Entra group authorization, console pairing, generic OIDC + GitHub/Google,
audit sinks, quickstart secret persistence). Written 2026-07-04, before any
implementation, per the contract-first house rule. Nothing in §17 is shipped
until §16 says so.

## 2. The two roles

The library plays two OAuth roles against a **single shared configuration**:

| Role | Owns | Endpoints | Tokens |
|---|---|---|---|
| **Resource Server (RS)** | `/mcp` protection, PRM (RFC 9728), 401 challenge, 403 step-up | served by the host app at its resource origin | **verifies** access tokens (audience = resource) |
| **AS-lite bridge (AS)** | DCR, authorize/approve, token, refresh, revoke, JWKS, AS metadata (RFC 8414) | served by the host app at its issuer origin | **mints** access + refresh tokens |

Both halves are framework-free use-cases in the core. A framework adapter
(Phase 3) wires them to HTTP. The split matters because the RS challenge and
audience fail-closed logic must be testable without a framework, and because the
PRM is published at the **resource** origin while the AS metadata is published at
the **issuer** origin (these may be different hosts).

## 3. Normative references

- **RFC 9728** — OAuth 2.0 Protected Resource Metadata (PRM). Discovery at
  `/.well-known/oauth-protected-resource`; `WWW-Authenticate: Bearer
  resource_metadata="<url>"` (§5).
- **RFC 8414** — OAuth 2.0 Authorization Server Metadata.
- **RFC 7591** — OAuth 2.0 Dynamic Client Registration Protocol (DCR).
- **RFC 7636** — PKCE, `S256` method.
- **RFC 6749** — OAuth 2.0 authorization-code + refresh grants; §4.1.2.1
  **error-redirect semantics** (post-validation errors redirect to
  `redirect_uri?error=…&state=…`; pre-validation errors never do) and §6 refresh
  client-binding.
- **RFC 7009** — Token revocation; the endpoint always returns 200 and treats an
  unknown token as a no-op.
- **RFC 6750** — Bearer token use; `scope`/`error` in `WWW-Authenticate`.
- **RFC 8707** — Resource Indicators; **audience is fail-closed** (a token
  without a matching `aud` is rejected).
- **RFC 8252** — Native apps; loopback redirect any-port rule (§7.3).
- **RFC 9207** — `iss` parameter in the authorization response (RC: also
  advertise `authorization_response_iss_parameter_supported: true`).
- **MCP Authorization 2025-11-25** — the conformance target clients implement.

## 4. Design principles

- **Proven core behind generic ports.** The verifier + bridge logic is
  battle-tested OAuth, extracted behind framework-free ports so any host or
  adapter can use it without coupling to a specific framework or database.
- **`StorePort` is the parity boundary.** The in-tree memory, sqlite, and mysql
  adapters (and **any further downstream SQL adapter**) must all satisfy the §12 invariants — that
  is exactly what fix #3 (documented rotation backfill) makes possible. Parity is
  asserted by the shared conformance suite, not by copying code.
- **Identity is pluggable.** The core never depends on a specific IdP; an
  `IdentityPort` (§6.5) resolves the verified subject. Concrete implementations
  (Cloudflare Access, Entra) shipped in Phase 3.
- **Fail-closed everywhere.** Ambiguous config, a missing identity, an unknown
  audience, or a replayed token is a hard failure, never a degraded default.

> The library defines only the contract surface above and the reference adapters.
> It does **not** name or depend on any particular database, host, or downstream
> consumer; a production deployment story belongs in the README, not here.

## 5. Configuration contract

All runtime behavior derives from a validated `BridgeConfig`. **Configuration is
fail-closed**: ambiguous, incomplete, or insecure configuration is a boot
`AuthConfigError`, never a degraded default. There is intentionally **no
unauthenticated/local-bypass flavor** (Captatum's `local-binary` bypass is
dropped — this is a library that enforces real auth everywhere it is used).

```ts
interface BridgeConfig {
  // --- identities (both REQUIRED, validated) ---
  issuer: string;            // AS issuer URL, e.g. "https://auth.example.com"
  resource: string;          // RS resource URL, e.g. "https://api.example.com/mcp"

  // --- signing material (REQUIRED, validated for shape + strength) ---
  consentSigningSecret: string;   // >=32 chars; HS256 for consent tokens
  signingPrivateJwk: JWK;         // EC P-256 (crv "P-256") private key with d,x,y
  signingKeyId?: string;          // optional; else derived from the JWK kid

  // --- redirect policy (stateless-DCR backstop; see §10) ---
  redirectAllowlist: string[];    // ADDS to the built-in MCP-client defaults

  // --- scope contract (see §11); REQUIRED, fail-closed ---
  scopeCatalog: string[];         // the complete set of scopes this resource honors
  defaultScopes: string[];        // granted when a request omits scope; MUST be ⊆ catalog

  // --- CSRF/Origin policy for the consent approve step (see §9) ---
  allowedOrigins: string[];       // same-origin issuer + any explicitly allowed origins

  // --- DCR mode (fix #4; see §9) ---
  dcr:
    | { mode: "stateless" }
    | { mode: "stored"; store: ClientStore };

  // --- local-dev escape hatch (see boot validation below) ---
  dev?: { allowInsecureLocalhost: boolean };

  // --- TTLs (seconds); each MUST be a positive integer ---
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  consentTokenTtlSeconds: number;
  authorizationCodeTtlSeconds: number;
}
```

**Boot validation (all throw `AuthConfigError`, never warn):**

- `issuer` and `resource` are absolute `https://` URLs (the bridge does not run
  over plain http in production). Their **origins** are computed once and reused.
  **Local-dev escape hatch:** `dev.allowInsecureLocalhost` permits `http://`
  `issuer`/`resource` **only on loopback** (`localhost`/`127.0.0.1`/`[::1]`); it is
  rejected at boot if either origin is not loopback and it emits a loud warning.
  This exists for the Phase 4 local example (Claude Code expects `http://localhost`);
  it can never weaken a real (non-loopback) deployment. Deployers who want zero http
  anywhere can use a tunnel (cloudflared / mkcert) instead — no flag required.
- `consentSigningSecret.trim().length >= 32`.
- `signingPrivateJwk` parses to an EC P-256 key with `d`, `x`, `y` present. (jose
  rejects zero-length keys; we validate shape explicitly so a misconfigured boot
  fails closed independent of jose upgrades.)
- `defaultScopes ⊆ scopeCatalog` and `scopeCatalog` is non-empty. An empty
  catalog means the resource honors no scopes and every authorize fails closed —
  the deployer MUST declare scopes explicitly.
- Every TTL is a positive integer.
- `dcr.mode` is `"stateless"` or `"stored"`; stored mode requires a `ClientStore`.

A config object is constructed via `createBridgeConfig(input)` (validates +
freezes). The frozen object is the only thing passed to use-cases.

## 6. Ports

DDD-lite: pure core (use-cases + ports, no infra imports) and adapters at the
edge. Every external capability is a port so the core is testable in isolation.

### 6.1 `ClockPort`
```ts
interface ClockPort { nowMs(): number; }
```
Core use-cases never call ambient wall-clock APIs; tests and audit provenance need
deterministic time. Reference: `SystemClock` (wraps `Date.now()`).

### 6.2 `AuditPort`
```ts
interface AuditPort { writeAuthEvent(event: AuthAuditEvent): Promise<void>; }
```
Append-only, metadata-only (see §13). `noopAudit` is the test/local default.
v0.2 ships three reference sinks (§17.7, exported from the main entry — no
subpath/peer dep): `JsonlFileAudit(filePath)`, `WebhookAudit(url, opts)`, and
`combineAudit(...sinks)`. All three are **fail-open**: `writeAuthEvent` never
rejects, so an audit-write failure never blocks the auth operation (the use-cases
`await` it with no try/catch). Tool-call auditing is the host app's concern, not
this library's.

### 6.3 `StorePort` (the conformance boundary — see §12)
Stores auth-code records, refresh-token families/tokens, and single-use consent
JTIs — **all secrets stored only as SHA-256 hashes**; there is **no separate grant
table** (prior grants are derived from active refresh-token records — §9.3).
Methods: `saveAuthCode`, `consumeAuthCode`, `saveRefreshToken`, `rotateRefreshToken`,
`revokeRefreshTokenFamily`, `findRefreshToken`, `consumeConsentJti`,
`findGrantedScopes`, `sweepExpired`, `close`. Full shapes in §12.
(`findGrantedScopes` is invoked only in **stored-DCR mode** — §9.3: in stateless
mode client_ids are ephemeral and unverified, so a grant keyed by
`(subject, clientId)` is semantically meaningless; stateless authorizations stand
alone.)

### 6.4 `ClientStore` (stored-DCR mode only — fix #4)
```ts
interface ClientRegistration {
  clientId: string;
  redirectUris: string[];
  applicationType: "native" | "web";   // RC item (b)
  issuedAtEpoch: number;
}
interface ClientStore {
  save(client: ClientRegistration): Promise<void>;
  find(clientId: string): Promise<ClientRegistration | null>;
}
```
Required only when `dcr.mode === "stored"`. Reference: in-memory map (Phase 2);
a persisted adapter is deployment-specific. `applicationType` drives the
per-client redirect policy (§10).

### 6.5 `IdentityPort` (boundary defined at Phase 2; Cloudflare Access + Entra implementations shipped at Phase 3)
Resolves a **verified subject** from an inbound authorize request. The core's
`authorize` use-case takes a required `subject: string`; the adapter/composition
root calls an `IdentityPort` to obtain it (or fails closed). Implementations:
- **CloudflareAccessIdentity** — verifies `Cf-Access-Jwt-Assertion` (RS256 against
  CF JWKS, aud/iss checked), subject = verified email.
- **EntraIdentity** — upstream OIDC auth-code+PKCE against Entra v2.0; ONE app
  registration for the bridge; validate iss/aud/tid; map oid/email → subject. The
  bridge then issues its OWN audience-bound tokens (no passthrough).

`GenericOidcIdentity`, the Google preset, the dedicated GitHub port, and the
console-pairing port are v0.2 scope — contracts locked in §17.5–§17.6.
Cloudflare Access and Entra's concrete shapes were fixed in Phase 3; the
boundary itself was stated at Phase 2 so the core never depends on a specific
IdP. The v0.2 group-authorization extension (`IdentityClaims.allowedScopes`
scope ceiling) is locked in §17.4.

**Identity-port hardening (addenda 11–12, binding on the Phase 3 implementations):**
- **Trust roots MUST be `https`.** A port's JWKS certs URL and issuer MUST be
  `https://` — http JWKS lets a MITM substitute signing keys = total auth bypass.
  Validate with a **raw `^https://` prefix check BEFORE `new URL()`** (Node's lenient
  URL parser normalizes `https:/host` into a valid-looking URL). Applies to
  CloudflareAccessIdentity and EntraIdentity.
- **Optional subject allowlist (defense-in-depth).** A port MAY accept a
  case-insensitive, trimmed subject/email allowlist; empty ⇒ delegate entirely to
  the IdP's own policy (e.g. Cloudflare Access Zero Trust). Never the sole gate.
- **Unit-testable claim validation.** Export the claim-validation logic as a pure
  function so it is unit-testable WITHOUT the JWKS network fetch.
- **Entra multi-tenant.** When `allowedTenantIds` is set, `tid` must be allowlisted
  AND `iss` must equal `entraIssuer(payload.tid)` (the standard Entra multi-tenant
  issuer pattern). Unset ⇒ single-tenant: `iss` must equal `entraIssuer(config.tenantId)`.
- **Entra nonce.** Pass a `nonce` in `getAuthorizationUrl` and validate `payload.nonce`
  on return (OIDC request binding) — recommended.
- **Entra subject allowlist.** Matches the immutable `oid` by default; matching the
  mutable preferred_username/email requires `allowMutableClaims` (Microsoft warns
  against using those claims for authorization).

### 6.6 `FetcherPort` (boundary now; CIMD impl v0.2)
```ts
interface FetcherPort { fetch(url: string, init?: FetchInit): Promise<FetchResult>; }
```
Reserved for v0.2 Client ID Metadata Documents. **Any metadata fetch MUST go
through an SSRF-guarded `FetcherPort`.** v0.1 does no outbound fetching; the
boundary exists so v0.2 cannot accidentally add a raw `fetch`. The full
enforcement contract — URL admission, the complete IANA IPv4/IPv6 blocklists,
DNS pinning, redirect refusal, byte/timeout caps, document validation — is
locked in **§17.1**.

### 6.7 `RateLimitPort` *(fix #7)*
```ts
interface RateLimitPort { check(key: string): Promise<boolean>; }
const noopRateLimit: RateLimitPort = { async check(): Promise<boolean> { return true; } };
```
Optional DoS defense for the unauthenticated `/oauth/register` + `/oauth/token`
endpoints (threat-model #8). The adapter calls `check("register:<ip>")` /
`check("token:<ip>")` before the use-case; `false` ⇒ **429 Too Many Requests**.
The default `noopRateLimit` allows everything (rate-limiting is advisory, not a
hard gate). A thrown error is treated as **fail-open** (allow) — a rate-limiter
outage must not lock out all auth; this is defense-in-depth, not a security boundary.
**`req.ip` behind a proxy:** the adapter keys on the framework's `req.ip`, which
behind a reverse proxy/tunnel is the proxy's address, not the client's. The
composition root MUST configure the framework to trust the proxy hop
(`trustProxy`/`trust proxy`) so `req.ip` is the real client — otherwise all proxied
traffic is attributed to one IP and the limiter is ineffective.

## 7. Crypto & token contracts

All signing goes through `jose` (the only runtime dep). **Algorithm pinning is
non-negotiable**: consent tokens are HS256, access tokens are ES256 (EC P-256),
and verifiers pin the algorithm set so a `none`-alg or key-confusion token is
rejected. Consent and access keys are **separate** (the consent secret never
validates an access token and vice-versa).

### 7.1 Consent token (HS256, single-use)
Short-lived JWT binding one authorize request to a single approval. Claims:
`iss`=issuer, `aud`=`"mcp-sso/consent"`, `sub`=verified subject,
`client_id`, `redirect_uri`, `resource`, `scope` (space-joined), `code_challenge`,
`code_challenge_method`=`"S256"`, `state`?, `jti` (random, single-use), `iat`,
`exp`. Verified with `algorithms: ["HS256"]`, pinned iss+aud, clock from
`ClockPort`. **Single-use:** the `jti` is consumed atomically on approve (§12
`consumeConsentJti`); a replay is rejected with `invalid_grant`.

### 7.2 Access token (ES256, audience-bound, fail-closed)
```ts
interface AccessTokenClaims { subject: string; clientId: string; scopes: string[]; }
```
JWT: header `{alg:"ES256", kid, typ:"JWT"}`, payload `client_id`, `scope`,
`sub`, `iss`=issuer, `aud`=**resource** (RFC 8707 audience binding), `iat`, `exp`.
Verified with `algorithms: ["ES256"]`, pinned iss + **aud=resource**
(fail-closed: a token whose `aud` ≠ resource is `invalid_token`, never accepted),
clock from `ClockPort`.

**Fix #6 — cached verification key:** the public JWK is imported to an ES256 key
**once** (memoized on the config) rather than per request, as the source does.
`verifyAccessToken` reuses the cached `CryptoKey`.

### 7.3 Authorization code (hashed, single-use)
Format `ac_<base64url(32 random bytes)>`. Stored only as `sha256(code)`.
Single-use: `consumeAuthCode` deletes on read; missing or expired → `invalid_grant`.
A failed PKCE or client/redirect mismatch **still consumes the code** (one-shot).

### 7.4 Refresh token (family, rotation, replay detection)
Format `rt.<familyId>.<base64url(32 random bytes)>`. `familyId` is a random
per-issuance id parseable from the token (so rotation knows which family to
rotate without a lookup). Stored only as `sha256(token)`.
- **Rotation:** `rotateRefreshToken(tokenHash, next, now)` marks the current
  token consumed, inserts the next, and returns the **consumed** record. Replay of
  an already-consumed token revokes the whole family.
- **Client binding (RFC 6749 §6):** the refresh grant MUST present a `client_id`
  matching the stored record; a mismatch revokes the family (theft signal).
- **Revocation:** `revoke` looks up the family by hash (rejecting unknown tokens
  harmlessly) and revokes the family.

### 7.5 PKCE S256 (timing-safe)
`verifyPkceS256(verifier, challenge)` rejects malformed inputs outright (verifier
must be 43–128 unreserved chars; challenge must be 43 base64url chars), then
compares `base64url(sha256(verifier))` to the stored challenge with
`timingSafeEqual`. A 1-char verifier can never match a stored challenge.

## 8. Resource-server verifier contract

The RS half. Framework-free; testable without any HTTP server.

### 8.1 `verifyAccessToken(token, config, clock?) → VerifiedAccessToken`
As §7.2. Throws `OAuthError("invalid_token", …, 401)` on any failure.

### 8.2 `buildUnauthorizedChallenge(config, opts?) → string`  *(fix #1)*
Returns the exact `WWW-Authenticate` value for a 401. The source's bug was a bare
`Bearer`; the fix emits the RFC 9728 `resource_metadata` URL plus the supported
`scope` (and optional `error`/`error_description`):
```
Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource", scope="mcp:read mcp:write", error="invalid_token", error_description="Bearer token is invalid"
```
- `resource_metadata` = the **PRM URL at the resource origin** (root form; the
  path-inserted form is also served — §9). Quoted per RFC 7235.
- `scope` = space-joined `scopeCatalog` (tells the client what it may request).
- `error`/`error_description` included when the rejection reason is known
  (`invalid_token`, `invalid_request`, `insufficient_scope`).

### 8.3 `requireScope(auth, required) → void`  (403 step-up)
Throws `OAuthError("insufficient_scope", …, 403)` if the verified subject lacks
the scope. The adapter emits a 403 whose `WWW-Authenticate` carries the same
`resource_metadata` + `scope` + `error="insufficient_scope"` so the client can
step up and re-authorize for the missing scope.

### 8.4 `RequestAuthorizer`
```ts
class RequestAuthorizer {
  constructor(deps: { config: BridgeConfig; clock: ClockPort; audit: AuditPort; });
  authorize(input: { authorization?: string | string[]; requiredScope?: string; }): Promise<{ subject: string; clientId: string; scopes: string[]; }>;
}
```
Extracts the bearer token, verifies it, enforces `requiredScope` if given, audits
the outcome, and rethrows `OAuthError` on failure. The adapter maps the thrown
`OAuthError` to a 401/403 with the challenge from §8.2/§8.3. **No bypass path.**

## 9. AS-lite bridge contract

The AS half. Each item is a framework-free use-case or pure metadata builder; an
adapter (Phase 3) exposes them over HTTP.

### 9.1 Metadata (RFC 8414 / RFC 9728)
- **`authorizationServerMetadata(config)`** (RFC 8414), served at
  `${issuer}/.well-known/oauth-authorization-server`. Emits `issuer`,
  `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `registration_endpoint`,
  `revocation_endpoint`, `response_types_supported: ["code"]`,
  `grant_types_supported: ["authorization_code","refresh_token"]`,
  `code_challenge_methods_supported: ["S256"]`, `scopes_supported: catalog`,
  `token_endpoint_auth_methods_supported: ["none"]` (public clients + PKCE), and
  **`authorization_response_iss_parameter_supported: true`** *(RC item (a))*.
- **`protectedResourceMetadata(config)`** (RFC 9728), served at **both**:
  - `${resourceOrigin}/.well-known/oauth-protected-resource` (root), and
  - `${resourceOrigin}/.well-known/oauth-protected-resource${resourcePath}`
    (path-inserted — *fix #2*; RFC 9728 §3.1 constructs the URL by appending the
    resource path, so a strict client that builds the URL itself finds it).

  Identical JSON at both paths. Emits `resource` (= the configured resource URL),
  `authorization_servers: [issuer]`, `scopes_supported: catalog`. (**No
  `jwks_uri` here:** in RFC 9728 the PRM `jwks_uri` is the *resource server's*
  own key set, not the AS's token-signing keys — placing the AS JWKS there is a
  spec misuse. The AS signing keys are advertised via the AS metadata `jwks_uri`
  above.)
- **JWKS** at `${issuer}/oauth/jwks`: `{ keys: [publicJwk(config)] }` (ES256
  public key, with `cache-control: public, max-age=60`).

### 9.2 DCR — `registerClient` (RFC 7591) *(fix #4; RC item (b))*
`POST /oauth/register` with form fields `redirect_uris` (required, each validated)
and optional `application_type` (`"native"` | `"web"`, default `"web"`).
- **Stateless mode (default):** any well-formed registration with allowlisted
  redirect URIs succeeds; the server mints an ephemeral `client_id`
  (`mcpdc_<random>`), returns `{ client_id, client_id_issued_at, redirect_uris,
  token_endpoint_auth_method: "none" }`, and persists nothing. At authorize, any
  non-empty `client_id` is accepted (matches the source). **Redirect policy = the
  global allowlist with the blanket loopback-for-everyone default, by design**
  (§10.1) — stateless mode persists no client metadata, so per-client redirect
  policies cannot apply.
- **Stored mode (opt-in):** at **registration time** each `redirect_uri` is
  validated through the **global allowlist (§10.1: built-ins + config)** and then
  recorded verbatim on the `ClientRegistration` (with `applicationType`, default
  `"web"`). At **authorize/token time** the `client_id` MUST exist in the store and
  the presented `redirect_uri` MUST match that client's **per-type policy (§10.2)**
  — native ⇒ RFC 8252 loopback any-port, web ⇒ https exact. This is the RC-aligned
  path: native and web clients get the right redirect handling by type, instead of
  loopback-for-everyone.

### 9.3 Authorize + consent

**Validation order & error channels (RFC 6749 §4.1.2.1).** The authorize flow has
two error channels, split by whether the `redirect_uri` is trusted yet:

- **Direct HTTP error (NEVER redirect)** — pre-validation failures where the
  redirect destination is untrusted: identity not resolved/rejected (the resource
  owner could not be authenticated), missing `client_id`, and `redirect_uri`
  failing §10. Also, at `approve`: a CSRF/`origin` failure (`invalid_origin`) and
  consent-token integrity failures (replay/invalid/expired). These throw
  `OAuthError`; the adapter answers a direct 4xx with the §9.5 body (no `Location`).
- **Redirect to `redirect_uri?error=<code>[&state=…][&error_description=…]`** —
  every error discovered **after** `client_id` + `redirect_uri` validate:
  `unsupported_response_type`, `invalid_target`, `invalid_scope`, `invalid_request`
  (bad PKCE params), `access_denied` (the user clicked Deny), and `server_error`.
  The core provides `buildErrorRedirect(redirectUri, code, state, description?)`;
  the use-case tags these errors with the validated `redirectUri` + `state` so the
  adapter answers 302. (This is what lets claude.ai render "you declined" instead
  of a dead JSON page. The source never implemented error redirects; this completes
  fix #5.)

**`prepare({ clientId, redirectUri, responseType, codeChallenge,
codeChallengeMethod, resource?, scope?, state?, subject })`** → `PreparedConsent`:
1. `subject` REQUIRED (the adapter/`IdentityPort` resolves it before calling
   `prepare`). No subject ⇒ `access_denied` 401 **direct**, never a placeholder.
2. `client_id` present and `redirect_uri` valid per §10 — else **direct**
   (pre-validation).
3. *(redirect-eligible from here)* `response_type=code`; `resource` **defaults to
   `config.resource` when omitted and MUST equal `config.resource` when present**
   (else `invalid_target`); `scope` normalized per §11 (else `invalid_scope`);
   PKCE `code_challenge_method=S256` + challenge present (else `invalid_request`).
4. **Scope accumulation *(RC item (c)) — stored-DCR mode only.*** Load
   `priorScopes = findGrantedScopes(subject, clientId, now)` (the union of scopes
   on this `(subject, clientId)`'s active refresh tokens). In **stateless mode**
   `priorScopes = []` — client_ids are ephemeral/unverified, so a grant keyed by
   them is meaningless; stateless authorizations stand alone.
5. Sign the consent token (§7.1), audit, and return
   `{ consentToken, …claims, priorScopes, requestedScopes }`. The consent page
   renders the **delta** = `requestedScopes − priorScopes` as "new" (rendering is
   an adapter concern, Phase 3; the core supplies both sets).

**`approve({ consentToken, approved?, origin? })`** → `{ redirectTo, code?, state? }`:
- **CSRF/`origin`** must be the issuer origin or in `allowedOrigins` — else
  `invalid_origin` 403 **direct** (a foreign origin is never redirected anywhere).
- **`approved === false` ⇒ Deny:** the consent token is **not** consumed; redirect
  to `redirect_uri?error=access_denied&state=…` (the user declined). *(Fix #5 —
  the source's unreachable Deny path; the UI button is Phase 3.)*
- Otherwise verify the consent token and **consume its single-use `jti`** (replay ⇒
  `invalid_grant` **direct** — an integrity failure, not a user-facing denial).
- **Mint the code with the accumulated scopes** — in stored mode the union of
  `requestedScopes + priorScopes`; in stateless mode exactly the requested scopes.
  Then 302 to `redirect_uri?code=…&iss=<issuer>[&state=…]` (RFC 9207 `iss`,
  RC item (a)).

### 9.4 Token
`POST /oauth/token`, `cache-control: no-store`. Response:
`{ access_token, token_type: "Bearer", expires_in, refresh_token, scope }`.
*(This is the USER-grant shape. The v0.2 `client_credentials` grant returns a
machine shape with no `refresh_token` member — the response type splits when
§17.2 ships.)*
- **`exchangeAuthorizationCode`**: consumes the code (§7.3), verifies PKCE S256
  and client/redirect binding, mints an ES256 access token (§7.2) + a refresh
  token (§7.4, new family).
- **`refresh`**: rotates the refresh token (§7.4); enforces RFC 6749 §6 client
  binding (mismatch ⇒ family revoked ⇒ `invalid_grant`); mints a new access token
  carrying the rotated record's scopes.
- **`revoke`** (RFC 7009): **always returns 200**; an unknown or already-revoked
  token is a **no-op** (never 4xx — RFC 7009 §2.2 forbids leaking token existence
  via the response). Looks up the family by hash and revokes it; a guessed family
  id revokes nothing.

### 9.5 Error bodies
**Raw OAuth endpoints** (token / register / revoke, and direct authorize errors)
use the RFC 6749 §5.2 / RFC 7591 §3.3 / RFC 7009 §2.2.1 shape — a top-level ASCII
`error` string plus an optional `error_description` string:
`oauthErrorBody(error)` → `{ error: error.code, error_description: error.message }`.
This string form is REQUIRED for interoperability: a standard client (and the
official MCP SDK, whose `OAuthErrorResponseSchema` requires `error` to be a string)
reads `body.error === "invalid_grant"` to drive recovery — drop the token and
re-authorize — so replay/expiry/PKCE/client-binding failures must surface as a
top-level string, NOT the `{error:{code,message}}` JSON-RPC inner-envelope shape.

The **JSON-RPC `/mcp` surface** uses a separate envelope (built by the framework
adapter, Phase 3): `{ jsonrpc:"2.0", error:{ code:-32001, message:"<oauth-code>:
<message>" }, id:null }`, with the `WWW-Authenticate` challenge on 401 (§8.2).

### 9.6 Framework adapters *(Phase 3 — thin wiring)*
The `/fastify`, `/express`, `/hono` adapters are **thin**: all logic stays in the
core use-cases; an adapter only parses the request, calls the use-case, and shapes
the response. Wiring rules:
- **Endpoints:** GET `/.well-known/oauth-authorization-server` →
  `authorizationServerMetadata`; GET `/.well-known/oauth-protected-resource` AND
  its path-inserted form → `protectedResourceMetadata` (§9.1); GET `/oauth/jwks` →
  `jwks`; POST `/oauth/register` → `registerClient` (behind `RateLimitPort`,
  §6.7); GET `/oauth/authorize` → resolve subject via `IdentityPort` → `prepare`,
  render the consent page; POST `/oauth/authorize/approve` → `approve`; POST
  `/oauth/token` → `exchangeAuthorizationCode`/`refresh` (behind `RateLimitPort`);
  POST `/oauth/revoke` → `revoke` (always 200).
- **Error → response:** an `OAuthError` with `.redirect` ⇒ **302** to the tagged
  `redirect_uri?error=…`; otherwise direct — status `error.status`, body
  `oauthErrorBody(error)` (§9.5). On the protected `/mcp` surface, 401/403 set the
  `WWW-Authenticate` challenge from `buildUnauthorizedChallenge` (§8.2/§8.3).
- **Consent page *(fix #5)*:** GET `/oauth/authorize` success renders an HTML page
  with **Approve AND Deny** buttons; Deny POSTs `approved=false`, which the core
  redirects as `access_denied` (§9.3). CSP `default-src 'none'; style-src
  'unsafe-inline'`, `X-Content-Type-Options: nosniff`, all values HTML-escaped.
- Framework adapters are optional `peerDependencies` (`fastify`/`express`/`hono`);
  anything added to `devDependencies` for testing gets a `dependency-ledger` entry
  with the 15-day check.

## 10. Redirect-URI policy

Two policies, by DCR mode. Both share the core rule: **no allow-all (`"*"`), no
unanchored prefix, userinfo rejected, hash stripped.** Shared built-in defaults
for MCP clients (these ADD to any config allowlist; a config cannot remove them):

```
https://claude.ai        // Claude (web) custom connectors
https://chatgpt.com      // ChatGPT custom connectors
http://localhost         // native MCP clients — any port (RFC 8252 §7.3)
http://127.0.0.1         // numeric loopback variant
```

### 10.1 Global allowlist (stateless-DCR mode) — `assertAllowedRedirectUri`
An entry matches if it is the exact redirect_uri, the exact ORIGIN
(`scheme://host[:port]`, no path) of the redirect_uri, or a **loopback origin**
(`localhost`/`127.0.0.1`/`[::1]`, same scheme, any port). A loopback entry
widens to any port only if it is an origin-only entry with no explicit port/path;
a port-scoped or path-specific loopback entry is NOT widened. Returns the
normalized URI.

### 10.2 Per-client policy (stored-DCR) — RC item (b)
At authorize/token in stored mode, the client's registered `applicationType`
selects the rule:
- **`native`** → RFC 8252: loopback (`localhost`/`127.0.0.1`/`[::1]`) on **any**
  port accepted; the presented `redirect_uri` must match a registered loopback
  origin. (Lets CLI/desktop clients use ephemeral ports.)
- **`web`** → `https` only, and the presented `redirect_uri` must **exactly** equal
  a registered URI (no port widening, no origin wildcard).

This replaces the source's blanket loopback-for-everyone default in stored mode.

## 11. Scope contract

- `scopeCatalog` (config, required) is the complete set this resource honors.
- `normalizeScopes(scope?, catalog)` → validates each requested scope against the
  catalog (unknown ⇒ `invalid_scope`), de-dupes, and falls back to
  `defaultScopes` when none requested. Returns the validated list.
- `scopeString(scopes)` → sorted, space-joined (stable token `scope` values).
- `requireScope(auth, required)` → 403 `insufficient_scope` step-up (§8.3).
- **Accumulation *(RC item (c)) — stored-DCR mode only.*** Re-authorization unions
  the requested scopes with those derived from this `(subject, clientId)`'s active
  refresh-token records (§9.3) — **no grant store**. In stateless mode there is no
  accumulation (client_ids are ephemeral). Consent UI shows the **delta** (new
  scopes only); rendering is an adapter concern (Phase 3), the core supplies the
  before/after sets.

## 12. Store-conformance contract

Every `StorePort` implementation MUST satisfy these invariants — the
`store-conformance` suite asserts them against **both** `MemoryStore` and
`SqliteStore`, and `MysqlStore`, and any further downstream SQL adapter must pass the same suite. **Fix #3**
documents the one contract the source left implicit.

### 12.1 Records (secrets are SHA-256 hex digests; timestamps are UTC ISO 8601 with EXACTLY 3 ms digits)
```ts
interface AuthCodeRecord {
  codeHash: string; clientId: string; subject: string; redirectUri: string;
  resource: string; scopes: string[]; codeChallenge: string;
  codeChallengeMethod: "S256"; expiresAt: string;
}
interface RefreshTokenRecord {
  tokenHash: string; familyId: string; previousTokenHash: string | null;
  clientId: string; subject: string; scopes: string[]; expiresAt: string;
}
interface SaveAuthCodeInput { /* AuthCodeRecord minus codeHash-as-source */ }
interface SaveRefreshTokenInput {
  tokenHash: string; familyId: string; previousTokenHash: string | null;
  clientId: string; subject: string; scopes: string[]; expiresAt: string;
}
```
Inputs are validated: `assertSha256Hex` for every hash; `assertUtcIsoTimestamp`
for every timestamp — which **requires exactly 3 millisecond digits** (e.g.
`2026-07-03T13:00:00.000Z`), rejecting both no-ms and ≠3-digit forms. Rationale:
stores compare expiry strings **lexicographically** (SQLite `TEXT` / in-memory
string compare), and mixed precision inverts ordering (`"...00Z"` sorts after
`"...00.500Z"`, flipping an expired token to valid). `codeChallengeMethod ===
"S256"`; on rotation `next.previousTokenHash === tokenHash`. **`consumeConsentJti`
validates its `expiresAtIso` too** (addendum 10 — a known gap in the source, where
`jti` rows were written with an unvalidated timestamp; the library closes it).

### 12.2 Invariants the suite asserts
1. **Hashed, single-use auth codes:** `consumeAuthCode` deletes on read; a second
   consume returns `null`; an expired code returns `null`; raw codes never appear
   in storage. SQLite asserts the on-disk file contains no raw secret and has no
   content/body/cache tables (state is OAuth-only).
2. **Consent JTI single-use:** `consumeConsentJti` returns `true` once, `false` on
   replay (atomic insert-or-ignore). It also **rejects a `expiresAtIso` that is not
   a 3-ms UTC timestamp** (addendum 10 — the source left this unvalidated; the
   library closes the gap).
3. **Rotation + replay revokes the family:** rotating a token returns the consumed
   record; replaying it returns `null` and revokes the family; subsequent rotation
   of any token in that family returns `null`.
4. **Rotation backfill — fix #3 (the documented contract):** `rotateRefreshToken`
   fills `clientId`/`subject`/`scopes` on the **next** record from the
   **consumed** row, ignoring the caller-supplied values. The caller passes
   `clientId`/`subject`/`scopes` it does NOT trust (e.g. from the wire); the store
   authoritative-copies them from the row being consumed. Thus an attacker who
   supplies a stolen refresh token with a different `client_id`/`subject`/`scopes`
   cannot poison the next token — those fields always come from the stored record.
   (The use-case still independently enforces RFC 6749 §6 client binding and
   revokes on mismatch; the backfill is defense-in-depth at the store layer.)
5. **Family-validity sweep (addendum 8):** an expired refresh token still rotates
   to `null`; `sweepExpired(now)` deletes a refresh token (consumed OR unconsumed)
   ONLY when **no token in its family has `expires_at >= now`** (a `NOT EXISTS`
   family-member-still-valid check), and deletes ANY family left empty (not only
   revoked ones). **Boundary:** `expires_at >= now` counts as still-valid (the
   suite asserts the exact-boundary case so adapters cannot disagree). This retains a consumed predecessor while a successor rotated
   from it is still valid — a naive per-token expiry sweep would delete the
   predecessor at its own expiry and drop the **replay signal** while the successor
   is live (a replay-detection regression; the suite includes the
   successor-outlives-predecessor case). Expired auth codes and JTIs are swept by
   their own expiry. **Accepted boundary:** replay after the WHOLE family is past
   validity is undetected (the rows are GC'd by then).
6. **Idempotent close:** `close()` is callable more than once; any op after close
   throws `Store is closed`.
7. **Granted-scope derivation *(RC item (c))*:** `findGrantedScopes(subject,
   clientId, nowIso)` returns the union of `scopes` across refresh-token records
   for that `(subject, clientId)` that are unconsumed, in non-revoked families,
   and not expired at `nowIso`. It is a **read over existing records — there is no
   grant table**. Returns `[]` when no active token exists (a first authorization
   therefore grants exactly the requested scopes).

### 12.3 Reference adapters
- `MemoryStore` (`/store/memory`) — in-process maps; dev/test only, labeled loud.
  Not HA; single-process.
- `SqliteStore` (`/store/sqlite`) — `node:sqlite` (built-in; no native dep),
  `:memory:` or file. STRICT tables, `BEGIN IMMEDIATE` transactions,
  `INSERT ... ON CONFLICT DO NOTHING` for consent JTIs. The schema migration is
  idempotent.
- `MysqlStore` (`/store/mysql`) — `mysql2` (optional peer dep; pooled). The first
  *async/pooled* reference adapter, so it is the binding example of addendum 13
  below: a pooled connection, `beginTransaction`/`commit`/`rollback` behind a
  begun-guard, `release()` in `finally` on every path. Timestamps are stored as
  `VARCHAR(24)` with a binary collation so expiry comparison is byte-lexicographic
  (identical semantics to SQLite `TEXT`, preserving the §12.1 3-ms ordering
  invariant — `DATETIME` would change comparison/tz semantics and is NOT used).
  Because a pool does NOT serialize writers the way `BEGIN IMMEDIATE` does,
  `rotateRefreshToken` takes a row lock via `SELECT ... FOR UPDATE` inside the
  transaction — without it, two concurrent rotations of the same token would both
  see `consumed_at IS NULL`, double-insert the successor, and break replay
  detection (§12.2 invariant 3). `INSERT IGNORE` substitutes for SQLite
  `ON CONFLICT DO NOTHING` on consent JTIs (the `ON DUPLICATE KEY UPDATE
  expires_at = expires_at` form reports `affectedRows=1` even on a no-op replay
  under MySQL 8.4, so it cannot distinguish first-use); the family-revoke upsert
  uses the MySQL 8.0.20+ row-alias `VALUES(...) AS new ON DUPLICATE KEY UPDATE`.
  Transactions run at **`READ COMMITTED`** (`SET TRANSACTION ISOLATION LEVEL
  READ COMMITTED` — the next-transaction form, before `BEGIN`): under InnoDB's
  default `REPEATABLE READ`, range scans (`sweepExpired`'s family DELETE, the
  rotation `FOR UPDATE`) take next-key/gap locks that deadlock each other;
  `READ COMMITTED` disables gap locking. The next-transaction form scopes the
  isolation to that one transaction, so a caller-supplied shared pool
  (`new MysqlStore(appPool)`) does not inherit READ COMMITTED after `release()`. `sweepExpired` is a two-step SELECT-exact-dead-rows-then-DELETE-by-PK
  so a successor committed mid-sweep can never be swept. **Pool sizing is the
  deployer's responsibility** — `createMysqlStore(config)` accepts a `mysql2`
  `PoolOptions` object (or URI string), so `connectionLimit` is set there; provision
  it for peak refresh-rotation concurrency (the default is 10). **Pool ownership:**
  `createMysqlStore` owns the pool it creates (`close()` ends it); constructing
  `new MysqlStore(appPool)` with a caller-supplied shared pool leaves ownership — and
  the `close()` lifecycle — with the caller, so closing the store won't tear down a
  pool other components still use. Two performance
  trade-offs are accepted as-is, both because the path is low-QPS OAuth state, not a
  hot loop: (1) `READ COMMITTED` is set per transaction (one extra ~1ms round-trip)
  because `mysql2`'s pool exposes no per-connection init hook to set it once; (2)
  statements use the text protocol (`query`) rather than prepared statements
  (`execute`), which do not support the `IN (?)` array expansion the two-step sweep
  relies on. Revisit either only if profiling flags it.

**Async-store transaction hygiene (addendum 13 — for any pooled/async adapter,
e.g. a MySQL-compatible or Postgres store):** acquire the connection → `begin` INSIDE the `try`
(behind a begun-guard) → `release` in `finally` on EVERY path, including a
`begin` throw; swallow cleanup errors from `rollback`/`release` so the original
error propagates. A `begin`-failure that leaks a connection otherwise exhausts the
pool = an auth outage. A pooled SQL adapter should also pin `READ COMMITTED`
isolation (gap-lock avoidance — see the `MysqlStore` note above) and fail-closed
assert strict mode (`STRICT_TRANS_TABLES` or `STRICT_ALL_TABLES` — either suffices for
InnoDB) + binary column collations at boot. (The in-tree
memory + sqlite adapters are synchronous, so this is forward guidance for async
adapters.)

## 13. Audit contract

Append-only `AuthAuditEvent`s, **metadata-only**. No token values, no
`Authorization`/`Set-Cookie`, no request bodies; redirect URIs canonicalized to
host. Events (the v0.1 set plus the v0.2 additions from §17.7): `oauth.register`,
`oauth.authorize.prepare`, `oauth.authorize.approve`, `oauth.token.authorization_code`,
`oauth.token.refresh`, `oauth.revoke`, `auth.request`, `identity.verify`,
`oauth.pairing.attempt`, `oauth.device.authorization`, `oauth.device.approve`,
`oauth.token.device_code`, `oauth.token.client_credentials`, `oauth.client.provision`,
`oauth.client.rotate_secret`, `oauth.cimd.fetch`. Each carries `occurredAt`,
`event`, `status: "success"|"failure"`, and optional `clientId`, `subject`,
`resource`, `scopes`, `redirectHost`, `reason`, `ip` (adapter-populated client IP;
personal data — the deployer owns retention/redaction). The test suite asserts
that serialized audit output never contains raw codes, refresh tokens, or access
tokens, across every event name (the v0.2 names are exercised by synthetic
events through each sink; the v0.1 names additionally by the live OAuth flow).

## 14. Error catalog

All are `OAuthError(code, message, status)`. The 401 rows drive §8.2; the 403 row
drives §8.3.

| code | status | WWW-Authenticate | When |
|---|---|---|---|
| `invalid_token` | 401 | `Bearer resource_metadata=…, scope=…, error="invalid_token"` | missing/bad/expired bearer; bad aud/iss/alg |
| `invalid_request` | 400 | — | malformed/missing parameter |
| `invalid_grant` | 400 | — | bad/expired/replayed code or refresh; PKCE fail; consent replay |
| `invalid_scope` | 400 | — | unknown scope requested |
| `invalid_redirect_uri` | 400 | — | redirect fails §10 |
| `invalid_target` | 400 | — | `resource` ≠ configured resource |
| `invalid_origin` | 403 | — | approve CSRF/Origin check failed |
| `access_denied` | 401 (no identity) / redirect (Deny) | context | no/failed identity ⇒ direct 401; user Deny ⇒ redirect (§9.3) |
| `unsupported_response_type` | 400 | — | response_type ≠ code |
| `unsupported_grant_type` | 400 | — | grant_type unsupported |
| `insufficient_scope` | 403 | `Bearer resource_metadata=…, scope=…, error="insufficient_scope"` | missing required scope (step-up) |
| `server_error` | 500 | — | internal failure (e.g. refresh generation) |
| `internal_error` | 500 | — | unexpected (mapped from non-OAuthError) |

`invalid_consent` (400) is internal to consent verification. `invalid_store_input`
(`StoreInputError`) is thrown by store validation and is a programmer error, not
an OAuth response.

**Redirect vs direct (RFC 6749 §4.1.2.1, see §9.3):** `access_denied` (Deny),
`unsupported_response_type`, `invalid_target`, `invalid_scope`, `invalid_request`
(bad PKCE), and `server_error` are delivered as **302 to `redirect_uri?error=…`**
when they occur after `client_id` + `redirect_uri` validate. `invalid_redirect_uri`,
a missing `client_id`, identity failure, `invalid_origin`, and consent-token
integrity failures are always **direct 4xx**.

## 15. Package & export map

Single package `mcp-sso`. Runtime dep: **`jose` only**. Framework adapters,
identity ports, and the MySQL/Redis adapters are optional `peerDependencies`
(the consumer installs only the ones it uses); `node:sqlite` is built-in (no
dep). No postinstall, no bundler. Dev runs on **Node 24 native TS** (`.ts`
imports, no build step); the published artifact is plain-`tsc` ESM + `.d.ts`.

Dev/test does **not** consume the package via its own exports: Node 24 native TS
imports source files directly (e.g. `../src/index.ts`), so there is no build step
during development. The exports map is **consumer-facing and always points at
`./dist`**; a `prepublishOnly` hook runs `tsc` → `./dist` (ESM + `.d.ts`) before
the npm artifact is cut, so the published package is never broken by `.ts` paths:

```
"exports": {
  ".":                          { "types": "./dist/index.d.ts",                    "default": "./dist/index.js" },
  "./store/memory":             { "types": "./dist/store/memory.d.ts",             "default": "./dist/store/memory.js" },
  "./store/sqlite":             { "types": "./dist/store/sqlite.d.ts",             "default": "./dist/store/sqlite.js" },
  "./store/mysql":              { "types": "./dist/store/mysql.d.ts",              "default": "./dist/store/mysql.js" },
  "./rate-limit/redis":         { "types": "./dist/rate-limit/redis.d.ts",         "default": "./dist/rate-limit/redis.js" },
  "./fastify":                  { "types": "./dist/adapters/fastify.d.ts",         "default": "./dist/adapters/fastify.js" },
  "./express":                  { "types": "./dist/adapters/express.d.ts",         "default": "./dist/adapters/express.js" },
  "./hono":                     { "types": "./dist/adapters/hono.d.ts",            "default": "./dist/adapters/hono.js" },
  "./identity/cloudflare-access": { "types": "./dist/identity/cloudflare-access.d.ts", "default": "./dist/identity/cloudflare-access.js" },
  "./identity/entra":             { "types": "./dist/identity/entra.d.ts",             "default": "./dist/identity/entra.js" }
}
```

The v0.2 reference audit sinks — `JsonlFileAudit`, `WebhookAudit`,
`combineAudit` (§17.7) — are exported from the **root `.` entry**, not a subpath:
they carry no runtime dependency (`node:fs` is built-in; `fetch` is native to Node
24), so there is no optional peer dep to isolate and a single
`import { JsonlFileAudit } from "mcp-sso"` is the intended consumer shape.

**Supply-chain settings:** `packageManager` pins pnpm via corepack;
`pnpm-workspace.yaml` sets `minimumReleaseAge: 21600` (**minutes** = 15 days —
the install-time floor and the `docs/dependency-ledger.md` 15-day curation rule
are the same standard); CI actions are pinned by SHA; npm publish uses
`--provenance` from GitHub Actions OIDC only (no local publishes). Every pin is
recorded in `docs/dependency-ledger.md` with version + publish date.

## 16. Spec-conformance matrix

| Requirement | Status | Where |
|---|---|---|
| RFC 9728 PRM (root) | ✅ v0.1 | §9.1 |
| RFC 9728 PRM (path-inserted) | ✅ v0.1 *(fix #2)* | §9.1 |
| `WWW-Authenticate: … resource_metadata=…, scope=…` (401) | ✅ v0.1 *(fix #1)* | §8.2 |
| `insufficient_scope` 403 step-up | ✅ v0.1 | §8.3 |
| RFC 8414 AS metadata | ✅ v0.1 | §9.1 |
| RFC 7591 DCR (stateless) | ✅ v0.1 | §9.2 |
| Stored-client DCR + `application_type` *(fix #4, RC b)* | ✅ v0.1 | §9.2, §10.2 |
| PKCE S256 (timing-safe) | ✅ v0.1 | §7.5 |
| RFC 8707 audience fail-closed | ✅ v0.1 | §7.2 |
| RFC 9207 `iss` + `authorization_response_iss_parameter_supported` *(RC a)* | ✅ v0.1 | §9.1, §9.3 |
| Scope accumulation on step-up *(RC c)* — stored-DCR mode | ✅ v0.1 (core+store; delta UI Phase 3) | §9.3, §11 |
| Refresh rotation + family replay revocation | ✅ v0.1 | §7.4, §12 |
| RFC 6749 §6 refresh client-binding | ✅ v0.1 | §7.4 |
| RFC 6749 §4.1.2.1 error-redirect channels | ✅ v0.1 | §9.3, §14 |
| RFC 7009 revocation (always 200; unknown = no-op) | ✅ v0.1 | §9.4 |
| Hashed single-use codes/tokens; single-use consent JTI | ✅ v0.1 | §7, §12 |
| Fail-closed boot + no identity bypass | ✅ v0.1 | §5, §9.3 |
| Consent Deny *(fix #5)* + error redirects | ✅ v0.1 core + adapter UI | §9.3, §9.6 |
| Rate-limit hook port *(fix #7)* — no-op default | ✅ v0.1 | §6.7 |
| CIMD (SSRF-guarded FetcherPort) | ⏳ boundary v0.1, **contract locked §17.1**, impl v0.2 | §6.6, §17.1 |
| Framework adapters (`/fastify` `/express` `/hono`) | ✅ Phase 3 | §9.6, §15 |
| Identity ports (Cloudflare Access, Entra) | ✅ Phase 3 | §6.5 |
| `client_credentials` (MCP ext `io.modelcontextprotocol/oauth-client-credentials`) | 🔒 v0.2 contract locked | §17.2 |
| Device authorization grant (RFC 8628) | 🔒 v0.2 contract locked | §17.3 |
| Entra group→scope ceiling (Gate 2) | 🔒 v0.2 contract locked | §17.4 |
| Console-pairing identity | 🔒 v0.2 contract locked | §17.5 |
| `GenericOidcIdentity` + Google preset + GitHub port | 🔒 v0.2 contract locked | §17.6 |
| Audit reference sinks + expanded events | ✅ v0.2 shipped (S1a) — JsonlFileAudit/WebhookAudit/combineAudit + 9 event names + `ip` | §13, §17.7 |
| Quickstart secret persistence | 🔒 v0.2 contract locked | §17.8 |

**RC re-check gate:** the 2026-07-28 RC is treated as additive hardening built in
now; revisit it when it finalizes (~end July 2026) before anything is called v1.0.
The RC changes nothing about the RS model or the bridge architecture.

## 17. v0.2 feature contracts (locked 2026-07-04)

> Written and reviewed **before implementation** (contract-first house rule,
> applied to the whole v0.2 batch at once because the features interact).
> Every open design question is resolved to an explicit decision here; deferred
> items are recorded as decisions too, with rationale. `docs/threat-model.md`
> carries the attacker analysis; `docs/authorization.md` carries the
> deployer-facing Gate 1/Gate 2 model. Spec facts below were verified against
> primary sources on 2026-07-04 (IETF drafts/RFCs, IANA registries,
> modelcontextprotocol.io, vendor docs).

### 17.1 CIMD — Client ID Metadata Documents (the SSRF enforcement contract)

**Conformance target: `draft-ietf-oauth-client-id-metadata-document-01`**
(2026-03-02). The MCP 2025-11-25 spec normatively references draft **-00**, but
-01 is strictly stricter (MUST-level RFC 6890 SSRF rule, redirect prohibition,
200-only rule) — we build to -01 deliberately. The MCP profile additionally
requires the document to contain `client_id`, `client_name`, and
`redirect_uris`.

**Config (opt-in; absent ⇒ CIMD disabled and URL-shaped client_ids are
rejected with `invalid_client`, direct):**

```ts
cimd?: {
  enabled: true;
  fetcher?: GuardedFetcher;     // BRANDED type — see below; omitted ⇒ the library
                                // constructs its own createGuardedFetcher()
  maxDocumentBytes?: number;    // default 5120 (the draft's recommended 5 KB cap)
  fetchTimeoutMs?: number;      // default 5000 — one wall-clock deadline, DNS→body
  cacheTtlCapSeconds?: number;  // default 3600; cache lifetime clamped [60, cap]
}
```

**The guard is structural, not advisory.** `GuardedFetcher` is a branded type
(unique symbol brand) that ONLY `createGuardedFetcher()` can produce — the
CIMD config does NOT accept a bare `FetcherPort`, because the core cannot
verify that an arbitrary `fetch()` object performs DNS pinning, IP blocking,
and redirect refusal. By default the library constructs the guarded fetcher
itself. Testability is preserved one layer down:
`createGuardedFetcher({ transport? })` accepts an injectable low-level
connect-to-validated-IP transport for tests, but the guard pipeline — URL
admission, blocklists, DNS validation, redirect refusal, caps — always runs
around whatever transport is injected and cannot be skipped. (`FetcherPort`
in §6.6 remains the generic boundary description; CIMD requires the brand.)

Boot: invalid caps are an `AuthConfigError`, and — because a compile-time
brand is invisible to plain-JS consumers and defeated by a cast — **if
`cimd.fetcher` is provided, boot MUST verify the RUNTIME brand**: a
non-exported unique symbol property that `createGuardedFetcher()` stamps on
the object it returns. An object without the stamp is rejected with
`AuthConfigError` at boot, never used. (The symbol is module-private; the
only way to obtain a branded fetcher is to have `createGuardedFetcher()`
construct it, so the guard pipeline is provably attached.) When enabled, AS
metadata emits
`client_id_metadata_document_supported: true` (draft §5 MUST when supported).
Detection is by shape: a `client_id` starting with `https://` takes the CIMD
path (draft §6.9 — our generated ids `mcpdc_`/`mcc_` never collide).

**17.1.1 URL admission (pure function, unit-testable, runs before any DNS):**

1. Raw-string checks first — every check in this step runs on the RAW
   client_id string BEFORE `new URL()`: length ≤ 2048; no raw or
   percent-encoded CR/LF (`\r`, `\n`, `%0d`, `%0a` case-insensitive); no
   other control chars; raw `^https://` prefix check (addendum 11 pattern);
   and **dot-segment rejection**: split the raw path on `/` and reject any
   segment equal to `.` or `..` in literal OR percent-encoded form (`%2e`,
   `%2E`, and mixed — decode each segment once for this comparison only).
   This MUST happen pre-parse: the WHATWG parser *normalizes* both literal
   and percent-encoded dot segments away (`/a/%2e%2e/b` parses to pathname
   `/b`), so a post-parse `pathname` inspection can never see them. Unit
   tests MUST cover the literal, `%2e`, `%2E`, and mixed-case variants.
2. Parse (WHATWG). MUST: non-root path component (`pathname.length > 1` — the
   draft requires "a path component"; we read that as a real path,
   fail-closed). MUST NOT: fragment, userinfo. **Query strings are rejected**
   (draft says SHOULD NOT; we fail closed — stricter than spec, documented).
3. Host rules: IP-literal hosts rejected (v4 and v6 — beyond-spec hardening; a
   bare-IP "identity" defeats the hostname-display trust model). Note the
   WHATWG parser canonicalizes dword/octal/hex forms (`https://2130706433/`)
   to dotted-quad hostnames, so literal-encoding bypasses are caught by this
   same check. `localhost`, `*.localhost`, and trailing-dot hostnames rejected
   pre-DNS. Explicit ports allowed (draft MAY) but must pass the port denylist
   `{22, 25, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 6379, 9200,
   11211, 27017}`.

**Loopback exception:** none in production. The draft permits a loopback AS to
fetch same-loopback client_ids; we bind that to the existing
`dev.allowInsecureLocalhost` flag (which already boot-fails on non-loopback
origins) — loopback CIMD fetches are permitted only under that flag.

**17.1.2 Fetch enforcement (`createGuardedFetcher` — the reference
`FetcherPort`):**

- **DNS pinning:** resolve ALL A + AAAA records; EVERY resolved address must
  pass the blocklist (any hit rejects the whole fetch — multi-record attacks);
  connect to one validated resolved IP (family-consistent), with `Host` header
  and TLS SNI set to the original hostname, certificate verified against the
  original hostname. The hostname is NEVER re-resolved after validation
  (closes the rebinding TOCTOU; TTL-0 tricks are irrelevant under pinning).
- **Blocked ranges — IPv4** (IANA IPv4 Special-Purpose registry, complete,
  plus multicast): `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`,
  `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24` (entire block, including
  its sub-registrations and the globally-reachable PCP/TURN anycasts —
  fail-closed), `192.0.2.0/24`, `192.31.196.0/24`, `192.52.193.0/24`,
  `192.88.99.0/24`, `192.168.0.0/16`, `192.175.48.0/24`, `198.18.0.0/15`,
  `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4` (multicast — separate
  IANA registry, blocked explicitly), `240.0.0.0/4` (incl.
  `255.255.255.255/32`).
- **Blocked ranges — IPv6** (IANA IPv6 Special-Purpose registry, complete,
  plus multicast): `::/128`, `::1/128`, `::/96` (IPv4-compatible, deprecated),
  `::ffff:0:0/96` (IPv4-mapped), `64:ff9b::/96` + `64:ff9b:1::/48` (NAT64),
  `100::/64`, `100:0:0:1::/64`, `2001::/23` (the entire IETF-protocol block —
  covers Teredo `2001::/32`, benchmarking, AMT, AS112, ORCHID/ORCHIDv2, DRIP;
  no legitimate metadata host lives there), `2001:db8::/32`, `2002::/16`
  (6to4), `2620:4f:8000::/48`, `3fff::/20` (new documentation block, RFC
  9637), `5f00::/16` (SRv6, RFC 9602), `fc00::/7`, `fe80::/10`, `fec0::/10`
  (deprecated site-local), `ff00::/8` (multicast). Zone-scoped addresses
  (`%zone`) rejected outright.
- **Embedded IPv4:** every IPv4-embedding IPv6 form (IPv4-mapped,
  IPv4-compatible, both NAT64 prefixes, 6to4, Teredo) is **blocked wholesale
  by the list above** — no extraction-and-recheck step exists to get subtly
  wrong. Membership tests compare **parsed binary addresses**, never strings.
- **Redirects: refused.** Draft -01 MUST NOT follow; any 3xx is an error. The
  core additionally asserts `result.url === <requested URL>` and
  `status === 200`, so a fetcher that silently followed a redirect is detected
  and the result rejected. (Max hop count is therefore 0 by contract.)
- **Response:** status 200 only (draft MUST); `Content-Type` must be
  `application/json` or a `+json` suffix type (our hardening — the draft only
  requires the body to be JSON); body read with a streaming hard cap of
  `maxDocumentBytes` — exceeding it REJECTS (never truncates: truncated JSON
  must never parse "successfully"); unknown `Content-Encoding` rejected and
  decompressed output counted against the same cap (decompression bombs).
- **Timeout:** one `AbortController` deadline (`fetchTimeoutMs`, default
  5000 ms) spanning DNS, connect, TLS, headers, and body. The spec is silent
  on timeouts; this value is our own hardening, recorded as such.
- **Concurrency/DoS:** single-flight per URL (concurrent authorizes for the
  same client_id coalesce into one fetch); a global in-flight cap (default 8);
  the authorize endpoint sits behind `RateLimitPort` (`cimd:<ip>`). Error
  responses are NOT cached (draft MUST NOT) — the rate-limit layer, not a
  negative cache, bounds refetch abuse.

**17.1.3 Document validation (pure function, unit-testable):**

- Strict `JSON.parse`; result must be a JSON object.
- `client_id` member MUST equal the fetched URL by **exact character-for-
  character comparison** (RFC 3986 §6.2.1 simple string comparison — no
  normalization, no case-folding, no trailing-slash equivalence).
- Required members (MCP profile): `client_id`, `client_name` (non-empty
  string, ≤ 256 chars — display data, HTML-escaped at render),
  `redirect_uris` (non-empty array).
- `token_endpoint_auth_method` MUST be absent or `"none"`. **v0.2 CIMD
  clients are public clients only** — the draft explicitly sanctions this
  profile restriction. `private_key_jwt` (confidential CIMD via published
  JWKS) is DEFERRED, together with 17.2's `private_key_jwt` — one future
  asymmetric-client-auth unit. `client_secret` /
  `client_secret_expires_at` present ⇒ reject (draft MUST NOT).
- `redirect_uris` entries: https (exact-match at authorize, per draft §4.5 /
  RFC 9700) or loopback http (RFC 8252 any-port at match time — consistent
  with §10.2 native policy). Same hygiene as §10: no wildcards, no fragments,
  no userinfo. If present: `response_types` must include `"code"`;
  `grant_types` ⊆ `{authorization_code, refresh_token}`; else reject.
- Unknown members ignored (the RFC 7591 registry allows extras). `logo_uri`
  is NOT fetched and NOT displayed in v0.2 (the draft requires
  prefetch-and-cache IF displayed; we sidestep the second fetch surface).

**17.1.4 Flow integration:**

- CIMD resolution runs in `prepare`, pre-validation (the fetched document IS
  the registration). Any failure — admission, DNS, blocklist, fetch, size,
  status, parse, validation — is a **direct** error (§9.3 channel) with ONE
  generic client-facing message ("client_id could not be resolved"): the error
  MUST NOT distinguish blocked-address from network-failure from invalid-
  document (**SSRF oracle prevention**). The specific reason goes to audit
  only (`oauth.cimd.fetch`, failure, reason code).
- The presented `redirect_uri` must exact-match a document entry (loopback
  any-port exception). Consent page MUST display the client_id host and the
  redirect host, SHOULD warn when every registered redirect is loopback (the
  MCP localhost-impersonation consideration); `client_name` renders as
  unverified display text.
- **Scope accumulation applies to CIMD clients in both DCR modes** — the §9.3
  stateless exclusion is about *ephemeral, unverified* ids; a CIMD client_id
  is stable and validated, so `findGrantedScopes(subject, clientIdUrl)` is
  meaningful.
- Token/refresh/revoke: NO re-fetch; binding is the existing auth-code-record
  and refresh-record client checks (§9.4). Validated documents cache per RFC
  9111 headers clamped to `[60, cacheTtlCapSeconds]` seconds, keyed by exact
  URL, in-memory per instance; invalid/error results never cached.
- No new store records.

### 17.2 `client_credentials` grant (MCP extension `io.modelcontextprotocol/oauth-client-credentials`)

The extension (ext-auth repo, status Draft) requires OAuth 2.1-shaped client
authentication and states outright: *"Dynamic Client Registration is not used
in this flow."* Decisions:

- **Stored-DCR mode only**, and machine clients are **provisioned
  out-of-band, never via `/oauth/register`**: the open registration endpoint
  MUST reject any request naming `token_endpoint_auth_method` other than
  `"none"` or a `grant_types` containing `client_credentials`
  (`invalid_client_metadata`). Otherwise anyone on the internet could mint
  themselves a secret. Config: `clientCredentials?: { enabled: boolean }`;
  boot `AuthConfigError` if enabled with `dcr.mode !== "stored"`.
- **Provisioning API (library function, not an endpoint):**
  `provisionMachineClient(store, { name?, allowedScopes, secretTtlSeconds? })`
  → `{ clientId, clientSecret }`. `clientId` = `mcc_<random>` — the prefix is
  enforced, giving a namespace disjoint from human subjects and from `mcpdc_`
  ids (RFC 9700 §4.15.1: the AS MUST let the RS distinguish machine tokens
  from user tokens; here `sub` starting `mcc_` ⇔ machine). The secret is
  returned ONCE and never retrievable.
- **`ClientStore` extension:** `applicationType` gains `"machine"`; machine
  records carry `allowedScopes: string[]` (validated ⊆ `scopeCatalog` at
  wiring) and `secrets: Array<{ hash, createdAtEpoch, expiresAtEpoch? }>`
  (max 2 active); `redirectUris` MUST be `[]`; machine clients are rejected at
  `/oauth/authorize` and the device endpoints (`invalid_client`).
- **Secret contract:** `mcs_` + base64url(32 CSPRNG bytes) — 256-bit,
  clearing RFC 6749 §10.10 (≥2⁻¹²⁸ MUST) and RFC 6819 §5.1.4.2.2. Stored as
  **unsalted SHA-256 hex only**: RFC 6819 §5.1.4.1.3 conditions salting/work
  factors on LOW-entropy credentials (user passwords); for a 256-bit random
  secret SHA-256 is sufficient, keeps the hot path cheap (bcrypt on the token
  endpoint is a DoS lever), and keeps `jose` the only dep. Digest comparison
  is constant-time.
- **Token-endpoint auth:** support BOTH `client_secret_basic` (RFC 6749 §2.3.1
  MUST — including the percent-decode-after-Basic-split quirk; our base64url
  alphabet makes encoding a no-op but we decode anyway) and
  `client_secret_post` (OAuth 2.1 §2.4.1 MUST — the two specs flipped the
  mandatory method; the MCP extension names `client_secret_basic`). Advertise
  `token_endpoint_auth_methods_supported:
  ["none","client_secret_basic","client_secret_post"]` and
  `grant_types_supported` += `client_credentials` (RFC 8414's default omits
  it). `private_key_jwt` (RFC 7523; the extension's RECOMMENDED method) is
  DEFERRED with 17.1's confidential-CIMD — recorded, not forgotten; the
  secret-based path is extension-compliant.
- **Grant semantics:** authenticate the client (failure ⇒ `invalid_client`
  401, `WWW-Authenticate: Basic` when Basic was attempted); `scope` normalized
  against the client's `allowedScopes` (omitted ⇒ the full allowed set —
  RFC 6749 §3.3 default); `resource` if present MUST equal `config.resource`
  (`invalid_target`). Mint an access token with `sub = client_id`
  (RFC 9068 §2.2) and the existing `client_id` claim; **NO refresh token**
  (RFC 6749 §4.4.3 SHOULD NOT — the client holds a durable credential; a
  refresh token is a second bearer secret with zero benefit). **This requires
  splitting the §9.4 response type**, whose current `TokenResponse` makes
  `refresh_token` required: the implementation defines `UserTokenResponse`
  (today's shape, refresh_token required — authorization-code, refresh, and
  device grants) and `MachineTokenResponse { access_token, token_type:
  "Bearer", expires_in, scope }` — no `refresh_token` member at all, not an
  optional one, so an accidental `refresh_token: undefined` is
  unrepresentable. The token endpoint returns one or the other by grant type.
- **Rotation:** `rotateMachineClientSecret(store, clientId, { graceSeconds =
  86400 })` — adds the new secret, expires the old at `now + grace` (the
  two-active-secrets overlap pattern, per Okta/Entra practice; RFC 7592 is
  Experimental and hard-cutover, not used). Verification accepts any
  unexpired stored hash.
- **Audit:** `oauth.token.client_credentials`, `oauth.client.provision`,
  `oauth.client.rotate_secret` — clientId/scopes metadata only; never a secret
  or a secret hash.
- The MCP `initialize`-handshake extension advertisement
  (`capabilities.extensions`) is the host app's/example's concern, not the
  bridge's.

### 17.3 Device authorization grant (RFC 8628)

Honest scope note: RFC 8628 is in neither the MCP core spec nor any official
MCP extension (SEP-2059 was closed unadopted). This ships for the owner's real
non-MCP-shaped clients (CLI over SSH, sandboxed CI agents) as standard OAuth,
discoverable via RFC 8414 metadata; MCP clients will not discover it via the
MCP spec.

- **Endpoint:** `POST ${issuer}/oauth/device_authorization` (behind
  `RateLimitPort`, key `device:<ip>`). Request: `client_id` required
  (stateless: any non-empty; stored: must exist and not be `machine`; CIMD
  URL ids allowed — the document is fetched/validated per 17.1), `scope`
  optional (§11 normalization), `resource` optional (must equal
  `config.resource`). Duplicate parameters rejected (§3.1 MUST NOT).
- **Response** (200, `application/json`, `cache-control: no-store`):
  `device_code`, `user_code`, `verification_uri` = `${issuer}/oauth/device`,
  `verification_uri_complete` = `${issuer}/oauth/device?user_code=XXXX-XXXX`,
  `expires_in` = `deviceCodeTtlSeconds` (config, default **600**), `interval`
  = **5**.
- **`user_code`:** 8 chars from the RFC 8628 §6.1 base-20 set
  `BCDFGHJKLMNPQRSTVWXZ` (~34.5 bits), displayed `XXXX-XXXX`; CSPRNG with
  rejection sampling. Input canonicalization per §6.1: uppercase, strip every
  character outside the charset, then compare. Stored as
  `sha256(canonical)`.
- **`device_code`:** `dc_` + base64url(32 bytes) (§5.2 "very high entropy"),
  stored hashed, treated as a bearer secret.
- **Brute force (§5.1 budget):** 34.5 bits × 600 s TTL × a built-in
  **in-process** per-IP cap of 5 wrong `user_code` submissions per 10 minutes
  (deliberately NOT dependent on the deployer wiring `RateLimitPort`; the
  port hook `device-verify:<ip>` adds defense-in-depth) ≈ the RFC's 2⁻³²
  target. The in-process limiter is per-instance; multi-instance deployments
  get the residual noted in the threat model.
- **Store additions (`StorePort`, conformance-suite invariants):**
  `DeviceCodeRecord { deviceCodeHash, userCodeHash, clientId, scopes,
  resource, status: "pending"|"approved"|"denied", subject: string|null,
  approvedScopes: string[]|null, intervalSeconds, lastPolledAt: string|null,
  expiresAt }` with methods: `saveDeviceCode`,
  `findDeviceCodeByUserCodeHash` (pending + unexpired only),
  `pollDeviceCode(hash, nowIso)` (atomic: stamps `lastPolledAt`; polls faster
  than `intervalSeconds` return a too-fast marker AND bump the stored
  interval +5 — server-side mirror of the client's `slow_down` MUST),
  `resolveDeviceCode(userCodeHash, {status, subject, approvedScopes}, nowIso)`
  (CAS `pending`→`approved`/`denied`), `consumeApprovedDeviceCode(hash,
  nowIso)` (single-use delete-on-read for token issuance), and `sweepExpired`
  extended to device codes. Timestamps follow §12.1 (3-ms rule).
- **Verification UI (adapter):** `GET /oauth/device` renders enter-the-code
  first (prefilled from `user_code` query for the `_complete` variant); on a
  canonicalized match, identity resolution runs (the SAME `IdentityPort`
  machinery as authorize), then the existing consent page in a device variant:
  it MUST echo the `user_code` and say the user is authorizing a device they
  should confirm is theirs (§5.4 remote-phishing mitigation), show client
  info + requested scopes + Approve/Deny, and end on "return to your device"
  (no redirect). **This is a distinct consent surface, not a reuse of §7.1's
  token** — the §7.1 `ConsentRequestClaims` requires `redirectUri` and
  `approve()` always resolves to a redirect, which the device flow has none
  of. Contract: a separate `DeviceConsentClaims` token — HS256 with the same
  consent secret but a DISTINCT pinned audience `"mcp-sso/device-consent"`
  (so the two token kinds can never validate on each other's surface),
  claims `{ userCodeHash, clientId, scopes, allowedScopes?, subject, jti,
  iat, exp }` — and a separate `approveDevice({ deviceConsentToken,
  approved?, origin? })` use-case returning `{ decision: "approved" |
  "denied" }` with no redirect member. It shares the Origin/CSRF rule and the
  single-use-JTI store primitive (`consumeConsentJti`) with §9.3. The §17.4
  group ceiling applies here exactly as at authorize.
- **Token endpoint:** `grant_type=urn:ietf:params:oauth:grant-type:device_code`
  + `device_code` + `client_id` (must match the record; mismatch ⇒
  `invalid_grant`). Error state machine, all HTTP 400 §5.2-shaped:
  `authorization_pending` (pending), `slow_down` (poll arrived before the
  current interval elapsed; interval grows +5 persistently),
  `access_denied` (denied — terminal; record deleted on delivery),
  `expired_token` (expired — terminal). Success: `consumeApprovedDeviceCode`
  (single-use) → mint access + refresh tokens (new family) with
  `approvedScopes` — this IS a user grant, so refresh tokens apply, unlike
  17.2.
- **Metadata:** `device_authorization_endpoint` + `grant_types_supported` +=
  the device URN.
- **Audit:** `oauth.device.authorization`, `oauth.device.approve`
  (approved/denied), `oauth.token.device_code`.

### 17.4 Entra group-based authorization (Gate 2 becomes a scope ceiling)

Entra-specific by design (the owner's real deployment; do not generalize
prematurely). Facts verified against Microsoft Learn 2026-07-04: JWT group
claims cap at **200 groups**, beyond which the claim is **omitted** and
`_claim_names`/`_claim_sources` overage markers appear instead; group
**object IDs are the only universally available, immutable, collision-safe
form** (display names are a documented spoof vector — any user can create a
duplicate-named group); the `_claim_sources` endpoint URL is legacy Azure AD
Graph and Microsoft says not to rely on it.

**Config (on `EntraConfig`):**

```ts
groupAuthorization?: {
  mapping: Record<string, string[]>; // Entra group OBJECT ID (GUID) → scopes
  baseScopes?: string[];             // scopes every authenticated subject gets; default []
}
```

- Boot validation: every `mapping` key must be GUID-shaped (display names
  rejected — fail-closed against the documented spoofing vector); scope
  values non-empty. The adapter wiring (`registerOAuthRoutes`), which sees
  both configs, MUST additionally validate every mapped scope ⊆
  `scopeCatalog` (`AuthConfigError`).
- **Combination model: UNION.** A subject's scope ceiling
  `allowedScopes = baseScopes ∪ ⋃ mapping[g]` over every group GUID `g` in
  the verified `groups` claim that has a mapping entry. No tier precedence,
  no highest-wins — union is order-independent and matches how directory
  membership composes. Unmapped groups contribute nothing.
- **Overage = fail closed.** `groups` absent + (`_claim_names.groups` or
  `hasgroups`) present ⇒ `verify()` fails with reason
  `entra_groups_overage`. The `_claim_sources` URL is NEVER dereferenced — a
  URL inside a token is data, not instructions. Documented remediation:
  configure the app registration with **"Groups assigned to the
  application"** (`groupMembershipClaims: "ApplicationGroup"`) — caveats
  recorded: requires Entra P1, direct membership only, no nesting — or reduce
  group sprawl.
- **No groups claim at all** (not configured in the app manifest, or the user
  is in zero groups) ⇒ ceiling = `baseScopes`; if that is empty ⇒ fail with
  `entra_no_groups` (likely `groupMembershipClaims` misconfiguration —
  documented). Nested groups: the `SecurityGroup` claim is transitive;
  `ApplicationGroup` is direct-only (deployer caveat in
  `docs/authorization.md`).
- **Graph API fallback: DEFERRED (explicit decision).** The designed
  extension point is `POST /users/{oid}/checkMemberGroups` (≤20 group IDs per
  call — allowlist-shaped, transitive, app-only permissions
  `GroupMember.Read.All` + `User.ReadBasic.All`), but it puts an outbound
  Microsoft Graph call inside the auth path (availability + latency), needs
  admin consent and a confidential Entra client, and `ApplicationGroup`
  filtering already solves overage for the mapping use case. Revisit on real
  deployment demand. (Microsoft's first-line recommendation — App Roles via
  the `roles` claim, which never overflows — is recorded as a backlog
  alternative, not v0.2.)
- **Plumbing (explicit signature changes — the ceiling must travel the whole
  path, not live as a local Entra patch).** Today the adapters reduce identity
  to a bare subject string (`resolveSubject(): Promise<string>` in
  `adapters/http.ts`), `Bridge.handleAuthorize(req, subject)` takes only the
  string, and `ConsentRequestClaims` has no ceiling field. The contract
  changes every hop:
  1. `IdentityClaims` gains optional `allowedScopes?: string[]` (set by the
     Entra port from the group mapping; any future port may set it).
  2. `resolveSubject` is REPLACED by `resolveIdentity(identity, input):
     Promise<{ subject: string; allowedScopes?: string[] }>` — same
     fail-closed `access_denied` behavior, richer return. (Internal adapter
     helper; not a public export — no compat shim needed.)
  3. `Bridge.handleAuthorize(req, identity: { subject; allowedScopes? })` —
     the bare-string form is removed in the same release.
  4. `AuthorizeRequestInput` gains `allowedScopes?: string[]`.
  5. `ConsentRequestClaims` gains `allowedScopes?: string[]`, carried in the
     consent JWT as an `allowed_scopes` claim (§7.1 shape extended), so
     `approve` re-intersects from the *verified token*, not from anything
     client-resupplied.
  6. The device-approval path (§17.3 `DeviceConsentClaims`) carries the same
     field the same way.
- **Core enforcement (IdP-agnostic):** with the ceiling present,
  `prepare` (and the device-flow approval) **narrows by intersection** with
  the ceiling — RFC 6749 permits granting fewer scopes than requested, and
  the token response `scope` + consent page reflect the narrowed set (this is
  not fail-open: the un-entitled scope is never granted; rejecting outright
  would only worsen interop since MCP clients cannot know what to request).
  An EMPTY intersection ⇒ `access_denied` (redirect channel). The ceiling is
  embedded in the consent-token claims, and `approve` re-intersects
  `union(requested, priorScopes)` against it — accumulated prior grants must
  not resurrect scopes a since-removed group granted. `defaultScopes` pass
  through the same intersection.
- **Refresh is NOT re-checked** (no identity at refresh): group revocation
  takes effect at the next full authorize. Residual risk documented in the
  threat model; deployers needing faster revocation shorten
  `refreshTokenTtlSeconds` or revoke families.
- Guest (B2B) behavior is UNVERIFIED in Microsoft's docs — added to the Entra
  live-verification checklist rather than assumed.
- **Audit:** new event `identity.verify` (success/failure + reason, incl.
  `entra_groups_overage`) — failed-login evidence for enterprises.

### 17.5 Console-pairing identity (zero-IdP setup)

`createConsolePairingIdentity({ subject = "console-operator",
codeTtlSeconds = 600, maxAttempts = 5, output = stderr })` — an
`IdentityPort` for single-operator deployments: a one-time code is printed to
the server console and pasted at the consent step. **Replaces the example's
`DEV_STUB_SUBJECT` outright** (the stub is deleted when this ships — a real
gate replaces no-gate).

- **Code:** 12 chars from the base-20 set `BCDFGHJKLMNPQRSTVWXZ`, displayed
  `XXXX-XXXX-XXXX` (~51.9 bits — deliberately above RFC 8628's 34.5-bit
  example because this code is the ENTIRE identity gate, not a secondary
  confirmation). CSPRNG rejection sampling; input canonicalization as 17.3;
  timing-safe comparison.
- **Lifecycle:** generated lazily when a pairing-needed authorize arrives
  (never at boot — no stale scrollback codes), printed to stderr with
  timestamp and expiry; ONE active code per process; single-use (consumed on
  success); invalidated by expiry (600 s) or by `maxAttempts` (5) wrong
  submissions, after which the next request prints a fresh code. **Never
  persisted** — process-memory only; restart = clean slate (fail-closed).
- **Session binding:** the code is bound to the pairing session (random nonce
  in the form) that triggered its printing — a code printed for one flow
  cannot be consumed by another, so an attacker triggering codes onto the
  operator's console gains nothing and cannot race a pasted code.
- **Rate limiting:** the attempt cap is built-in and in-process — it cannot be
  misconfigured away; the `RateLimitPort` hook (`pairing:<ip>`) adds
  defense-in-depth.
- **Trust boundary (threat model):** whoever can read the process's stderr IS
  the operator. Log pipelines (docker logs, CloudWatch, Loki) EXTEND that
  boundary — codes land in them; TTL + single-use + attempt cap bound but do
  not eliminate the exposure. **Deployment envelope: single-operator/personal
  deployments with operator-private console output. Explicit non-goal
  everywhere else** — multi-operator or shared-log environments must use a
  real IdP port. The printed banner and docs say exactly this.
- Audit: `oauth.pairing.attempt` (success/failure — brute-force evidence).

### 17.6 `GenericOidcIdentity` + Google preset + dedicated GitHub port

**`createGenericOidcIdentity(config)`** — the missing generic port:

- Config: `issuer` (https, the exact-match anchor), `clientId`,
  `clientSecret?`, `redirectUri`, `endpoints: "discover" |
  { authorizationEndpoint, tokenEndpoint, jwksUri }` (manual mode — zero
  boot-time fetching), `scopes?` (default `openid profile email`),
  `subjectAllowlist?` (matches `sub`), `allowEmailAllowlist?` (opt-in; only
  matches when `email_verified === true`).
- **Discovery** (`endpoints: "discover"`): fetched ONCE at boot from
  `${issuer}/.well-known/openid-configuration`; the document's `issuer` MUST
  exactly equal the configured issuer (OIDC Discovery §4.3; RFC 8414 §3.3:
  "MUST NOT be used" on mismatch — boot failure); all endpoints + `jwks_uri`
  MUST pass the raw `^https://` check (addendum 11). Discovery/JWKS fetches
  use plain https (NOT the 17.1 SSRF guard): the issuer is deployer-trusted
  config, and enterprise IdPs legitimately live on private networks —
  documented rationale. Redirects on the discovery fetch: not followed
  (fail closed).
- **id_token validation:** `iss` exact-match; `aud` must contain `clientId`
  and multiple-audience tokens are rejected outright (fail-closed
  simplification of OIDC Core §3.1.3.7); `exp`/`iat` via jose with
  `ClockPort`; algorithms pinned to `{RS256, ES256}` ∩ the provider's
  advertised set; **nonce always sent, always verified** (once sent, OIDC
  Core makes the claim mandatory — missing/mismatch is a hard failure);
  `at_hash` validated if present, absence accepted (code flow). Subject =
  `sub`, keyed as `(issuer, sub)`; email is a display attribute, never the
  identity key.
- **PKCE:** always S256. If discovery omits `code_challenge_methods_supported`
  (per RFC 8414 that means no PKCE support), boot FAILS unless the deployer
  sets `allowProviderWithoutPkce: true` (state + nonce + client secret still
  bind the flow; the flag is loud).
- **Google preset** (`createGoogleIdentity`): the generic port pinned to
  `https://accounts.google.com` + discovery; `clientSecret` REQUIRED
  (Google's advertised token auth methods are secret-based only; its docs'
  newer "Optional" marking is unverified — we treat it as required);
  subject = `sub` per Google's own don't-key-on-email guidance; optional
  `hostedDomain` validated against the **`hd` claim** (Google: check the
  claim, never the email's domain); email surfaced only when
  `email_verified === true`. `iss` accepted ONLY as
  `https://accounts.google.com` (the schemeless legacy variant is rejected;
  if live verification ever hits it, any allowance will be an explicit,
  documented Google-only quirk).
- **GitHub = its own dedicated port** (`createGitHubIdentity`), NOT a preset:
  GitHub OAuth Apps have **no OIDC discovery document (404, verified) and no
  id_token** — identity comes from the REST API, so forcing it through the
  generic port would mean a degenerate bespoke branch inside it. Contract:
  hardcoded `https://github.com/login/oauth/{authorize,access_token}`;
  `Accept: application/json` on the token exchange (default response is
  form-encoded); `state` required; PKCE S256 sent (supported since
  2025-07-14; optional) AND `client_secret` always required; scope
  `user:email` only; identity: `GET https://api.github.com/user` → subject =
  the **numeric `id`** as a string (stable; `login` is mutable), email from
  `GET /user/emails` filtered to `primary && verified` (else no email
  attribute). Allowlist matches the numeric id by default; matching `login`
  requires the mutable-claims opt-in (mirrors Entra's `allowMutableClaims`).
  The upstream GitHub token is discarded after the identity calls (the bridge
  mints its own tokens), so OAuth Apps suffice; GitHub Apps work identically
  if the deployer prefers.
- **Entra refactor:** the public `identity/entra` API is UNCHANGED in v0.2;
  sharing internals with the generic port is permitted as an implementation
  detail, not required.
- **Verification + guides (decided, not deferred):** every new port/preset
  ships with (1) exported pure claim-validation functions unit-tested without
  network, (2) a manual live checklist at the top of the file (Entra
  pattern: register → sign in → claims validated → allowlist negative test →
  bridge mints its own token), (3) a README conformance row only after a real
  live pass. Setup guides are **human-facing docs written to be
  agent-executable** (exact console paths and field names —
  `docs/identity/{github,google,entra}.md`); a scripted/agentic setup flow is
  explicitly out of v0.2 scope (provider UIs churn; an agent can follow the
  docs).
- Export map additions: `./identity/generic-oidc`, `./identity/google`,
  `./identity/github`, `./identity/console-pairing`.

### 17.7 Audit reference sinks + event coverage

> **SHIPPED S1a** (`src/audit/jsonl-file.ts`, `src/audit/webhook.ts`,
> `src/audit/combine.ts`; exported from the root entry per §15). The 9 event
> names and `ip` field are in `src/ports/audit.ts`. The use-cases that *emit* the
> new names land with their features (S2 identity.verify, S3 client_credentials,
> S5 device, S6 cimd); the sinks + type are stable now so later sessions only
> call `writeAuthEvent`. Fail-open verified: each sink's `writeAuthEvent` never
> rejects, and `combineAudit` survives any subset of sinks rejecting.

- **Decision: no new port.** `AuditPort` IS the sink boundary; a second
  `AuditSinkPort` would be indirection with no gain. v0.2 ships reference
  implementations:
  - `JsonlFileAudit(filePath)` — one `JSON.stringify`d event per line
    (JSON encoding escapes newlines ⇒ log-injection-safe by construction),
    `O_APPEND` writes, file created `0600`; NO rotation (logrotate is the
    deployer's).
  - `WebhookAudit(url, { timeoutMs = 5000, headers?, fetchImpl? })` — per-event
    POST, https required (raw prefix check), redirects not followed, at-most-once
    (no retry). Deliberately NOT behind the 17.1 SSRF guard: the URL is
    static deployer config (trusted), and SIEM collectors legitimately live
    on private networks — documented rationale. `fetchImpl` is an optional DI
    seam (defaults to the global `fetch`) for test-injecting the transport
    without an https server; not a deployer-facing knob.
  - `combineAudit(...sinks)` — fan-out; one sink's failure never stops the
    others.
- **Failure policy:** an audit-write failure NEVER blocks the auth operation
  (matches `RateLimitPort`'s advisory posture — audit is evidence, not a
  gate); failures surface on stderr. Residual (threat model): audit loss under
  sink outage — deployers with hard evidence requirements should use the file
  sink + a log shipper.
- **New `AuthAuditEventName` values:** `identity.verify`,
  `oauth.pairing.attempt`, `oauth.device.authorization`,
  `oauth.device.approve`, `oauth.token.device_code`,
  `oauth.token.client_credentials`, `oauth.client.provision`,
  `oauth.client.rotate_secret`, `oauth.cimd.fetch`. `AuthAuditEvent` gains
  optional `ip?: string` (adapter-populated; personal data — noted in docs).
  The §13 metadata-only rule is unchanged and the no-secrets serialization
  test extends to every new event.
- **Retention: documentation guidance, not a library mechanism.** The library
  emits; the deployer retains (compliance frameworks set their own periods).

### 17.8 Quickstart secret persistence (auto-keygen)

`loadOrCreateQuickstartSecrets({ dir = "./.mcp-sso" })` →
`{ signingPrivateJwk, consentSigningSecret }`:

- If `${dir}/secrets.json` exists: load, validate shape (§5 boot checks), and
  on POSIX **reject group/other-readable files** (`mode & 0o077` ⇒ boot error
  with the exact `chmod 600` remediation; the check is skipped on Windows,
  documented). If absent: generate (EC P-256 keypair via jose; consent secret
  = base64url(48 bytes)), `mkdir` `0700`, write `0600` with `O_EXCL`, and
  write `${dir}/.gitignore` containing `*` so the directory can never be
  committed.
- **Fail-closed:** unwritable directory, partial write, bad permissions, or
  an unparseable file is a boot `AuthConfigError`. NEVER fall back to
  ephemeral in-memory keys — silent key rotation on restart would invalidate
  every outstanding token while masking the misconfiguration.
- Env-var configuration remains the primary production path; this is the
  zero-setup path (same audience as 17.5). Threat-model entry: plaintext key
  material on disk, boundary = the OS user account; production belongs in
  env/secret managers. (`npx mcp-sso init` remains a possible wrapper later;
  the function is the contract.)

### 17.9 Worked-example design notes (v0.2 examples)

- Express + Hono equivalents of `examples/fastify-sqlite` — execution only,
  no new contract surface. Examples use console pairing (17.5) or a real IdP;
  the `DEV_STUB_SUBJECT` pattern is removed.
- **API-key-gateway example** (mcp-sso as the SSO front door for a backend
  that only accepts a static API key): the backend key lives in an env var
  (`BACKEND_API_KEY`), read once at boot into a closure — never logged, never
  audited, never present in token claims or responses; injected server-side
  on the proxied backend call only after `RequestAuthorizer` accepts the
  bridge-minted token. Missing key = boot failure. Secret-manager integration
  is out of scope for the example but the read is isolated behind a single
  `getBackendCredential()` swap point. The MCP client never sees the key.

### 17.10 distributed `RateLimitPort` (Redis/Valkey) — shipped v0.1.2

> Implemented at `src/rate-limit/redis.ts` (subpath `./rate-limit/redis`); `ioredis`
> is an optional peer dep. Retained under §17 (contracts) as the locked spec for the
> shipped adapter, not a forward-looking v0.2 contract.

Scope confirmed earlier (roadmap): a Redis/Valkey-backed `RateLimitPort`
ONLY — not a Redis `StorePort`. Contract: fixed-window counter per key — one Lua
script does atomic `INCR` + `EXPIRE`-on-first-increment (the TTL is set exactly
once per window, on `n == 1`; never reset mid-window). Config
`{ windowSeconds: number, limit: number, keyPrefix?: string }` (`keyPrefix`
defaults to `mcp-sso:rl:` so a shared Redis is namespaced; it MUST NOT collide
with a non-string key, which would degrade to fail-open). Constructor validates
both `windowSeconds` and `limit` as positive integers (fail-closed on misconfig).
Keys are as in §6.7 (`register:<ip>` etc.). Failure semantics are UNCHANGED from
§6.7: `check()` THROWS on Redis error, so the bridge `guard()` fails OPEN
(availability over advisory defense). Client library enters as an optional peer
dep through the §15 ledger process (15-day rule). The hot path runs the script via
`EVALSHA` (Redis caches compiled scripts by SHA1 after the first call, so only the
hash crosses the wire); on `NOSCRIPT` (Redis restart or `SCRIPT FLUSH`) it falls
back to `EVAL`, which re-loads the script for next time. Atomicity and fail-open
are identical either way.

## 18. Contract-change protocol

1. Update **this document** first (port/schema/error/endpoint/TTL).
2. If a runtime behavior changed, check the threat model and the store-conformance
   invariants (§12) — and whether it affects memory/sqlite/mysql parity (and any
   further downstream SQL adapter).
3. Then change code; the conformance suite and unit tests must stay green.
4. Never weaken a fail-closed control to make a test pass. If a test and a
   fail-closed rule conflict, the rule wins; change the test (and document why).
