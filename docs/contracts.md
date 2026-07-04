# Contracts

> **Contract-first.** This document is the source of truth for every port, schema,
> endpoint, token claim, and error shape in `mcp-idp-bridge`. It is written and
> reviewed **before** implementation code, and it MUST be updated before any change
> to a port, schema, or error shape. `docs/threat-model.md` reasons about this
> surface; `docs/dependency-ledger.md` records the pins. If code and this document
> disagree, this document wins until one of them is deliberately changed.
>
> Status: **v0.1** (private). Spec conformance target: **MCP Authorization
> 2025-11-25** (the stable spec clients implement), with the **2026-07-28 RC**
> hardening items built in now because all are backward-compatible additions.

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
17. [Contract-change protocol](#17-contract-change-protocol)

---

## 1. Purpose & scope

`mcp-idp-bridge` is a spec-correct **OAuth 2.1 layer for remote MCP servers** with
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
memory + sqlite reference adapters and a shared conformance suite, and the
identity-port boundary.

**v0.1 does NOT include:** framework adapters (`/fastify` `/express` `/hono`),
concrete identity-port implementations (Cloudflare Access, Entra), a runnable
example, multi-tenant/SaaS, UI beyond the consent page, generic-OIDC-provider
ambitions, token introspection, or the CIMD implementation (its port boundary is
defined now; impl is v0.2). Those are later phases — see `docs/threat-model.md`
for the boundary.

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
- **`StorePort` is the parity boundary.** The in-tree memory + sqlite adapters
  and **any downstream SQL adapter** must all satisfy the §12 invariants — that
  is exactly what fix #3 (documented rotation backfill) makes possible. Parity is
  asserted by the shared conformance suite, not by copying code.
- **Identity is pluggable.** The core never depends on a specific IdP; an
  `IdentityPort` (§6.5) resolves the verified subject. Concrete implementations
  arrive in Phase 3.
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
Append-only, metadata-only (see §13). Reference: `noopAudit` (tests) and a
`ConsoleAudit`. Tool-call auditing is the host app's concern, not this library's.

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

### 6.5 `IdentityPort` (boundary now; implementations Phase 3)
Resolves a **verified subject** from an inbound authorize request. The core's
`authorize` use-case takes a required `subject: string`; the adapter/composition
root calls an `IdentityPort` to obtain it (or fails closed). Implementations:
- **CloudflareAccessIdentity** — verifies `Cf-Access-Jwt-Assertion` (RS256 against
  CF JWKS, aud/iss checked), subject = verified email.
- **EntraIdentity** — upstream OIDC auth-code+PKCE against Entra v2.0; ONE app
  registration for the bridge; validate iss/aud/tid; map oid/email → subject. The
  bridge then issues its OWN audience-bound tokens (no passthrough).

`GenericOidcIdentity` only if it falls out naturally. Concrete shapes are fixed in
Phase 3; the boundary is stated now so the core never depends on a specific IdP.

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
Reserved for v0.2 Client-issued Metadata Discovery. **Any metadata fetch MUST go
through an SSRF-guarded `FetcherPort`** (reference: Captatum's `guardedFetch`
design — scheme allow-list, CRLF rejection, resolved-IP private-range check,
connect-to-IP, per-hop re-validation, byte cap, timeout). v0.1 does no outbound
fetching; the boundary exists so v0.2 cannot accidentally add a raw `fetch`.

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
`iss`=issuer, `aud`=`"mcp-idp-bridge/consent"`, `sub`=verified subject,
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
`SqliteStore`, and any downstream SQL adapter must pass the same suite. **Fix #3**
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

**Async-store transaction hygiene (addendum 13 — for any pooled/async adapter,
e.g. a MySQL-compatible or Postgres store):** acquire the connection → `begin` INSIDE the `try`
(behind a begun-guard) → `release` in `finally` on EVERY path, including a
`begin` throw; swallow cleanup errors from `rollback`/`release` so the original
error propagates. A `begin`-failure that leaks a connection otherwise exhausts the
pool = an auth outage. (The in-tree memory + sqlite adapters are synchronous, so
this is forward guidance for async adapters.)

## 13. Audit contract

Append-only `AuthAuditEvent`s, **metadata-only**. No token values, no
`Authorization`/`Set-Cookie`, no request bodies; redirect URIs canonicalized to
host. Events: `oauth.register`, `oauth.authorize.prepare`, `oauth.authorize.approve`,
`oauth.token.authorization_code`, `oauth.token.refresh`, `oauth.revoke`,
`auth.request`. Each carries `occurredAt`, `event`, `status: "success"|"failure"`,
and optional `clientId`, `subject`, `resource`, `scopes`, `redirectHost`,
`reason`. The test suite asserts that serialized audit output never contains raw
codes, refresh tokens, or access tokens.

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

Single package `mcp-idp-bridge`. Runtime dep: **`jose` only**. Framework adapters
and identity ports are optional `peerDependencies` (the consumer installs the one
framework/IdP it uses); `node:sqlite` is built-in (no dep). A SQL adapter is a
downstream/local concern. No postinstall, no bundler. Dev runs on **Node 24 native
TS** (`.ts` imports, no build step); the published artifact is plain-`tsc` ESM +
`.d.ts`.

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
  "./fastify":                  { "types": "./dist/adapters/fastify.d.ts",         "default": "./dist/adapters/fastify.js" },
  "./express":                  { "types": "./dist/adapters/express.d.ts",         "default": "./dist/adapters/express.js" },
  "./hono":                     { "types": "./dist/adapters/hono.d.ts",            "default": "./dist/adapters/hono.js" },
  "./identity/cloudflare-access": { "types": "./dist/identity/cloudflare-access.d.ts", "default": "./dist/identity/cloudflare-access.js" },
  "./identity/entra":             { "types": "./dist/identity/entra.d.ts",             "default": "./dist/identity/entra.js" }
}
```

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
| CIMD (SSRF-guarded FetcherPort) | ⏳ boundary v0.1, impl v0.2 | §6.6 |
| Framework adapters (`/fastify` `/express` `/hono`) | ✅ Phase 3 | §9.6, §15 |
| Identity ports (Cloudflare Access, Entra) | ✅ Phase 3 | §6.5 |

**RC re-check gate:** the 2026-07-28 RC is treated as additive hardening built in
now; revisit it when it finalizes (~end July 2026) before anything is called v1.0.
The RC changes nothing about the RS model or the bridge architecture.

## 17. Contract-change protocol

1. Update **this document** first (port/schema/error/endpoint/TTL).
2. If a runtime behavior changed, check the threat model and the store-conformance
   invariants (§12) — and whether it affects memory/sqlite parity (and any
   downstream SQL adapter).
3. Then change code; the conformance suite and unit tests must stay green.
4. Never weaken a fail-closed control to make a test pass. If a test and a
   fail-closed rule conflict, the rule wins; change the test (and document why).
