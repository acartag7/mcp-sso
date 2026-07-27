# Contracts

> **Contract-first.** This document is the source of truth for every port, schema,
> endpoint, token claim, and error shape in `mcp-sso`. It is written and
> reviewed **before** implementation code, and it MUST be updated before any change
> to a port, schema, or error shape. `docs/threat-model.md` reasons about this
> surface; `docs/dependency-ledger.md` records the pins. If code and this document
> disagree, this document wins until one of them is deliberately changed.
>
> Status: **v0.2.3 shipped** (`mcp-sso@0.2.3` on npm); **v0.3 implementation
> is pending release**. §17 contains a mix of shipped, implemented-on-main, and
> contract-only surfaces; do not infer release status from a section's
> presence. Spec conformance target: **MCP
> Authorization 2025-11-25** (the stable spec clients implement); the next
> spec version is **final on 2026-07-28** (its RC was locked 2026-05-21) —
> the RC's backward-compatible hardening items (e.g. RFC 9207 `iss`) are
> built in now. Before any release claims conformance with the 2026-07-28
> final text, the manual maintainer checklist in
> [`docs/verification.md` — "Spec-release re-verification (due
> 2026-07-28)"](verification.md#spec-release-re-verification-due-2026-07-28)
> MUST be completed.

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

**v0.1 did NOT include:** multi-tenant/SaaS, UI beyond the consent page,
generic-OIDC-provider support (the `GenericOidcIdentity` port + Google preset
landed in v0.2/S4a; v0.1 shipped only Cloudflare Access + Entra as concrete
identity ports), token introspection, or the CIMD implementation (its port
boundary is defined now; impl is v0.2). Framework
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

### 4.1 Dynamic-key and parsed-record composition boundary

> **CONTRACT ONLY — implementation is gated.** This is the bounded replacement
> for a rejected repo-wide own-property sweep. The frozen acceptance rows below
> land in their own PR before any implementation.

This contract applies only when an externally controlled value is used as a
property key, or when an untrusted parsed record is copied into another record.
It does not require generic own-property parsing for fixed, statically named
field reads.

- A dynamic lookup uses `Map`, a null-prototype record, or an `Object.hasOwn`
  guard. An inherited entry is absent and follows that boundary's existing
  missing/unmapped failure.
- A dynamic write cannot invoke an inherited setter. It uses `Map` or a
  null-prototype record. `__proto__` and `constructor` either remain inert data
  in that container or are excluded by an explicit projection before
  composition.
- An untrusted parsed record is never spread or assigned wholesale into an
  ordinary security-sensitive record. Code projects the named fields the
  boundary consumes; unknown fields remain ignored.
- No descriptor walk, accessor classifier, recursive snapshot, or general
  own-property DSL is part of this contract.

The first bounded gates are:

| Boundary | Required behavior | Existing failure behavior |
|---|---|---|
| Hono-owned header/query-name accumulation (§9.6) | Attacker-controlled keys are written to a null-prototype record; `__proto__`/`constructor` cannot change the normalized record's prototype | Missing or malformed OAuth fields retain the endpoint's existing `invalid_request` or field-specific rejection; no new error taxonomy |
| Entra group→scope lookup (§17.4) | A verified group GUID can select only an own mapping entry or equivalent `Map` entry; an inherited match contributes no scopes | With groups present, no own mapped group, and empty `baseScopes`: `entra_no_mapped_groups` |
| CIMD parsed document composition (§17.1.3) | The returned document is the named projection of `client_id`, `client_name`, and `redirect_uris`; the parsed source record is not exposed for a later spread/merge. Unknown `__proto__`/`constructor` members are ignored like other extensions | Malformed known members remain `document_invalid`; the unknown names alone do not reject an otherwise valid document |

The Entra implementation already uses `Object.entries` plus `Map`; that is the
compliant pattern and needs an acceptance pin, not a rewrite. Hono normalization
and removal of CIMD's unused `raw` record are implementation-pending. Before
either changes, a separate frozen-acceptance PR adds one polluted-prototype
negative row (plus its ordinary positive control) for each table row. The
implementation PR mutation-verifies each row independently.

Pre-existing host-level prototype pollution and deliberately hostile in-process
ports or adapters are outside the remote-attacker threat model: code already
executing in-process can replace the verifier itself. This residual is explicit
in threat-model row 34.

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
  // Every entry MUST satisfy the §10.0 redirect-entry grammar (canonical origin
  // or exact-URI form). Enforced at boot by createBridgeConfig (§5): the array
  // is snapshotted once, validated, frozen, and published as the same copy.
  // An EMPTY array is valid — the built-in defaults cover the common case.
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

  // --- CIMD (opt-in; Client ID Metadata Documents; see §17.1 + §17.1.5) ---
  cimd?: {
    enabled: true;
    // No `fetcher` knob (§17.1.6 decision 5): the core constructs the branded
    // guarded fetcher from these caps + allowLoopback derived SOLELY from
    // dev.allowInsecureLocalhost. Tests inject only below-guard cimdTransport/
    // cimdResolver deps (never a whole GuardedFetcher).
    maxDocumentBytes?: number;    // integer [1024, 65536], default 5120 (§17.1.5 rule 21)
    fetchTimeoutMs?: number;      // integer [1000, 30000], default 5000
    cacheTtlCapSeconds?: number;  // integer [60, 86400], default 3600
    maxInFlight?: number;         // integer [1, 64], default 8 (global in-flight cap)
    maxWaitersPerFetch?: number;  // integer [1, 4096], default 256 (followers parked on ONE fetch; §17.1.6 dec 7)
  };

  // --- TTLs (seconds); each MUST be a positive integer ---
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  consentTokenTtlSeconds: number;
  authorizationCodeTtlSeconds: number;
}
```

**Boot validation (all throw `AuthConfigError`, never warn):**

- The input admits **only** the `BridgeConfig` fields enumerated above — no
  other own property (string- or symbol-keyed). Any extra key is a boot
  `AuthConfigError` **naming the offending key**. The frozen `bridge.config`
  object is the thing passed to every adapter and consent renderer, so a value a
  JS/cast-TS caller parked on the input — e.g. a backend API key, or a typo like
  `issuers` — would otherwise ship on that public object. Park secrets in your
  own closure; do not put them in the `createBridgeConfig` input.
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
- `redirectAllowlist` is an array, and **every entry satisfies the §10.0
  redirect-entry grammar**. `createBridgeConfig` snapshots the array once,
  validates that copy, and publishes the same frozen copy — origin form or canonical exact-URI form, `https`/
  `http` only, no wildcard, userinfo, query, fragment, whitespace, control
  character, backslash, or malformed percent-escape. Each rule is checked on the
  RAW entry as well as any parsed field (§10.0 explains why: WHATWG
  normalization erases the syntax the decision depends on). An empty array is
  valid. The error **names the offending entry** and, for a non-canonical one,
  shows its canonical form — a deployer with several origins configured must not
  have to bisect.

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
(`findGrantedScopes` is invoked ONLY in **stored-DCR mode for opaque clients** — per
§17.1.6 decision 3, every scheme-shaped (`https://`/CIMD) client_id stands alone
(`priorScopes = []`) in both modes, because refresh rows carry no registration
provenance. In stateless mode client_ids are ephemeral, so a grant keyed by
`(subject, clientId)` is meaningless; those authorizations stand alone.)

### 6.4 `ClientStore` (stored-DCR mode only — fix #4)
```ts
type ApplicationType = "native" | "web" | "machine";   // "machine" added §17.2

interface ClientSecret {                               // §17.2 machine only
  hash: string;                 // unsalted SHA-256 hex of the secret string
  createdAtEpoch: number;       // UTC seconds
  expiresAtEpoch?: number;      // UTC seconds; undefined = live until rotated
}

interface UserClientRegistration {
  clientId: string;
  redirectUris: string[];        // ≥1, validated via §10
  applicationType: "native" | "web";   // RC item (b)
  issuedAtEpoch: number;
}
interface MachineClientBase {
  clientId: string;             // "mcc_<random>" — sub prefix marks machine tokens
  redirectUris: string[];       // always [] — machine clients have no redirect
  applicationType: "machine";
  issuedAtEpoch: number;
  name?: string;                // deployer-supplied display label (unverified)
  allowedScopes: string[];      // ⊆ scopeCatalog, validated at provisioning
  version: number;              // positive integer; incremented by every mutation
}
type MachineClientRegistration =
  | (MachineClientBase & {
      status: "active";
      secrets: [ClientSecret] | [ClientSecret, ClientSecret];
    })
  | (MachineClientBase & {
      status: "disabled";
      secrets: [];
      disabledAtEpoch: number;
    });
type ClientRegistration = UserClientRegistration | MachineClientRegistration;

interface ClientStore {
  save(client: UserClientRegistration): Promise<void>;
  find(clientId: string): Promise<ClientRegistration | null>;
}

interface MachineClientMutationAudit {
  occurredAt: string;
  event: "oauth.client.provision" | "oauth.client.rotate_secret" | "oauth.client.disable";
  clientId: string;
  scopes: string[];
}

interface MachineClientStore extends ClientStore {
  createMachineClient(
    client: Extract<MachineClientRegistration, { status: "active" }>,
    audit: MachineClientMutationAudit,
  ): Promise<boolean>;  // false = id already exists; no write/audit committed
  compareAndSwapMachineClient(
    expectedVersion: number,
    client: MachineClientRegistration,
    audit: MachineClientMutationAudit,
  ): Promise<boolean>;  // false = missing/version conflict; no write/audit committed
}
```
Required only when `dcr.mode === "stored"`. Reference: in-memory map (Phase 2);
a persisted adapter is deployment-specific. The `applicationType` discriminant
selects the record shape and drives the per-client redirect policy (§10):
`native`/`web` are user clients (§9.2 DCR, §10.2 redirect policy); `machine`
records are provisioned out-of-band (§17.2) and carry `allowedScopes` +
versioned lifecycle state instead of redirect URIs. Active records carry exactly
one or two secret hashes. Disabled records carry no secret hashes and a required
disable epoch. A discriminated union makes the disabled-but-still-authenticating
state unrepresentable. `MachineClientStore` is required by the exported
provision/rotate/disable use-cases. `ClientStore.save` accepts user registrations
only; every machine-record write goes through `createMachineClient` or
`compareAndSwapMachineClient`. Each mutation method MUST commit the client row
and supplied required durable audit event in one backend transaction or commit
neither; `false` is a conflict/no-write result. The ordinary `AuditPort` event
emitted after that transaction is only a best-effort fan-out copy and is not the
durable evidence gate.

### 6.5 `IdentityPort` (boundary defined at Phase 2; Cloudflare Access + Entra implementations shipped at Phase 3)
Resolves a **verified subject** from an inbound authorize request. The core's
`authorize` use-case takes a required `subject: string`; the adapter/composition
root calls an `IdentityPort` to obtain it (or fails closed). Implementations:
- **CloudflareAccessIdentity** — verifies `Cf-Access-Jwt-Assertion` (RS256 against
  CF JWKS, aud/iss checked), subject = the token's `sub` (a stable CF identity id; `email` the fallback — opaque-`sub`-first, matching the Entra `oid`-first sibling; CF carries the email in a separate claim, so do not key on email).
- **EntraIdentity** — upstream OIDC auth-code+PKCE against Entra v2.0; ONE app
  registration for the bridge; validate iss/aud/tid; map oid/email → subject. The
  bridge then issues its OWN audience-bound tokens (no passthrough).

`GenericOidcIdentity` and the Google preset ship as `RedirectIdentityPort`s
(S4a); the dedicated GitHub port and the console-pairing port are covered in
§17.5–§17.6 (console-pairing shipped S1b; GitHub still locked). The
**upstream redirect-leg orchestrator** (`RedirectIdentityPort` +
`createUpstreamRedirectFlow` — the mounted browser-redirect flow the Entra
primitives currently leave to the host) is locked in **§17.11**.
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
- **Required construction config MUST be non-empty.** A blank required field —
  CloudflareAccess `audience`, Entra `tenantId`/`clientId`, generic-OIDC
  `clientId`/`issuer`/`redirectUri` — fails closed at construction (empty ==
  missing config). A blank value would otherwise build a malformed URL or make the
  `aud` check vacuous instead of raising a clear boot error.
- **Optional subject allowlist (defense-in-depth).** A port MAY accept a
  case-insensitive, trimmed subject/email allowlist; empty ⇒ delegate entirely to
  the IdP's own policy (e.g. Cloudflare Access Zero Trust). Never the sole gate.
- **Unit-testable claim validation.** Export the claim-validation logic as a pure
  function so it is unit-testable WITHOUT the JWKS network fetch.
- **Entra multi-tenant.** When `allowedTenantIds` is set, `tid` must be allowlisted
  AND `iss` must equal `entraIssuer(payload.tid)` (the standard Entra multi-tenant
  issuer pattern). Unset ⇒ single-tenant: `iss` must equal `entraIssuer(config.tenantId)`.
- **Entra nonce.** Pass a `nonce` in `getAuthorizationUrl` and validate `payload.nonce`
  on return (OIDC request binding) — recommended. The §17.11 redirect orchestrator
  always does this (orchestrator-minted CSPRNG nonce, threat-model row 31).
  **Header-driven mode (`identityHeader`) residual:** when a fronting proxy
  delivers a raw Entra id_token in a header, mcp-sso never minted the nonce, so
  the port's verifying wrapper (`createEntraIdentity().verify` /
  `verifyEntraIdToken` — jose `jwtVerify` enforces the RS256 signature and
  expiry, then the pure `validateEntraIdToken` claim checks apply: iss/tid/aud,
  and `nonce` only when an expected value is set) does NOT replay-bind the
  token. `validateEntraIdToken` alone is claim validation on an
  ALREADY-signature-verified payload (exported pure for unit-testability — it
  never checks the signature and only requires `exp` presence); a custom
  `IdentityPort` MUST route raw tokens through the verifying wrapper, never
  the pure validator alone. Replay
  protection for a header-delivered id_token belongs to the fronting proxy —
  deploy header mode only behind a proxy that itself performed the nonce-bound
  code exchange and verified the token before forwarding (Cloudflare Access's
  signed assertion is the model), never behind one that merely relays tokens it
  did not validate. Documented as the row-12 residual in the threat model.
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
**Hono has no framework `req.ip`:** the hono adapter takes an explicit
`clientIp?: (c: Context) => string | undefined` option and NEVER reads
`X-Forwarded-For` (or any other client-supplied header) on its own — an
attacker-controlled header must not select the rate-limit bucket
(bucket-per-request = limiter bypass) or forge the audit `ip`. Without
`clientIp`, requests carry no IP: the limiter keys everything into the one
shared `unknown` bucket (collectively throttled, never bypassable) and audit
events omit `ip`. A deployer behind a trusted proxy supplies an extractor
wired to their actual topology (e.g. the rightmost trusted `X-Forwarded-For`
hop, or the runtime's connection info).

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
`code_challenge_method`=`"S256"`, `state`?, `allowed_scopes`? (space-joined
identity ceiling — §17.4; present only when the resolved identity supplied an
`allowedScopes` ceiling, so `approve` re-intersects from the *verified token*
rather than client-resupplied input), `cimd_verified`? (§17.1.6 decision 3 —
boolean `true` only, minted ONLY on genuine CIMD validation; OMITTED when
absent/false; any present non-`true` value fails verification), `jti` (random,
single-use), `iat`, `exp`. Verified with `algorithms: ["HS256"]`, pinned iss+aud, clock from
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
`redirect_uris` is client-supplied untrusted input and carries the same hard
caps §10.0 states: **1..16 entries** (the same bound §17.1.5 rule 19 puts on a
CIMD document's array, same rationale — it bounds the authorize-time
exact-match scan) and **≤ 2048 UTF-8 bytes per entry, checked on the raw
string before parsing**.
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
  recorded on the `ClientRegistration` (with `applicationType`, default
  `"web"`). Each entry MUST be
  §10.0-valid **in fully canonical form** — the omitted-root-slash exemption is
  `redirectAllowlist`-only and does NOT extend to DCR, so `https://a.test` is
  REJECTED `invalid_redirect_uri` at registration rather than accepted and
  folded to `https://a.test/`. Reject-don't-fold rather than the earlier
  "recorded verbatim" (which let a client register a URI it could never
  authorize with) and rather than accept-then-canonicalize (which creates a
  twin: the server stores and echoes a spelling different from the one the
  client sent, and §10.2's RAW comparison then refuses the client's own
  original spelling). One accepted spelling in, the same bytes stored, the
  same bytes echoed, and the same bytes matched at authorize — which is what
  makes raw equality sound end to end. The DCR RESPONSE therefore echoes
  exactly what was registered. At **authorize time** the `client_id` MUST exist in the store and
  the presented `redirect_uri` MUST match that client's **per-type policy (§10.2)**
  — native ⇒ RFC 8252 loopback any-port, web ⇒ https exact. This is the RC-aligned
  path: native and web clients get the right redirect handling by type, instead of
  loopback-for-everyone.
- **Machine-shape rejection (§17.2).** Open registration can NEVER mint a
  secret-bearing (machine) client: a request naming
  `token_endpoint_auth_method` other than `"none"`, or a `grant_types`
  containing `client_credentials`, is rejected with `invalid_client_metadata`
  (400) in BOTH modes. `application_type: "machine"` is likewise not a valid
  DCR value. Machine clients are provisioned out-of-band only.

### 9.3 Authorize + consent

**Validation order & error channels (RFC 6749 §4.1.2.1).** The authorize flow has
two error channels, split by whether the `redirect_uri` is trusted yet:

- **Direct HTTP error (NEVER redirect)** — pre-validation failures where the
  redirect destination is untrusted: identity not resolved/rejected (the resource
  owner could not be authenticated), a subject in the reserved `mcc_` machine
  namespace (RFC 9700 §4.15.1 — user grants must never mint a `sub` an RS would
  classify as a machine token; enforced at `prepare`, the choke point every
  user grant passes through, and re-checked in the §9.4 grant handlers BEFORE
  any side effect so a legacy stored code/refresh record from a pre-guard
  deployment cannot keep minting: a legacy code is burned (single-use) but no
  refresh token is saved and no success is audited; a legacy refresh record's
  WHOLE family is revoked — `invalid_grant` either way), missing `client_id`,
  and `redirect_uri` failing §10. Also, at `approve`: a CSRF/`origin` failure (`invalid_origin`) and
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
codeChallengeMethod, resource?, scope?, state?, subject, allowedScopes?, registration? })`** → `PreparedConsent`:
*(`registration?: CimdRegistration` — §17.1.6 decision 1c; supplied ONLY by the
upstream-redirect orchestrator for a carried CIMD registration, NEVER bound to
client-controlled request input; when present, `prepare` uses it and does not fetch.)*
1. `subject` REQUIRED (the adapter/`IdentityPort` resolves it before calling
   `prepare`). No subject ⇒ `access_denied` 401 **direct**, never a placeholder.
2. `client_id` present and `redirect_uri` **mode-appropriately validated** (§17.1.6
   decision 1a): §10 for an opaque non-scheme id; the shared CIMD document matcher for
   a validated lowercase-`https://` CIMD id (from the carried `registration` or the
   §17.1.4 success cache/fetch); any other scheme-shaped value ⇒ direct
   `invalid_client` — else **direct** (pre-validation).
3. *(redirect-eligible from here)* `response_type=code`; `resource` **defaults to
   `config.resource` when omitted and MUST equal `config.resource` when present**
   (else `invalid_target`); `scope` normalized per §11 (else `invalid_scope`);
   PKCE `code_challenge_method=S256` + challenge present (else `invalid_request`).
4. **Scope ceiling *(§17.4, shipped S2a).*** When the resolved identity supplied
   an `allowedScopes` ceiling, the requested scopes (and `defaultScopes`, when no
   `scope` was requested) are **narrowed by intersection** with it; an **empty
   intersection ⇒ `access_denied`** over the redirect channel. The ceiling is
   embedded in the consent-token claims (§7.1 `allowed_scopes`). Without a
   ceiling this step is a no-op (v0.1 behavior, including an empty requested set).
5. **Scope accumulation *(RC item (c)) — stored-DCR opaque clients only.*** Load
   `priorScopes = findGrantedScopes(subject, clientId, now)` ONLY for an opaque client
   resolved through `ClientStore` in stored-DCR mode. For **every scheme-shaped
   (`https://`/CIMD) client_id, and in stateless mode, `priorScopes = []`** — never
   keyed on `clientId.startsWith("https://")` and never on `cimd_verified` (§17.1.6
   decision 3; CIMD accumulation is deferred — refresh rows carry no provenance). Those
   authorizations stand alone.
6. Sign the consent token (§7.1), audit, and return
   `{ consentToken, …claims, priorScopes, requestedScopes }`. The consent page
   renders the **delta** = `requestedScopes − priorScopes` as "new" (rendering is
   an adapter concern, Phase 3; the core supplies both sets).

**`approve({ consentToken, approved?, origin? })`** → `{ redirectTo, code?, state? }`:
- **CSRF/`origin`** must be exactly one primitive string equal to the issuer
  origin or a member of `allowedOrigins` — else `invalid_origin` 403 **direct**
  (a foreign origin is never redirected anywhere). `Bridge.handleApprove`
  reads the normalized `NormRequest.headers` through `headerString`; an
  array-valued header or more than one case-insensitive `Origin` key becomes
  absent and fails closed rather than selecting one value.
- **Approve-time scheme gate FIRST (§17.1.6 decision 3):** immediately after
  `verifyConsentToken` and BEFORE the Deny branch below — a lowercase-`https://`
  client_id is approvable only when `cimd_verified === true` AND `cimd` enabled;
  any other scheme-shaped client_id, or `cimd_verified:true` on a non-CIMD id,
  ⇒ direct `invalid_consent` (so a legacy URL-shaped token cannot even be
  Deny-redirected to its attacker `redirect_uri`).
- **Only `approved === true` approves (fail-closed):** anything else — `false`,
  absent, or malformed — ⇒ Deny: the consent token is **not** consumed; redirect
  to `redirect_uri?error=access_denied&state=…`. The adapter's form parsing is
  equally strict (only `true`/`"true"` approves) so a POST missing the
  `approved` field can never auto-approve at either layer. *(Fix #5 — the
  source's unreachable Deny path; the UI button is Phase 3. Hardened 2026-07-07:
  the original text keyed Deny on `approved === false`, which made the ABSENT
  case an approval — a fail-open default on the consent decision.)*
- On approval (the consent token was already verified above, before the scheme gate
  and Deny branch — `authorize.ts:142`), **consume its single-use `jti`** (replay ⇒
  `invalid_grant` **direct** — an integrity failure, not a user-facing denial).
- **Mint the code with the accumulated scopes** — in stored-DCR mode for an opaque
  `ClientStore`-resolved client, the union of `requestedScopes + priorScopes`; for
  **every scheme-shaped (CIMD) client and in stateless mode, exactly the requested
  scopes** (`priorScopes = []` — §17.1.6 decision 3).
  When the verified consent token carries an `allowedScopes` ceiling (§17.4), that
  union is **re-intersected against it** — accumulated prior grants cannot
  resurrect a scope a since-removed group granted. Then 302 to
  `redirect_uri?code=…&iss=<issuer>[&state=…]` (RFC 9207 `iss`, RC item (a)).

### 9.4 Token
`POST /oauth/token`, `cache-control: no-store`. Response:
`{ access_token, token_type: "Bearer", expires_in, refresh_token, scope }`.
*(This is the USER-grant shape — `UserTokenResponse`, returned by
`exchangeAuthorizationCode`/`refresh`/device. The `client_credentials` grant
(§17.2, shipped S3b) returns `MachineTokenResponse`: identical except it has NO
`refresh_token` member at all — not an optional one.)*
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
  `Bridge.handleToken` performs normalized header/body extraction inside this
  error boundary, so a throwing accessor maps to the fixed `internal_error`
  response rather than escaping into framework-specific handling.
- **Consent page *(fix #5)*:** GET `/oauth/authorize` success renders an HTML page
  with **Approve AND Deny** buttons; Deny POSTs `approved=false`, which the core
  redirects as `access_denied` (§9.3). CSP `default-src 'none'; style-src
  'unsafe-inline'`, `X-Content-Type-Options: nosniff`, all values HTML-escaped.
- Framework adapters are optional `peerDependencies` (`fastify`/`express`/`hono`);
  anything added to `devDependencies` for testing gets a `dependency-ledger` entry
  with the 15-day check.
## 10. Redirect-URI policy

### 10.0 The redirect-entry grammar (ONE definition, every consumer)

> **Status: implemented.** The shared predicate is enforced at all nine
> consumers below; the differential table remains historical evidence of the
> parser disagreement this section closed.
>
> **The implementation PR owes exactly this, and it is enumerable rather than
> "one negative test per rejected shape" left to judgment:**
>
> 1. A boot validator applying §10.0 to every `redirectAllowlist` entry —
>    under the §5 read-once/publication rule: the validator snapshots the
>    caller's array, validates THAT copy, and publishes the same frozen copy
>    it validated (never the caller's array), so a post-boot mutation or
>    accessor-backed entry cannot put an unvalidated value where request-time
>    reads look (the validate-vs-publish class). `redirectAllowlist` now follows
>    that rule. **And it is not the only array in the config:**
>    `scopeCatalog`, `defaultScopes` and `allowedOrigins` remain tracked by issue
>    #100 and are deliberately NOT silently fixed here. This obligation owns
>    `redirectAllowlist`; the other three are the same class, tracked by issue
>    #100, and are deliberately NOT silently fixed here. Consumer (5) covers the
>    direct-call path that bypasses boot entirely; this obligation covers the
>    array boot itself owns.
> 2. **Registration-time enforcement (the write side), in BOTH DCR modes:**
>    `registerClient` applies §10.0 to each `redirect_uris` entry BEFORE any
>    other effect, REJECTING any entry that is not already fully canonical —
>    the omitted-root-slash exemption is `redirectAllowlist`-only and does not
>    extend here, so nothing is folded on the client's behalf. Stateless mode
>    validates and echoes the entry unchanged (it persists nothing, but the
>    same endpoint must not accept and echo an entry the grammar forbids: one
>    grammar, every consumer includes the stateless sibling); stored mode
>    additionally persists it unchanged. Registered === echoed === presented,
>    byte for byte, which is what makes §10.2's raw comparison sound. The write side also enforces the **1..16 array
>    cardinality cap** (§9.2, bounding the authorize-time scan) and the
>    **stored client's §10.2 per-type
>    policy**: a `web` registration (the default when `application_type` is
>    omitted) rejects any non-`https` entry, and a `native` registration
>    rejects any non-loopback entry — at WRITE time, not first at authorize.
>    Without that, `http://localhost/cb` registers as `web` (passes the
>    allowlist and §10.0) and then §10.2 refuses it forever, and a
>    non-loopback https entry registers as `native` with the same outcome:
>    the exact register-but-never-authorize defect this obligation exists to
>    close, reachable through type policy instead of canonicality. The raw `redirect_uris` field crosses this boundary as
>    `unknown[]`, never pre-narrowed: `Bridge.handleRegister` hands the raw value
>    through and the §10.0 check rejects a non-string member, never filters it.
>    **Preserving raw members does NOT remove the read-once requirement, and
>    the two land together:** a getter- or Proxy-backed `redirectUris` passed straight
>    to `registerClient` can serve benign entries to the validator and
>    different, unvalidated entries to `ClientStore.save` and to the echoed
>    response. So `registerClient` **snapshots the array ONCE
>    (from one captured length and one read per index after the `Array.isArray`
>    check), validates THAT copy, and persists and echoes the SAME copy** — obligation 1's read-once rule
>    applied to the DCR boundary, with an accessor-backed regression test
>    (an array whose indices return a valid entry on first read and a
>    forbidden one afterwards must be REJECTED or must persist only what was
>    validated — never a mix). Sibling axis, checked: the adapter's own
>    `grant_types` follows the same snapshot discipline, and the §17.2
>    machine-shape rejection (§9.2) depends on seeing unfiltered members.
>    **Preserving the members is only half of it:** every `grant_types` member is a primitive
>    string or the registration is rejected `invalid_client_metadata`** (the
>    §9.2 error for malformed metadata), with `[7]` and `[null]` as witnesses.
>    Preserving a malformed member for inspection and then not inspecting it
>    is strictly worse than filtering it.
>    **The CONTAINER is checked before its members**, on both fields: a
>    present-but-non-array `grant_types` or `redirect_uris` is rejected
>    `invalid_client_metadata`, never coerced. This closes the earlier
>    `stringArray` collapse where every non-array became empty. Witnesses:
>    `grant_types: "client_credentials"`,
>    `grant_types: 7`, and `redirect_uris: "https://a.test/cb"` (the
>    same shape as the `allowedOrigins` substring-gate defect — a bare string where an array is
>    expected) all rejected. Absent remains valid for `grant_types` (it is
>    optional); `redirect_uris` absent is already `invalid_request` per §9.2.
>    **This coercion defect is a CLASS with FOUR members, not two.**
>    `Bridge.handleRegister` also reads `token_endpoint_auth_method` and
>    `application_type` through `formField` (`src/adapters/bridge.ts:114,116`;
>    `src/adapters/http.ts`), whose
>    `typeof value === "string" && value ? value : undefined` collapses a
>    number, `null`, an object, AND the empty string to `undefined`. The Bridge
>    therefore passes both fields raw to `registerClient`. The rule generalizes:
>    **a present DCR metadata field of the wrong type is
>    `invalid_client_metadata`, never coerced to `undefined`/`[]`/absent** —
>    for all four of `redirect_uris`, `grant_types`,
>    `token_endpoint_auth_method`, and `application_type`, each with `7`,
>    `""`, `null`, `{}` witnesses, each exercised through the Bridge per (c)
>    above. **One more incidental the removed `.filter()` was providing:** it
>    dropped EMPTY-STRING members too, so after the prescribed change
>    `grant_types: [""]` is a primitive string that passes the member check and
>    still reaches a gate that only asks `.includes("client_credentials")`.
>    Members must therefore be **non-empty** primitive strings, with `[""]` a
>    witness alongside `[7]` and `[null]`. (`redirect_uris: [""]` is already
>    covered — the empty string is an obligation-6 rejection row.)
>    `registerClient` REJECTS a non-canonical entry at registration,
>    not to store the normalized return: storing a value the client did not
>    send trades this defect for the twin described in §9.2. Write and read
>    guards must land together or the pair is worse than neither.
> 3. §10.2 applying §10.0 to every registered URI **it reads** (stored-state
>    sibling, below) — not only at registration. Covers records written before
>    this grammar existed or populated out-of-band.
> 4. `assertCimdRedirectUri` enforcing §10.0 rather than its own shape rules
>    (§17.1.5 rule 20, as amended there) — AND `projectCimdRegistration`
>    with one CIMD-specific note: **the omitted-root-slash exemption is
>    `redirectAllowlist`-only** (see "Canonical spelling" above), so it does
>    not apply here either — a CIMD `redirect_uris` entry must be
>    the full canonical `href` (`https://a.test/`, never `https://a.test`),
>    and the non-canonical spelling is rejected `document_invalid`. CIMD is
>    the sharpest case for that scoping: config gets a boot error naming the
>    canonical form and DCR gets a rejection at registration, but CIMD has NO
>    response channel at all, so EITHER projection choice for the
>    accepted-then-folded spelling breaks someone silently (project raw: the
>    §17.1.6 exact matcher can never match the canonical form a conforming
>    client presents; project canonical: a client presenting the exact string
>    published in its own document fails). Rejecting the non-canonical
>    spelling at document-validation time is the only choice that keeps
>    stored === published === presented as the same bytes — raw-equality
>    matching stays sound and the author learns at validation, not via a
>    silent authorize failure. The CIMD round-trip test covers both sides:
>    a document entry `https://a.test` is rejected `document_invalid`;
>    `https://a.test/` validates, projects verbatim, and matches a presented
>    `https://a.test/`.
> 5. `assertAllowedRedirectUri` applying §10.0 to every allowlist entry **it
>    reads** before matching (consumer (5) — the export-path sibling of 3;
>    rationale in the consumer list below). A non-conforming entry is refused
>    `invalid_redirect_uri`, never skipped and never matched.
> 6. **One rejection test per row of this closed list.** Two requirements on
>    HOW each row is tested, because without them the whole list is
>    tautological. Before §10.0, every entry-grammar witness below could "pass"
>    by rejecting with `redirect_uri is not allowed` (allowlist NON-MEMBERSHIP),
>    while accepting once the entry was actually placed:
>
>    - **(a0) EVERY row states its setup — rejections included.** The
>      per-consumer setup rule under obligation 7 covers positives only, which
>      left the rejection rows setup-free and therefore membership-gated.
>      Concretely: the DCR omitted-slash row (`https://a.test`) needs
>      `redirectAllowlist: ["https://a.test/"]` or it fails for
>      non-membership; the non-canonical PRESENTED rows need a registration of
>      `https://a.test/cb` (stored: plant the client; stateless: allowlist the
>      origin) or they fail the same way; the presented-fragment row needs its
>      origin reachable — or use a built-in host (`https://claude.ai/cb#frag`)
>      when zero config is the point. Spelled out for that row, the one most
>      likely to be written setup-free: *stored `web`* registers
>      `https://client.test/cb` and presents it with `#frag`; *stored `native`*
>      registers `http://127.0.0.1/cb` and presents that with `#frag`;
>      *stateless* puts `https://client.test/` on the allowlist. Before §10.0,
>      both matchers set `url.hash = ""` and accepted these requests; the tests
>      must fail if that normalize-then-match behavior returns.
>    - **(a) Defeat membership first.** For a matcher/export or stored-read
>      leg, the forbidden string MUST be placed as the allowlist/registered
>      entry under test (or the leg must be pinned to boot / the CIMD document
>      validator, where the entry IS the input). A witness that is merely
>      absent from the allowlist proves nothing about the grammar: probed —
>      `javascript:alert(1)`, `http://a.test/cb`, and
>      `https://client.test/cb#frag` all reject with "not allowed" when
>      unplaced, and all three ACCEPT when placed.
>    - **(b) Assert the REASON, not just the throw.** Each test asserts the
>      error identifies the grammar rule and names the offending entry —
>      never merely that an `OAuthError` was raised. (Rows whose subject is
>      not a single entry — a non-array `redirectAllowlist`, a 17-entry DCR
>      array — assert the field name and the rule instead; "names the
>      offending entry" is not literally satisfiable there.)
>    - **(c) Pin the PRODUCTION path for adapter-boundary rows.** The
>      container/member rows must be exercised through `Bridge.handleRegister`
>      with a raw JSON body, not against `registerClient` alone. The historical
>      bypass was adapter-only (`stringArray` collapsed the malformed container
>      before the core saw it), so a core-only unit test could stay green while
>      the production path remained open.
>
>    The rows. Each asserts the error names the offending ENTRY, **except the
>    field-level rows** — a non-array `redirectAllowlist`, a 17-entry DCR
>    array, and the four wrong-typed metadata fields have no single offending
>    entry to name, so those assert the FIELD name and the rule instead
>    (per (b) above; the blanket wording was not literally satisfiable):
>    `*`; any `*`-bearing entry — in the host
>    (`https://*.a.test/cb`) OR the path (`https://a.test/cb*`,
>    `https://a.test/*`; a host-star is WHATWG-canonical — verified — so the
>    test proves the `*` rule fires on its own, not via canonicality); a non-`http(s)`
>    scheme (`javascript:`, `data:`); userinfo (`https://u:p@a.test`) AND empty
>    userinfo (`https://@a.test`) AND **canonical** userinfo
>    (`https://u:p@a.test/` — its own `href`, so the test proves userinfo is
>    rejected by its own rule, not as a canonicality side effect); a query
>    delimiter — non-canonical (`https://a.test?`) AND canonical
>    (`https://a.test/?`, `https://a.test/cb?`); a fragment — including the
>    canonical trailing forms (`https://a.test/#`, `https://a.test/cb#`); a
>    percent-encoded C0 control or DEL (`https://a.test/cb%0A`, `%0D`, `%00`,
>    AND `%7F` — DEL is in the rule, so it gets its own witness; each
>    canonical, each rejected); a trailing-dot host (`https://a.test.` AND its
>    canonical spelling `https://a.test./`);
>    whitespace (leading/trailing/interior); a literal control character; a
>    backslash; a malformed percent-escape; a non-canonical origin
>    (`HTTPS://A.TEST`, `https://%65xample.com`, `https://a.test:443`, the
>    default-port fold `http://localhost:80`, and ALL THREE IPv4 variant
>    spellings the grammar text names — dword `https://2130706433`, hex
>    `https://0x7f.0.0.1`, octal `https://0177.0.0.1`); a
>    non-canonical exact-URI (`https://a.test:443/cb`, `https://a.test/x/../cb`,
>    `https://a.test/./cb`); an entry longer than 2048 UTF-8 bytes; the empty
>    string `""` AND a whitespace-only entry (degenerate emptiness gets its own
>    witnesses — an empty string is not a parse error to swallow, it is a
>    named rejection); an unparseable entry (`https://`, no host — `new URL`
>    throws, and the thrown case must map to the same named rejection, never
>    propagate) AND a **degenerate authority that PARSES**
>    (`https:///cb` — three slashes; WHATWG reads `cb` as the HOST and yields
>    `https://cb/`, verified, so this is not caught by the throw path and
>    needs its own witness); an entry with interior tab/CR/LF
>    (`https://a.test/c<TAB>b` — stripped by the parser, so only the raw
>    check sees it); a non-canonical IPv6 spelling
>    (`http://[0:0:0:0:0:0:0:1]/cb`, which folds to `http://[::1]/cb`); `http://a.test/cb` (http on a non-loopback host); a
>    non-string entry; a non-array `redirectAllowlist`; a **17-entry DCR
>    `redirect_uris` array** (the §9.2 cardinality cap gets its own boundary
>    witness — per-entry tests cannot catch an oversized array); a `web`
>    registration carrying `http://localhost/cb` AND a `native` registration
>    carrying a non-loopback https entry (the obligation-2 per-type write
>    guard, one witness per type); a PRESENTED `redirect_uri` carrying a
>    fragment (`https://client.test/cb#frag`) rejected at authorize in both
>    DCR modes (the reject-don't-strip rule under "The two matching
>    policies" — before §10.0 both matchers stripped and matched); a CIMD document entry
>    in omitted-slash form (`https://a.test` — rejected `document_invalid`
>    per obligation 4's CIMD tightening) AND a **DCR registration** in the
>    same form (rejected `invalid_redirect_uri`, per the exemption's
>    config-only scope — accepting it would create the twin that breaks the
>    registration-to-authorization round-trip under raw equality); and
>    **non-canonical PRESENTED
>    `redirect_uri`s against a canonical registration** — one witness per fold
>    WHATWG performs, because each collapsed into a false match before §10.0:
>    scheme case (`HTTPS://a.test/cb`), host case (`https://A.TEST/cb`),
>    default port (`https://a.test:443/cb`), dot segments
>    (`https://a.test/x/../cb`), and all of them at once
>    (`HTTPS://A.TEST:443/x/../cb`, verified to normalize to exactly
>    `https://a.test/cb` on Node 24). Each must be REFUSED against a
>    registration of `https://a.test/cb`, in both DCR modes — these are the
>    request-bytes-never-registered cases, and the `web` leg is where the
>    §10.2 exact-match policy lives.
> 7. **Positive tests** that the grammar does not over-reject. **Each case is
>    listed under the consumer it applies to** — this list must never say
>    "every consumer", because the consumers have DIFFERENT admissible sets:
>    the omitted-slash exemption is `redirectAllowlist`-only (obligations 2
>    and 4 reject it), emptiness is `redirectAllowlist`-only (DCR and CIMD
>    require 1..16 entries per §9.2 / §17.1.5 rule 19), and stored DCR
>    additionally partitions by `applicationType`. A positive case asserted
>    against the wrong consumer is a test that CANNOT pass without weakening a
>    rule. **Every case states its SETUP**, because the built-in defaults are
>    exactly `https://claude.ai`, `https://chatgpt.com`, `http://localhost`,
>    `http://127.0.0.1` — `a.test` is NOT among them, and stored DCR validates
>    registrations through the same global allowlist (§9.2), so any `a.test`
>    positive requires `redirectAllowlist: ["https://a.test/", …]` in config.
>    A positive case whose setup is unstated is not reproducible, and an
>    implementer will read the failure as a rule to weaken.
>    - *`redirectAllowlist` (boot)* — the entries ARE the setup: all four built-in defaults; the
>      omitted-slash forms `https://a.test`, `https://xn--80a.test` (punycode
>      — the ASCII form of the Cyrillic host above), `http://[::1]:9`; their
>      canonical spellings; `https://a.test/cb%2F..%2Fadmin` (canonical,
>      inert); **and an EMPTY array** (the built-in defaults cover the common
>      case — §10.0's "empty is valid" rule lives here and only here).
>    - *Stored DCR, `web`* (setup: `a.test` configured): `https://a.test/` and
>      `https://a.test/cb%2F..%2Fadmin` — https, canonical, 1..16 entries.
>      NOT `http://[::1]:9/` (web is https-only) and not an empty array.
>      `https://claude.ai/cb` also passes with an empty config allowlist.
>    - *Stored DCR, `native`* (setup: empty config allowlist suffices —
>      `localhost` and `127.0.0.1` are built-in; `[::1]` is NOT, so
>      `http://[::1]:9/` needs it configured): `http://127.0.0.1/cb`,
>      `http://localhost/cb`, and `http://[::1]:9/` — loopback, canonical.
>      NOT a non-loopback https entry (§10.2 native policy) and not an empty
>      array.
>    - *Stateless DCR*: the **§10.1 global-allowlist set — NOT the `web` set**.
>      Stateless mode persists no `applicationType`, so §9.2's
>      loopback-for-everyone policy applies and the per-type partition above
>      does not exist here. Positives split by SETUP, because the built-in
>      defaults are `claude.ai`, `chatgpt.com`, `localhost`, `127.0.0.1` and
>      nothing else — `a.test` is not among them:
>      *with an EMPTY config allowlist*, `https://claude.ai/cb` plus the
>      canonical loopback paths `http://localhost/cb`,
>      `http://localhost:54321/cb` (any port), `http://127.0.0.1:8080/cb` all
>      pass; *with `redirectAllowlist: ["https://a.test/"]`*, `https://a.test/`
>      passes too. Both verified on HEAD — and `https://a.test/` is REJECTED
>      under the empty-list setup, which is why the two are not one bullet. Borrowing the
>      https-only `web` set here would let an implementation reject the
>      primary native-client loopback path while passing this obligation.
>      §9.2 persists nothing but echoes the accepted entry unchanged.
>    - *CIMD document* (no config allowlist involved — rule 20's own
>      scheme/host rule governs, so no setup is needed):
>      `https://a.test/` plus a loopback `http://[::1]:9/` — canonical
>      spelling, 1..16 entries.
>    Plus a **round-trip** test per applicable consumer: a URI accepted at
>    registration is still accepted at authorize (obligations 2 and 3 agree).
> 8. A **differential test** exercising **all NINE consumers of the closed
>    list — nine legs, numbered to match the consumer list below, because an
>    earlier prose version of this sentence named seven and a skim-implementer
>    could build a seven-leg suite: (1) boot · (2) DCR write, both modes ·
>    (3) §10.2 stored read · (4) CIMD document · (5) exported matcher ·
>    (6) flow-cookie CIMD registration · (7) consent token at approve ·
>    (8) opaque flow-cookie params · (9) authorization-code record.** In
>    detail — boot config, the DCR registration write in BOTH modes (the
>    stateless leg asserts rejection AND that nothing forbidden is echoed;
>    the stored leg asserts rejection before persistence), the §10.2
>    stored-state READ,
>    CIMD document validation, the exported §10.1 matcher called DIRECTLY
>    with an entries array that never passed boot, the flow-cookie CIMD
>    consumption at callback, and the consent-token redirect at
>    `approve`: for each row of the table
>    below, every consumer agrees. The stored-read leg is exercised with
>    **pre-existing/out-of-band state** (a record placed directly in the
>    `ClientStore`, never through `registerClient`); the direct-call leg
>    passes the forbidden entry straight to `assertAllowedRedirectUri`; the
>    flow-cookie leg forges a validly-signed cookie whose carried
>    `CimdRegistration` holds the forbidden entry (modeling a pre-upgrade
>    in-flight cookie) and asserts the callback refuses it; the consent-token
>    leg mints a VALIDLY SIGNED consent token carrying the forbidden redirect
>    (modeling a token issued before the upgrade) and asserts `approve`
>    refuses it on BOTH the Deny and the Approve path, with a DIRECT error
>    rather than a redirect to the suspect value; the opaque-cookie leg
>    forges a signed cookie whose `params.redirect_uri` is forbidden and NO
>    `cimd` claim is present (so the CIMD gate returns early) and asserts
>    every callback error path refuses rather than redirecting to it; the
>    authorization-code leg stores a code record carrying a forbidden
>    `redirectUri` directly in the store and asserts the token endpoint
>    refuses `invalid_grant` even when the presented value matches those
>    bytes and PKCE verifies —
>    wiring the shared predicate into the entry boundaries while any
>    read-time consumer forgets its check must FAIL this test, or a legacy
>    record, a directly-supplied array, an in-flight cookie (CIMD or opaque),
>    a live consent token, or an unexpired authorization code carrying a
>    forbidden entry can still authorize. (The measured table has three
>    columns because the read guards did not exist on `40d9f58`; the
>    test covers nine.) That agreement is the property this section exists to
>    create, and without it the differential can silently return.

Everything below — the §10.1 global allowlist, the §10.2 per-client policy, and
the §17.1 CIMD document/matcher — decides against **this single grammar**. It is
stated first because the alternative has been demonstrated: three call sites
each inferred their own notion of a "valid entry" and disagreed on nearly every
non-obvious input, which is a **parser differential**, not a set of unrelated
bugs. Measured on `40d9f58`:

**Measurement protocol** (stated because the verdict depends on it — an
earlier version of this table gave one column with no protocol and was wrong
in two cells): each entry is placed in `redirectAllowlist` and probed twice —
**self** = present the entry string itself as the `redirect_uri`; **widens** =
present a DIFFERENT path on **that row's own canonical origin** (e.g.
`https://a.test/OTHER` for the `a.test` rows, but
`https://xn--80a.test/OTHER` for the Cyrillic row and
`https://example.com/OTHER` for the percent-encoded row — the probe follows
the origin the entry CANONICALIZES to, which is the whole point of those two
rows). "Widens"
is the origin-wide grant; "self" is whether the entry is a live redirect
target at all.

| entry | §10.1 self | §10.1 widens | CIMD matcher | CIMD doc validator |
| --- | --- | --- | --- | --- |
| `*` | reject | reject | **accept** | reject |
| `https://a.test/cb*` | **accept** | reject | **accept** | **accept** |
| `javascript:alert(1)` | **accept** | reject | **accept** | reject |
| `data:text/html,<script>1</script>` | **accept** | reject | **accept** | reject |
| `https://u:p@a.test` | reject | **accept** | **accept** | reject |
| `https://@a.test` | **accept** | **accept** | **accept** | reject |
| `https://a.test?` | **accept** | **accept** | **accept** | **accept** |
| `HTTPS://a.test/cb` | reject | reject | **accept** | **accept** |
| `https://a.test:443/cb` | reject | reject | **accept** | **accept** |
| `https://a.test/x/../cb` | reject | reject | **accept** | **accept** |
| `https://а.test` (Cyrillic `а`) | **accept** (as `xn--80a.test/`) | **accept** (as `xn--80a.test`) | **accept** | **accept** |
| `https://%65xample.com` | **accept** (as `example.com/`) | **accept** (as `example.com`) | **accept** | **accept** |
| `http://remote.test/cb` | **accept** | reject | **accept** | reject |

**The `javascript:` and `data:` rows were the sharpest reading of the measured
pre-§10.0 behavior:** the old §10.1 matcher had no scheme check and returned
true on exact normalized equality before any other rule, making those entries
live redirect targets when configured. The shared predicate now rejects them
before matching; the table remains the historical evidence for consumer (5).

**Definition.** A redirect entry — whether it comes from `redirectAllowlist`,
a stored `ClientRegistration.redirectUris`, or a CIMD document's
`redirect_uris` — is EXACTLY one of two forms, and nothing else:

- **Origin form** — `scheme "://" host [ ":" port ]`, with **nothing after the
  authority**: no path (or the single `/`), no query, no fragment, no userinfo.
- **Exact-URI form** — origin form followed by a path of **at least one
  non-root segment**: no query, no fragment, no userinfo.

**Classification is total and unambiguous:** the bare authority and the
root-slash spelling (`https://a.test`, `https://a.test/`) are BOTH origin form
— the root slash alone is never an exact-URI path, so no entry satisfies both
definitions. The first character after the authority decides: nothing or a
lone `/` ⇒ origin form; `/` followed by
at least one NON-EMPTY segment ⇒ exact-URI form. A path that is only slashes
(`https://a.test//`) is neither: it is canonical under WHATWG (verified —
`pathname === "//"`) but has no non-empty segment, so it satisfies neither
form and is **REJECTED**. Stating it explicitly because the two readings
disagree — the definition requires a non-root segment while "`/` followed by
anything" would admit it — and an empty-segment path is exactly the shape
that makes two matchers differ.

**Origin form is origin-wide ONLY in §10.1.** The same entry means something
narrower everywhere else, and the difference is security-relevant, so it is
stated rather than left to inference: under **§10.2** (both `web` and
`native`) and under the **§17.1.6 CIMD matcher**, a registered entry matches
by the per-type rule — path included — so an origin-form registration
authorizes only the origin ROOT path. Measured on HEAD: a `web` client
registered `https://app.test/` presenting `https://app.test/cb` is REFUSED
(`src/redirect.ts:86`), while the same entry in `redirectAllowlist` ALLOWS
it; a `native` client registered `http://127.0.0.1/` presenting
`http://127.0.0.1:54321/cb` is likewise refused (`src/redirect.ts:102`
compares `pathname`). A client or document that wants a callback path MUST
register exact-URI form.

**A canonical root callback is VALID and is not rejected.** Registering
`https://a.test/` is a legitimate choice — it authorizes exactly
`https://a.test/`, the origin root, and nothing else — so obligation 2 and
obligation 4 both ACCEPT it, and obligation 4's round-trip witness
(`https://a.test/` validates, projects verbatim, and matches a presented
`https://a.test/`) stands unchanged. What obligation 2 rejects is only the
**omitted-slash spelling** (`https://a.test`), and for the reason stated in
"Canonical spelling" — the twin it would create under raw equality, not
anything about origin form. There is no register-but-never-authorize record
here: a client registering the canonical root gets exactly the grant its
entry describes. The narrowing above is a statement about GRANT WIDTH — an
origin-form entry means origin-wide in §10.1 and root-only in §10.2/CIMD —
not a rejection rule. A deployer who wants
`https://a.test/` to match ONLY the root path cannot express that in origin
form and must accept that the root-slash spelling is origin-wide — stated
here because the two readings differ in grant width, which is exactly the
ambiguity class this grammar exists to remove.

**`http` is loopback-only, in the grammar itself:** the `http` scheme is
valid ONLY with host exactly `localhost`, `127.0.0.1`, or `[::1]`;
`http://prod.example.com/cb` is rejected at the entry boundary, not left for
per-consumer policy. This lifts the rule §10.2 (`web` ⇒ https) and §17.1.5
rule 20 (http ⇒ loopback) already apply into the shared grammar, so
stateless-mode §10.1 — which previously had no HTTPS floor of its own —
cannot be configured to send an authorization code over cleartext to a
non-loopback host.

**Canonical spelling is required in BOTH forms**, not just exact-URI form: the
raw entry MUST equal `new URL(entry).href`, with exactly one exemption — an
origin-form entry MAY omit the root slash WHATWG appends (`https://a.test` is
accepted for `https://a.test/`; nothing else is).

**The exemption is scoped to the §10.1 allowlist — deployer config AND the
built-in defaults — and to nothing else.** The built-ins are themselves
omitted-slash entries (`https://claude.ai`, `https://chatgpt.com`,
`http://localhost`, `http://127.0.0.1` — all four verified non-canonical: each
gains a root slash under `new URL(entry).href`), so the exemption must cover
them or obligation 1's "every built-in default is §10.0-valid" unit test
cannot pass. They are left in that spelling deliberately: it is the form
deployers read in the docs and copy into config, and §10.1 matches them
origin-wide either way (see below).** It is safe exactly there because a §10.1
origin-form entry matches **origin-wide**, never by raw equality against a
presented URI, so the two spellings cannot disagree about a match. **Boot does
NOT rewrite the entry**: the array published is byte-identical to the array
validated (obligation 1's read-once/publication rule — a separately normalized
copy would be an array boot never validated, which is the
validate-vs-publish class this repo has hit six times). The accepted
omitted-slash spelling is therefore stored and matched AS WRITTEN, and it
works because the §10.1 origin branch derives the origin from the parsed entry
rather than comparing its bytes — `https://a.test` and `https://a.test/` both
yield origin `https://a.test`, so the fold happens at COMPARISON time inside
the matcher, never at storage time. A rejection still names the canonical form
to paste back. On every OTHER surface the omitted-slash
form is **REJECTED**, not accepted-then-folded:

- **DCR `redirect_uris`** (obligation 2) — because §10.2 compares registered
  URIs by RAW equality. Accept-then-fold creates a twin: the client registers
  `https://a.test`, the server persists and echoes `https://a.test/`, and a
  client that re-presents its own original spelling fails a comparison that
  forbids normalizing the presented side. Rejecting at registration surfaces
  the fix once, at the moment the client can act on it, instead of as an
  authorize-time failure with no stated cause.
- **CIMD documents** (obligation 4) — same reason, and worse: CIMD has no
  registration response at all, so a fold is invisible to the client.

That leaves ONE spelling in play wherever raw equality decides, on both the
stored and presented sides, which is what makes the reject-don't-normalize
rule internally consistent. Without this rule on origin
form, `https://%65xample.com` is accepted, parses to `https://example.com`, and
is then granted **origin-wide** access to `example.com` under §10.1 — an entry
whose text names one host and whose effect names another, which is precisely
what "reject, don't normalize" exists to prevent. The same applies to
`HTTPS://EXAMPLE.com` and any other spelling WHATWG folds — including two
folds a deployer may not expect: WHATWG **strips the scheme's default port**
(`:80` on `http`, `:443` on `https`), so `http://localhost:80` is
non-canonical and rejected — write `http://localhost`; only a non-default port
survives (`http://localhost:8080`). And WHATWG **resolves alternative IPv4
spellings** — a dword/integer host (`https://2130706433`), hex labels
(`https://0x7f.0.0.1`), and octal labels all fold to `https://127.0.0.1/`
(verified, Node 24), so every one of them is non-canonical and rejected; the
canonical rule is what catches them, and the rejection list below names them so
an implementation checking parsed fields cannot miss the class §17.1.5 rule 6
enumerates for the CIMD client_id.

Two consequences of requiring canonical spelling, recorded so an implementer
does not "helpfully" relax either:

- A **Unicode homograph** entry (`https://а.test`, Cyrillic `а`) is REJECTED
  under §10.0 — it canonicalizes to `https://xn--80a.test/`, so it is
  non-canonical as written. Its punycode spelling (`https://xn--80a.test`) IS
  accepted: that is the entry's true identity, and the deployer wrote what
  they get. The pre-§10.0 matcher accepted the homograph entry and granted it
  `xn--80a.test` origin-wide; the shared grammar now rejects it before matching.
- An entry containing **percent-encoded path characters**
  (`https://a.test/cb%2F..%2Fadmin`) is ACCEPTED and is inert: canonical already,
  and it matches only its own literal self (verified — it matches neither
  `/admin` nor `/cb/../admin`). §10.0 governs entry SYNTAX, not path semantics;
  it grants nothing beyond the exact URI written.

In both forms: `scheme` is `https` or `http` (an allowlist — `javascript:`,
`data:`, `file:` and every other scheme are rejected, never enumerated as
exceptions); the raw entry contains no `*`, no whitespace (leading, trailing, or
interior), no control characters, no backslash, and no `%` that does not begin a
valid percent-triplet. The whitespace rule is checked on the RAW string for a
reason WHATWG makes concrete: it **strips** interior tab, CR, and LF outright
(`https://a.test/c\tb` parses to `https://a.test/cb` — verified), so a
parsed-field check cannot see them at all, and a canonicality check alone
would reject them only incidentally. Leading/trailing whitespace is likewise
trimmed before parsing.

Four more raw rules close the class of entries that are WHATWG-canonical yet
carry syntax the forms above forbid — each is a shape where `entry ===
new URL(entry).href` holds and a canonicality-only validator would therefore
accept what the form definitions reject:

- **No raw `?` or `#` code point anywhere in the entry**, independent of what
  the parser reports. `https://a.test/?`, `https://a.test/cb?`,
  `https://a.test/#`, and `https://a.test/cb#` are all their own `href`
  (verified, Node 24) and all parse to an EMPTY `search`/`hash` — so a
  parsed-field check classifies `https://a.test/?` as origin form and grants it
  **origin-wide** match under §10.1. An empty query is still a query. This is
  the same rule §17.1.5 rule 2 applies to the CIMD client_id, for the same
  reason.
- **No `@` anywhere before the path** — userinfo is rejected by an independent
  check, never as a side effect of canonicality: `https://u:p@a.test/` (with
  the trailing slash) IS canonical, so a validator relying on `entry !== href`
  to catch userinfo accepts it.
- **No percent-triplet whose decoded byte is a C0 control or DEL**
  (`%00`–`%1F`, `%7F`, any hex case): `https://a.test/cb%0A` is canonical
  (verified) and survives the literal-control-character rule above. Same
  decision as §17.1.5 rule 2's %-encoded CR/LF rejection — one verdict for the
  same bytes in both fields.
- **No trailing dot on the host**: `https://a.test./` is canonical under WHATWG
  (the dot is preserved, not folded — verified), but §17.1.5 rule 7 rejects a
  trailing-dot host for the CIMD client_id, and the same host string being a
  valid redirect entry and an invalid client_id is exactly the
  parser-differential class this section exists to kill — **for the same
  BYTES**. That qualifier is load-bearing: the two fields legitimately differ
  on Unicode-vs-punycode (§10.0 rejects `https://а.test` as non-canonical and
  accepts `https://xn--80a.test`, while §17.1.5's client_id rules treat the
  IDNA forms on their own terms), and that is a difference of INPUT
  normalization, not of host validity. The rule this row states is narrower:
  one host STRING must not be valid in one field and invalid in the other.

Percent-hex case is NOT folded: WHATWG preserves `%2f` and `%2F` alike (both
are their own `href`, verified), so both spellings are canonical and they are
**distinct entries** under the exact-string match — an entry written `%2f`
matches only a presented URI carrying `%2f`. This is deliberate: re-serializing
to force one case would be normalization, and the rule is reject-or-accept,
never rewrite.

**Duplicates and IPv6 spelling.** A `redirect_uris` array or
`redirectAllowlist` containing the SAME canonical entry twice is **valid** —
duplicates are inert under both origin-wide and raw-equality matching, and
rejecting them would fail a config that means exactly what it says. They do
count against the §9.2 cardinality cap (the cap bounds the scan, and a
duplicate costs a scan step like any other entry). An **IPv6 host** must be
in WHATWG canonical compressed form: `http://[::1]/cb` is canonical, while
`http://[0:0:0:0:0:0:0:1]/cb` folds to it and is therefore rejected
(verified) — the general canonicality rule already covers this, and it is
named here because IPv6 has more non-canonical spellings than any other host
form. **Custom/private-use schemes** (reverse-DNS native-app schemes like
`com.example.app:/cb`) are rejected by the closed `https`/`http` scheme list,
not by name — there is no per-scheme blocklist to keep current, and adding
support would be a contract amendment, never an implementation choice.

**Hard cap.** Every entry is length-checked on the RAW string BEFORE parsing:
an entry longer than **2048 UTF-8 bytes** is rejected — the same bound §17.1.5
rule 1 places on the CIMD client_id, applied for the same reason (hard caps on
every untrusted input, before the parser sees it). DCR `redirect_uris` arrays
are additionally capped at **1..16 entries** (§9.2 — same bound and rationale
as §17.1.5 rule 19: it limits the authorize-time exact-match scan).
`redirectAllowlist` has no entry-count cap, and that is a decision rather than
an omission: it is deployer-written boot configuration, validated once at boot,
and its size is not attacker-influenced.

**Every rule is checked on the RAW string before, or in addition to, any parsed
field.** WHATWG normalization erases the very syntax the decision depends on —
`new URL` drops empty userinfo (`https://@a.test` yields `username === ""`),
maps a bare `?` to `search === ""`, lowercases the scheme, strips the default
port, and resolves `..` segments. A validator reading only parsed fields is
therefore checking a different string than the one the deployer wrote and the
matcher later compares.

**The grammar has exactly NINE consumers, and this list is closed:**
(1) boot (`createBridgeConfig`) for `redirectAllowlist`; (2) the DCR
registration write in BOTH modes (§9.2 — entries must arrive already
canonical; stored persists them unchanged, stateless persists nothing and
echoes them unchanged, per obligation 2: the
same endpoint must not accept or echo what the grammar forbids); (3) the
stored-state READ at AUTHORIZE (§10.2 — the paragraph below; token
exchange never re-reads the registration on the authorization-code path,
which is precisely why consumer (9) exists); (4) CIMD document validation
(`assertCimdRedirectUri`, §17.1.5 rule 20); (5) the **exported §10.1 matcher
itself** (`assertAllowedRedirectUri`), which applies the predicate to each
allowlist entry it READS before matching; (6) the **flow-cookie CIMD
consumption at callback** (`parseCimdRegistrationClaim` + the §17.1.6
redirect match), which re-validates each carried `redirect_uris` entry —
the second stored-state sibling, detailed two paragraphs below; (7) the
**consent-token redirect at `approve`** (`OAuthAuthorizationUseCase.approve`,
`src/authorize.ts:193-234`), which re-validates `consent.redirectUri` after
verifying the token's signature and BEFORE using it — for the Deny redirect,
for the stored authorization code, and for the success redirect alike. (7) is
the third stored-state sibling and closes the same rolling-upgrade window as
(6): within `consentTokenTtlSeconds`, a consent token signed by `prepare()`
under the OLD grammar carries a redirect the new grammar rejects, and a valid
signature is not a grammar check — the token proves *we issued this*, never
*this entry is still valid*. A non-conforming carried redirect is refused
`invalid_redirect_uri` as a DIRECT error (never a redirect to the value under
suspicion — §9.3's untrusted-destination channel rule); (8) the **opaque
flow-cookie redirect at callback** (`claims.params.redirect_uri`,
read at `src/adapters/upstream-flow.ts:161`), which every callback error path
redirects to BEFORE `bridge.handleAuthorize` re-runs §10 — and there are FIVE
such sites, not two: rows 7/8 (IdP error) at `:176-177` and rows 10/11
(exchange-failed / identity_rejected) at `:182-185`. **The guard is placed
ONCE at extraction**, immediately after the value is read at `:161`, never
per-site, or the three later sites are missed — an opaque
pre-upgrade cookie carries no `cimd` claim, so consumer (6)'s gate returns
early (`assertCallbackCimdPolicy`, `src/adapters/upstream-flow-cimd.ts:79`)
and never inspects it; (9) the **authorization-code record at token
exchange** (`consumeValidCode`, `src/token.ts:208-218`), which snapshots and
re-validates `record.redirectUri` before comparison, PKCE, or token persistence.
This stops a code minted under the old grammar from minting access and refresh
tokens after the upgrade — §10.2's registration read does NOT cover this, because
the code path never re-reads the client registration.

**Why the list ends at nine, and how to re-derive it.** Consumers (3), (6),
(7), (8), and (9) are the places a redirect_uri **outlives the check that
admitted it**: the stored client record, the CIMD registration in the flow
cookie, the opaque params in the same cookie, the consent token, and the
authorization-code record. A signature or a store hit proves *we issued
this*, never *this is still valid* — so each re-validates on READ.

The membership test is mechanical: **can this value be read back after the
check that admitted it, by a process running the NEW grammar, without passing
that check again?** Both halves matter. "Readable later" alone is too wide —
the CIMD validated-success cache (`src/cimd/resolve.ts:90`,
`this.cache = new CimdSuccessCache()`) satisfies it and is deliberately NOT a
consumer: the cache is a private in-process LRU per resolver, so a process
running the new grammar starts EMPTY, and any process still holding a legacy
entry is by definition still running the old grammar. No upgrade state can
cross it, and a re-check on the hit path would guard nothing. Persistence or
signing is what lets a carrier outlive the CODE that admitted it; in-process
memoization does not.

When adding a carrier, state its window, because the LONGEST window in a given
deployment bounds how long a rolling upgrade stays exploitable — and which
carrier is longest is **deployment-dependent, not fixed**: a stored
`ClientRegistration` is unbounded (it persists until re-registered), while
`consentTokenTtlSeconds` / `authorizationCodeTtlSeconds` are validated only as
POSITIVE INTEGERS with no maximum (`validateTtl`, `src/config.ts:139-142`).
Only `flowTtlSeconds` carries a contract-imposed ceiling (600 s default,
≤ 3600). Typical defaults order them code ≈ consent (~300 s) < flow (600 s) <
stored record (unbounded), but an implementation must not rely on that
ordering. (5) exists
because the matcher is a
root export (`src/index.ts`): it is reachable with an entries array that
never passed boot — a consumer calling the helper directly, or (pre-#106) a
caller mutating the array after boot — so without its own read-side check the
one-grammar invariant holds only for arrays `createBridgeConfig` produced. A
non-conforming entry encountered at match time is refused
`invalid_redirect_uri` (fail closed and loud, the same rule as the §10.2 read
guard) — never silently skipped, which is the `"*"` defect this section
started from, and never matched. (6) exists because
`parseCimdRegistrationClaim` checks only types and cardinality, and the
§17.1.6 matcher returns true on `entry === presented` BEFORE any shape
check — so during a rolling upgrade, a still-valid cookie minted under the
old grammar carries a query-bearing or non-canonical entry that exact-matches
its way through the callback; updating document validation (4) alone does not
close that window. Every consumer applies the ONE
shared predicate — none re-derives the grammar from its own parsing. (1), (2),
and (4) reject at the boundary the entry enters; (3), (5), and (6) are
deliberately read-time re-checks of entries that entered before the grammar
existed, out-of-band, or through the public export — not a second grammar.

**Stored state is re-validated at READ, not only at write** (the entry-point
guard's stored-state sibling). A `ClientStore` can return records written before
this grammar existed, or populated out-of-band by a deployer — the registration
guard never saw them. Verified on `40d9f58`: a stored native record holding
`http://@127.0.0.1/cb` (empty userinfo, which §10.0 forbids) is **accepted** at
authorize by `assertRedirectAllowedForClient`. So §10.2 MUST apply §10.0 to each
registered URI it reads, and a record carrying a non-conforming entry is refused
`invalid_redirect_uri` rather than matched. The check is per-entry at match time,
not a migration: a store is not required to be rewritten, and a legacy record
simply stops authorizing until re-registered.

The same read-time rule covers the OTHER carrier of registered redirect URIs:
the **CIMD registration carried in the signed flow cookie** (§17.1.6 decision
1c). A cookie minted before this grammar was enforced carries a
`CimdRegistration` whose `redirect_uris` the §10.0-era validator never saw —
within `flowTtlSeconds` of an upgrade, exactly like a legacy store record.
When `handleCallback` consumes the carried registration, each of its
`redirect_uris` entries is re-checked against §10.0; a non-conforming entry
fails the row-5a matrix (direct 400, `flow_cookie_invalid` audit), so a
pre-upgrade in-flight cookie cannot grandfather an entry past the grammar.
This is consumer (6) of the closed list — it is load-bearing, not
belt-and-braces: `parseCimdRegistrationClaim` validates types and cardinality
only, and the §17.1.6 matcher's `entry === presented` fast path runs BEFORE
any shape check, so without this re-check an old cookie's exact-matching
forbidden entry sails through. The same "not a migration" stance applies: the
flow simply fails and the client re-authorizes.

**Why reject rather than normalize.** A non-canonical entry could be rewritten
to its canonical form instead of refused. It is refused because config should
mean what it says: silently rewriting `https://a.test:443/cb` leaves a manifest
whose text no longer describes the deployed policy, and the same rewrite applied
to an entry the deployer *intended* differently is an undetectable widening. The
error names the offending entry and shows its canonical form to paste back.

**Empty is valid — for `redirectAllowlist` ONLY.** An empty `redirectAllowlist`
is correct configuration (the built-in defaults below cover the common case);
only *entries* can be invalid, never emptiness. This does NOT generalize: DCR
`redirect_uris` and a CIMD document's array both require **1..16 entries**
(§9.2 / §17.1.5 rule 19), so emptiness there is a rejection. The obligation-7
positive list is partitioned per consumer for exactly this reason.

### The two matching policies

Two policies, by DCR mode. Both consume entries already valid per §10.0, and
share the core rule: **no allow-all (`"*"`), no unanchored prefix, userinfo
rejected.** On fragments there is no split left: **entries never contain one**
(§10.0 rejects a fragment, including a bare trailing `#`), and a **presented**
`redirect_uri` carrying a raw `#` is **REJECTED** `invalid_redirect_uri` — not
stripped. RFC 6749 §3.1.2 forbids a fragment in the redirection endpoint URI,
and CIMD's §17.1.3 rejects rather than strips — one verdict for the same shape
on every path. This supersedes the
earlier "hash stripped" wording; a stripped-then-matched fragment is exactly
the accept-what-was-never-registered behavior the exact-match rule exists to
prevent. The §10.0 obligation list owes a rejection test for a presented
`https://client.test/cb#frag` in both DCR modes. Shared
built-in defaults for MCP clients (these ADD to any config allowlist; a config
cannot remove them):

```
https://claude.ai        // Claude (web) custom connectors
https://chatgpt.com      // ChatGPT custom connectors
http://localhost         // native MCP clients — any port (RFC 8252 §7.3)
http://127.0.0.1         // numeric loopback variant
```

Two properties of this default set worth stating rather than leaving to
inference: **`http://[::1]` is deliberately NOT a default** — the §10.1 matcher
recognizes all three loopback hosts (`localhost`/`127.0.0.1`/`[::1]`) as
loopback, but an IPv6-literal callback only matches if the deployer adds
`http://[::1]` to `redirectAllowlist` explicitly (an IPv6-only loopback client
is rare enough that the default set stays minimal; the matcher capability is
already there). And the defaults are themselves §10.0-governed entries: they
are compile-time constants today, so the implementation owes a **unit test
asserting every `DEFAULT_ALLOWED_REDIRECT_ORIGINS` entry is §10.0-valid** —
the guard against a future edit adding a non-canonical or non-grammar default
that no boot validator would ever see.

### 10.1 Global allowlist (stateless-DCR mode) — `assertAllowedRedirectUri`
An entry matches if it is the exact redirect_uri, the exact ORIGIN
(`scheme://host[:port]`, no path) of the redirect_uri, or a **loopback origin**
(`localhost`/`127.0.0.1`/`[::1]`, same scheme, any port). A loopback entry
widens to any port only if it is an origin-only entry with no explicit port/path;
a port-scoped or path-specific loopback entry is NOT widened. Returns the
unchanged canonical URI.

This matcher is consumer (5) of the closed list: it applies the shared §10.0
predicate to each entry it reads BEFORE matching, refusing a non-conforming
entry `invalid_redirect_uri` rather than skipping or matching it. That is not
redundant with boot validation — the matcher is a root export
(`src/index.ts`) reachable with an entries array `createBridgeConfig` never
saw. A directly supplied non-conforming entry is rejected loudly rather than
silently skipped or matched.

Two consequences that make §10.0's raw-syntax rules load-bearing rather than
cosmetic:

- **Origin-form entries match origin-wide** (any path on that origin). That is
  the form's purpose, and it is exactly why the grammar forbids a query
  delimiter or empty userinfo inside it: `https://ok.test?` and
  `https://@ok.test` parse to an empty `search`/`username`, so a parsed-field
  check classifies them origin-only and grants that origin-wide match — while
  the text reads as something narrower.
- **Exact-URI entries match by RAW string equality** — the presented
  `redirect_uri` is compared byte-for-byte against the entry, with **no
  normalization of either side**. This is why the grammar requires canonical
  form: a non-canonical entry (`HTTPS://…`, `…:443/cb`, a `/x/../cb` dot
  segment, surrounding whitespace) matches **nothing**, so the deployer's
  configured callback fails at boot instead of at authorization.

  The presented `redirect_uri` MUST ITSELF BE §10.0-VALID: canonical
  spelling, no fragment (rejected, per "The two matching policies" above),
  no userinfo, http only on loopback. A non-canonical presented value is
  refused `invalid_redirect_uri` — never folded into a match. The **native
  loopback exception is unchanged and remains the only one**: RFC 8252 §7.3
  ports vary by design, so that branch compares scheme + hostname + pathname
  + search with the port ignored, on two values that are each already
  canonical.

### 10.2 Per-client policy (stored-DCR) — RC item (b)
At **authorize** in stored mode (the authorization-code token path never
re-reads the registration — verified: `src/token.ts`'s only `clientStore.find`
is on the `client_credentials` machine-client path, `token.ts:169`), the
client's registered `applicationType`
selects the rule (every registered URI it reads is first re-validated against
§10.0 — the stored-state read guard, obligation 3 there):
- **`native`** → RFC 8252: the registered entry must be a §10.0-valid loopback
  URI (`localhost`/`127.0.0.1`/`[::1]`); the presented `redirect_uri` matches it
  on **scheme + hostname + pathname + search, with the port ignored** — never
  host-only. **The port-ignoring rule is scoped, and the three statements of
  it elsewhere must agree with this one:** §10.1 widens only a PORTLESS
  LOOPBACK ORIGIN entry (any port on that origin); stored-`native` and the
  §17.1.6 CIMD loopback-`http` case compare scheme+host+path+search with the
  port ignored; and every `https` comparison stays exact raw equality WITH
  the port included (§17.1.5 rule 20's "port included" applies to that case,
  not to loopback `http`). A reader who takes any one of those sentences as
  the general rule derives a different matcher — which is why they are
  enumerated together here. "Origin" appears nowhere in this rule on purpose: the match tuple
  includes the path and query, exactly as §17.1.5 rule 20 and the shipped
  matcher (`src/redirect.ts:95-103`) define it, so a client registered for
  `http://127.0.0.1/cb` does not match a presented `http://127.0.0.1/other`.
  Only the port is elastic (lets CLI/desktop clients use ephemeral ports).
- **`web`** → `https` only, and the presented `redirect_uri` must equal a
  registered URI by **RAW string comparison** — no port widening, no origin
  wildcard, and **no normalization of the presented value** (RFC 6749
  §3.1.2.3 simple string comparison). A presented value that is not itself
  §10.0-valid is refused before any
  comparison.

This replaces the source's blanket loopback-for-everyone default in stored mode.

## 11. Scope contract

- `scopeCatalog` (config, required) is the complete set this resource honors.
- `normalizeScopes(scope?, catalog)` → validates each requested scope against the
  catalog (unknown ⇒ `invalid_scope`), de-dupes, and falls back to
  `defaultScopes` when none requested. Returns the validated list.
- `scopeString(scopes)` → sorted, space-joined (stable token `scope` values).
- `requireScope(auth, required)` → 403 `insufficient_scope` step-up (§8.3).
- **Accumulation *(RC item (c)) — stored-DCR opaque clients only.*** Re-authorization
  unions the requested scopes with those derived from this `(subject, clientId)`'s
  active refresh-token records (§9.3) — **no grant store**. In stateless mode, and for
  every scheme-shaped (CIMD) client_id in any mode, there is no accumulation
  (`priorScopes = []`); CIMD accumulation is deferred (§17.1.6 decision 3). Consent UI shows the **delta** (new
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
   therefore grants exactly the requested scopes). **Registration provenance
   (§17.1.6 decision 3):** v0.2 refresh records carry NO registration provenance, so
   they are NOT eligible accumulation evidence for a CIMD authorization — the caller
   MUST NOT invoke `findGrantedScopes` for a scheme-shaped (`https://`/CIMD) client_id
   (accumulation runs only for opaque stored-DCR clients). A future CIMD-accumulation
   extension MUST add immutable mint-time provenance to the auth-code and
   refresh-family lineage, preserve it across rotation, filter this read by expected
   provenance, and treat absent/unknown provenance as ineligible — with an explicit
   legacy-row migration rule. Not part of v0.2. (This closes prior-grant resurrection
   by construction: a pre-CIMD stateless URL-keyed grant is never read into a CIMD
   authorization. Note it does NOT revoke already-issued legacy tokens — they keep
   their own scopes until expiry/revocation; enabling CIMD is not a retroactive
   re-validation of existing grants.)
8. **Token-hash preexistence (collision parity):** `rotateRefreshToken` whose
   `next.tokenHash` already exists returns `null` WITHOUT consuming the
   predecessor (the failed rotation is retryable — matches the SQL stores'
   check-before-update), and `saveRefreshToken` with an already-stored
   `tokenHash` **rejects** — it never silently overwrites. An overwrite would
   rebuild the row with `consumedAt: null`, resurrecting a consumed token and
   erasing the family's replay signal. Practically unreachable under SHA-256,
   but all reference stores must agree (parity by fixture — this invariant was
   previously asserted for MySQL only, and `MemoryStore` silently diverged).

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
`oauth.client.rotate_secret`, `oauth.client.disable`, `oauth.cimd.fetch`, and (§17.11, lands with the
upstream-redirect implementation) `oauth.upstream.callback`. Each carries `occurredAt`,
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
integrity failures are always **direct 4xx**. *(§17.11 extension:* on the
upstream redirect flow, an identity rejection at the **callback** occurs after
the `redirect_uri` was validated and integrity-protected in the signed flow
context, so it redirects as `access_denied`; flow-binding/integrity failures
there — missing/invalid/expired/replayed flow cookie, state mismatch, missing
code — remain direct 4xx.)*

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
  "./identity/entra":             { "types": "./dist/identity/entra.d.ts",             "default": "./dist/identity/entra.js" },
  "./identity/console-pairing":   { "types": "./dist/identity/console-pairing.d.ts",   "default": "./dist/identity/console-pairing.js" },
  "./identity/generic-oidc":      { "types": "./dist/identity/generic-oidc.d.ts",      "default": "./dist/identity/generic-oidc.js" },
  "./identity/google":            { "types": "./dist/identity/google.d.ts",            "default": "./dist/identity/google.js" }
}
```

The v0.2 reference audit sinks — `JsonlFileAudit`, `WebhookAudit`,
`combineAudit` (§17.7) — are exported from the **root `.` entry**, not a subpath:
they carry no runtime dependency (`node:fs` is built-in; `fetch` is native to Node
24), so there is no optional peer dep to isolate and a single
`import { JsonlFileAudit } from "mcp-sso"` is the intended consumer shape.
Quickstart secret persistence (`loadOrCreateQuickstartSecrets`, §17.8) is
root-exported for the same reason (it depends only on `jose` + node builtins).
The console-pairing identity (§17.5) ships as the `./identity/console-pairing`
subpath, parallel to the other identity ports; its framework-free authorize
helpers (`handlePairingAuthorize`, `renderPairingPage`) are root-exported so a
consumer can mount the pairing surface alongside the `skipAuthorize` adapter
option (the in-repo example imports them from source; package consumers import
them from the root entry). The framework-free `Bridge` class — the central object
a consumer constructs and passes to a framework adapter — is root-exported
(`import { Bridge, RequestAuthorizer } from "mcp-sso"`). `isMcpPath(requestUrl)` —
the `/mcp` Streamable-HTTP path check a consumer's `onRequest` Origin-gate hook uses
to scope DNS-rebinding protection to MCP paths (it robustly handles the
absolute-form request-target `POST http://host/mcp`, which a raw `=== "/mcp"` misses;
run before the bearer check, for every method — see `examples/fastify-sqlite`) — is
root-exported (`import { isMcpPath } from "mcp-sso"`) so adopters of the recommended
Origin-gate pattern need not import an internal adapter path. Deployer guidance for the audit sinks lives in
[`docs/audit-deployment.md`](./audit-deployment.md).

**Consumer-facing example helpers (DX):** five symbols the in-repo example leans on
to implement the recommended patterns are root-exported, so a package consumer
replicating those patterns imports them from `mcp-sso` instead of reimplementing
them (and re-opening the footguns they centralize): the normalized request/response
shapes `NormRequest` and `NormResponse` (co-exported with `isMcpPath` — the types
the already-exported `handlePairingAuthorize` and `createUpstreamRedirectFlow`
take/return, so a consumer mounting the pairing surface or an upstream callback can
type-check them); the state-dir security controls `ensureStateDir` (the ATOMIC
helper — `mkdir 0o700` + `assertRealDir` + the managed `*` `.gitignore`, which a
consumer on the Cloudflare/Entra/gateway path — managing its own state dir — applies
for the SAME bar the example does; it derives whether the `.gitignore` may be created
from `mkdir`'s return, so a caller cannot drop a `*` ignore into a pre-existing tree)
and `assertRealDir` (the fs-trust bar alone — rejects a symlink or
group/other-accessible state dir so another local user cannot replace `auth.db`),
co-exported with `loadOrCreateQuickstartSecrets` (the raw `ensureGitignore(dir,
canCreate)` stays internal — its caller-asserted boolean is a footgun); and `assertCallbackPath` (the upstream callback-PATH
validator — a pure check that the pathname starts with `/`, is plain (no
query/fragment/whitespace/control or dot-segments), normalizes to itself under the
issuer origin, and is not a reserved OAuth route or the resource path), co-exported
with `createUpstreamRedirectFlow`. It validates the PATH only — the
`identity.redirectUri === issuerOrigin + callbackPath` equality is enforced
separately, at mount, by `createUpstreamRedirectFlow` (and mirrored by the example's
`assertUpstreamConfigBeforeState`); a consumer doing early-fail boot validation
pairs `assertCallbackPath` with its own redirectUri equality check. All five are
dep-free (node builtins / pure string logic), so root-exporting them does not widen
the `jose`-only runtime posture.

**Init CLI (`npx mcp-sso init`):** the package ships a `bin` — `mcp-sso init [target]`
(default `.`) — that scaffolds a working zero-setup MCP server a stranger can boot with
`npm install && npm start` and pair with via a console-printed one-time code (then
`claude mcp add --transport http my-bridge http://127.0.0.1:3000/mcp`). It generates:
`package.json` (`"type": "module"`, `"start": "node server.ts"`, exact-pinned deps —
`mcp-sso` at the running version + `fastify` + `@modelcontextprotocol/sdk` at the
versions mcp-sso is tested against, recorded in `docs/dependency-ledger.md`; Node
`>=24`, native TS, no build step); `server.ts` (the composition root, built from the
root exports + the `./fastify`, `./store/sqlite`, `./identity/console-pairing` subpaths
— quickstart secrets + console pairing + sqlite + the `/mcp` Streamable-HTTP Origin
gate + a protected `/mcp`, zero-setup loopback by default); `.gitignore`
(`node_modules/` + the `.mcp-sso/` state dir); `.npmrc` (`ignore-scripts=true` —
dependency lifecycle scripts disabled unless the operator vets one, the project's
supply-chain posture); and `README.md` (the run steps +
pointers to `docs/gateway-deployment.md` / `docs/live-verification.md` for production
identity providers). The init binary itself is **dep-free** (node builtins only) — it
adds nothing to the `jose`-only runtime. It refuses to overwrite an existing file or
follow a symlink (atomic `O_NOFOLLOW|O_EXCL|O_CREAT`; it refuses to write through any
path component an attacker could swap — a symlinked target/ancestor, a missing segment
raced in before `mkdir`, or an existing real dir NOT owned by you — when its *real*
(symlink-followed) parent is group/other-writable; sticky + victim-owned paths, e.g.
`mkdtemp` under `/tmp`, and system symlinks like macOS `/tmp`→`/private/tmp`, are allowed
so a normal temp-dir scaffold isn't a false positive). **Filesystem-trust boundary (inherent
Node limit):** the check covers the common write-redirection paths, but a fully race-free
secure `mkdir` needs `mkdirat`/`openat` — resolve-and-create relative to a held directory
fd — which Node's `fs` does not expose. A residual TOCTOU therefore remains in exotic cases
(a trusted symlink whose *destination's real ancestry* is attacker-swappable, on a
multi-user host where an attacker has write access to the user's own path); the realistic
cases are refused, and this residual is inherent to Node, not a logic gap. **Dependency posture:** the generated
`package.json` pins the top-level deps **exactly** (the versions mcp-sso is tested
against); the scaffold cannot ship a curated transitive lockfile (that needs network
resolution at scaffold time), so the operator's `npm install` creates
`package-lock.json` (to commit) — locking the transitive graph at first install. The
server is the zero-setup pairing path; a real IdP (Cloudflare Access / Entra / Google /
OIDC) is a documented graduation (see `examples/fastify-sqlite`), not a scaffolded
default — the done-bar is the pairing round-trip, not a production deploy. **Config-
validation ordering (benign residual):** the generated server pre-validates the
`OAUTH_ISSUER`/`OAUTH_RESOURCE` URLs before the state-creating helper, but the deeper
config validation (`createBridgeConfig` — scheme, scope shapes) runs *after*
`loadOrCreateQuickstartSecrets`, so a malformed env value leaves a `secrets.json`. That
file is owner-only (`0600` in a `0700` gitignored dir), holds secrets generated
independently of the rejected config (so they are valid, not bad), and is reused verbatim
on the next (fixed) boot — no leak, no exposed/bad/committed state; full pre-validation
would need a library secret-free `validateConfig` (deferred).

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
| Stored-client DCR + `application_type` *(fix #4, RC b)* | ✅ implemented, including the §10.0 stored-state read guard | §9.2, §10.2 |
| Redirect-entry grammar §10.0 (ONE definition, all NINE consumers: boot · DCR write in both modes · stored read · CIMD doc · exported matcher `assertAllowedRedirectUri` · flow-cookie CIMD registration · flow-cookie opaque params · consent-token redirect at approve · authorization-code record at token exchange) | ✅ implemented — the nine-leg differential test passes across every consumer | §10.0, §10.1, §10.2, §17.1.5 rule 20, §17.1.6 dec 1c |
| PKCE S256 (timing-safe) | ✅ v0.1 | §7.5 |
| RFC 8707 audience fail-closed | ✅ v0.1 | §7.2 |
| RFC 9207 `iss` + `authorization_response_iss_parameter_supported` *(RC a)* | ✅ v0.1 | §9.1, §9.3 |
| Scope accumulation on step-up *(RC c)* — **stored-DCR opaque clients only** (CIMD clients stand alone; CIMD accumulation deferred — §17.1.6 dec 3) | ✅ v0.1 (core+store; delta UI Phase 3) | §9.3, §11, §17.1.6 |
| Refresh rotation + family replay revocation | ✅ v0.1 | §7.4, §12 |
| RFC 6749 §6 refresh client-binding | ✅ v0.1 | §7.4 |
| RFC 6749 §4.1.2.1 error-redirect channels | ✅ v0.1 | §9.3, §14 |
| RFC 7009 revocation (always 200; unknown = no-op) | ✅ v0.1 | §9.4 |
| Hashed single-use codes/tokens; single-use consent JTI | ✅ v0.1 | §7, §12 |
| Fail-closed boot + no identity bypass | ✅ v0.1 | §5, §9.3 |
| Consent Deny *(fix #5)* + error redirects | ✅ v0.1 core + adapter UI | §9.3, §9.6 |
| Rate-limit hook port *(fix #7)* — no-op default | ✅ v0.1 | §6.7 |
| CIMD (SSRF-guarded FetcherPort) | ✅ implemented — S6a primitives + S6b flow integration (§17.1.5/§17.1.6), frozen acceptance suite active (`s6b-cimd-flow`), including §10.0 redirect-entry canonicality. **Not yet live-verified** against a real CIMD-first client (CIMD-LIVE pending), and any 2026-07-28 spec-final conformance claim is gated on the `docs/verification.md` spec-release re-verification | §6.6, §17.1 |
| Framework adapters (`/fastify` `/express` `/hono`) | ✅ Phase 3 | §9.6, §15 |
| Identity ports (Cloudflare Access, Entra) | ✅ Phase 3 | §6.5 |
| `client_credentials` (MCP ext `io.modelcontextprotocol/oauth-client-credentials`) | ✅ v0.2 shipped (S3a provisioning/rotation + S3b grant: Basic+post auth, `MachineTokenResponse`, metadata-gated advertisement) | §17.2 |
| Device authorization grant (RFC 8628) | 🔒 v0.2 contract locked | §17.3 |
| Entra group→scope ceiling (Gate 2) | ✅ v0.2 shipped (S2a core `allowedScopes` engine + S2b Entra group→scope producer) | §17.4 |
| Console-pairing identity | ✅ v0.2 shipped (S1b) — `createConsolePairingIdentity`, 12-char base-20 code, lazy/single-use/TTL/attempt-cap, `oauth.pairing.attempt` | §17.5 |
| `GenericOidcIdentity` + Google preset + GitHub port | ✅ v0.2 shipped (S4a) — GenericOidcIdentity + Google preset as `RedirectIdentityPort`s (discovery + manual endpoints, multi-audience reject, at_hash, iat required); GitHub port still 🔒 locked (separate dedicated port) | §17.6 |
| Upstream redirect-leg orchestrator (`RedirectIdentityPort` + flow cookie) | ✅ v0.2 shipped — `createUpstreamRedirectFlow` + `createEntraRedirectIdentity`, signed flow cookie (HS256 consent secret, per-flow aud `mcp-sso/upstream-flow` + `callbackPath`, single-use `upf_` jti), 13-row callback failure table, `oauth.upstream.callback` audit | §17.11 |
| Audit reference sinks + expanded events | ✅ v0.2 shipped (S1a) — JsonlFileAudit/WebhookAudit/combineAudit + 9 event names + `ip` | §13, §17.7 |
| Quickstart secret persistence | ✅ v0.2 shipped (S1b) — `loadOrCreateQuickstartSecrets`, 0700/0600/O_EXCL + perm check, fail-closed | §17.8 |

**Spec-final re-check gate:** the RC's (locked 2026-05-21) backward-compatible
hardening items are built in now; before any release claims conformance with
the 2026-07-28 final text, complete [`docs/verification.md` — "Spec-release
re-verification (due
2026-07-28)"](verification.md#spec-release-re-verification-due-2026-07-28).
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

> **Draft `-02` (2026-07-06) review — performed 2026-07-10, recorded here
> 2026-07-16 (closes issue #58).** The conformance target deliberately
> remains `-01`. Every normative change in `-02` is already satisfied by
> this contract **as written** — a property of the contract text, not of an
> implementation (CIMD has no runtime path until the S6 sessions ship code
> against this section): (1) `-02` §3's MUST — Client Identifier URLs
> compared using RFC 3986 §6.2.1 simple string comparison (`-02`'s
> changelog records this as a clarification, with the
> no-default-port-normalization example made explicit) — is carried by the
> raw-string identity rule below plus 17.1.3's exact
> character-for-character comparison; (2) the production loopback
> prohibition (`-02` §8.6) is carried by the loopback exception's binding
> to `dev.allowInsecureLocalhost`; (3) `-02` §8.6's MUST NOT on fetching
> document-contained URLs *that resolve to special-use IP addresses* is
> satisfied a fortiori — the contract forbids fetching ANY URL inside the
> document (17.1.3: `logo_uri` neither fetched nor displayed); (4) the
> periodic re-fetch SHOULD (`-02` §5) is carried by 17.1.4's cache clamp —
> re-fetch happens at the next authorize after cache expiry; 17.1.4's
> token/refresh/revoke no-re-fetch rule is about per-request fetching, not
> staleness; (5) the private-key-material MUST NOT (`-02` §4.1) is carried
> by 17.1.3's explicit rejection of private/symmetric key material in
> `jwks`, paired with the public-client-only profile; (6) `-02` §8.2's
> strengthened client-authentication language (an AS MUST authenticate a
> `private_key_jwt`-declaring client per RFC 7523) is satisfied vacuously —
> 17.1.3 rejects any document declaring a `token_endpoint_auth_method`
> other than absent/`"none"`. `-02` also renumbers sections. Unlabeled
> draft citations in this section remain in `-01` numbering; citations
> explicitly tagged `-02` are already re-pinned. The mapping for the next
> re-pin: §4.5 → §4.2 (redirect URL registration), §5 → §6 (AS metadata),
> §6.5 → §8.6 (SSRF), §6.6 → §8.7 (response size), §6.9 → §7.1
> (pre-registered + unregistered clients) — draft-section citations only
> (`contracts.md`-internal cross-references such as the §6.6 `FetcherPort`
> note are not draft citations). Re-pin to `-02` (or later) at the next
> §17.1 contract revision, re-pointing the citations then.

**Config (opt-in; absent ⇒ CIMD disabled and URL-shaped client_ids are
rejected with `invalid_client`, direct):**

```ts
cimd?: {
  enabled: true;
  // No `fetcher` knob — §17.1.6 decision 5; the core constructs the guarded
  // fetcher from these caps + allowLoopback (dev.allowInsecureLocalhost only).
  maxDocumentBytes?: number;    // default 5120 (the draft's recommended 5 KB cap)
  fetchTimeoutMs?: number;      // default 5000 — one wall-clock deadline, DNS→body
  cacheTtlCapSeconds?: number;  // default 3600; effectiveTtl=min(max-age,cap)−Age−elapsed (§17.1.6 dec 4)
  maxInFlight?: number;         // integer [1, 64], default 8 (global in-flight cap; §17.1.5 rule 21)
  maxWaitersPerFetch?: number;  // integer [1, 4096], default 256 — callers parked on ONE in-flight fetch
                                // (§17.1.6 decision 7). Total waiters ≤ maxInFlight × maxWaitersPerFetch.
}
```

**The guard is structural, not advisory (§17.1.6 decision 5).** `GuardedFetcher`
is a branded type (unique symbol brand) that ONLY `createGuardedFetcher()` can
produce. **The `cimd` config does NOT accept a deployer-supplied whole fetcher at
all** — the core constructs the guarded fetcher itself from the caps above, with
`allowLoopback` derived SOLELY from `dev.allowInsecureLocalhost` (a branded fetcher
still carries the profile it was built with, so accepting one would let
`createGuardedFetcher({allowLoopback:true})` reopen the prod loopback bypass — hence
no knob, per decision 5). Testability is preserved one layer down: below-guard
`cimdTransport?`/`cimdResolver?` deps on `BridgeDeps`/`UpstreamFlowDeps` (rule 14)
inject a low-level connect-to-validated-IP transport / resolver for tests, but the
guard pipeline — URL admission, blocklists, DNS validation, redirect refusal, caps —
always runs around whatever is injected and cannot be skipped, and these seams cannot
widen `allowLoopback` or the caps. (`FetcherPort` in §6.6 remains the generic boundary
description; CIMD requires the brand.)

Boot: invalid caps are an `AuthConfigError`. There is no `cimd.fetcher` field to
brand-check (decision 5 removed it); the runtime brand still gates any internal use of
`createGuardedFetcher()`'s result so the guard pipeline is provably attached. When
enabled, AS
metadata emits
`client_id_metadata_document_supported: true` (draft §5 MUST when supported).
Detection is by shape: a `client_id` starting with `https://` takes the CIMD
path (draft §6.9 — our generated ids `mcpdc_`/`mcc_` never collide).

**Raw-string identity rule (RFC 3986 §6.2.1; `-02` §3 MUST).** The presented
`client_id` string IS the client's identity, raw: the fetch target (17.1.2),
the document `client_id` comparison operand (17.1.3), the cache key (17.1.4),
and every stored/emitted identifier derived from it (the registration
`client_id` and audit fields) are the exact string the client presented — never
a parsed-and-re-serialized form. (A CIMD `client_id` is NOT a `findGrantedScopes`
key: scope accumulation never runs for a scheme-shaped client — §17.1.6 decision 3.) A WHATWG
re-serialization (`new URL(id).href`) drops an explicit `:443` and lowercases
the host, so a re-serialized operand would treat
`https://example.com:443/client` as equal to `https://example.com/client`,
defeating simple string comparison. The 17.1.1 parse exists for VALIDATION
(and to extract connection parameters — host for DNS/SNI, port); its output
is never a comparison operand, fetch target, cache key, or stored identifier.

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
   11211, 27017}`. (Rationale: the 17.1.2 IP blocklist is the SSRF security
   boundary; the port denylist is cross-protocol hardening — it keeps the
   fetcher from speaking HTTPS at well-known non-HTTP service ports — not a
   boundary of its own.)

**Loopback exception:** none in production. The draft (`-02` §8.6) permits a
development/testing AS that itself runs on a loopback address to fetch
client_ids resolving to the same loopback interface; we bind that to the
existing `dev.allowInsecureLocalhost` flag (which already boot-fails on
non-loopback origins — that flag carries the AS-side condition). Under the
flag, ONLY two checks relax, and only for a URL whose host is `localhost` or
`*.localhost`: (1) the 17.1.1 rejection of those hostnames — 17.1.1 stays a
pure pre-DNS function; under the flag it simply stops rejecting them — and
(2) the `127.0.0.0/8` + `::1/128` blocklist rows, enforced at 17.1.2's DNS
step, which additionally requires EVERY resolved A/AAAA record to be a
loopback address (the draft's resolves-to-the-AS's-own-loopback-interface
condition; a single non-loopback record rejects the whole fetch — the same
every-record rule as the rest of 17.1.2). A hostname outside
`localhost`/`*.localhost` gets NO relaxation: if its records resolve to
loopback they still reject — attacker-controlled DNS must not steer a dev AS
into itself. IP-literal hosts stay rejected (17.1.1). The raw `^https://`
requirement is NOT relaxed: 17.1.1 has no scheme carve-out, and admitting
http-loopback CIMD would be a §18 contract change, never an implementation
decision. Everything else in the pipeline still runs under the flag.

**17.1.2 Fetch enforcement (`createGuardedFetcher` — the reference
`FetcherPort`):**

- **Fetch target:** the URL fetched is the RAW presented `client_id` string
  (raw-string identity rule above). The admission parse extracts the
  connection parameters — the parsed host (case-normalized by the parse;
  hostname matching is case-insensitive, so this is the "original hostname"
  the DNS-pinning bullet names for DNS/SNI/certificate purposes) and the
  port — but the request is built from the presented string, never from a
  re-serialized URL.
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
  core additionally asserts that no redirect occurred and `status === 200`,
  so a fetcher that silently followed a redirect is detected and the result
  rejected. (Max hop count is therefore 0 by contract.) Redirect detection
  MUST rest on **explicit no-redirect evidence from the transport result** —
  the Fetch API's `redirected === false`, or an equivalent
  redirects-followed count of 0 — asserted by the core. A normalized-URL
  comparison alone is NOT sufficient evidence: a transport that silently
  followed a redirect from a non-canonical admitted `client_id` to its own
  canonical form (`https://Example.com:443/client` →
  `https://example.com/client`) reports a final URL identical to the
  requested URL's serialization, so that hop is invisible to URL comparison.
  The final-URL check (the transport-reported final URL against the WHATWG
  serialization of the fetch target — the **same serialization** on both
  sides) is kept as defense-in-depth on top of the explicit indicator.
  Neither check is an identity comparison: identity comparisons remain
  raw-string-only per the raw-string identity rule, and a legitimately
  admitted raw `client_id` carrying an explicit `:443` or a mixed-case host
  is NOT spuriously rejected by either check.
- **Response:** status 200 only (draft MUST); `Content-Type` must be
  `application/json` or a `+json` suffix type (our hardening — the draft only
  requires the body to be JSON); body read with a streaming hard cap of
  `maxDocumentBytes` — exceeding it REJECTS (never truncates: truncated JSON
  must never parse "successfully"); unknown `Content-Encoding` rejected and
  decompressed output counted against the same cap (decompression bombs).
- **Timeout:** one `AbortController` deadline (`fetchTimeoutMs`, default
  5000 ms) spanning DNS, connect, TLS, headers, and body. The spec is silent
  on timeouts; this value is our own hardening, recorded as such.
- **Concurrency/DoS:** single-flight keyed by the RAW presented `client_id`
  string (raw-string identity rule — concurrent authorizes for the same
  client_id coalesce into one fetch; distinct raw strings never coalesce,
  even when they re-serialize identically); a global in-flight cap (default 8);
  the authorize endpoint sits behind `RateLimitPort` (`cimd:<ip>`). Error
  responses are NOT cached (draft MUST NOT) — the rate-limit layer, not a
  negative cache, bounds refetch abuse.

**17.1.3 Document validation (pure function, unit-testable):**

- Strict `JSON.parse`; result must be a JSON object.
- `client_id` member MUST equal the RAW presented `client_id` string by
  **exact character-for-character comparison** (RFC 3986 §6.2.1 simple string
  comparison — no normalization, no case-folding, no trailing-slash
  equivalence; the raw-string identity rule — comparing against a
  parsed/re-serialized URL would let an explicit-`:443` or case-folded-host
  difference pass, and MUST reject instead).
- Required members (MCP profile): `client_id`, `client_name` (non-empty
  string, ≤ 256 chars — display data, HTML-escaped at render),
  `redirect_uris` (non-empty array).
- `token_endpoint_auth_method` MUST be absent or `"none"`. **v0.2 CIMD
  clients are public clients only** — the draft explicitly sanctions this
  profile restriction. `private_key_jwt` (confidential CIMD via published
  JWKS) is DEFERRED, together with 17.2's `private_key_jwt` — one future
  asymmetric-client-auth unit. `client_secret` /
  `client_secret_expires_at` present ⇒ reject (draft MUST NOT).
- **Private or symmetric key material rejects the document** (`-02` §4.1:
  "private key material MUST NOT be included ... only public keys ... are
  permitted" — enforced AS-side as a fail-closed conformance check, even
  though v0.2 never uses document keys). If a `jwks` member is present it
  MUST parse as a JWK Set — an object whose `keys` member is an array of
  objects; malformed ⇒ reject — and every key MUST be public-only: a key
  bearing any private or symmetric JOSE parameter (`d`, `p`, `q`, `dp`,
  `dq`, `qi`, `oth`, `k` — the complete registered RFC 7517/7518 set)
  rejects the whole document. Without this rule a nonconformant document
  would be accepted with the key material silently ignored. `jwks_uri` is a
  URL and is never fetched (17.1.4 / the no-second-fetch posture), so it
  cannot carry key material into the AS.
- `redirect_uris` entries: **§10.0-valid** (that grammar governs — not a
  restatement, and not a per-site re-derivation: the CIMD matcher previously
  accepted `*`, `javascript:`, and non-canonical entries that §10.1 refused).
  https entries exact-match at authorize (draft §4.5 / RFC 9700); loopback http
  matches RFC 8252 any-port (consistent with §10.2 native policy). If present: `response_types` must include `"code"`;
  `grant_types` ⊆ `{authorization_code, refresh_token}`; else reject.
- Unknown members ignored (the RFC 7591 registry allows extras). `logo_uri`
  is NOT fetched and NOT displayed in v0.2 (the draft requires
  prefetch-and-cache IF displayed; we sidestep the second fetch surface).
- **Named projection (§4.1, implementation pending):** the returned
  `CimdDocument` exposes only `client_id`, `client_name`, and `redirect_uris`;
  the parsed source object is not returned for a later spread or merge. Unknown
  members, including `__proto__` and `constructor`, remain ignored and cannot
  affect an output record's prototype. **Lifecycle note (§17.1.6 decision 1c):**
  the committed `CimdDocument` interface still exposes `raw` until the §4.1
  removal lands; until then S6b MUST project into the distinct `CimdRegistration`
  named type (`{ client_id, client_name, redirect_uris }`) at the fetch boundary
  **before** any caching or flow-cookie signing — a raw `CimdDocument` is never
  cached, signed, or passed as the `registration` option.

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
- **Scope accumulation does NOT apply to CIMD clients in v0.2** (§17.1.6 decision 3):
  a CIMD authorization stands alone (`priorScopes = []`) in both DCR modes.
  Accumulation stays a stored-DCR opaque-client feature — deferred for CIMD because
  refresh records carry no registration provenance, so a pre-CIMD stateless grant for
  the same URL would silently resurrect. (The target AI clients request their full
  scope set up front, so the convenience is unused; a provenance-aware version is a
  future minor — §12 note.)
- Token/refresh/revoke: NO re-fetch; binding is the existing auth-code-record
  and refresh-record client checks (§9.4). Validated documents cache per RFC
  9111 headers (freshness per §17.1.6 decision 4: `effectiveTtlSeconds =
  min(valid max-age, cacheTtlCapSeconds) − Age − elapsedSeconds`; a valid
  `max-age` below 60 is non-cacheable, never clamped up), keyed by the
  RAW presented `client_id` string (raw-string identity rule —
  `https://example.com/client` and `https://example.com:443/client` are
  distinct clients and distinct cache entries), in-memory per instance, bounded
  to a finite entry ceiling with LRU eviction (§17.1.6 decision 4); this SAME
  cache also serves the upstream-redirect authorize resolution (§17.1.6 decision
  1a); invalid/error results never cached.
- No new store records.

### 17.1.5 Precision amendments (S6 pre-implementation, 2026-07-22)

These close ambiguities and fail-open gaps found by the cross-family S6a spec
critique and confirmed by an adversarial amendment-verify pass (critics/verifiers:
GPT-5.6 Sol, Grok 4.5, GLM 5.2), each empirically re-verified on the project's
Node 24 runtime. They **TIGHTEN** the bullets above; where a rule here and a
bullet above differ, this subsection wins — **except for the §10.0
redirect-entry grammar, which governs every consumer including CIMD** (rule 20
is amended accordingly; a subsection-wins precedence over the shared grammar is
what let the CIMD matcher and §10.1 diverge in the first place). Every rule is fail-closed. No new
subsystem is introduced — these pin behavior the primitives already imply so the
S6a bake-off cannot diverge and review cannot discover. **This subsection is
contract text; the enforcement lands with the S6 code, not with this docs
change:** each S6a-scope rule is to be covered by a negative test in the frozen
S6a acceptance suite, and the flow rules (H) are to be implemented and tested in
S6b. **Status: those PRs have landed** — the S6a primitives, both frozen
acceptance suites, and the S6b flow integration are implemented, and §16 now
tracks CIMD as implemented, including the §10.0 amendment to rule 20.
What remains beyond that is live verification (CIMD-LIVE) and,
for any conformance claim against the 2026-07-28 final spec text, the
`docs/verification.md` spec-release re-verification.

**A. Admission input + raw pre-parse checks (tightens 17.1.1 step 1).**
1. The admission argument MUST be a primitive `string`, non-empty, and ≤ 2048
   **UTF-8 bytes** (`Buffer.byteLength(raw,"utf8")`); no type coercion. A
   non-string, empty, or over-length input rejects pre-parse.
2. Before `new URL()`, reject on the RAW string: any raw backslash `\` (WHATWG
   maps `\`→`/` on special schemes: `https://h/a\..\b` parses to pathname `/b`,
   invisible to a `/`-split — verified); any raw `?` (query delimiter, incl. a
   trailing `?` that parses to empty `search`); any raw `#` (fragment delimiter,
   incl. a trailing `#` that parses to empty `hash`); leading or trailing ASCII
   whitespace (WHATWG trims a trailing space — verified); any C0 control
   (U+0000–U+001F), DEL (U+007F), or raw/`%`-encoded CR/LF in all case variants.
   **Userinfo:** reject any `@` in the RAW AUTHORITY only — the substring after
   `https://` up to the first `/` (or end) — INCLUDING empty userinfo
   (`https://@h/c` parses to username `""`, host `h` — verified). A `@` in the
   PATH is a legal `pchar` and is allowed (`https://cdn.example/@scope/c.json`).
   No separate whole-string malformed-percent scan is required: a malformed
   escape in a path segment fails the rule-3 one-pass decode, and a malformed
   escape in the authority fails `new URL()` or the rule-6 raw-host check.
3. **Raw-path extraction (pins "split the raw path on `/`").** Because rule 2 has
   rejected raw `\`, authority `@`, `?`, `#`, and required a literal lowercase
   `^https://` prefix, the raw path is unambiguous: the substring beginning at the
   first `/` at or after index 8 (the char after `https://`). No such `/` ⇒ no
   path component ⇒ reject (17.1.1 step 2). Split that substring on `/`;
   percent-decode EACH segment exactly ONCE (a decode failure rejects; recursion
   is forbidden, so `%252e`→`%2e` is NOT a dot segment — verified); reject if a
   decoded segment equals `.` or `..`.

**B. Host checks run on the PARSED hostname (tightens 17.1.1 step 3).**
4. All host rules evaluate `url.hostname` AFTER `new URL()` (WHATWG canonicalizes
   dword/octal/hex and IDNA-narrows fullwidth digits to a dotted quad —
   `https://1．2．3．4/`→`1.2.3.4`, `https://2130706433/`→`127.0.0.1` — verified;
   caught by the IP-literal rule only when it runs on the parsed host).
5. **IP-literal rejection strips brackets first:** `new URL("https://[::1]/x")
   .hostname` returns `"[::1]"` WITH brackets and `net.isIP("[::1]")` returns 0
   (verified) — a naive `net.isIP(hostname)` admits every bracketed IPv6 literal.
   Rule: let `h` = hostname with one leading `[` and trailing `]` removed if both
   present; reject if `net.isIP(h) !== 0` OR the original hostname began with `[`.
6. **Non-ASCII / IDNA hostnames reject (deliberate v0.2 policy).** This is a
   chosen fail-closed policy, not a logical necessity: `new URL(
   "https://exämple.com/x").hostname` becomes `xn--exmple-cua.com` (verified),
   so admitting IDNA would force either a fetch target that differs from the raw
   identity or a punycode re-serialization as identity — both undesirable in v0.2.
   Rule: reject unless the **raw-authority host** is pure ASCII, equals
   `url.hostname` case-insensitively, AND contains no `xn--`-prefixed label — a
   pre-encoded IDNA A-label (e.g. `xn--exmple-cua.com`) is itself a punycode
   identity and is likewise deferred; without this an A-label host passes the
   pure-ASCII check and opens a homograph allow-path. Raw-authority-host extraction (validation
   only; never a fetch target/cache key/identity): after `https://`, take chars
   up to the first `/` or end = the authority; (authority `@` already rejected in
   rule 2); if it starts with `[`, the host is the substring through the matching
   `]`; else the host is the authority with an optional trailing `:port` removed
   at the LAST `:`. (IDNA/punycode CIMD identities are a §18 change, never a
   coder decision.)
7. **Trailing-dot and localhost matcher (pins the wording; restores the blanket
   rule).** FIRST, independently of any relaxation: reject ANY `url.hostname`
   ending in `.` (the blanket trailing-dot rejection of 17.1.1 step 3; the
   loopback exception does NOT relax it). THEN reject `localhost` and
   `*.localhost`: host equals `localhost`, or host ends with `.localhost` (so
   `notlocalhost` does NOT match; `a.b.localhost` does). The loopback exception
   relaxes exactly this localhost matcher and the loopback blocklist rows —
   nothing else.

**C. DNS resolution + blocklist membership (tightens 17.1.2 DNS pinning).**
8. Both A and AAAA are queried within the one deadline. An explicit no-data
   result for ONE family (`ENODATA`/`ENOTFOUND`) is permitted; any other resolver
   error rejects the whole fetch. The combined answer MUST contain ≥ 1 and ≤ 64
   addresses; **zero addresses rejects** (`[].every()` is `true` — verified — so
   an empty answer must never pass the blocklist or the loopback every-record
   check vacuously). More than 64 rejects.
9. Every returned address MUST be parseable and its parsed family MUST match the
   query record type; a whitespace/zoned/non-decimal/family-mismatched/otherwise
   unparseable record rejects the WHOLE fetch — records are never silently
   skipped (skipping a malformed record and passing the rest is the loopback
   fail-open in 17.1.1's exception).
10. **Blocklist engine is total on BOTH add and check.** Membership compares
    parsed binary addresses. If `net.BlockList` is used: (a) IPv6 subnets MUST be
    added with an explicit `"ipv6"` family — `addSubnet("::1",128)` THROWS
    `ERR_INVALID_ADDRESS` without it (verified); and (b) **every `check()` MUST
    pass the address family** — `check("::1")` returns `false` even after the
    subnet was added with family `"ipv6"`, while `check("::1","ipv6")` returns
    `true` (verified); omitting the family silently makes the ENTIRE IPv6
    blocklist inert (loopback, ULA, link-local, multicast, documentation all
    pass — a full IPv6 SSRF bypass). Use `check(addr, net.isIP(addr)===4?"ipv4":
    "ipv6")` with the per-record family from rule 9. Any error constructing the
    blocklist is a boot failure, never a caught-and-skipped range.

**D. Connection / transport (tightens 17.1.2 fetch enforcement).**
11. **Proxy env is forbidden.** The transport connects DIRECTLY to the validated
    IP and MUST NOT honor `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY` (any
    case) — a proxy re-resolves the hostname and defeats DNS pinning (SSRF
    bypass; threat rows 13/25).
12. **The deadline covers DNS with cancellation.** `dns.promises.resolve4/6` do
    not accept an `AbortSignal`, and a bare timer/race bounds only the caller
    while background resolution keeps running. Use a per-fetch
    `dns.promises.Resolver` (or an equivalently cancellable resolver seam) and
    call `.cancel()` at the shared `fetchTimeoutMs` deadline; the single-flight
    slot (H/24) is not released until resolution has settled or been cancelled,
    so a hanging resolver can neither exceed the deadline nor leak past the
    in-flight cap.
13. **Request + connection shape.** GET only; no body; no credentials/cookies; no
    `Authorization`/`Cookie`/`Proxy-Authorization`; only fixed allowlisted
    `Accept: application/json` and `Accept-Encoding: identity` headers. The HTTP
    request-target is **origin-form** (path + query) derived from the admitted
    URL — NEVER absolute-form to a directly-connected origin. The `Host` header
    is the parsed hostname, plus `:${url.port}` ONLY when `url.port !== ""` (a
    non-default explicit port survives WHATWG); a default-443 form carries no
    explicit port. TLS SNI and certificate verification use the parsed ASCII
    hostname with brackets/port stripped. The raw client_id string is carried
    separately as identity/evidence, never as the request-target.
14. **Injected transport seam (test-only, below the guard).** Its request is
    `{ connectIp, family, port, servername, hostHeader, requestTarget, signal,
    redirect:"manual" }` — `connectIp` is the already-validated address it MUST
    connect to (no DNS/proxy re-resolution). Its result is `{ status,
    redirected:boolean, finalUrl, headersDistinct, encodedBody }` where
    `headersDistinct` **preserves duplicate header occurrences** (Node's
    `IncomingMessage.headers` keeps only the first `Content-Type`, so a normalized
    map cannot satisfy rule 15's duplicate check — use `rawHeaders`/
    `headersDistinct`). The public guarded-fetch API accepts only the raw
    client_id; no generic `FetchInit` overrides.

**E. Response handling (tightens 17.1.2 response; supersedes its gzip allowance).**
15. A duplicate or multi-value `Content-Type` header rejects (an essence-ambiguous
    response is untrusted). Essence match is case-insensitive with parameters
    allowed: media type `application/json` or any type ending in `+json`.
16. **Content-Encoding: identity only (v0.2).** The request sends
    `Accept-Encoding: identity`; ANY present `Content-Encoding` response header
    rejects — **including a bare `identity`; ONLY an ABSENT `Content-Encoding` is
    accepted** (examples that reject: `gzip`, `x-gzip`, `br`, `deflate`, `zstd`,
    `identity`, list-forms like `gzip, gzip`, and any unknown coding). This SUPERSEDES 17.1.2's gzip allowance: dropping
    compression eliminates the decompression-bomb class entirely rather than
    defending it (least machinery on a T3 SSRF boundary; a 5 KiB JSON document
    does not need compression). gzip interoperability, if a real metadata host
    ever requires it, is a documented §18 follow-up with its own streaming
    stream-and-abort defense — not v0.2. The single streaming cap therefore
    applies to wire bytes only: exceeding `maxDocumentBytes` REJECTS (never
    truncates).
17. Response header total size is bounded by Node's built-in
    `--max-http-header-size` default (~16 KiB) plus the one deadline; the built-in
    transport MUST NOT raise or disable that platform cap. An application-level
    header-byte counter is an accepted v0.2 residual (peak-memory only, no
    correctness impact) — documented, not enforced.

**F. Document validation typing + cardinality (tightens 17.1.3).**
18. The parsed root MUST be a non-null, non-array plain object
    (`typeof x==="object" && x!==null && !Array.isArray(x)`). Each member is
    type-checked before use: `client_id`/`client_name` MUST be strings,
    `redirect_uris` MUST be an array; a wrong JSON type rejects (never coerced).
19. `redirect_uris` length MUST be 1..16 (bounds the authorize-time exact-match
    linear scan). A `jwks` object's `keys` MUST be an array of plain objects
    (malformed rejects); no separate numeric keys-count cap is imposed — the
    5120-byte-default (≤ 64 KiB) body cap bounds the parse, and v0.2 never uses
    document keys, so the public-only per-key scan is the only obligation. JSON
    depth is bounded by the body cap; no separate depth limit.
20. **CIMD redirect hygiene uses a NEW pure validator, not the §10 exports.**
    *(AMENDED by §10.0 — read that first. The grammar there governs WHICH entries
    are valid, for CIMD exactly as for §10.1/§10.2, superseding this rule's
    looser shape rules wherever they differ: an https entry carrying a query or
    in non-canonical form is REJECTED under §10.0 even though the raw-shape rule
    below would admit it. What survives unchanged is the mechanical part — that
    CIMD needs its OWN pure per-URI error-mapping wrapper rather than reusing the
    §10 matcher exports, which require allowlist or stored-client context.
    `assertCimdRedirectUri` therefore stays,
    and becomes the CIMD-side enforcement OF §10.0 rather than a second grammar.
    The §17.1.5 "this subsection wins" precedence does NOT extend to the entry
    grammar.)*
    Neither `assertAllowedRedirectUri` (allowlist membership) nor
    `assertRedirectAllowedForClient` (stored-client context) is a pure per-URI
    error-mapping surface. `assertCimdRedirectUri(raw: unknown): void` supplies
    the CIMD `document_invalid` mapping over the same shared predicate; it is not
    a package export. Full edge class (enumerate before coding,
    per the identity-port lesson): argument MUST be a primitive non-empty string,
    no coercion; reject raw `\`, C0/DEL, CR/LF, malformed percent triplets, any
    userinfo (INCLUDING empty `@`), any fragment (INCLUDING a trailing `#`), and
    any `*` anywhere in the raw entry — host, path, or elsewhere (`https://a.test/cb*`
    is rejected here exactly as §10.0 rejects it; the earlier "in the host"
    scoping was narrower than the grammar and is superseded); accept `https:`
    with ANY host, or `http:` ONLY with host exactly
    `localhost`, `127.0.0.1`, or `[::1]` (the loopback restriction binds the
    `http:` case alone — the earlier "EITHER https: OR http: with host
    exactly…" phrasing read as if https also required loopback, contradicting
    the "Only the `http:` case is loopback" sentence below; this spelling and
    that sentence now say the same thing, and it is the same rule §10.0 now
    states grammar-wide) — **in each case only if the entry is
    also §10.0-valid** (canonical spelling, no query; this REPLACES the earlier
    "validated for shape only here" wording, which admitted queries and
    non-canonical forms). Matching at authorize is EXACT raw-string comparison,
    port included, with no normalization at match time — which is sound
    precisely because §10.0, once enforced, forces the stored entry into
    canonical form;
    raw-equality against a non-canonical entry is what made the two matchers
    disagree. Only the
    `http:` case is loopback. The authorize-time (S6b) loopback any-port match
    reuses the existing runtime semantics of src/redirect.ts:95-103 — scheme,
    hostname, pathname, and search equal; port ignored; fragment already rejected
    at validation — resolving the looser "origin" wording elsewhere.

**G. Config cap numeric domains (tightens the `cimd` config + boot + §5).**
21. The `cimd` config key MUST be enumerated in the canonical §5 `BridgeConfig`
    shape and in `KNOWN_CONFIG_KEYS` (§5 rejects every unenumerated key at boot,
    so the field is boot-rejected until listed). The concurrency bound is a named
    property `maxInFlight?`. Each cap has a closed integer domain; a non-integer,
    `NaN`, `Infinity`, or out-of-range value is an `AuthConfigError` at boot (an
    unbounded value defeats the very controls threat rows 13/25 describe):
    `maxDocumentBytes` ∈ [1024, 65536] (default 5120); `fetchTimeoutMs` ∈
    [1000, 30000] (default 5000); `cacheTtlCapSeconds` ∈ [60, 86400] (default
    3600); `maxInFlight` ∈ [1, 64] (default 8); `maxWaitersPerFetch` ∈ [1, 4096]
    (default 256 — §17.1.6 decision 7).

**H. Flow-integration items (enforced + tested in S6b; recorded here for the suite).**
22. **"URL-shaped" is mechanical.** A `client_id` matching raw scheme syntax
    `^[A-Za-z][A-Za-z0-9+.-]*://` is NEVER eligible for the stateless-DCR
    ephemeral-client fallback. Only a literal lowercase `https://` prefix enters
    CIMD admission; every other scheme-shaped value (including `HTTPS://`,
    `http://`, `ftp://`) is rejected `invalid_client` (direct). When CIMD is
    disabled/absent, a `https://`-shaped `client_id` is likewise rejected
    `invalid_client`, never treated as a stateless-DCR client.
23. For a CIMD `client_id`, `prepare`'s redirect validation is the document
    exact-match (loopback any-port per rule 20), REPLACING §9.3 step 2's §10
    global-allowlist check for that client. Non-CIMD flows are unchanged.
24. Single-flight/overload: coalesce concurrent fetches for the same RAW
    client_id; a coalesced follower does NOT consume an in-flight slot. When
    `maxInFlight` distinct fetches are in flight, a new DISTINCT client_id fetch
    rejects with `CimdReason` **`overloaded`** (§17.1.6 decision 6; client-facing map
    = the decision-2 generic `invalid_client`), never queues unboundedly. A key's entry is removed
    on settle (success, error, or timeout/cancellation). Error/invalid results
    are never cached.
    **Followers are bounded too (§17.1.6 decision 7).** `maxInFlight` bounds
    concurrent OUTBOUND fetches; it does not bound how many inbound callers may
    park on ONE of them. A new `maxWaitersPerFetch` cap bounds that second
    quantity: when an in-flight entry already has `maxWaitersPerFetch` waiters, a
    further follower for that same client_id rejects `overloaded` (the SAME
    `CimdReason`, the same decision-2 generic — no new client-visible surface, no
    new oracle). Total concurrent waiting resolutions are therefore bounded above
    by `maxInFlight × (maxWaitersPerFetch + 1)` (the `+1` per entry is the
    initiating resolution; the cap counts FOLLOWERS only). This does NOT reverse the
    no-slot rule above: a follower still consumes no FETCH slot, so one popular
    client_id can never starve distinct client_ids out of `maxInFlight`.
25. Cache freshness (RFC 9111, in-memory per instance, keyed by raw client_id):
    `no-store` or `no-cache` ⇒ do not cache; absent, malformed, duplicate, or
    conflicting `Cache-Control`/`max-age`, and a negative/non-integer/overflow
    `Age` or an `Age` ≥ the effective lifetime ⇒ no cache entry (fail toward
    re-fetch, which the rate limiter bounds). A valid `max-age` **below 60 is
    non-cacheable** (never honored, never clamped up — this REPLACES the earlier
    clamp-to-60 behavior, per §17.1.6 decision 4); otherwise `effectiveTtlSeconds =
    min(valid max-age, cacheTtlCapSeconds) − Age − elapsedSeconds` and a non-positive
    `effectiveTtlSeconds` is not cached. A quoted `max-age` value is treated as
    malformed (no cache entry).

### 17.1.6 S6b flow-integration amendments (decisions 1–6, 2026-07-23)

Resolves the S6b cross-family flow-integration critique (GPT-5.6 Sol / Grok / GLM)
against current `main` (post #85–#91). **Contract text; enforcement lands with the
S6b code + frozen suite.** Decision 1 is the owner-chosen "extend §17.11"
(2026-07-23): CIMD is a first-class client type in upstream-redirect mode
(Hosted-Claude + Entra target). These TIGHTEN §17.1.4, §17.1.5 H (22–25), and
extend §17.11; where a rule here differs, this subsection wins. Every rule is
fail-closed.

**Design stance (read first — this is the anti-over-scope boundary).** The
authorization decision for a CIMD client is made ONCE, at authorize, and carried
forward to the callback under the flow cookie's existing HS256 signature. The
validated CIMD registration handed to `bridge.handleAuthorize` at callback is
**orchestrator-resolved trusted state — the same trust category as `subject` and
`allowedScopes` already on that options object.** Its integrity source is the flow
cookie signature (`consentSigningSecret`) + the single-use `upf_` jti; **no
separate capability/brand/registry system is introduced.** An in-process caller
fabricating that field is at the same trust level as the library core — there is no
external attacker sink, and it is deliberately NOT defended with new machinery
(the §17.1 `GuardedFetcher` rationale applied honestly, and the boundary that keeps
this from becoming a descriptor-snapshot edifice). `prepare`'s redirect re-check
(1d) is the fail-closed defense-in-depth; the trust model and residuals below are
pinned so review VERIFIES conformance rather than re-deriving the threat model each
round.

**Decision 1 — CIMD in upstream-redirect mode (§17.11 extension).**

*Problem.* §17.11 calls `bridge.handleAuthorize` at **callback** (upstream-flow.ts:152)
from a synthetic request; `prepare` — where CIMD otherwise resolves — fires after
the IdP hop. `resolveAuthorizeRedirect` (upstream-flow.ts:99) validates
`redirect_uri` at authorize. For a CIMD id both are wrong as written, and
re-fetching at callback is a second fetch + a TOCTOU window + a late failure after
the user has already authenticated. Fix: resolve once at authorize, carry forward.

*Shared redirect matcher (used by 1a, 1d, and prepare).* CIMD redirect membership is
a **single NEW pure matcher** (not the §10 export functions, which strip fragments and
consult a stored client): an https registration entry matches by **exact raw-string**
`presented === registered` (rule 20 / the raw-string identity rule — no normalization
AT MATCH TIME, port included; sound because §10.0 already required the registered entry
to be canonical); a loopback `http` entry matches RFC 8252 **any-port** using the compare
semantics of `src/redirect.ts:95-103` (scheme, host, path, and search equal; port
ignored; fragment already rejected). It is NOT array `∈`/`includes` (that rejects a
legitimate any-port loopback redirect). Authorize (1a), the callback gate (1d), and
`prepare`'s re-check MUST call this SAME matcher.

*1a. Shape-first three-way dispatch; CIMD REPLACES §10 for CIMD ids.* Client_id
shape is classified identically at BOTH the authorize resolve (`upstream-flow.ts:99`)
and `prepare`'s `resolveRedirect` (`authorize.ts:188-196`) — the entry-guard and its
stored-state sibling: **(1)** a literal-lowercase-`https://` client_id (rule 22) with
`cimd` enabled → the CIMD path; **(2)** ANY other scheme-shaped value
(`^[A-Za-z][A-Za-z0-9+.-]*://`, including `HTTPS://`/`http://`/`ftp://`) AND a
lowercase-`https://` id while `cimd` is disabled → **direct `invalid_client`**, never
a stateless fallback and never an IdP hop; **(3)** an opaque non-scheme id → the
unchanged §10 path (and MUST carry no `cimd` claim, 1d). For branch (1) the CIMD path
REPLACES redirect validation — the stored-mode `store.find` "Unknown client_id"
miss MUST NOT fire (else every CIMD id dies on a stored-DCR deployment and
Hosted-Claude+Entra never works). Resolve the document through the **§17.1.4 success
cache** (raw-client-id-keyed) backed by the branded guarded fetcher — all §17.1.5
rules; under the `cimd:<ip>` rate-limit + single-flight + `maxInFlight` cap alongside
the existing `upstream:<ip>` guard; a cache hit resolves without a network fetch.
Validate the presented `redirect_uri` with the shared matcher against
`document.redirect_uris`. **This is at most one network fetch (cache miss); a
callback re-fetch is forbidden (1d).**

*1b. Anti-oracle ordering.* Resolve + redirect exact-match complete BEFORE
`Set-Cookie` / the IdP 302. Any failure ⇒ the decision-2 generic (`invalid_client`
401) and `oauth.cimd.fetch` (failure, reason); success ⇒ `oauth.cimd.fetch`
(success). The 4096-byte `Set-Cookie` oversize guard (upstream-flow.ts:104), for a
CIMD id, maps to the SAME generic `invalid_client` (never `invalid_request`) so it
is not a content oracle. The `oauth.cimd.fetch` **success** audit is emitted only
**after the oversize guard passes**: a resolution whose document is valid but whose
projected flow-cookie would exceed 4096 bytes is rejected as the generic
`invalid_client` and audited as a **failure** (reason `oversize`), never a success
event followed by a silent rejection — so the audit trail matches the actual outcome. Hosted-Claude-class registrations (a short URL + a few
redirects) serialize to ~1–2 KiB and fit comfortably. **Documented residual:**
because the validated projection rides the signed flow cookie, redirect-mode
effective document size is **cookie-bound (≤4096 serialized), not only
`maxDocumentBytes`-bound** — a document-*valid* registration with many or long
`redirect_uris` (still within rule 19 / `maxDocumentBytes`) can exceed the cookie
budget and then fails closed as `invalid_client`, whereas direct mode would accept
it. This is a deliberate least-machinery tradeoff (no compression, truncation, or
second store is added to enlarge the redirect-mode ceiling).

*1c. Carry the validated registration forward under signature.* Define a distinct
named projection type **`CimdRegistration = { client_id: string; client_name: string;
redirect_uris: readonly string[] }`** — `client_name` REQUIRED and non-empty per
§17.1.3; constructed by explicit named-field projection at the fetch boundary and the
flow-token-parse boundary; it is NOT the committed `CimdDocument` (which still exposes
`raw`, `guarded-fetcher.ts`/`document.ts`) — signing `fetchResult.document` directly
would leak attacker-controlled members into the cookie (§4.1). The flow JWT gains a
`cimd` claim carrying exactly a `CimdRegistration` (no key material), covered by the
existing HS256 signature + single-use jti. At callback, after the flow JWT is
verified, the orchestrator passes it as a **new named option
`registration?: CimdRegistration`** on `bridge.handleAuthorize`, threaded
`handleAuthorize → AuthorizeRequestInput → prepare` — optional, in the SAME trusted
category as `{subject, allowedScopes}`; **only `createUpstreamRedirectFlow` (after the
1d gate) may set it, and adapters/frameworks MUST NEVER bind it to any
client-controlled request field.** When it is present `prepare` uses it and **does
NOT re-fetch** — the decision is atomic at authorize and carried forward (no
post-authentication late fetch; no TOCTOU; the consent page shows exactly the
validated document). The consent renderer receives display-only CIMD fields on
`PreparedConsent` (client_id host, redirect host, `client_name` as unverified text —
threat row 17); only `cimd_verified` is copied into the consent JWT (decision 3).

*1d. Fail-closed consistency (a signed-claim schema check — NOT a capability
system).* Split across two seams (GLM): **(i)** `verifyFlowToken`
(`upstream-flow-internals.ts`) strict-parses the `cimd` claim SHAPE — object;
`client_id` a primitive string raw-equal to `params.client_id`; `redirect_uris` an
array length 1..16 of strings; `client_name` a **non-empty string ≤256** (matching
§17.1.3 — an absent/empty name is a shape a validated document could never produce);
projecting ONLY the named fields into a fresh `CimdRegistration` (never `Object.assign`
/ never reuse the lenient string-only `params` loop). A present-but-malformed claim
fails cookie verification ⇒ **callback row 3** (`invalid_request`, audit
`flow_cookie_invalid`), consistent with the other cookie-integrity failures.
**(ii) POLICY (new row 5a).** `handleCallback`, after the state match (row 5) and
BEFORE jti consumption / exchange / any redirect-channel response (rows 7/8/10/11),
enforces the **claim/mode matrix + redirect match**: a
literal-lowercase-`https://` client_id requires `cimd` enabled AND a present valid
`cimd` claim; a non-CIMD client_id MUST carry NO `cimd` claim; and
`params.redirect_uri` MUST match the claim's `redirect_uris` via the **shared
matcher**. Any violation ⇒ **direct 400 `invalid_request` with audit reason
`flow_cookie_invalid`** (new **row 5a**; `flow_cookie_invalid` is the audit reason, NOT
an OAuth code — same pattern as rows 3/4). This closes the
IdP-error/exchange/identity-reject branches redirecting to an unmatched
`params.redirect_uri` before `prepare` runs. **The no-fetch switch is
registration-PRESENCE, not "mode"** (`prepare` is shared by direct/header/pairing):
when a `registration` option is supplied `prepare` MUST NOT fetch; when it is absent
AND the client_id is a lowercase-`https://` CIMD id, `prepare` resolves through the
shared **§17.1.4 success cache** (at most one guarded fetch on a miss); an **opaque
non-scheme client_id never fetches** (three-way dispatch, 1a); the redirect
orchestrator MUST supply `registration` for every CIMD id. `prepare`'s defensive re-check
(`params.redirect_uri` matches `registration.redirect_uris`, shared matcher) is a
**PRE-validation check inside `resolveRedirect` that throws a DIRECT
`OAuthError(invalid_client)` — never a 302** (a failed re-check means the signed
cookie is internally inconsistent, so `params.redirect_uri` is untrusted). **Frozen
S6b test:** with `registration` supplied, inject a `cimdTransport`/`cimdResolver`
(1e) whose call throws; assert the callback→prepare path still completes for a CIMD id
— proving carry-forward, not re-fetch.

*1e. Direct/header mode + the below-guard test seam.* `prepare` fetches at prepare
and validates there (base S6b, when no `registration` is supplied). Only redirect
mode pre-resolves at authorize and carries forward. Because decision 5 makes the core
own fetcher construction (no deployer-supplied whole fetcher), the ONLY test-injection
surface is a **below-guard seam** enumerated on BOTH `BridgeDeps` and
`UpstreamFlowDeps` as optional `cimdTransport?` / `cimdResolver?` (the rule-14
transport/resolver seams, which cannot widen `allowLoopback` or the caps) — never a
`BridgeConfig` field, never a whole `GuardedFetcher`. Mode mutual-exclusion (§17.11
adapter wiring) unchanged.

*Trust model + residuals (pinned — review verifies these, does not re-derive):*
- The `cimd` registration on `handleAuthorize` options is orchestrator-resolved
  trusted state (integrity = flow-cookie signature), NOT a new deployer-facing
  trust boundary. No brand/capability system; in-process fabrication is the same
  trust level as the core (no external sink; undefended by design). `prepare`'s
  redirect re-check is defense-in-depth.
- *Residual (inherent, shared):* CIMD resolution runs at authorize BEFORE the user
  authenticates, so an unauthenticated caller can trigger one outbound guarded
  fetch to a blocklist-passing URL. Bounded by `cimd:<ip>` rate-limit +
  single-flight + `maxInFlight` + the SSRF guard; inherent to validating a redirect
  before the IdP hop; not eliminated.
- *Residual:* the flow JWT now integrity-covers `redirect_uris`, so a leaked
  `consentSigningSecret` elevates flow-JWT forgery to CIMD-registration
  substitution — same secret/trust §17.11 already assumes.

**Decision 2 — CimdError → one anti-oracle OAuth error (mapped at the resolution
boundary).** Every `CimdError` (all `CimdReason`s incl. decision-6 `overloaded`)
AND any unexpected throw in the CIMD resolution path ⇒ `invalid_client` 401, body
`{"error":"invalid_client","error_description":"client_id could not be resolved"}`,
mapped INSIDE the resolution boundary. **The two boundaries are named by file**
(they are the ONLY resolution sites): **(1)** `flow.handleAuthorize`'s authorize-time
resolve (`upstream-flow.ts:86`) — the map wraps resolve+match so a `CimdError` NEVER
reaches the `upstream-flow.ts:107-109` catch, which would return `internal_error` 500
(a channel distinguishable from the generic `invalid_client` 401 — reopening the
oracle); **(2)** `prepare`'s CIMD branch (direct-mode fetch, plus any redirect-mode
re-check that can throw). `bridge.handleAuthorize` is explicitly **NOT** a resolution
boundary in redirect mode. `mapCimdError` is an **exhaustive switch over `CimdReason`
plus a fail-closed default**; a non-`CimdError` throw (cache/clock/resolver wrapper)
maps to the same generic error AND audits one **fixed allowlisted reason
`fetch_failed`** — never the exception text (log-injection/leak). Reasons go to
`oauth.cimd.fetch` (failure) ONLY. The `cimd:<ip>` `RateLimitPort` denial is a
**pre-resolution direct 429** (`temporarily_unavailable`, the existing rate-limit
error) that is **OUTSIDE** this anti-oracle mapping (it is not a resolution outcome);
decision 2's map begins at URL admission / cache resolution and covers every
admission / DNS / blocklist / fetch / status / content-type / encoding / size /
timeout / document / redirect-match / overload failure. *Enforced property (no overclaim):* all CIMD
resolution **FAILURES** collapse to one client-visible **status + headers + OAuth
code + description** — closing the SSRF content/reachability oracle. (A **success**
necessarily proceeds to the normal authorize response — Set-Cookie + IdP 302 — and is
not claimed indistinguishable.) Response **timing is NOT equalized** (block ≈ instant,
timeout ≈ `fetchTimeoutMs`, success slowest) and remains a bounded residual side
channel, bounded by rate-limit + single-flight + `maxInFlight` + DNS-pinning +
blocklist + the deadline. The earlier "matches unknown-stored-client" parity wording
is DROPPED (that sibling uses description "Unknown client_id" — authorize.ts:192 /
upstream-flow.ts:176 — so parity is not claimed).

**Decision 3 — consent provenance; scope accumulation is stored-DCR-opaque-only
(CIMD accumulation DEFERRED).** `ConsentRequestClaims` (crypto.ts:19-34) gains
`cimdVerified?: true`, minted into the consent JWT as `cimd_verified: true` ONLY when
`prepare` established the CIMD registration by genuine validation this flow (direct:
its own validated fetch/cache result — a cache HIT counts, no network fetch; redirect:
the carried-forward validated registration, 1c). `signConsentToken` OMITS the claim
when absent/false (never `cimd_verified:false`); strict `payload.cimd_verified === true`
is the sole true path; any present non-`true` value INVALIDATES the token (fail-closed).
**This claim proves the provenance of the CURRENT authorization flow ONLY; it does NOT
establish the provenance of any existing refresh-token record, and is NEVER a
scope-accumulation entitlement.**

*Scope accumulation stays a stored-DCR opaque-client feature; every CIMD client stands
alone in v0.2.* The core MAY call `findGrantedScopes(subject, clientId, now)` ONLY for
an opaque client resolved through `ClientStore` in stored-DCR mode. For **every
scheme-shaped (`https://`) `client_id`, in BOTH stateless and stored mode**,
`priorScopes` MUST be `[]` and the code is minted from the current request's scopes
only (still bounded by the identity `allowedScopes` ceiling). The gate is fail-closed
on the **NEGATIVE class** — accumulation runs iff `dcr.mode === "stored" && NOT
scheme-shaped(clientId)` (the same canonical classifier rule 22 uses), **NEVER keyed on
`clientId.startsWith("https://")` and NEVER on `cimd_verified`** — so a missing or
mis-propagated `cimdVerified` value can never enable a grant-store read. Both sites:
prepare-time (authorize.ts:124) and approve-time (authorize.ts:158).

*Why deferred, not built (design-for-eventual-shape, build-minimal):* the current
refresh records (§12) carry no registration provenance, so a CIMD authorization cannot
safely union prior rows — a pre-CIMD stateless URL-keyed grant would silently resurrect
into a new document-bound CIMD grant. Doing it correctly needs immutable mint-time
registration provenance propagated through auth-code → token exchange → refresh-family
creation → rotation across all three stores, plus a legacy-row migration/default rule
(see the §12 note) — real security-core machinery for a re-authorization *convenience*
that the target AI clients (Claude, Cursor, VS Code — which request their full scope set
up front) do not use. It is a future-minor extension gated on real demand, never
inferred from the current flow's `cimd_verified` bit.

*Approve-time scheme/claim consistency gate (stored-state sibling of rule 22 — KEPT,
decoupled from accumulation).* Immediately after `verifyConsentToken` (authorize.ts:142)
and BEFORE the `approved !== true` deny branch (authorize.ts:145-149, which 302s to the
token's `redirectUri`), before any token-claim audit or `consumeConsentJti`
(authorize.ts:153): a lowercase-`https://` client_id is valid only when `cimd` is enabled
AND `cimd_verified === true`; any other scheme-shaped client_id, or `cimd_verified:true`
on a non-CIMD-shaped id, is invalid ⇒ **direct `invalid_consent`**, no code or state
change (so a legacy URL-shaped stateless consent token cannot be redeemed at all). This
is a validity check only — it is NOT an accumulation decision.

*Sibling reversals (S6b updates in lockstep):* §6.3, §9.3 step 5 + the approve "mint the
code with the accumulated scopes" bullet, §11, the §16 conformance-matrix row, and
§17.1.4 all state accumulation = **stored-DCR opaque clients only; CIMD clients stand
alone**; every "CIMD accumulates in either mode" claim is removed. The §7 `cimd_verified`
claim stays for the consistency gate + audit. Frozen suite: seed an active legacy
URL-keyed refresh row with a broader scope and prove a genuine CIMD authorization (BOTH
modes) reports `priorScopes = []` and mints only the requested, ceiling-bounded scopes; a
control case proves an opaque stored-DCR client still accumulates.

**Decision 4 — CimdFetchResult minimal cache view; RFC-9111-correct freshness (the
success cache serves BOTH modes).** The raw-client-id-keyed validated-success cache
(§17.1.4) is used at **both** direct-mode `prepare` AND upstream-redirect authorize
(1a) — NOT direct-mode-only. Redirect mode is the only mode that resolves
attacker-selected CIMD URLs BEFORE authentication, so without a cross-request cache an
unauthenticated caller sending sequential authorize requests for one valid CIMD id
would drive an unbounded series of outbound fetches (single-flight coalesces only
CONCURRENT requests; `maxInFlight` caps only concurrency; the rate limiter is optional
+ fail-open). Carrying the doc through one flow prevents a callback re-fetch; the
cache collapses repeated same-id fetches to one per freshness window **for cacheable
responses only** — a deliberately non-cacheable response (`no-store`, absent
`Cache-Control`, or `max-age` below 60, all attacker-controllable) is re-fetched on
each request and is bounded only by the optional `cimd:<ip>` limiter (documented
residual, threat rows 25/35; a mandatory origin-independent success budget is the §18
option, not built in v0.2). `CimdFetchResult`
(guarded-fetcher.ts:8, `{ document }`) is extended additively with a **minimal
duplicate-aware cache view** — the `Cache-Control` directive occurrences and the
`Age` field occurrences ONLY (from the transport's `headersDistinct`, rule 14) — NOT
the full header map (an unnecessary trust-boundary expansion). Error/invalid results
carry no cache view and are never cached. SUPERSEDES rule 25's upward clamp, with
pinned conservative arithmetic (all via `ClockPort`, no ambient `Date.now`):
`Cache-Control` directive names are ASCII case-insensitive; an **absent `Age` is 0**;
`Age` is cacheable only as exactly one occurrence matching `^[0-9]+$` within the
safe-integer bound (duplicate/list/signed/whitespaced ⇒ non-cacheable). All lifetime
arithmetic is in **seconds**; timestamps are **milliseconds** via `ClockPort`. Capture
`t0Ms = clock.nowMs()` before the fetch and **`t1Ms = clock.nowMs()` immediately after
the guarded fetch completes** (including body validation — this is the observable seam;
the guarded-fetcher returns only after the body is read, so a "last response header"
instant is not available); `elapsedSeconds = floor((t1Ms − t0Ms)/1000)`, and a
**negative or non-finite `elapsedSeconds` makes the response non-cacheable** (never
extends lifetime across a clock step);
`effectiveTtlSeconds = min(valid max-age, cacheTtlCapSeconds) − Age − elapsedSeconds`;
a **non-positive `effectiveTtlSeconds` is not cached**; **absolute expiry (ms) =
`t1Ms + effectiveTtlSeconds * 1000`** (unit-correct: seconds × 1000). A valid
`max-age` **below 60 is treated as non-cacheable** (fail toward re-fetch, which the
rate limiter bounds — one behavior, never clamped up). `no-store`/`no-cache`,
duplicate/conflicting `Cache-Control`/`max-age`, or a quoted `max-age` ⇒ no cache
entry. **The cache is bounded** to a finite entry ceiling (default 256 entries) with
deterministic LRU eviction; at the ceiling a new entry evicts the least-recently-used
one (never grows unbounded) — this caps the unauthenticated distinct-id memory
footprint (threat rows 25/35).

**Decision 5 — loopback derives from the dev flag; the core owns fetcher
construction (least machinery).** `allowLoopback` is **never a `cimd` config field**
(confirmed absent from `config.ts`); its effective value derives SOLELY from the
already-validated `dev.allowInsecureLocalhost === true`. The core CONSTRUCTS the
branded guarded fetcher itself from the validated `cimd` cap profile (rule-21
domains) + `allowLoopback` from the dev flag. A deployer-supplied **whole
`cimd.fetcher` is not a production config knob** — test injection uses the
`transport`/`resolver` seams (rule 14, already below the guard), which cannot widen
`allowLoopback` or the caps. This closes the prod loopback bypass
(`createGuardedFetcher({allowLoopback:true})` injected where
`dev.allowInsecureLocalhost` is off) by removing the injection point rather than
adding a profile-equality checker. **This amendment EDITS (not merely supersedes) the
canonical config in the SAME commit** — the `fetcher?: GuardedFetcher` field and its
brand-verification paragraph are deleted from §5 `BridgeConfig.cimd` and from §17.1
(a "supersedes" note is insufficient because `contracts.md` is the config source of
truth: leaving the snippet live lets S6b keep the injection point). `createGuardedFetcher`
remains the primitive/test factory but its whole result is NEVER accepted by
`BridgeConfig`. #90 already closed the prototype/inherited-option and unknown-key
vectors on the constructed fetcher's own options. *Residual (documented, not a gap):*
a production custom egress (e.g. a pinned corporate egress IP) has no v0.2 config knob
— consistent with rule 11 forbidding proxy env; it is a §18 follow-up if a real
deployment ever needs it, never a re-added whole-fetcher knob.

**Decision 6 — overload reason code (exhaustive mapper).** `CimdReason` (errors.ts)
gains `overloaded` for the rule-24 in-flight-cap rejection (a DISTINCT-client fetch
while `maxInFlight` distinct fetches are already in flight); **rule 24's "rejects
(generic error)" text is amended to name reason `overloaded`.** Audited to
`oauth.cimd.fetch` as `overloaded`; client-facing mapping is the decision-2 generic.
`overloaded` is simply added to `CimdReason` (rule 24 previously named no reason).
Covered by `mapCimdError`'s exhaustive switch
+ fail-closed default (decision 2), which a frozen test forces down the default path
with an unknown reason.

**Threat-model additions** (see [`threat-model.md`](threat-model.md) — CIMD ×
upstream-redirect row): (1) approve-then-swap CLOSED (validate-once + carry-forward);
(2) unauthenticated outbound-fetch-at-authorize RESIDUAL; (3) `consentSigningSecret`
value elevation RESIDUAL; (4) resolution-timing side channel RESIDUAL.

#### Decision 7 — bound the WAITERS on a single in-flight fetch (2026-07-25)

*Amends rule 24. Contract text; enforcement lands with its own frozen row + code.*

**The gap.** `maxInFlight` bounds concurrent outbound fetches. Single-flight
then collapses N concurrent requests for one raw `client_id` into ONE fetch —
correct, and rule 24 deliberately exempts followers from consuming a fetch slot
so a popular client cannot starve distinct client_ids. But the follower
REQUESTS still exist: each holds a socket, a promise chain, and a closure for up
to `fetchTimeoutMs` (≤ 30 s). Nothing bounded that count. Measured on the S6b
implementation: **10 000 concurrent same-id resolutions ⇒ 1 fetch, 0 settled,
~15.4 MB retained**, driven by an UNAUTHENTICATED caller (CIMD resolution runs
at upstream-authorize step 3a, before any IdP redirect). The only existing
defence is the `cimd:<ip>` limiter, which is OPTIONAL and FAIL-OPEN
(`noopRateLimit` returns `true`), so a default deployment has no bound at all.
This is the CWE-770 shape (allocation of resources without limits) on an
anonymous path.

**The rule.** A new `cimd.maxWaitersPerFetch` cap bounds callers parked on one
in-flight entry:

1. Domain `[1, 4096]`, default **256**, validated with the other caps (rule 21 —
   non-integer / out-of-domain / `NaN` ⇒ `AuthConfigError` at boot).
2. When an in-flight entry already has `maxWaitersPerFetch` waiters, a further
   follower for that SAME client_id rejects `CimdError("overloaded")` — the
   existing reason (decision 6), the existing decision-2 generic
   `invalid_client`. **No new client-visible surface and no new oracle:** an
   over-cap follower is byte-identical to every other resolution failure.
3. Audited `oauth.cimd.fetch` failure, reason `overloaded`, like any other.
4. Rule 24's no-slot rule is UNCHANGED: a follower still consumes no FETCH slot.
   Decision 7 bounds a different quantity. Both properties hold together.
5. Total concurrent waiting resolutions are bounded above by
   **`maxInFlight × (maxWaitersPerFetch + 1)`** — the `+1` is the INITIATING
   resolution, which also waits on its own fetch. Default
   `8 × (256 + 1) = 2056`, ≈ 3 MB at the measured ~1.5 KB/waiter. The cap counts
   FOLLOWERS only; the leader is never rejected by it. This composed number is
   the statement a deployer can hand to a security review, so it is stated
   exactly rather than rounded.

**Why 256 and not lower.** The cap must not break a legitimate thundering herd —
e.g. a workforce opening an MCP client at the start of a shift, all naming the
same `client_id` against a cold cache. 256 same-id waiters is far above that
pattern while still bounding the surface. It is a CEILING, not a throttle:
per-tenant shaping remains the deployer's `RateLimitPort`.

**Threat-model delta.** Residual (2) above narrows: the unauthenticated
outbound-fetch surface remains, but its memory/connection amplification is now
bounded rather than open-ended.

### 17.2 `client_credentials` grant (MCP extension `io.modelcontextprotocol/oauth-client-credentials`)

> **SHIPPED BASELINE.** S3a (PR #16, `0589ed3`) shipped the machine-client records +
> out-of-band provisioning/rotation primitives + the timing-safe `verify` and
> the boot/config/DCR/redirect guards. S3b ships the `/oauth/token` grant itself:
> `client_secret_basic` + `client_secret_post` client auth, the
> `MachineTokenResponse` split, the `client_credentials`-aware RFC 8414 metadata,
> and the `oauth.token.client_credentials` audit event.
>
> **UNRELEASED 0.3.0 AMENDMENT.** Versioned insert/CAS lifecycle writes,
> transactional durable mutation audits, disable tombstones, and the
> active/disabled record union below are implemented in this pending amendment
> for 0.3.0 but are not present in npm 0.2.3.

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
- **Lifecycle API (library functions, not endpoints).** The lifecycle
  use-cases take a deps object — `{ store, catalog, clock, audit }` — so they
  can validate `allowedScopes` against `scopeCatalog` (item below), stamp
  epochs, and emit audit without hidden globals. `catalog` is
  `config.scopeCatalog`; mutation `store` is `MachineClientStore`.
  - `provisionMachineClient(deps, { name?, allowedScopes, secretTtlSeconds? })`
    → `{ clientId, clientSecret }`. `clientId` = `mcc_<random>` — the prefix is
    enforced, giving a namespace disjoint from human subjects and from `mcpdc_`
    ids (RFC 9700 §4.15.1: the AS MUST let the RS distinguish machine tokens
    from user tokens; here `sub` starting `mcc_` ⇔ machine — made sound in
    BOTH directions by `prepare` rejecting any user-grant subject that starts
    with `mcc_` (§9.3 direct-error list) AND by the token grant handlers
    (code-exchange and refresh) rejecting a stored record whose subject is in
    the reserved namespace with `invalid_grant` BEFORE any side effect — the
    exchange saves no refresh token and audits no success (the single-use
    code is burned); the refresh path revokes the legacy family outright so
    it stops rotating — so neither a live IdP-supplied subject nor a legacy
    stored grant from a pre-guard deployment can impersonate the machine
    namespace, and the audit/refresh ledger reflects only real issuance —
    THIRD enforcement point: machine access tokens mint a
    `gty: "client_credentials"` marker claim, and `verifyAccessToken`
    accepts an `mcc_` `sub` ONLY with `sub == client_id` (RFC 9068 §2.2)
    AND that marker. The pair is required because stateless-DCR clients
    choose their own `client_id`, so `sub == client_id` alone could be
    satisfied by a pre-guard human token; the marker cannot, since only the
    machine grant mints it and the grant first ships in the SAME release as
    the marker (no legitimate unmarked machine token can exist from any
    published version — and any from pre-release `main` expires within
    `accessTokenTtlSeconds`). Residual: an RS that decodes these JWTs
    WITHOUT mcp-sso's verifier must classify by the same pair, never the
    `sub` prefix alone — stated in the README). The secret is
    returned ONCE and never retrievable. `allowedScopes` MUST be a non-empty
    subset of `catalog` (each entry a single RFC 6749 scope token; unknown or
    malformed ⇒ `invalid_scope`) — the per-client ceiling is fixed at
    provisioning, so a later catalog narrowing cannot silently widen a machine
    client. `secretTtlSeconds?` (positive integer), when given, sets the
    provisioned secret's `expiresAtEpoch = now + ttl` (a bounded-lifetime
    first secret). The computed epoch MUST also be a non-negative safe integer;
    overflow is `invalid_request` before the client id or secret is minted and
    before any store mutation. Omitted TTL ⇒ the secret is live until rotated.
    The inserted record starts `status:"active"`, `version:1`.
  - `rotateMachineClientSecret(deps, clientId, { graceSeconds = 86400 })` →
    `{ clientSecret, version }` (see Rotation below). `graceSeconds` is a
    positive integer. Its computed `now + graceSeconds` expiry MUST also be a
    non-negative safe integer; otherwise rotation is `invalid_request` before a
    secret is minted or a store mutation is attempted. The incremented mutation
    version MUST remain a positive safe integer; an active stored record whose
    version cannot be incremented is `invalid_client` before a secret is minted
    or a store mutation is attempted.
  - `disableMachineClient(deps, clientId)` →
    `{ clientId, disabledAtEpoch, version }`. The CAS transition sets
    `status:"disabled"` and `secrets:[]`; it is an auditable tombstone, not a
    delete. The same safe version-increment gate runs before its CAS. Repeated
    disable and rotation of a disabled client are `invalid_client`.
  - `verifyMachineClientSecret(deps, clientId, presentedSecret)` → `boolean`:
    the timing-safe comparison primitive the token endpoint (§9.4
    client_credentials grant, S3b) composes into client authentication. Finds
    an active machine client, SHA-256s the presented secret, and constant-time
    compares it against each **unexpired** stored hash (expired entries
    skipped). Non-machine / unknown `clientId` ⇒ `false` (never throws — the
    grant maps the boolean to `invalid_client`).
- **`ClientStore` extension:** `applicationType` gains `"machine"`; machine
  records carry `allowedScopes: string[]` (validated ⊆ `scopeCatalog` at
  wiring), positive `version`, and the closed active/disabled lifecycle union
  in §6.4. `redirectUris` MUST be `[]`; machine clients are rejected at
  `/oauth/authorize` and the device endpoints (`invalid_client`).
  `ClientStore.save` remains the user-registration write and does not accept
  machine records; machine writes exist only on `MachineClientStore`.
  `MachineClientStore.createMachineClient` and
  `compareAndSwapMachineClient` atomically persist the row plus required
  durable audit. Provision is insert-only. Rotate/disable increment version and
  fail on CAS conflict before a generated secret is returned.
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
  mandatory method; the MCP extension names `client_secret_basic`). A request
  presenting BOTH a `Basic` header and a body `client_secret` uses two auth
  methods and is rejected (`invalid_client`, RFC 6749 §2.3).
  `Bridge.handleToken` reads normalized headers through `readHeader`; an
  array-valued header or more than one case-insensitive `Authorization` key is
  `invalid_client` before body authentication is considered, so ambiguity never
  degrades to an absent header and `client_secret_post`. If any ambiguous value
  names the case-insensitive Basic scheme — including a bare malformed `Basic`,
  but not a `BasicX` prefix — `Bridge.handleToken` still returns the Basic
  challenge. For `client_credentials`, it attempts the
  `oauth.token.client_credentials` failure audit before rejecting, without
  reading the client store; a synchronous or rejected audit write cannot replace
  that `invalid_client` response. Advertise
  `token_endpoint_auth_methods_supported:
  ["none","client_secret_basic","client_secret_post"]` and
  `grant_types_supported` += `client_credentials` (RFC 8414's default omits
  it) — but ONLY when `clientCredentials.enabled` (a disabled grant is never
  advertised, so discovery cannot steer a client to a surface the bridge would
  reject with `unsupported_grant_type`; `"none"` is always advertised for the
  PKCE user grants). `private_key_jwt` (RFC 7523; the extension's RECOMMENDED
  method) is DEFERRED with 17.1's confidential-CIMD — recorded, not forgotten;
  the secret-based path is extension-compliant.
- **Grant semantics:** authenticate the client (failure ⇒ `invalid_client`
  401, `WWW-Authenticate: Basic` when Basic was attempted); `scope` validated
  against BOTH the client's `allowedScopes` ceiling AND the live `scopeCatalog`
  (a scope outside either ⇒ `invalid_scope`); omitted ⇒ the full allowed set
  (RFC 6749 §3.3 default). The catalog check matches the user-grant fail-closed
  gate (`normalizeScopes`): a scope removed from the catalog AFTER a machine
  client was provisioned is never minted — the persisted ceiling is not the
  whole truth, so drift surfaces as `invalid_scope` until the client is
  re-provisioned (the same discipline a drifted user refresh token imposes).
  The stored ceiling is itself validated at grant time — a non-empty array of
  scope tokens; `verifyMachineClientSecret` validates the secret slots but NOT
  `allowedScopes`, so a custom/migrated store returning a valid-secret record
  with a malformed/missing/empty ceiling fails closed as `invalid_client`
  (never a raw `TypeError`/500, never an empty-scope token). The `mcc_`
  clientId prefix — the RS's machine-vs-user distinguishability signal
  (RFC 9700 §4.15.1) — is likewise re-checked at grant time: a custom/migrated
  store returning a machine record whose id lacks the prefix fails closed as
  `invalid_client` (no JWT `sub` collision with a human/`mcpdc_` subject).
  `resource` if present MUST equal `config.resource` (`invalid_target`). Mint
  an access token with `sub = client_id`
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
- **Rotation:** `rotateMachineClientSecret(deps, clientId, { graceSeconds =
  86400 })` — adds the new secret (live, no `expiresAtEpoch`), expires the
  currently-live secret at `now + grace` (the two-active-secrets overlap
  pattern, per Okta/Entra practice; RFC 7592 is Experimental and
  hard-cutover, not used). The record's `secrets` array is then **exactly**
  the permitted active set: the new live secret plus at most one grace secret
  (the latest-expiring); any older/expired (`expiresAtEpoch ≤ now`) entry is
  dropped so the array never exceeds two unexpired hashes. So a rotation from
  a single-secret record yields `[{old, expiresAt=now+grace}, {new}]`; a
  second rotation before the first grace elapses supersedes the prior grace
  secret (its overlap is cut) to hold the two-active cap. Unknown clientId or
  a non-machine/disabled clientId ⇒ `invalid_client`. An expiry outside the
  non-negative safe-integer domain is `invalid_request` before mint/CAS. A
  stored version that cannot be safely incremented is `invalid_client` before
  mint/CAS.
  Verification accepts any unexpired stored hash on an active record. Two
  concurrent rotations read the same version; exactly one CAS can commit. A
  loser returns no secret and gets a conflict error, so every successfully
  returned secret remains in the committed record.
- **Disable:** `disableMachineClient` CASes an active record to a versioned
  tombstone with no accepted hashes after applying the same safe
  version-increment gate. Later client authentication fails `invalid_client`.
  Already-issued stateless access tokens are not recalled and remain valid only
  until their original `exp`; deployments bound that window with
  `accessTokenTtlSeconds` (Captatum uses 600 seconds).
- **Audit:** `oauth.token.client_credentials`, `oauth.client.provision`,
  `oauth.client.rotate_secret`, `oauth.client.disable` — clientId/scopes
  metadata only; never a secret or a secret hash. Each successful client
  mutation supplies its success event to `MachineClientStore`, which commits
  it atomically with the row. The post-commit `AuditPort` copy is best-effort:
  an EPIPE or sink exception cannot turn a committed credential into an
  unreturned one. Failure audits are likewise best-effort and never replace the
  original lifecycle error.
- The MCP `initialize`-handshake extension advertisement
  (`capabilities.extensions`) is the host app's/example's concern, not the
  bridge's.
- **Concurrency:** machine lifecycle writes require the
  `MachineClientStore` insert/CAS primitives. A backend that cannot provide the
  atomic row+audit transaction does not satisfy the port and cannot be used by
  these lifecycle functions. The base `ClientStore.save` method accepts only a
  `UserClientRegistration`, so there is no second non-CAS machine write in the
  public port. `client_credentials` issuance remains a read-only client lookup
  plus JWT signing and needs no token-side transaction.

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

> **SHIPPED S2a — IdP-agnostic `allowedScopes` ceiling plumbing (core).** The
> scope-ceiling *engine* is implemented and shipped: `IdentityClaims.allowedScopes?`,
> `Bridge.resolveIdentity(identity, input, ip?)` (replaces the `resolveSubject`
> helper and emits `identity.verify` — implemented as a Bridge method rather than
> the http.ts free function, so all three adapters share one DRY emission path),
> `Bridge.handleAuthorize(req, { subject, allowedScopes? })`
> (bare-string form removed), `AuthorizeRequestInput.allowedScopes?`,
> `ConsentRequestClaims.allowedScopes?` carried as the consent-JWT `allowed_scopes`
> claim, `prepare` narrows requested/default scopes by intersection (empty ⇒
> `access_denied` on the redirect channel), and `approve` re-intersects
> `union(requested, priorScopes)` against the ceiling read from the *verified
> consent token* (prior grants cannot resurrect a since-removed-group scope).
> Refresh is not re-checked. **No shipped identity port sets `allowedScopes`
> except Entra (see below), so v0.1 behavior is unchanged unless a port supplies
> a ceiling.**
>
> **SHIPPED S2b — the Entra group→scope *producer*.** `EntraConfig.groupAuthorization`
> (`mapping: Record<GUID, string[]>` + `baseScopes?`) ships in
> `src/identity/entra-groups.ts` (pure, JWKS-free, unit-testable) wired into
> `src/identity/entra.ts`. GUID-only mapping keys, non-empty scope values, and
> duplicate (case-insensitive) keys are boot-rejected (`AuthConfigError`); the
> mapped/base ⊆ `scopeCatalog` subset check runs at
> `createEntraIdentity(config, { scopeCatalog })` — the construction-time
> junction where both the Entra mapping and the bridge catalog are in scope (the
> shipped `registerOAuthRoutes` takes an opaque `IdentityPort` and does not see
> the EntraConfig; S2a kept the engine IdP-agnostic, so the port-construction
> call is the honest, enforceable junction — one extra arg). The verified
> `groups` claim is unioned with `baseScopes` into the ceiling; overage (`groups`
> absent + `_claim_names.groups` or `hasgroups`) fails closed with
> `entra_groups_overage` and `_claim_sources` is NEVER dereferenced; no groups +
> empty `baseScopes` fails with `entra_no_groups`. Reasons flow through
> `Bridge.resolveIdentity`'s `identity.verify` emission (S2a). Gates green
> (typecheck · lines · 244/244 test · build). **Live-tenant verification (incl.
> guest/B2B + overage) is owner-pending** — manual checklist at the top of
> `src/identity/entra.ts`.

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

- Boot validation (shipped S2b, `assertGroupAuthorizationMapping`): every
  `mapping` key must be GUID-shaped (display names rejected — fail-closed
  against the documented spoofing vector; case-insensitive, duplicate keys
  rejected), scope values non-empty AND each a single RFC 6749 scope token
  (`isScopeToken` / `SCOPE_TOKEN_RE` from `scopes.ts` — a whitespace/quote/
  control-bearing value is rejected so it cannot corrupt the space-joined
  `allowed_scopes` JWT round-trip; the boot-layer instance the PR #8 sweep left
  open). The mapped/base ⊆ `scopeCatalog` subset check runs at
  `createEntraIdentity(config, { scopeCatalog })` — the composition root where
  both the Entra mapping and the bridge catalog are in scope. (The original
  wording pointed at `registerOAuthRoutes`; the shipped S2a adapter takes an
  opaque `IdentityPort` and does not see the `EntraConfig`, so port construction
  is the honest, enforceable junction. A mapped scope absent from the catalog can
  never be granted anyway — the engine intersects against catalog-validated
  requested scopes — so the subset check is a deployer foot gun guard surfacing
  misconfiguration loudly at boot, not a security boundary. The separate
  `scopeCatalog`/`defaultScopes` entry shape-validation is a tracked backlog
  item, NOT bundled here.)
- **Combination model: UNION.** A subject's scope ceiling
  `allowedScopes = baseScopes ∪ ⋃ mapping[g]` over every group GUID `g` in
  the verified `groups` claim that has a mapping entry. No tier precedence,
  no highest-wins — union is order-independent and matches how directory
  membership composes. The verified GUID is a dynamic lookup key (§4.1): only
  an own mapping entry or equivalent `Map` entry contributes scopes. An
  inherited entry is unmapped and contributes nothing; if no mapped group and
  no `baseScopes` remain, the existing `entra_no_mapped_groups` failure applies.
- **Overage = fail closed.** `groups` absent + (`_claim_names.groups` or
  `hasgroups`) present ⇒ `verify()` fails with reason
  `entra_groups_overage`. The `_claim_sources` URL is NEVER dereferenced — a
  URL inside a token is data, not instructions. Documented remediation:
  configure the app registration with **"Groups assigned to the
  application"** (`groupMembershipClaims: "ApplicationGroup"`) — caveats
  recorded: requires Entra P1, direct membership only, no nesting — or reduce
  group sprawl.
- **No usable groups ⇒ fail closed with a reason that names the likely knob.**
  No `groups` claim at all (not configured in the app manifest, or the user is
  in zero groups) + empty `baseScopes` ⇒ `entra_no_groups` (likely a
  `groupMembershipClaims` misconfiguration). A `groups` claim IS present but
  every group is unmapped + empty `baseScopes` ⇒ `entra_no_mapped_groups` (a
  deployer *mapping* gap, not a manifest problem — the distinct reason points
  the operator at `groupAuthorization.mapping` rather than the Entra app
  manifest; audit fidelity for a product whose wedge is auditable execution).
  Both are entitled-to-nothing and fail closed; non-empty `baseScopes` resolves
  to the baseline ceiling instead. Nested groups: the `SecurityGroup` claim is
  transitive; `ApplicationGroup` is direct-only (deployer caveat in
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
- **Audit:** event `identity.verify` (emitted by `Bridge.resolveIdentity`,
  S2a; success/failure + reason) carries the Entra reasons
  `entra_groups_overage`, `entra_no_groups`, and `entra_no_mapped_groups` —
  failed-login evidence for enterprises.

### 17.5 Console-pairing identity (zero-IdP setup)

> **SHIPPED S1b** (`src/identity/console-pairing.ts`, subpath
> `./identity/console-pairing`; the example's `DEV_STUB_SUBJECT` dev bypass is
> deleted — a real gate replaces no-gate). The framework-free authorize
> orchestration is `handlePairingAuthorize` (`src/adapters/pairing-flow.ts`),
> mounted via the adapters' `skipAuthorize` option; `beginSession()` generates +
> prints the code lazily (one active code per process, reused while live), and
> `verify({ code, nonce, ip? })` does the timing-safe check + emits
> `oauth.pairing.attempt`. The code is NEVER audited — it is 12 chars, below the
> 32-char redactor in `src/audit/util.ts`, so the event's `reason` is always an
> enum literal (asserted in `test/identity-console-pairing.test.ts`).

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
- **Session binding:** the code is single-use and bound to the pairing *session*
  (a random nonce in the form) and to the operator who pastes it — not to the
  specific OAuth request parameters (`client_id`, `redirect_uri`, `scope`, …),
  which round-trip through the form. Those parameters are re-displayed on the
  consent page before the grant is minted, so the operator sees and approves the
  resource + scopes at consent time. An attacker who triggers a code onto the
  operator's console gains nothing without the printed code; only the operator
  pasting it completes the flow.
- **Rate limiting:** the attempt cap is built-in and in-process — it cannot be
  misconfigured away; the `RateLimitPort` hook (`pairing:<ip>`) adds
  defense-in-depth.
- **Trust boundary (threat model):** whoever can read the process's stderr IS
  the operator. Log pipelines (docker logs, CloudWatch, Loki) EXTEND that
  boundary — codes land in them; TTL + single-use + attempt cap bound but do
  not eliminate the exposure. **Deployment envelope: single-operator/personal
  deployments with operator-private console output + LOOPBACK binding.** A host
  example binds the pairing authorize surface to `127.0.0.1` by default
  (`defaultListenHost`); a non-loopback bind (or tunneling the loopback
  listener publicly) exposes the surface + the attempt budget to the network and
  is an explicit envelope breach — public/networked deployments must use a real
  IdP port (Cloudflare Access, etc.), not pairing. The printed banner and docs
  say exactly this.
- Audit: `oauth.pairing.attempt` (success/failure — brute-force evidence).

### 17.6 `GenericOidcIdentity` + Google preset + dedicated GitHub port

> **SHIPPED S4a (generic + Google):** `createGenericOidcIdentity` +
> `createGenericOidcRedirectIdentity`, and the Google preset
> (`createGoogleIdentity` + `createGoogleRedirectIdentity`), ship as
> `RedirectIdentityPort`s consumed by the §17.11 orchestrator. They are
> unit/flow-verified only (synthetic RS256/ES256 id_tokens through the real
> `validateGenericOidcIdToken`/`validateGoogleIdToken` → bridge path); a real
> live sign-in is owner-pending (manual checklist at the top of each source
> file). The dedicated GitHub port stays 🔒 locked (its own port — no OIDC
> discovery, no id_token; identity via the REST API). Setup guides:
> [`docs/identity/generic-oidc.md`](./identity/generic-oidc.md),
> [`docs/identity/google.md`](./identity/google.md).

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
  and multiple-audience tokens are rejected outright (a single-element
  `[clientId]` array is accepted; an array with any second audience is
  rejected before the contains-check — fail-closed simplification of OIDC
  Core §3.1.3.7; the check lives in the pure validator, NOT jose's
  `audience` option, which accepts multi-audience tokens); `exp` **and**
  `iat` presence required (OIDC Core §2 mandates `iat`; jose validates
  `exp`/`nbf` against the clock but does **not** validate `iat`'s value, so
  the pure validator asserts both claims' *presence* — a deliberate tightening
  over the Entra `exp`-only check; the Entra public API is unchanged. A
  far-future `iat` is **not** separately rejected: `exp` bounds the token's
  lifetime, and rejecting `iat`-ahead-of-now would break legit issuers with
  clock skew — accepting it gives an attacker who can already sign nothing
  beyond what `exp` already grants);
  algorithms pinned to `{RS256, ES256}` ∩ the provider's advertised
  `id_token_signing_alg_values_supported` — a **missing** advertised set
  defaults to `{RS256, ES256}` (don't over-reject providers that omit the
  metadata), but a **present** set with an empty intersection boot-FAILS
  (no usable alg); **nonce always sent, always verified** (once sent, OIDC
  Core makes the claim mandatory — missing/mismatch is a hard failure);
  `at_hash` validated when present **in the code flow** (the access_token is
  available). Subject = `sub`, canonicalized to `${issuer}|${sub}` as the bridge
  subject string — the bridge keys granted scopes by the subject string, so an
  opaque `sub` that collides across issuers (e.g. a stored-DCR store reused after
  changing issuers) must not inherit another issuer's grants. (Entra `oid` / CF
  `sub` are globally-unique GUID/UUID; a generic `sub` is not, hence the issuer
  namespace. The optional `subjectAllowlist` matches the raw `sub` claim.) Email is a display
  attribute, never the identity key.
  - **`at_hash` header-mode residual:** when a raw id_token is verified
    standalone with no `access_token` (header mode), `at_hash` — if present
    — is **skipped**, not rejected: there is no access_token to hash it
    against. This is the same residual class as the header-mode nonce
    (threat-model row 12): the fronting proxy owns the access_token binding.
    Never computed against `undefined`.
- **PKCE:** always S256. If discovery omits `code_challenge_methods_supported`
  (per RFC 8414 that means no PKCE support), boot FAILS unless the deployer
  sets `allowProviderWithoutPkce: true` (state + nonce + client secret still
  bind the flow; the flag is loud).
- **Token-endpoint client auth (confidential clients):** the secret is sent by the
  method resolved from discovery `token_endpoint_auth_methods_supported` —
  `client_secret_post` when supported (else `client_secret_basic`), boot-failing if
  neither is advertised for a confidential client. Omitting the field defaults to
  `client_secret_basic` (OIDC Discovery §3). A deployer may force either via
  `tokenEndpointAuthMethod`. Public clients (no secret) are unaffected (PKCE only).
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
    POST, https required (raw prefix check), userinfo (`user:pass@`) rejected at
    construction (credentials belong in `headers`; a fetch error would otherwise
    echo the URL), redirects not followed, at-most-once (no retry). Deliberately
    NOT behind the 17.1 SSRF guard: the URL is static deployer config (trusted),
    and SIEM collectors legitimately live on private networks — documented
    rationale. `fetchImpl` is an optional DI seam (defaults to the global
    `fetch`) for test-injecting the transport without an https server; not a
    deployer-facing knob. Error messages reaching stderr are redacted
    (`src/audit/util.ts`) and the configured header values and URL query-string
    params scrubbed — a transport that echoes request headers, the URL, or a
    credential-bearing query (`?access_token=…`) into an Error.message cannot
    leak them.
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
  `oauth.client.rotate_secret`, `oauth.client.disable`, `oauth.cimd.fetch`. `AuthAuditEvent` gains
  optional `ip?: string` (adapter-populated; personal data — noted in docs).
  The §13 metadata-only rule is unchanged and the no-secrets serialization
  test extends to every new event.
- **Retention: documentation guidance, not a library mechanism.** The library
  emits; the deployer retains (compliance frameworks set their own periods).

### 17.8 Quickstart secret persistence (auto-keygen)

> **SHIPPED S1b** (`src/quickstart.ts`, root-exported). The standalone
> `examples/fastify-sqlite` boots zero-config via
> `loadOrCreateQuickstartSecrets`; the env-var path (`configFromEnv`) remains for
> production. POSIX permission check, `O_EXCL` create, `0700`/`0600`, and the
> `.gitignore` are all asserted in `test/quickstart.test.ts` (rows S1b.1–S1b.4);
> no ephemeral fallback under any failure mode.

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
  env/secret managers. (`npx mcp-sso init` is now implemented — §15 "Init CLI" —
  scaffolding a server that uses this helper; the function remains the contract.)
- **Filesystem-trust bar (the quickstart reference — every state-dir code path
  meets this):** writes are `0600` (files) / `0700` (dirs) with `O_EXCL` for
  create-don't-clobber; reads of trusted content go through `open(O_NOFOLLOW |
  O_NONBLOCK)` + `fstat` + read-fd (atomic: refuses a symlink, won't hang on a
  FIFO/special file, no lstat→readFile race) + a perm check (`mode & 0o077`
  fails closed, POSIX); a pre-existing dir is `assertRealDir`'d (reject symlink
  + group/other-accessible mode); the `.gitignore` is the managed `*\n` (write
  into a dir we created, require exact in a pre-existing one).
- **Parity rule:** EVERY code path that creates or reads the state dir —
  `loadOrCreateQuickstartSecrets`, the example's Cloudflare Access branch
  (`ensureStateDir`), the sqlite store (`openSqliteStore` chmod 0600), the audit
  sink (`JsonlFileAudit` O_NONBLOCK) — meets this bar. A control fixed in one
  path MUST be applied to every sibling that touches the same resource (the
  "sweep for sibling instances" discipline — global CLAUDE.md).

### 17.9 Worked-example design notes (v0.2 examples)

- Express + Hono equivalents of `examples/fastify-sqlite` — execution only,
  no new contract surface. Examples use console pairing (17.5) or a real IdP;
  the `DEV_STUB_SUBJECT` pattern is removed.
- **API-key-gateway example** (mcp-sso as the SSO front door for a backend
  that only accepts a static API key): the backend key lives in an env var
  (`BACKEND_API_KEY`), read once at boot into a closure — never logged, never
  audited, never placed in token claims, and never injected into any response
  the gateway itself generates; it is injected server-side on the proxied backend
  call only after `RequestAuthorizer` accepts the bridge-minted token. Missing
  key = boot failure. Secret-manager integration is out of scope for the example
  but the read is isolated behind a single `getBackendCredential()` swap point.
  **Boundary (transparent proxy):** the gateway forwards backend response bodies
  verbatim, so it cannot prevent a *backend that itself echoes the injected
  credential* from exposing it — a backend MUST never reflect its received
  `Authorization`. The gateway's guarantee is that it does not introduce the key
  into any client-visible surface; the trusted backend must not either.

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

### 17.11 Upstream redirect-leg orchestrator (locked 2026-07-06)

The framework-free orchestrator for **redirect-based upstream IdPs** — the
`pairing-flow.ts`-style sibling that turns the shipped Entra *primitives*
(`getAuthorizationUrl`, `exchangeCodeForToken`, `verify` — §6.5) into a mounted
flow: GET `/oauth/authorize` → persist flow state → 302 to the IdP → callback →
validate → exchange → verify → `bridge.handleAuthorize` → consent page. Today a
deployer must hand-write this dance (state CSRF binding, nonce/id_token replay,
callback validation — the highest-risk per-deployment code in the system); every
live-verified row so far ran via Cloudflare Access, whose edge did the browser
leg. One orchestrator serves Entra now and the §17.6 ports
(GenericOidc/Google/GitHub) later.

**Port surface — `RedirectIdentityPort` (new, in `ports/identity.ts`):**

```ts
interface RedirectIdentityPort {
  /** The exact redirect URI registered at the IdP. Boot-asserted equal to
   *  issuerOrigin(config) + callbackPath — the callback is served by the same
   *  app at the issuer origin, and a mismatch is silent breakage at the IdP. */
  redirectUri: string;
  buildAuthorizationUrl(req: {
    state: string; nonce: string;
    codeChallenge: string; codeChallengeMethod: "S256";
  }): string;
  /** Exchange the code and verify the resulting identity. MUST bind the
   *  id_token to `nonce` when the provider issues id_tokens (OIDC); a provider
   *  with no id_token (the §17.6 GitHub port) verifies identity via its REST
   *  calls and reports through the same result type — that gap is documented
   *  per-port, never silent. */
  exchangeAndVerify(args: {
    code: string; codeVerifier: string; nonce: string;
  }): Promise<RedirectExchangeResult>;
}

type RedirectExchangeResult =
  | { ok: true; identity: IdentityClaims }
  /** Transport/protocol failure — non-200, timeout, malformed body, missing
   *  id_token (for a provider that issues them). No identity decision made. */
  | { ok: false; kind: "exchange_failed"; reason: string }
  /** Verified-context denial — bad iss/aud/tid/nonce, allowlist, group
   *  rejection. An identity decision WAS made: the user is refused. */
  | { ok: false; kind: "identity_rejected"; reason: string };
```

A **throw** from `exchangeAndVerify` is always classified `exchange_failed`
(unexpected infrastructure failure — one deterministic rule, so the two
failure channels below can never depend on which exception a port happened to
raise); `identity_rejected` exists only as an explicit returned value.

The **orchestrator** (not the port) generates `state`, `nonce`, and the PKCE
verifier/challenge — uniform CSPRNG entropy guarantees, 32 random bytes
base64url each. Entra ships `createEntraRedirectIdentity(config, opts?)`
(subpath `./identity/entra`) wrapping the existing primitives — the current
`EntraIdentity` API is unchanged. Its default token-endpoint transport is the
global `fetch` against the hardcoded `https://login.microsoftonline.com`
endpoint with a 10 s `AbortSignal.timeout` deadline (deployer-trusted endpoint,
deliberately NOT the §17.1 SSRF guard — same rationale as §17.6 discovery); the
transport stays injectable for tests. It requests upstream scope
`openid profile email` exactly — **no `offline_access`**: the bridge discards
the upstream token response, so requesting a long-lived upstream refresh token
it will never use violates least-grant.

**Factory — `createUpstreamRedirectFlow` (new, `src/adapters/upstream-flow.ts`,
root-exported like `handlePairingAuthorize`):**

```ts
createUpstreamRedirectFlow({
  bridge: Bridge;
  identity: RedirectIdentityPort;
  store: StorePort;           // REQUIRED — the SAME instance the Bridge uses
  clock: ClockPort;           // REQUIRED — the same instance the Bridge uses
  audit: AuditPort;           // REQUIRED — the Bridge's sink (pass noopAudit only deliberately)
  rateLimit?: RateLimitPort;  // default noopRateLimit — mirrors BridgeDeps exactly
  callbackPath?: string;      // default "/oauth/callback"
  flowTtlSeconds?: number;    // default 600
  // Below-guard test seams ONLY (§17.1.6 decisions 1e/5) — never a whole GuardedFetcher,
  // never a BridgeConfig field; cannot widen allowLoopback or the caps:
  cimdTransport?: CimdTransport;   // optional low-level connect-to-validated-IP transport
  cimdResolver?: DnsResolver;      // optional DNS resolver seam (the guarded-fetcher DnsResolver type)
}) → UpstreamRedirectFlow    // { handleAuthorize(req), handleCallback(req), callbackPath }
```

The flow's mandatory controls (the `upstream:<ip>` rate-limit guard, the
single-use jti via `consumeConsentJti`, `ClockPort` time for the flow JWT, and
the `oauth.upstream.callback` emission) need these ports **explicitly**: the
`Bridge` deliberately keeps its own deps private (only `config` is public, which
also supplies `consentSigningSecret`/`issuer` here), and this contract adds NO
new Bridge surface. The composition root already holds `BridgeDeps` — it passes
the same instances to both, and the factory's required/optional split
**mirrors `BridgeDeps` exactly** (`store`/`clock`/`audit` required,
`rateLimit` optional defaulting to no-op): `store` because flow jti rows must
live in the same store as the consent JTIs (`sweepExpired` coverage +
multi-replica replay scope), and `clock`/`audit` because making them
defaultable would let a forgotten argument silently split time and evidence
between a bridge and its flow — omitting audit must be a visible, deliberate
`noopAudit` at the call site, never an accident.

Boot validation (all `AuthConfigError`, fail-closed): `callbackPath` is a
**plain pathname** — starts with `/`; contains no `?`, `#`, `%`, `\`,
whitespace, or control characters (framework routes match by pathname, so a
query-bearing "path" would register a route the real callback request never
hits; percent-encoding and backslashes have no business in a configured route
and are rejected outright rather than decoded); has no empty (`//`) or dot
(`.`/`..`) segments; and `new URL(issuerOrigin + callbackPath).pathname` MUST
equal the configured string exactly. The character checks run on the RAW
string BEFORE any URL parsing (the §17.1 dot-segment lesson: WHATWG parsers
normalize `/%2e%2e/` away, so a post-parse check cannot see it), and the
normalized-equality check catches whatever survives — otherwise a path like
`/foo/%2e%2e/oauth/token` registers one route while browsers deliver the
callback to a reserved one. The reserved-route comparison runs on this
validated literal, which the checks above make identical to its normalized
form. `callbackPath` must be none of the reserved routes (`/oauth/authorize`, `/oauth/authorize/approve`,
`/oauth/token`, `/oauth/register`, `/oauth/revoke`, `/oauth/jwks`, anything
under `/.well-known/`, or the resource path); `identity.redirectUri` contains
no query or fragment and `=== issuerOrigin(config) + callbackPath` exactly;
`flowTtlSeconds` is a positive integer ≤ 3600. Both handlers are GET-only and
speak `NormRequest`/`NormResponse` (§9.6) — no new runtime deps (jose + core).

**Cross-redirect state: a signed flow cookie (DECIDED — not StorePort
records).** The flow context crosses the redirect as an HS256-signed JWT in a
cookie, single-used through the existing consent-JTI registry:

- *Why a cookie is required regardless:* binding the callback to the browser
  that initiated the flow (login-CSRF/session-fixation defense, and the
  same-browser guarantee below) needs a **browser-held secret**. Server-side
  records keyed by `state` cannot provide that — anyone who obtains a callback
  URL could complete the flow in a victim's browser. Given the cookie is
  mandatory, a parallel StorePort record (new methods + conformance rows +
  three store migrations) would duplicate state the cookie carries statelessly.
- *Single-use without new store surface:* the flow JWT's `jti` (prefix `upf_`,
  32 random bytes base64url — namespaced so it can never collide with consent
  JTIs) is consumed via the shipped `consumeConsentJti(jti, expiresAtIso)`
  (§12: true on first use, false on replay; swept by `sweepExpired`).
  Multi-replica deployments on a shared store (mysql) get cross-replica replay
  detection for free; the per-process memory store detects replay per instance
  only (same residual class as consent JTIs — threat model).
- A store failure during consumption propagates as a direct 500 per §9.5
  (consistent with `handleApprove`) — never fail-open.

**Flow JWT (the cookie value):** header `{alg:"HS256", typ:"JWT"}`; claims
`iss`=issuer, `aud`=**`"mcp-sso/upstream-flow" + callbackPath`** (see
"flow-instance binding" below), `jti` (`upf_…`, single-use),
*(suite-faithfulness rule, added 2026-07-26, scope clarified same day: a
FROZEN acceptance test must never import or hardcode an **implementation
constant** — a value the contract does not specify, which can therefore
change without a contract amendment. It MAY (and, where the contract pins an
exact value, MUST) assert what the CONTRACT specifies. Two consequences,
one per suite: `s6b-redirect.test.ts` predates the per-flow binding and pins
only behavior §17.11 owned then, so it observes the audience once through
the public seam — mint a cookie via `handleAuthorize`, decode, reuse — and
survives audience amendments unchanged. `flow-instance-binding.test.ts` is
the frozen suite FOR the per-flow amendment: §17.11 contracts
`aud === "mcp-sso/upstream-flow" + callbackPath` exactly, so that suite
derives the expected audience from the contracted formula and asserts it —
behavior-only assertions there would pass an implementation that keeps the
deployment-wide audience and adds a side claim, violating the locked
contract. Deriving from the contract's own text is pinning the contract;
importing `FLOW_AUDIENCE` from
`src/adapters/upstream-flow-internals.ts` — what the original
`s6b-redirect.test.ts` did, forcing a frozen edit for a contract-legitimate
change — is pinning the implementation, and the `check:seams` CI gate now
rejects it.)*
`iat`, `exp`=`iat`+`flowTtlSeconds`, `state` (upstream state, 32B base64url),
`nonce` (32B base64url), `code_verifier` (the **upstream** PKCE verifier, RFC
7636 43-char base64url), and `params` — the round-tripped client OAuth params,
exactly the `OAUTH_PARAM_KEYS` set (`response_type`, `client_id`,
`redirect_uri`, `code_challenge`, `code_challenge_method`, `resource`, `scope`,
`state`; string values only, absent keys omitted), plus (§17.1.6 decision 1c) an
optional **`cimd`** claim carrying exactly a `CimdRegistration`
(`{ client_id, client_name, redirect_uris }`) — present ONLY for a CIMD-path
authorize, absent for opaque clients, covered by the same HS256 signature and
strict-parsed at callback row 3 (1d). Verified with
`algorithms: ["HS256"]`, pinned `iss`+`aud`, clock from `ClockPort`.

**Flow-instance binding (amended — the `aud` is per-flow, not deployment-wide).**
The audience is `"mcp-sso/upstream-flow" + callbackPath` (e.g.
`mcp-sso/upstream-flow/oauth/callback`), so each flow accepts only cookies it
minted. `callbackPath` is the binding value because it is already required to be
unique per mounted flow and is boot-validated (`assertCallbackPath`) into a
canonical, non-forgeable literal; no new config knob is introduced. A cookie
whose `aud` does not match the callback's own value fails `jwtVerify` and is
reported as the existing **row 3** `flow_cookie_invalid` — no new failure row,
no new error code.

*Why:* the audience was previously the deployment-wide constant
`"mcp-sso/upstream-flow"`, carrying no callback path, provider id, or per-flow
identity, so **every flow built from one signing secret accepted every other
flow's cookies**. A deployment mounting two flows under one issuer (two IdPs)
could therefore have a cookie minted for the intended IdP redeemed through a
different configured one — an authentication-provider **confused deputy**.
Reproduced before the fix: flow B's callback returned 302 while calling IdP B's
`exchangeAndVerify` with flow **A's** PKCE verifier and nonce, and accepting A's
carried CIMD registration. The initiating request is unauthenticated (CIMD
resolution runs at authorize step 3a, before any IdP redirect), so a remote
caller can start flow A and reuse its state/challenge against IdP B. The shipped
adapters mount a single flow — hence MEDIUM, not HIGH — but the exported factory
does not prevent the multi-flow topology and nothing documented it as
unsupported. Binding is preferred over forbidding the topology: two IdPs under
one issuer is a shape a deployer may legitimately want.

*Compatibility:* this changes the flow-token claim shape. Flow cookies are
short-lived (`flowTtlSeconds`, default 600 s) and only ever in flight during a
login, so an in-flight cookie minted before an upgrade fails row 3 and the user
retries — no persistent state is invalidated.
**Signing key: `consentSigningSecret`** (decided): one deployment secret that
already crosses replicas; cross-type replay is impossible because both
verifiers pin distinct `aud` values (`mcp-sso/consent` vs
`mcp-sso/upstream-flow`), and a hypothetical flow-JWT forgery is strictly
weaker than the consent-token forgery the same secret already implies (a flow
token asserts no subject — identity still comes from the IdP exchange). The
§7 HS256/ES256 key separation is unchanged. The JWT is signed, **not
encrypted**: the browser's owner can read their own in-flight params and PKCE
verifier; the verifier's only power is redeeming the code bound to this same
browser's flow. Naming note: `state`/`nonce`/`code_verifier` here are the
**upstream (bridge→IdP) leg's** values; the *client's* `state` and
`code_challenge` ride untouched inside `params` (two independent PKCE pairs —
see below).

**Cookie profile (this library sets its FIRST cookie here — threat-model row 4
amended accordingly).** Decided at boot from the issuer origin scheme:

- https issuer: name **`__Host-mcp-sso-upstream`**, attributes
  `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=<flowTtlSeconds>`. Per the
  `__Host-` prefix rules (RFC 6265bis): `Path` MUST be exactly `/`, `Secure`
  MUST be present, and the `Domain` attribute MUST NOT be set — on the
  clearing `Set-Cookie` too, or browsers treat it as a different cookie.
- http loopback issuer (legal only under §5 `dev.allowInsecureLocalhost`):
  name `mcp-sso-upstream`, same attributes minus `Secure` (the `__Host-`
  prefix requires `Secure`); still no `Domain`, still `Path=/`.

`SameSite=Lax` is load-bearing: the callback is a top-level cross-site GET
navigation from the IdP, which Lax permits while still blocking cross-site
subresource/POST delivery — this is also why the flow **locks the query
response mode** (`response_mode=query` for Entra; a form_post-style callback
would arrive cookieless under Lax and MUST NOT be used). `HttpOnly` keeps the
PKCE verifier out of script reach. The cookie is cleared (`Max-Age=0`, same
attributes) on every callback response that had a readable cookie — success or
failure. One flow per browser: a second authorize overwrites the cookie
(last-writer-wins); the superseded flow's callback then fails the state match
(direct 400). If the serialized `Set-Cookie` value would exceed **4096 bytes**,
`handleAuthorize` fails direct `invalid_request` (oversized client params) — EXCEPT
when this authorize took the CIMD path (§17.1.6 decision 1b), where oversize maps to
the decision-2 generic `invalid_client` so document size is not a content oracle.

**`flow.handleAuthorize(req)` (GET `/oauth/authorize`):**

1. `RateLimitPort` guard, key **`upstream:<ip>`** (extends the §6.7 key set;
   same advisory posture — `false` ⇒ 429, thrown ⇒ fail-open). Rationale: each
   initiated flow authorizes at most one outbound token-endpoint call at the
   callback, so limiting initiation bounds exchange amplification.
2. Any `OAUTH_PARAM_KEYS` parameter present **more than once** (array-valued
   in `NormRequest.query`) ⇒ **direct 400 `invalid_request`** before any
   cookie is set — RFC 6749 §3.1 forbids repeated request parameters, and
   silently picking first/last would make parameter-pollution behavior
   adapter-dependent.
3. `client_id` present and `redirect_uri` **mode-appropriately validated**
   (§17.1.6 decision 1a): for a literal-lowercase-`https://` CIMD id with `cimd`
   enabled, the CIMD document match (shape-first, BEFORE any `store.find`);
   for an opaque non-scheme id, §10; any other scheme-shaped value ⇒ direct
   `invalid_client`. Else **direct 4xx** (§9.3 pre-validation; `invalid_request`
   / `invalid_redirect_uri` / `invalid_client`). No other param is validated
   here (DECIDED): `prepare` (§9.3) stays the single source of truth for
   `response_type`/scope/PKCE validation — a malformed request costs one IdP
   round-trip and then errors on the proper §9.3 channel, instead of this leg
   growing a drift-prone duplicate validator.
4. Generate `state`/`nonce`/verifier+challenge, sign the flow JWT, `Set-Cookie`,
   302 to `identity.buildAuthorizationUrl(...)`. Nothing is persisted
   server-side at this step; an abandoned flow is just an expired cookie.

**`flow.handleCallback(req)` (GET `callbackPath`) — validation order and
failure table.** The redirect channel becomes available only because the
`redirect_uri` inside the *verified* flow JWT already passed **mode-appropriate
validation** (§10 for opaque ids, the CIMD document match for CIMD ids — §17.1.6
decision 1) at authorize time; any failure to establish that context is a
**direct 4xx, never a redirect**:

| # | Condition | Channel | Error / audit reason |
|---|---|---|---|
| 1 | `state`/`code`/`error`/`error_description` present more than once (RFC 6749 §3.1 — no first/last picking) | direct 400 `invalid_request` | `duplicate_params` |
| 2 | flow cookie absent | direct 400 `invalid_request` | `flow_cookie_missing` |
| 3 | flow JWT signature/`iss`/`aud` invalid | direct 400 `invalid_request` | `flow_cookie_invalid` |
| 4 | flow JWT expired | direct 400 `invalid_request` | `flow_expired` |
| 5 | `state` query param absent or ≠ JWT `state` (timing-safe compare; length mismatch fails) | direct 400 `invalid_request` | `state_mismatch` |
| 5a | **(§17.1.6 decision 1d, POLICY)** CIMD claim/mode/redirect inconsistency — for a lowercase-`https://` client_id: `cimd` disabled, or an **absent** `cimd` claim, or `params.redirect_uri` not matching the claim's `redirect_uris` (shared matcher); or a non-CIMD client_id carrying a `cimd` claim. (A present-but-**malformed** claim already failed cookie verification at row 3.) Checked AFTER state match, BEFORE jti consumption / exchange / any redirect-channel row | direct 400 `invalid_request` | `flow_cookie_invalid` |
| 6 | `jti` already consumed (callback replay) | direct 400 `invalid_request` | `flow_replayed` |
| 7 | IdP `error` param ∈ `access_denied`/`consent_required`/`interaction_required`/`login_required` | **302 redirect** `access_denied` | `upstream_denied` |
| 8 | IdP `error` param = anything else | **302 redirect** `server_error` | `upstream_error` |
| 9 | no `code` param (and no `error`) | direct 400 `invalid_request` | `missing_code` |
| 10 | `exchangeAndVerify` returns `kind: "exchange_failed"` **or throws** (non-200, timeout, malformed body, missing id_token from an id_token-issuing provider) | **302 redirect** `server_error` | `exchange_failed` |
| 11 | `exchangeAndVerify` returns `kind: "identity_rejected"` (id_token invalid, nonce mismatch, tid/allowlist/group rejection) | **302 redirect** `access_denied` | `identity_rejected` (detail in `identity.verify`) |
| 12 | `bridge.handleAuthorize` errors | its own §9.3 channels | unchanged |
| 13 | success | 200 consent page | — |

The `jti` is consumed at step 6 — before the IdP `error` branch and before the
exchange — so a callback URL is single-use as a whole and a replay can never
trigger a second outbound exchange. Redirect-channel errors carry **fixed**
`error_description` strings ("upstream identity provider denied the request",
"upstream identity provider error", "upstream identity verification failed");
the IdP's own `error`/`error_description` values are **attacker-influenceable
query params and are never echoed** into the redirect, response body, or logs.
The final redirect's `state` is the *client's* state from the verified
`params`, never attacker input. An RFC 9207 `iss` param on the upstream
callback is not validated in this release (DECIDED): mix-up defense applies to
clients talking to multiple ASes; a flow instance has exactly ONE upstream IdP,
and state+nonce+PKCE bind the callback to it. Revisit at §17.6 (S4a) if a
generic deployment ever configures interchangeable upstreams.

**§9.3 extension (explicit deviation):** §9.3 routes identity failure as a
direct 401 because it normally occurs *pre*-validation. On this flow the
identity outcome arrives *after* the `redirect_uri` was **mode-appropriately
validated** (§10 for opaque ids, the CIMD document match for CIMD ids — §17.1.6
decision 1) and integrity-protected, so a verified-context identity rejection
(row 11) uses the **redirect channel with `access_denied`** — the clean RFC 6749
§4.1.2.1 answer an MCP client can render ("denied") — while every
flow-binding/integrity failure (rows 1–6 incl. 5a, 9) stays direct. Threat row
5's invariant holds: a redirect is only ever issued to a **validated** URI (§10
or the CIMD document match). §14's redirect-vs-direct note is amended to match.

**Upstream PKCE (bridge→IdP leg): REQUIRED.** The orchestrator always generates
a verifier/challenge pair and always passes the challenge to
`buildAuthorizationUrl` (S256 only). This is the **second, independent** PKCE
pair in the system: the *client's* pair (client ↔ bridge, verified by the
bridge at `/oauth/token` — §7.5) rides opaquely in `params`; the *upstream*
pair (bridge ↔ IdP, verifier in the flow cookie) binds the IdP's code to this
browser's flow — an injected/stolen code cannot be redeemed inside a foreign
flow because the exchange presents the wrong verifier. `nonce` provides the
same binding at the id_token layer. A provider that cannot accept PKCE may
ignore the challenge only under §17.6's loud opt-out
(`allowProviderWithoutPkce`); Entra supports it unconditionally.

**Same-browser binding (the confused-deputy closure — REQUIRED).** §7.1's
consent token is only as strong as the path that delivers it: the consent page
(carrying the single-use consent token) MUST be returned **only as the direct
HTTP response to the callback request that presented a valid flow cookie** —
never via a second redirect, an intermediate retrievable URL, or any other
channel. Chain: the flow cookie binds initiate→callback to one browser; the
consent token binds callback→approve within that browser (Origin check +
single-use JTI, §9.3); both hops are single-use. This closes the
session-binding residual: the browser that approves consent is
cryptographically the browser that just authenticated at the IdP.

**Upstream token handling (existing rule, restated as binding here):** the
id_token is verified and then discarded; any `access_token`/`refresh_token` in
the IdP's token response is **discarded immediately — never stored, logged,
audited, forwarded, or placed in the flow cookie**. The bridge mints its own
audience-bound tokens (§1). The verified identity — including any
`allowedScopes` ceiling a port derives (Entra groups, §17.4) — is handed to
`bridge.handleAuthorize(synthetic, { subject, allowedScopes?, registration? })`
with the synthetic request's `query` reconstructed from the verified `params`
(pairing-flow precedent), so the §17.4 ceiling plumbing applies unchanged. For a
CIMD id, `registration` = the verified flow JWT's `cimd` claim (§17.1.6 decisions
1c/1d), so `prepare` consumes it and does not re-fetch.

**Audit.** One new event name: **`oauth.upstream.callback`** (added to §13 and
`AuthAuditEventName` at implementation) — emitted on **every** callback outcome
with `status` success/failure and `reason` from the fixed enum in the failure
table; optional `clientId` (from `params`) and `ip`. `identity.verify` is
emitted whenever an identity **decision was reached** — `ok: true` (success)
and `kind: "identity_rejected"` (failure, with the port's reason) — with the
same shape and semantics as `Bridge.resolveIdentity`'s emission (S2a);
`exchange_failed` reaches no identity decision, so it emits only the
`oauth.upstream.callback` failure, never a spurious `identity.verify`. Whether
the implementation routes through `resolveIdentity` internally or emits
directly is an implementation choice; the observable events are identical. The authorize
(redirect-out) leg is deliberately not audited: it carries no identity, and the
flow is evidenced at the callback (an abandoned flow is an expired cookie the
server never sees — a documented, trivial blind spot of the cookie decision).
**Never logged or audited, anywhere:** `state`, `nonce`, `code`, id_tokens,
upstream tokens, the PKCE verifiers, or the flow cookie value — audit carries
enum reasons and metadata only (§13).

**Adapter wiring.** `FastifyAdapterOptions`/`ExpressAdapterOptions`/
`HonoAdapterOptions` gain `upstream?: UpstreamRedirectFlow`. When set: GET
`/oauth/authorize` → `upstream.handleAuthorize`, GET `upstream.callbackPath` →
`upstream.handleCallback`; all other routes unchanged. Exactly one authorize
mode per adapter instance — `upstream` is mutually exclusive with `identity`/
`identityHeader` (header-driven) and with `skipAuthorize` (pairing); any
combination throws at registration (fail-closed, mirrors the existing
`skipAuthorize` guard). The example's `buildExample` gains an Entra-redirect
branch (env-selected, e.g. `ENTRA_TENANT_ID`/`ENTRA_CLIENT_ID`/
`ENTRA_REDIRECT_URI`) alongside the CF and pairing branches;
`defaultListenHost` maps it to `0.0.0.0` (CF-class network deployment — the
real IdP is the gate, unlike pairing's loopback envelope).

**Deployment envelope / callback exposure (§17.5-style guidance):** this flow
is *designed* for network exposure — the upstream IdP (plus Gate 1, Entra app
assignment/Conditional Access) is the authentication gate. The callback URL
registered at the IdP MUST be the public https `issuerOrigin + callbackPath`
(Entra itself refuses plain-http redirect URIs off-loopback); http is legal
only on loopback under the §5 dev flag, where the cookie drops `Secure`/
`__Host-`. The docs state the failure path exactly: a redirect-URI mismatch
surfaces as the IdP's own error page (never a bridge redirect), and the §10
allowlist still governs the *client-facing* redirect leg independently.

**Alternatives considered (recorded, rejected):**

- **StorePort flow records** — rejected as the state carrier: browser binding
  needs a cookie regardless (above), and records would add store surface
  (methods, conformance rows, three adapters) to duplicate what the signed
  cookie carries statelessly. Single-use still uses the store (JTI registry) —
  the one property a cookie cannot self-enforce.
- **Fronting with oauth2-proxy feeding the header-driven authorize** — rejected
  as the recommended posture: default proxy-injected headers are NETWORK trust
  (the CF port verifies a *signed* assertion; oauth2-proxy's default headers
  are not signed), a forwarded upstream id_token breaks nonce binding (the
  bridge did not mint the nonce), and `/oauth/register`+`/oauth/token`+
  `/.well-known/*` would need skip-auth carve-outs where an over-broad regex
  is an auth bypass. Kept as comparison material, not a supported recipe.

**Out of scope (this contract):** the generic-OIDC port itself (§17.6, S4a —
it will *implement* `RedirectIdentityPort`), any change to the Entra
primitives' behavior, `client_credentials`/device flow (§17.2/§17.3), IdP
logout/re-auth prompting (`prompt`/`login_hint` passthrough), and multiple
simultaneous upstream IdPs on one bridge instance (exactly one
`RedirectIdentityPort` per flow/adapter).

**ID-JAG adjacency (recorded 2026-07-10; posture: TRACK).** The MCP
Enterprise-Managed Authorization extension (Stable 2026-06-18,
modelcontextprotocol/ext-auth) defines ID-JAG — the Identity Assertion JWT
Authorization Grant (draft-ietf-oauth-identity-assertion-authz-grant,
WG-adopted, pre-WGLC; informally "Cross-App Access"): the client obtains an
IdP-issued assertion via RFC 8693 token exchange and redeems it at the MCP AS
under RFC 7523 jwt-bearer; the AS validates it against the IdP's JWKS and
mints an audience-restricted token, advertising
`urn:ietf:params:oauth:grant-profile:id-jag` in
`authorization_grant_profiles_supported`. This is the spec-native sibling of
this section's flow for ENTERPRISE-MANAGED clients: it replaces the
interactive browser leg + consent page with IdP-admin policy, and requires
client-side token exchange plus IdP-side issuance — as of 2026-07-10 the only
end-to-end MCP deployment is Claude EMA beta / VS Code Preview on Okta Early
Access (protocol-level ID-JAG issuance elsewhere is pre-GA: Athenz beta,
Keycloak in progress); no IdP this library's deployments use (Entra,
Cloudflare Access — nor the other shipped ports, Google/generic OIDC) issues
ID-JAGs. It does NOT replace the AS itself (assertion validation,
audience-bound minting, refresh rotation, and audit land HERE if adopted),
the RS verifier, registration (§17.1/§9.2), client_credentials (§17.2),
pairing (§17.5), or the gateway pattern. No contract change now. Escalation
triggers, recorded here so this contract stays self-contained: an IdP this
library's deployments use begins issuing ID-JAGs, or a real client requests
`urn:ietf:params:oauth:grant-profile:id-jag`. Any future id-jag leg is a NEW
§17.x contract through the §18 protocol, never an amendment to this
section's flow.

## 18. Contract-change protocol

1. Update **this document** first (port/schema/error/endpoint/TTL).
2. If a runtime behavior changed, check the threat model and the store-conformance
   invariants (§12) — and whether it affects memory/sqlite/mysql parity (and any
   further downstream SQL adapter).
3. Then change code; the conformance suite and unit tests must stay green.
4. Never weaken a fail-closed control to make a test pass. If a test and a
   fail-closed rule conflict, the rule wins; change the test (and document why).
