# 6. Ports

DDD-lite: pure core (use-cases + ports, no infra imports) and adapters at the
edge. Every external capability is a port so the core is testable in isolation.

## 6.1 `ClockPort`
```ts
interface ClockPort { nowMs(): number; }
```
Core use-cases never call ambient wall-clock APIs; tests and audit provenance need
deterministic time. Reference: `SystemClock` (wraps `Date.now()`).

**0.3.0 amendment.**
`finiteClockSnapshot(clock, futureOffsetMs?)` MUST read the underlying port
exactly once and require a safe-integer millisecond value in the repository's
canonical four-digit UTC range (`0000-01-01T00:00:00.000Z` through
`9999-12-31T23:59:59.999Z`). When a non-negative safe-integer future offset is
supplied, the snapshot plus that offset MUST remain in the same range.
`fixedClockSnapshot(nowMs)` MUST expose that already-validated value through the
existing `ClockPort` interface without reading the underlying port.

The access/consent JWT operation owners named here MUST fail closed on an
invalid snapshot before token processing or audit timestamp formatting.
`verifyAccessToken` and `RequestAuthorizer.authorize` map it to the existing
`invalid_token` 401; `verifyConsentToken` and
`OAuthAuthorizationUseCase.approve` map it to the existing `invalid_consent`
400. Clock validation is the first step in both operation owners; on `approve`,
an invalid clock therefore takes precedence over the Origin check. The two
operation owners MUST pass the fixed snapshot through verification
and their remaining expiry/store/audit work so a stateful custom clock cannot
give the decision and its audit event different times. When the initial
snapshot is invalid, no timestamped audit event is emitted: neither ambient
time nor a fabricated timestamp is an honest `occurredAt`.
`OAuthAuthorizationUseCase.approve` supplies the larger of the consent-JTI and
authorization-code TTL offsets, so both derived store timestamps are proven
canonical before consent-token processing.

This amendment is deliberately limited to the proven access/consent JWT class.
Console-pairing expiry remains the separate §17.5/B2-F6 slice; unrelated clock
consumers are not refactored here.

## 6.2 `AuditPort`
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

## 6.3 `StorePort` (the conformance boundary — see §12)
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

**Stored-DCR capabilities.** The library-owned
`STORED_DCR_GRANT_GENERATION` and `STORED_DCR_RESOURCE_BINDING` are both
currently `1`. A `StorePort` used with `dcr.mode:"stored"` MUST advertise
`storedDcrGrantGeneration: 1` and `storedDcrResourceBinding: 1`;
`assertStoredDcrGenerationStore` makes
`OAuthAuthorizationUseCase` and `OAuthTokenUseCase` construction fail closed
when either capability is absent or different. This is an additive runtime
capability check so an old custom store cannot silently ignore the generation
or resource argument and contribute a legacy or cross-resource grant.

While stored-DCR mode is active, the use-cases pass generation `1` to
`consumeAuthCode`, `rotateRefreshToken`, and `findGrantedScopes`, plus the
exact configured resource to `findGrantedScopes`. The reference stores check
the generation and resource inside their transaction/critical section, and
`findGrantedScopes` returns only rows whose token and family each match both.
The optional method arguments remain omitted in stateless-DCR mode. A CIMD grant
issued while stored-DCR mode is active carries the same deployment cutover
generation, but remains excluded from scope accumulation under §17.1.6. Full
record and legacy rules are in §12.

**Authorization-code resource predicate.** `consumeAuthCode` accepts an
optional trailing `expectedResource`. When supplied, a conforming store compares
the stored `resource` string to the exact configured resource string inside the
same atomic operation that would consume the code. A mismatch returns `null`
without deleting the record. The token use-case repeats the resource comparison on every
returned record; this is the security boundary for custom implementations that
ignore an added runtime argument. Such an implementation cannot mint a token for
the wrong resource, but it is nonconforming and may consume the legitimate code.
The optional trailing parameter is a source-compatible StorePort extension for a
patch security release: existing callers may omit it, existing schemas already
store `resource`, and no migration is required. Custom stores must implement the
predicate to retain wrong-resource retry semantics and pass §12 conformance.

**Refresh-family resource predicate.** Every new `SaveRefreshTokenInput` carries
the exact configured `resource` string from its authorization-code record. A family and
each member persist that value; it is immutable for the family.
`rotateRefreshToken` accepts an optional trailing `expectedResource`. A
conforming store checks that both the selected token row and its family have a
non-legacy resource exactly equal to that value inside the same atomic operation
as rotation, before replay handling, predecessor consumption, successor insert,
or family revocation. A missing, malformed, or mismatching resource returns
`null` without a mutation. The successor's resource is authoritative-copied
from the selected row, not from `next`. `OAuthTokenUseCase.refresh` supplies the
current `BridgeConfig.resource` and independently repeats equality on the
returned record before signing or success audit work, so a custom store that
ignores the added argument cannot mint a wrong-resource token. The optional
trailing argument preserves calls that do not yet supply a resource, but legacy
durable rows without one still fail closed under §12.

The TypeScript write shape requires an exact resource string. To keep an old
untyped JavaScript caller from silently acquiring the current bridge resource,
reference stores convert an omitted write member to the reserved unbound marker
`mcp-sso:unbound-refresh-resource`. That marker is persisted rather than a
`NULL`, copied only as stored state, and is rejected by every rotation before
any mutation; callers cannot supply it explicitly.

**Granted-scope resource predicate.** `findGrantedScopes` accepts an optional
trailing `expectedResource`. In stored-DCR mode the authorization use-case
supplies `BridgeConfig.resource`; a conforming store returns scopes only when
both the active token and its family persist that exact, non-legacy string.
Thus a pre-resource row, an unbound compatibility write, or a refresh family
issued by resource A cannot contribute scopes to a resource-B authorization
code. A new `storedDcrResourceBinding: 1` capability makes older custom stores
fail at construction rather than silently ignoring this argument. Stateless
callers omit the argument and retain the prior read-only derivation behavior.

## 6.4 `ClientStore` (stored-DCR mode only — fix #4)
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
interface MachineClientRegistration {              // v0.3.0 public shape
  clientId: string;             // "mcc_<random>" — sub prefix marks machine tokens
  redirectUris: string[];       // always [] — machine clients have no redirect
  applicationType: "machine";
  issuedAtEpoch: number;
  name?: string;                // deployer-supplied display label (unverified)
  allowedScopes: string[];      // ⊆ scopeCatalog, validated at provisioning
  secrets: ClientSecret[];      // ≤ 2 unexpired ("active"); see §17.2 rotation
}
interface MachineClientBase {
  clientId: string;
  redirectUris: string[];
  applicationType: "machine";
  issuedAtEpoch: number;
  name?: string;
  allowedScopes: string[];
  resource: string;             // exact BridgeConfig.resource at provisioning
  version: number;              // positive safe integer; incremented by mutation
}
interface ActiveMachineClientRegistration extends MachineClientBase {
  status: "active";
  secrets: [ClientSecret] | [ClientSecret, ClientSecret];
}
interface DisabledMachineClientRegistration extends MachineClientBase {
  status: "disabled";
  secrets: [];
  disabledAtEpoch: number;
}
type VersionedMachineClientRegistration =
  | ActiveMachineClientRegistration
  | DisabledMachineClientRegistration;
type LegacyMachineClientRegistration = MachineClientRegistration;
type StoredMachineClientRegistration =
  | MachineClientRegistration
  | VersionedMachineClientRegistration;
type ClientRegistration =
  | UserClientRegistration
  | StoredMachineClientRegistration;

interface ClientStore {
  save(client: ClientRegistration): Promise<void>;
  find(clientId: string): Promise<ClientRegistration | null>;
}

interface MachineClientMutationAudit {
  occurredAt: string;
  event:
    | "oauth.client.provision"
    | "oauth.client.rotate_secret"
    | "oauth.client.disable";
  clientId: string;
  scopes: string[];
  resource: string;
}

interface MachineClientStore extends ClientStore {
  createMachineClient(
    client: ActiveMachineClientRegistration,
    audit: MachineClientMutationAudit,
  ): Promise<boolean>;
  compareAndSwapMachineClient(
    expectedVersion: number,
    client: VersionedMachineClientRegistration,
    audit: MachineClientMutationAudit,
  ): Promise<boolean>;
}
```
Required only when `dcr.mode === "stored"`. Reference: in-memory map (Phase 2);
a persisted adapter is deployment-specific. The `applicationType` discriminant
selects the record shape and drives the per-client redirect policy (§10):
`native`/`web` are user clients (§9.2 DCR, §10.2 redirect policy); `machine`
records are provisioned out-of-band (§17.2). The v0.3.0
`MachineClientRegistration` name and `ClientStore.save(ClientRegistration)`
signature remain source-compatible; lifecycle functions never use `save` for a
machine mutation. Their `MachineClientDeps.store` remains typed as
`ClientStore`, then requires the additive `MachineClientStore` methods at
runtime and fails before generating a credential or mutating state when either
method is absent. Every new machine write uses that extension: create or
compare-and-swap commits the versioned row and supplied metadata-only durable
audit record in one backend transaction, or neither. `false` means collision,
missing row, or version conflict; it MUST commit neither row nor audit. New
rows start at version 1. A new versioned machine row stores the exact, uncanonicalized
`BridgeConfig.resource` supplied as `MachineClientDeps.resource`; a rotation and
disable copy that stored value unchanged, including into the tombstone. A disable
writes a tombstone with no secret hashes. The durable mutation audit carries the
same stored resource, so its row/audit evidence names one binding.

`ClientStore.find` is also a runtime boundary: a persisted or migrated row is
not trusted merely because the port has a TypeScript return type.
`parseMachineClientRegistration(value, expectedClientId, nowEpoch)` accepts a
stored machine row only when its embedded `clientId` is the requested `mcc_` key,
`redirectUris` is empty, `applicationType` is `"machine"`, `issuedAtEpoch` is a
non-negative safe integer, optional `name` is non-empty, `allowedScopes` is a
non-empty array of scope tokens, and `secrets` is the §17.2 shape: lowercase
SHA-256 hashes, non-negative safe-integer timestamps, at most one slot without
an expiry, and at most two active slots (`expiresAtEpoch` absent or
`expiresAtEpoch > nowEpoch`). Structurally valid expired history is accepted;
rotation drops it rather than making an otherwise valid migrated row
unreadable. It also requires `resource` to be a non-blank absolute URL string,
preserves its original bytes, and never canonicalizes it. A resource-less
v0.3.0 `MachineClientRegistration` remains a public read-compatibility type,
but its row is not a valid authentication or lifecycle input and requires
reprovisioning. A resource-bearing unversioned row with BOTH `status` and
`version` absent is treated as active version 0; either field present without
the other is malformed. A store CAS with `expectedVersion: 0` MUST match only
such an unversioned row. Its first rotation or disable writes the version-1
shape atomically. New records and versioned records require the full lifecycle
shape: exact resource string, positive safe-integer version, active with one
or two secrets, or disabled with zero secrets and a non-negative safe-integer
disable epoch. The parser returns a fresh known-field snapshot. Secret
verification, rotation, disable, and the single authenticated
`client_credentials` store snapshot use that parser with the current clock
epoch and require its stored resource to be exactly equal to the configured
resource; a malformed, legacy, mismatched, over-active, or key-mismatched row
fails closed before a secret is accepted, a record is mutated, or a token is
minted. The parser deliberately
does not re-check the stored ceiling against the current catalog: catalog
narrowing is enforced when resolving the grant (§17.2), so a still-valid
subset remains usable.

A thrown read of any stored-row member (including a getter or Proxy trap on
`resource`) is treated as malformed input and returns no parsed row; it does
not escape as a token-endpoint internal error. A rejection from
`ClientStore.find` itself remains an infrastructure failure and propagates.
Before validation, the parser reads each stored-row and nested-secret member
once into a local snapshot and builds its projection only from that snapshot.
A stateful getter therefore cannot validate one `clientId` and then project a
different identity or scope ceiling.

## 6.5 `IdentityPort` (boundary defined at Phase 2; Cloudflare Access + Entra implementations shipped at Phase 3)
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

## 6.6 `FetcherPort` (boundary now; CIMD impl v0.2)
```ts
interface FetcherPort { fetch(url: string, init?: FetchInit): Promise<FetchResult>; }
```
Reserved for v0.2 Client ID Metadata Documents. **Any metadata fetch MUST go
through an SSRF-guarded `FetcherPort`.** v0.1 does no outbound fetching; the
boundary exists so v0.2 cannot accidentally add a raw `fetch`. The full
enforcement contract — URL admission, the complete IANA IPv4/IPv6 blocklists,
DNS pinning, redirect refusal, byte/timeout caps, document validation — is
locked in **§17.1**.

## 6.7 `RateLimitPort` *(fix #7)*
```ts
interface RateLimitPort { check(key: string): Promise<boolean>; }
const noopRateLimit: RateLimitPort = { async check(): Promise<boolean> { return true; } };
```
Optional DoS defense for unauthenticated registration, token exchange,
revocation, and direct header-based identity verification (threat-model #8).
`Bridge` calls `check("register:<ip>")` / `check("token:<ip>")` before those
use-cases, and `check("revoke:<ip>")` at the start of `Bridge.handleRevoke`,
before its `formObject` normalization, token hashing, store access or mutation,
and audit work. Shipped adapters first apply their own request-body boundary and
then call `Bridge`, so revocation admission is not an adapter body-parser gate:
Hono's 256 KiB body cap remains earlier and an over-cap request returns 413
without consuming a revocation-limit slot.
`Bridge.resolveIdentity` calls `check("authorize:<ip>")` before
`IdentityPort.verify`; `false` ⇒ **429 Too Many Requests**. A denied revocation
does no token-use-case, store, or audit work; an admitted unknown or
already-revoked token retains RFC 7009's HTTP 200 existence-hiding behavior.
Upstream redirect, console pairing, and CIMD keep their separate
`upstream:<ip>`, `pairing:<ip>`, and `cimd:<ip>` budgets.
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
