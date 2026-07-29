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

**0.3.2 stored-DCR generation capability.** The
library-owned `STORED_DCR_GRANT_GENERATION` is currently `1`. A `StorePort`
used with `dcr.mode:"stored"` MUST advertise
`storedDcrGrantGeneration: 1`; `assertStoredDcrGenerationStore` makes
`OAuthAuthorizationUseCase` and `OAuthTokenUseCase` construction fail closed
when that capability is absent or different. This is an additive runtime
capability check so an old custom store cannot silently ignore the generation
argument and contribute a legacy grant.

While stored-DCR mode is active, the use-cases pass generation `1` to
`consumeAuthCode`, `rotateRefreshToken`, and `findGrantedScopes`. The reference
stores check it inside the same transaction/critical section as consumption or
rotation, and `findGrantedScopes` returns only matching rows. The optional
method argument remains omitted in stateless-DCR mode. A CIMD grant issued while
stored-DCR mode is active carries the same deployment cutover generation, but
remains excluded from scope accumulation under §17.1.6. Full record and legacy
rules are in §12.

**0.4.0 resource-lineage capability (PENDING — NOT ENFORCED at this
commit).** `RefreshTokenRecord` and refresh-family state gain one nullable
resource for upgrade compatibility and explicit legacy detection. `rotateRefreshToken` and
`findGrantedScopes` gain an optional resource expectation; a multi-resource
bridge—and any stored-DCR bridge where prior-scope accumulation is
possible—requires the additive `resourceBinding: 1` capability marker so an
old custom store cannot silently ignore it. Rotation compares the stored
family and token resources inside its atomic operation and
authoritative-copies the stored resource to the successor. Scope derivation keys by
`(subject, clientId, resource, grantGeneration)`. Full legacy and migration
rules are in §12.2 invariant 11.

`assertResourceBindingStore(config, store)` checks the marker during
construction whenever the normalized catalog has multiple entries or
`dcr.mode === "stored"`. `Bridge`, `OAuthAuthorizationUseCase`, and
`OAuthTokenUseCase` each call it so the exported direct-use-case path cannot
bypass the composition-root guard. Requiring it for stored singleton mode is
load-bearing: `findGrantedScopes` returns only scopes, so the use-case cannot
repair a custom store that ignored the resource predicate. The check precedes
any store write, audit event, network operation, content-parser registration,
or framework route registration. Absence or a value other than `1` is a boot
`AuthConfigError`, never a first-refresh surprise.

```ts
interface ResourceBindingExpectation {
  resource: string;
  allowLegacySingletonBinding: boolean;
}

interface ResourceMismatch {
  status: "resource_mismatch";
}

type RefreshRotationResult =
  | RefreshTokenRecord
  | ResourceMismatch
  | null;

rotateRefreshToken(hash, next, now, expectedGeneration?, resourceBinding?):
  Promise<RefreshRotationResult>
findGrantedScopes(subject, clientId, now, expectedGeneration?, resourceBinding?)
```

The last parameter is optional for source compatibility. Multi-resource use
passes `{ resource, allowLegacySingletonBinding: false }`; singleton use passes
the sole resource and sets `allowLegacySingletonBinding: true` only when
`legacySingletonResource` explicitly attests that same canonical resource.
Without that attestation singleton use passes `false`; null legacy lineage
cannot be inferred from whichever resource happens to be configured now.
Existing custom implementations returning only `RefreshTokenRecord | null`
remain valid narrow implementations. A `resource_mismatch` result is emitted
only when an otherwise-valid, **unconsumed** current family/token pair differs
from the expected canonical resource; it carries no record fields and commits
no mutation. `OAuthTokenUseCase` maps it to `invalid_target`.
**That mapping MUST happen before the refresh preparation wrapper**, whose
`catch` revokes the whole family to kill an unreturned successor (§7.4). The
no-mutation property is a store-layer guarantee only; the mismatch outcome is a
truthy value, so a use-case that lets it fall into that wrapper would revoke the
victim's entire family on a wrong-resource guess — turning a non-mutating
rejection into a cross-resource denial-of-service against a token the caller
already holds. The typed outcome is checked immediately after the rotation call
and outside the wrapper. A consumed
predecessor is replay-handled first: the store revokes its family even when the
request names a different configured resource, returns `null`, and the
use-case reports `invalid_grant`. Missing, expired, replayed, malformed,
generation-mismatched, or unattested-null lineage likewise remains `null` and
maps to `invalid_grant`.

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
  resource?: string | null;     // PENDING 0.4.0; new writes non-null canonical
  redirectUris: string[];
  applicationType: "machine";
  issuedAtEpoch: number;
  name?: string;
  allowedScopes: string[];
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
rows start at version 1. A disable writes a tombstone with no secret hashes.

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
unreadable. For upgrade compatibility, a complete v0.3.0 row with BOTH
`status` and `version` absent is treated as active version 0; either field
present without the other is malformed. A store CAS with `expectedVersion: 0`
MUST match only such an unversioned row. Its first rotation or disable writes
the version-1 shape atomically, so verification remains available while stores
roll forward. New records and versioned records require the full lifecycle
shape: positive safe-integer version, active with one or two secrets, or
disabled with zero secrets and a non-negative safe-integer disable epoch. The
parser returns a fresh known-field snapshot. Secret verification, rotation,
disable, and the single authenticated `client_credentials` store snapshot use
that parser with the current clock epoch; a
malformed, over-active, or key-mismatched row fails closed before a secret is
accepted, a record is mutated, or a token is minted. The parser deliberately
does not re-check the stored ceiling against the current catalog: catalog
narrowing is enforced when resolving the grant (§17.2), so a still-valid
subset remains usable.

**0.4.0 machine resource binding (PENDING — NOT ENFORCED at this commit).**
New active and disabled machine records carry one canonical `resource`.
`MachineClientBase` gains `resource?: string | null` — optional in the type only
so a pre-0.4 row remains readable — and
**`parseMachineClientRegistration` adds `resource` to its enumerated acceptance
criteria**, alongside `clientId`/`redirectUris`/`applicationType`/
`issuedAtEpoch`/`name`/`allowedScopes`/`secrets`: present means a non-empty
string that survives `canonicalResource` unchanged, and a malformed or
non-string value makes the row unreadable rather than unbound. The parser is the
single chokepoint between the untrusted store and the token use-case, so the
value it returns is the one `client_credentials` compares. Omitting it from the
parser leaves only two outcomes, both wrong: every machine credential reads as
legacy-unbound and the feature is dead, or an implementer reaches around the
parser to the raw row and compares an unvalidated, possibly non-canonical string
against a canonicalized request value — breaking the §5.1 one-parser rule. Without that
parser rule the enforcement boundary is unreachable, because the value
`client_credentials` compares would never have been type-checked at the store
boundary. Absent is the legacy case governed by the attestation rule below.
A lifecycle CAS (`rotateMachineClientSecret`, `disableMachineClient`) whose
deps name a different resource than the stored record is `invalid_target`
BEFORE the CAS: rotation and disable preserve the stored resource and are never
a rebinding primitive, so a credential provisioned for A cannot be moved to B by
rotating it under B's dependencies. `MachineClientDeps.resource` is therefore an
**expectation to check, never the source of the written value**: the CAS
new-record copies `resource` from the parsed stored record, so even an
implementation that skipped the equality check could not rebind A to B by
passing different deps. `MachineClientDeps.catalog` must be the catalog owned by
`deps.resource`; because a caller supplies both independently, provisioning
validates that pairing against the configured catalog rather than trusting it. Re-provisioning is the only path to another
resource, and it issues a new credential.
Provisioning dependencies add that resource beside the existing per-resource
catalog; rotation and disable preserve it through the existing CAS operation.
A legacy record without the field resolves only under a singleton catalog and
writes the sole resource on its first successful lifecycle mutation only when
`legacySingletonResource` attests it. It is `invalid_client` when the
attestation is absent and under every multi-resource catalog.

At 0.4 activation a client store used by machine provisioning, lifecycle
mutation, or `client_credentials` issuance MUST advertise the additive
`machineClientResourceBinding: 1` capability. The public `ClientStore` gains
optional readonly `machineClientResourceBinding?: 1` for structural
compatibility, while `MachineClientStore` refines it to required readonly
`machineClientResourceBinding: 1`. `assertMachineClientResourceStore` runs at
entry to `provisionMachineClient`, `rotateMachineClientSecret`, and
`disableMachineClient`, and in `OAuthTokenUseCase` construction when
`clientCredentials.enabled`, before client-id/secret generation, a store read
or write, token signing, success-audit emission, or framework route
registration. A best-effort failure audit may follow the rejection and omits
resource under §13 because no resource-bound store capability was established.
Merely implementing the pre-0.4 lifecycle method names is insufficient: an old
custom store can otherwise accept an extra record field, discard it, and report
a successful atomic mutation. Missing or different capability is an
`AuthConfigError`. Ordinary stored-DCR deployments with machine credentials
disabled do not require this capability.

At the same activation `MachineClientMutationAudit` gains a required canonical
`resource`; every successful create/CAS transaction persists that resource in
both the credential row and its durable evidence. Failure events remain
best-effort and follow §13's post-resolution rule.

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
Optional DoS defense for unauthenticated registration, token exchange, and
direct header-based identity verification (threat-model #8). `Bridge` calls
`check("register:<ip>")` / `check("token:<ip>")` before those use-cases and
`Bridge.resolveIdentity` calls `check("authorize:<ip>")` before
`IdentityPort.verify`; `false` ⇒ **429 Too Many Requests** with no identity-port
call or `identity.verify` audit. Upstream redirect, console pairing, and CIMD
keep their separate `upstream:<ip>`, `pairing:<ip>`, and `cimd:<ip>` budgets.
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
