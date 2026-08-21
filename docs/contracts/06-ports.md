# 6. Ports

DDD-lite: pure core (use-cases + ports, no infra imports) and adapters at the edge. Every external capability is a port so the core is testable in isolation.

## 6.1 `ClockPort`
```ts
interface ClockPort { nowMs(): number; }
```
Core use-cases never call ambient wall-clock APIs. Tests and audit provenance need deterministic time. Reference: `SystemClock` (wraps `Date.now()`).

**0.3.0 amendment.** `finiteClockSnapshot(clock, futureOffsetMs?)` MUST read the underlying port exactly once and require a safe-integer millisecond value in the repository's canonical four-digit UTC range (`0000-01-01T00:00:00.000Z` through `9999-12-31T23:59:59.999Z`). When a non-negative safe-integer future offset is supplied, the snapshot plus that offset MUST remain in the same range. `fixedClockSnapshot(nowMs)` MUST expose that already-validated value through the existing `ClockPort` interface without reading the underlying port.

The access/consent JWT operation owners named here MUST fail closed on an invalid initial snapshot before token processing or audit timestamp formatting. `verifyAccessToken` and `RequestAuthorizer.authorize` map it to the existing `invalid_token` 401. `verifyConsentToken` and `OAuthAuthorizationUseCase.approve` map it to the existing `invalid_consent`
400. Initial clock validation is the first step in both operation owners. On `approve`, it therefore takes precedence over the Origin check. Access-token operations and every approval exit before JTI consumption MUST pass that fixed initial snapshot through their remaining expiry/store/audit work. When the initial snapshot is invalid, no timestamped audit event is emitted: neither ambient time nor a fabricated timestamp is an honest `occurredAt`. **0.3.3 correction.** `OAuthAuthorizationUseCase.approve` takes an initial canonical snapshot for JWT verification and the pre-consume audit/error paths. It MUST NOT derive the consent-JTI timestamp from the current consent TTL. The JTI timestamp comes from `verifyConsentToken`'s independently validated signed `exp` under §7.1, so a TTL change cannot alter an already-signed token's replay window. After successful JTI consumption it takes a second, fresh canonical commit snapshot with the authorization-code TTL offset validated. The commit snapshot MUST be greater than or equal to the initial snapshot. A stateful or adjusted clock cannot move the authorization decision backward. That snapshot rechecks signed expiry and owns code expiry plus all later audit timestamps. If the commit snapshot is invalid or moves backward after JTI consumption, approval fails with no timestamped audit event. The JTI remains consumed. This replaces the earlier single snapshot that supplied the larger of the consent-JTI and authorization- code TTL offsets.

The original amendment was limited to the proven access/consent JWT class. **0.3.6 correction:** every library read of a caller-supplied `ClockPort` now routes through the clock boundary in `ports/clock.ts`. No use-case, identity adapter, resolver, audit formatter, or helper calls the underlying `nowMs()` directly. `integerClockSnapshot` performs that single read, rejects a non-safe- integer result, and re-casts a throw to a library-owned `RangeError` so a port cannot select an OAuth status, code, description, or redirect. `finiteClockSnapshot` also enforces the canonical UTC range for every timestamp, expiry, store, verification, and audit use. The sole lossy consumer is CIMD shared-cache observation: as already required by §17.1.4 rule 25 and §17.1.6, an invalid or throwing cache-timing observation becomes a non-finite observation, clears temporal cache state, and fails toward re-fetch. It does not turn an otherwise valid fetched document into an authorization failure. A later audit timestamp still requires `finiteClockSnapshot`.

This does not force one snapshot across an entire multi-step flow: operation owners that require a stable timestamp still take one validated value and pass a `fixedClockSnapshot`, while components whose contract requires fresh reads keep their existing read cadence through the boundary. A read for which no canonical timestamp exists emits no fabricated timestamped audit event. The library JWT signers independently require both their mint time and the configured TTL offset to fit the canonical range, including the upstream-flow cookie signer. Token-exchange owners also supply a fixed canonical operation snapshot, and authorization owners independently validate every later store or audit timestamp before returning the signed consent token.

Machine-client persisted timestamps use Unix epoch seconds and therefore have a narrower lower bound than the general four-digit UTC clock domain. Their shared `epochSeconds` boundary rejects a canonical pre-1970 clock before a lifecycle write, so provisioning cannot create a record its own parser refuses.

**Token-issuance amendment.** Each `OAuthTokenUseCase` issuance owner, authorization-code exchange, refresh rotation, and client credentials, takes one canonical initial snapshot before grant validation, client-store access, or OAuth store mutation. User-grant operations validate the larger of the access- and refresh-token TTL offsets. Client credentials validates the access-token offset. The operation passes a `fixedClockSnapshot` through code consumption or rotation, client-secret expiry checks, JWT signing, refresh expiry, compensation, and success or failure audit construction. No later step reads the underlying port. An invalid initial snapshot or overflowing future offset escapes as an internal failure before state or audit work. The Bridge maps it to its sanitized 500 `internal_error`, because no valid timestamp exists for an honest audit event. Revocation is not an issuance path and retains one validated timestamp snapshot for its complete lookup, mutation, and audit sequence.

## 6.2 `AuditPort`
```ts
interface AuditPort { writeAuthEvent(event: AuthAuditEvent): Promise<void>; }
```
Append-only, metadata-only (see §13). `noopAudit` is the test/local default. v0.2 ships three reference sinks (§17.7, exported from the main entry, no subpath/peer dep): `JsonlFileAudit(filePath)`, `WebhookAudit(url, opts)`, and `combineAudit(...sinks)`. All three are **fail-open**: `writeAuthEvent` never rejects, so an audit-write failure never blocks the auth operation (the use-cases `await` it with no try/catch). Tool-call auditing is the host app's concern, not this library's.

## 6.3 `StorePort` (the conformance boundary: see §12)
Stores auth-code records, refresh-token families/tokens, and single-use consent JTIs, **all secrets stored only as SHA-256 hashes**. There is **no separate grant table** (prior grants are derived from active refresh-token records, §9.3). Methods: `saveAuthCode`, `consumeAuthCode`, `saveRefreshToken`, `rotateRefreshToken`, `revokeRefreshTokenFamily`, `findRefreshToken`, `consumeConsentJti`, `findGrantedScopes`, `sweepExpired`, optional `startExpiryCollection`, and `close`. Full shapes in §12. `Bridge` invokes the optional lifecycle hook with its exact configured `ClockPort` only after boot validation succeeds. A direct store consumer invokes it after the store is ready. The three reference stores then own the §12.2 non-overlapping timer, so deployers do not wire one. A custom store may omit the hook only when it provides an equivalent lifecycle using the same configured clock. `close()` must stop any owned collection. Persistent stores also keep §12's monotonic sweep watermark: tombstone deletion and watermark advancement are atomic, and later JTI consumption/approval is fenced by the original supplied signed expiry. Automatic MySQL collection also subtracts §12's explicit five-minute replica-clock bound from its local aggregate clock before sweeping every record class. Direct multi-replica callers of `sweepExpired` own the same coordination. Under the 0.3.3 consent correction, `consumeConsentJti(jti, expiresAtIso)` receives the canonical verified signed JWT expiry from the caller and MUST persist that exact expiry. `sweepExpired` retains the JTI while `expires_at >= now` (§7.1, §12.2). The port and SQL schema shapes are unchanged by the correction. (`findGrantedScopes` is invoked ONLY in **stored DCR mode for opaque clients**, per §17.1.6, every scheme-shaped (`https://`/CIMD) client_id stands alone (`priorScopes = []`) in both modes, because refresh rows carry no registration provenance. In stateless mode client_ids are ephemeral, so a grant keyed by `(subject, clientId)` is meaningless. Those authorizations stand alone.)

**Stored DCR capabilities.** The library-owned `STORED_DCR_GRANT_GENERATION` and `STORED_DCR_RESOURCE_BINDING` are both currently `1`. A `StorePort` used with `dcr.mode:"stored"` MUST advertise `storedDcrGrantGeneration: 1` and `storedDcrResourceBinding: 1`. `assertStoredDcrGenerationStore` makes `OAuthAuthorizationUseCase` and `OAuthTokenUseCase` construction fail closed when either capability is absent or different. This is an additive runtime capability check so an old custom store cannot silently ignore the generation or resource argument and contribute a legacy or cross-resource grant.

While stored DCR mode is active, the use-cases pass generation `1` to `consumeAuthCode`, `rotateRefreshToken`, and `findGrantedScopes`, plus the exact configured resource to `findGrantedScopes`. The reference stores check the generation and resource inside their transaction/critical section, and `findGrantedScopes` returns only rows whose token and family each match both. The optional method arguments remain omitted in stateless DCR mode. A CIMD grant issued while stored DCR mode is active carries the same deployment cutover generation, but remains excluded from scope accumulation under §17.1.6. Full record and legacy rules are in §12.

**Authorization-code resource predicate.** `consumeAuthCode` accepts an optional trailing `expectedResource`. When supplied, a conforming store compares the stored `resource` string to the exact configured resource string inside the same atomic operation that would consume the code. A mismatch returns `null` without deleting the record. The token use-case repeats the resource comparison on every returned record. This is the security boundary for custom implementations that ignore an added runtime argument. Such an implementation cannot mint a token for the wrong resource, but it is nonconforming and may consume the legitimate code. The optional trailing parameter is a source-compatible StorePort extension for a patch security release: existing callers may omit it, existing schemas already store `resource`, and no migration is required. Custom stores must implement the predicate to retain wrong-resource retry semantics and pass §12 conformance.

**Refresh-family resource predicate.** Every new `SaveRefreshTokenInput` carries the exact configured `resource` string from its authorization-code record. A family and each member persist that value. It is immutable for the family. `rotateRefreshToken` accepts an optional trailing `expectedResource`. A conforming store checks that both the selected token row and its family have a non-legacy resource exactly equal to that value inside the same atomic operation as rotation, before replay handling, predecessor consumption, successor insert, or family revocation. A missing, malformed, or mismatching resource returns `null` without a mutation. The successor's resource is authoritative-copied from the selected row, not from `next`. `OAuthTokenUseCase.refresh` supplies the current `BridgeConfig.resource` and independently repeats equality on the returned record before signing or success audit work, so a custom store that ignores the added argument cannot mint a wrong-resource token. The optional trailing argument preserves calls that do not yet supply a resource, but legacy durable rows without one still fail closed under §12.

**Explicit family-revocation resource predicate.** `revokeRefreshTokenFamily` accepts an optional trailing `expectedResource`. When supplied, a conforming store changes the family only when its stored resource is an exact match inside the same atomic update. `OAuthTokenUseCase.revoke` first checks the found token record against `BridgeConfig.resource`, then supplies that resource to the store mutation. A missing, legacy, or different resource is handled exactly like an unrecognized token: HTTP 200 with no durable mutation. Callers that omit the argument retain the replay/compensation behavior for a family already selected by a resource-bound rotation.

**Returned OAuth-record boundary.** The authorization-code, refresh-rotation, and revocation owners project the selected fields of every returned auth-code or refresh-token record into fresh plain data inside `callPort`. A throwing getter/Proxy is an infrastructure failure and cannot supply an `OAuthError` to the response mapper. Plain malformed auth-code records fail as `invalid_grant`. An unreadable or malformed refresh record is an infrastructure failure. After an indeterminate rotation result the owner revokes the known family before the error escapes, because the successor may already have been committed. The upstream flow likewise requires `consumeConsentJti` to return a primitive boolean before it proceeds to an IdP exchange.

The TypeScript write shape requires an exact resource string. To keep an old untyped JavaScript caller from silently acquiring the current bridge resource, reference stores convert an omitted write member to the reserved unbound marker `mcp-sso:unbound-refresh-resource`. That marker is persisted rather than a `NULL`, copied only as stored state, and is rejected by every rotation before any mutation. Callers cannot supply it explicitly.

**Granted-scope resource predicate.** `findGrantedScopes` accepts an optional trailing `expectedResource`. In stored DCR mode the authorization use-case supplies `BridgeConfig.resource`. A conforming store returns scopes only when both the active token and its family persist that exact, non-legacy string. Thus a pre-resource row, an unbound compatibility write, or a refresh family issued by resource A cannot contribute scopes to a resource-B authorization code. A new `storedDcrResourceBinding: 1` capability makes older custom stores fail at construction rather than silently ignoring this argument. Stateless callers omit the argument and retain the prior read-only derivation behavior.

## 6.4 `ClientStore` (stored DCR only)
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
  applicationType: "native" | "web";
  issuedAtEpoch: number;
}
interface MachineClientRegistration {              // v0.3.0 public shape
  clientId: string;             // "mcc_<random>", sub prefix marks machine tokens
  redirectUris: string[];       // always [], machine clients have no redirect
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
Required only when `dcr.mode === "stored"`. `SqliteStore` is the shipped single-process persistent implementation: its admitted SQLite database stores user registrations in the same file as authorization codes, refresh families, and consent JTIs. The `applicationType` discriminant selects the record shape and drives the per-client redirect policy (§10): `native`/`web` are user clients (§9.2 DCR, §10.2 redirect policy). `machine` records are provisioned out-of-band (§17.2). The v0.3.0 `MachineClientRegistration` name and `ClientStore.save(ClientRegistration)` signature remain source-compatible. Lifecycle functions never use `save` for a machine mutation. Their `MachineClientDeps.store` remains typed as `ClientStore`, then requires the additive `MachineClientStore` methods at runtime and fails before generating a credential or mutating state when either method is absent. Every new machine write uses that extension: create or compare-and-swap commits the versioned row and supplied metadata-only durable audit record in one backend transaction, or neither. `false` means collision, missing row, or version conflict. It MUST commit neither row nor audit. New rows start at version 1. A new versioned machine row stores the exact, uncanonicalized `BridgeConfig.resource` supplied as `MachineClientDeps.resource`. A rotation and disable copy that stored value unchanged, including into the tombstone. A disable writes a tombstone with no secret hashes. The durable mutation audit carries the same stored resource, so its row/audit evidence names one binding.

`SqliteStore.save` accepts only the user-registration shapes produced by `POST /oauth/register`: a generated `mcpdc_` identifier, a non-negative safe-integer issue epoch, exact `native` or `web` type, and 1..16 redirect entries that each pass the matching §10.2 registration policy. It snapshots those input members before validation and performs no SQL write on rejection. A client-id collision fails rather than replacing the existing row. It rejects machine rows: SQLite does not implement `MachineClientStore`, and machine lifecycle state requires the atomic row-plus-audit methods above rather than the compatibility `save` method. `find` returns a fresh value decoded from the persisted redirect JSON. The authorization and token boundaries still apply their normal untrusted-store parsers before using it. Closing `SqliteStore` closes both port surfaces.

The parser and lifecycle entry points accept that raw resource only when it is eligible for `BridgeConfig.resource`: HTTPS, or HTTP on `localhost`, `127.0.0.1`, or `[::1]` for a matching `dev.allowInsecureLocalhost` bridge. They reject remote HTTP, blank, and malformed values before mutation or success audit.

**Lifecycle provenance boundary.** `provisionMachineClient`, `rotateMachineClientSecret`, and `disableMachineClient` invoke `createMachineClient`, `find`, and `compareAndSwapMachineClient` through the §13 `callPort` boundary like every other pluggable-port call site. Whatever the store throws is re-cast to `PortFailureError` before it reaches the lifecycle caller or the failure audit: a store-authored `OAuthError` can no longer pose as a library-raised one (retry guidance, 409 conflict shape) nor write its own code into the `oauth.client.*` failure-audit `reason`, which classifies it as `internal_error`. The original stays on `PortFailureError.cause` for the operator's local diagnostics. A `false` return remains control flow (identifier collision, version conflict) and passes through untouched, so the library's own collision/conflict errors are unchanged.

`ClientStore.find` is also a runtime boundary: a persisted or migrated row is not trusted merely because the port has a TypeScript return type. For the authorization-code flow, `parseAuthorizationClientRegistration(value, expectedClientId)` accepts the stored `applicationType` discriminant only when it is exactly `"native"`, `"web"`, or `"machine"`. It also requires the embedded `clientId` to equal the requested lookup key and the type-appropriate redirect container: 1..16 entries for `native`/`web`, or an empty array for `machine`. It snapshots only the fields the authorization redirect decision consumes. Unrelated persistence metadata does not determine authorization validity. The parser reads every selected record member, array length, and array slot once and returns a fresh known-field snapshot. Missing, undefined, null, blank, unknown, wrongly typed, or throwing values fail closed as a malformed stored client. A state-changing getter cannot validate one value and later project another because only the captured value is used. `machine` is a recognized stored type but remains ineligible for the authorization-code flow. Both direct authorize and the upstream redirect flow use this parsed snapshot. The upstream callback re-reads and parses an opaque stored client after its signed flow cookie and state are validated but before JTI consumption, IdP error handling, code exchange, consent signing, or callback success audit, so a row corrupted after flow initiation cannot survive through an early-return branch.

`parseMachineClientRegistration(value, expectedClientId, nowEpoch)` accepts a stored machine row only when its embedded `clientId` is the requested `mcc_` key, `redirectUris` is empty, `applicationType` is `"machine"`, `issuedAtEpoch` is a non-negative safe integer, optional `name` is non-empty, `allowedScopes` is a non-empty array of scope tokens, and `secrets` is the §17.2 shape: lowercase SHA-256 hashes, non-negative safe-integer timestamps, at most one slot without an expiry, and at most two active slots (`expiresAtEpoch` absent or `expiresAtEpoch > nowEpoch`). Structurally valid expired history is accepted. Rotation drops it rather than making an otherwise valid migrated row unreadable. It also requires `resource` to be a non-blank absolute URL string, preserves its original bytes, and never canonicalizes it. A resource-less v0.3.0 `MachineClientRegistration` remains a public read-compatibility type, but its row is not a valid authentication or lifecycle input and requires reprovisioning. A resource-bearing unversioned row with BOTH `status` and `version` absent is treated as active version 0. Either field present without the other is malformed. A store CAS with `expectedVersion: 0` MUST match only such an unversioned row. Its first rotation or disable writes the version-1 shape atomically. New records and versioned records require the full lifecycle shape: exact resource string, positive safe-integer version, active with one or two secrets, or disabled with zero secrets and a non-negative safe-integer disable epoch. The parser returns a fresh known-field snapshot. Secret verification, rotation, disable, and the single authenticated `client_credentials` store snapshot use that parser with the current clock epoch and require its stored resource to be exactly equal to the configured resource. A malformed, legacy, mismatched, over-active, or key-mismatched row fails closed before a secret is accepted, a record is mutated, or a token is minted. The parser deliberately does not re-check the stored ceiling against the current catalog: catalog narrowing is enforced when resolving the grant (§17.2), so a still-valid subset remains usable.

Lifecycle creation uses the same non-negative epoch domain required by this parser. A canonical clock before 1970 rejects before credential generation, row mutation, durable success audit, or supplemental success audit.

A thrown read of any stored-row member (including a getter or Proxy trap on `resource`) is treated as malformed input and returns no parsed row. It does not escape as a token-endpoint internal error. A rejection from `ClientStore.find` itself remains an infrastructure failure and propagates. Before validation, the parser reads each stored-row and nested-secret member once into a local snapshot and builds its projection only from that snapshot. A stateful getter therefore cannot validate one `clientId` and then project a different identity or scope ceiling.

## 6.5 `IdentityPort`

**Reader map.** An identity adapter has three jobs: verify the upstream proof, choose one stable subject, and optionally return a scope ceiling. Browser redirect adapters also own the upstream redirect exchange. The exact per-provider requirements and header-mode residuals remain below.

Resolves a **verified subject** from an inbound authorize request. The core's `authorize` use-case takes a required `subject: string`. The adapter/composition root calls an `IdentityPort` to obtain it (or fails closed). Implementations:
- CloudflareAccessIdentity. Verifies `Cf-Access-Jwt-Assertion` (RS256 against CF JWKS, aud/iss checked), subject = the token's `sub` (a stable CF identity id. `email` the fallback, opaque-`sub`-first, matching the Entra `oid`-first sibling. CF carries the email in a separate claim, so do not key on email).
- EntraIdentity. Upstream OIDC auth-code+PKCE against Entra v2.0. ONE app registration for the bridge. Validate iss/aud/tid. Subject = the exact usable non-blank `oid` when present, otherwise the exact already-accepted issuer + `"|"` + the exact usable non-blank signature-verified OIDC `sub`. A blank or wrongly typed `oid` falls back to `sub`. A blank or wrongly typed `sub` with no usable `oid` fails closed with `entra_no_subject`. `preferred_username` and `email` never select the stored grant subject. The bridge then issues its OWN audience-bound tokens (no passthrough).

The throw channel is untrusted. A thrown `OAuthError` may preserve only an exact 401 or 403 status. The Bridge replaces its code with `access_denied`, its description with `Identity rejected: port_error`, its audit reason with `port_error`, and drops any redirect. Every other thrown status and every non-OAuth throw is a `PortFailureError` and therefore reaches HTTP only as the generic direct 500 channel. OAuth classification and the status read happen inside the port boundary. An accessor failure is an unreadable status and the Bridge never re-reads the thrown object. A returned `{ ok:false }` remains the normal shipped identity-rejection path: exact shipped reason codes are allowlisted for audit, an unknown custom reason collapses to `identity_rejected`, and the public description is the fixed `Identity rejected`. The discriminant, subject, and optional ceiling are snapshotted inside the same boundary, so a returned accessor cannot throw a port-authored response after `verify` resolves.

`RedirectIdentityPort.buildAuthorizationUrl` has the same direct-response ownership boundary: a thrown or malformed return becomes the generic 500, not the port's OAuth code/status/description. `exchangeAndVerify` remains mapped to the fixed callback failure table. Its returned discriminant, identity, ceiling, kind, and reason are snapshotted before use, and custom rejection text is not written to identity audit.

`GenericOidcIdentity` and the Google preset ship as `RedirectIdentityPort` implementations. Console pairing ships under `mcp-sso/identity/console-pairing`. The dedicated GitHub port remains contract-only. §17.11 defines the upstream redirect orchestrator built from `RedirectIdentityPort` and `createUpstreamRedirectFlow`. §17.4 defines the `IdentityClaims.allowedScopes` scope ceiling. The core depends on these boundaries, not a specific identity provider.

**Identity-port hardening:**
- **Trust roots MUST be `https`.** A port's JWKS certs URL and issuer MUST be `https://`, http JWKS lets a MITM substitute signing keys = total auth bypass. Validate with a **raw `^https://` prefix check BEFORE `new URL()`** (Node's lenient URL parser normalizes `https:/host` into a valid-looking URL). Applies to CloudflareAccessIdentity and EntraIdentity.
- **Required construction config MUST be non-empty.** A blank required field, CloudflareAccess `audience`, Entra `tenantId`/`clientId`, generic-OIDC `clientId`/`issuer`/`redirectUri`, fails closed at construction (empty == missing config). A blank value would otherwise build a malformed URL or make the `aud` check vacuous instead of raising a clear boot error.
- **Optional subject allowlist (defense-in-depth).** A port MAY accept a subject/email allowlist. Empty ⇒ delegate entirely to the IdP's own policy (e.g. Cloudflare Access Zero Trust). Matching semantics are port-specific and MUST be documented. Opaque immutable identifiers are not presumed to be case-insensitive or whitespace-normalized. Never the sole gate.
- **Unit-testable claim validation.** Export the claim-validation logic as a pure function so it is unit-testable WITHOUT the JWKS network fetch.
- **Bounded JWKS documents.** Cloudflare Access, Entra, and generic OIDC use one shared capped-fetch seam for jose's remote JWK set. `maxJwksDocumentBytes` defaults to **65536 bytes** on every port: deliberately above ordinary few-KB key sets and equal to the discovery-document cap, while still bounding a hostile or broken IdP response. The option is an integer in **[1024, 1048576]** and is validated at construction before jose can fetch. Invalid values fail boot rather than selecting a default. The seam counts the response stream and cancels it as soon as the cap is exceeded, while jose's five-minute `cacheMaxAge` remains unchanged. An over-cap body is the existing JWKS infrastructure-failure class, `exchange_failed` on redirect identities, never `identity_rejected`, because no identity decision was reached.
- **Entra multi-tenant.** When `allowedTenantIds` is set, `tid` must be allowlisted AND `iss` must equal `entraIssuer(payload.tid)` (the standard Entra multi-tenant issuer pattern). Unset ⇒ single-tenant: `iss` must equal `entraIssuer(config.tenantId)`.
- **Entra nonce.** Pass a `nonce` in `getAuthorizationUrl` and validate `payload.nonce` on return (OIDC request binding), recommended. The §17.11 redirect orchestrator always does this (orchestrator-minted CSPRNG nonce, threat-model row 31).
- **Entra token times.** A verified id_token requires both `iat` and `exp` as finite NumericDate numbers. The signed-token wrappers require `iat` at `jwtVerify`. The pure claim validator requires and type-checks `exp` and repeats the `iat` type/finite check so an already-verified payload cannot bypass the same identity decision. This preserves `entra_bad_claim` for a signed token missing `iat` and `entra_missing_exp` for one missing `exp`. **Header-driven mode (`identityHeader`) residual:** when a fronting proxy delivers a raw Entra id_token in a header, mcp-sso never minted the nonce, so the port's verifying wrapper (`createEntraIdentity().verify` / `verifyEntraIdToken`, jose `jwtVerify` enforces the RS256 signature and expiry, then the pure `validateEntraIdToken` claim checks apply: iss/tid/aud, finite `iat`/`exp`, and `nonce` only when an expected value is set) does NOT replay-bind the token. `validateEntraIdToken` alone is claim validation on an ALREADY-signature-verified payload (exported pure for unit-testability, it never checks the signature). A custom `IdentityPort` MUST route raw tokens through the verifying wrapper, never the pure validator alone. Replay protection for a header-delivered id_token belongs to the fronting proxy, deploy header mode only behind a proxy that itself performed the nonce-bound code exchange and verified the token before forwarding (Cloudflare Access's signed assertion is the model), never behind one that merely relays tokens it did not validate. Documented as the row-12 residual in the threat model.
- **Entra subject allowlist.** Keeps trimmed, case-insensitive matching for `oid`. Otherwise it matches the accepted issuer + `"|"` + `sub` byte-for-byte. Raw `sub` is not a candidate because it discards issuer namespacing. Matching mutable `preferred_username`/`email` requires `allowMutableClaims === true` (Microsoft warns against using those claims for authorization). Only those mutable candidates are compared case-insensitively. No mutable candidate or allowlist entry is trimmed. This opt-in changes allowlist candidates only: an allowlist match never selects or changes the stored grant subject.

**Entra no-`oid` compatibility amendment (2026-08-13).** No durable-state migration is performed because an old username/email key cannot be attributed safely to an immutable account from stored data alone. Existing no-`oid` grants remain under their old mutable keys. The next full login uses the issuer-namespaced `sub` and may require reapproval. Existing access tokens, authorization codes, in-flight consent, and refresh-token families retain their already-issued subjects for their normal lifetimes. Refresh does not re-run Entra identity verification or rewrite a family subject. Successful rotation preserves that legacy subject and renews the successor to the current sliding `refreshTokenTtlSeconds`. Deterministic cutoff requires explicit family revocation (or replay-family revocation), while an inactive family expires after its current TTL.

## 6.6 `FetcherPort` (boundary now. CIMD impl v0.2)
```ts
interface FetcherPort { fetch(url: string, init?: FetchInit): Promise<FetchResult>; }
```
Reserved for v0.2 Client ID Metadata Documents. **Any metadata fetch MUST go through an SSRF-guarded `FetcherPort`.** v0.1 does no outbound fetching. The boundary exists so v0.2 cannot accidentally add a raw `fetch`. The full enforcement contract, URL admission, the complete IANA IPv4/IPv6 blocklists, DNS pinning, redirect refusal, byte/timeout caps, document validation, is locked in **§17.1**.

## 6.7 `RateLimitPort`

This section is the exact call-site reference. [Why rate limits depend on client IP trust](../explanation/rate-limits-and-client-ip.md) explains the threat, proxy topology, and outage behavior.

```ts
interface RateLimitPort {
  check(key: string): Promise<boolean>;
}

const noopRateLimit: RateLimitPort = {
  async check(): Promise<boolean> { return true; },
};
```

`RateLimitPort.check` returns `true` to admit a request and `false` to deny it. The response to a denial or exception depends on the call site.

### Boot requirements

| Composition | Requirement |
| --- | --- |
| `BridgeConfig.dcr.mode === "stored"` | `Bridge` requires a bounded `RateLimitPort`. `noopRateLimit` counts as missing. |
| `BridgeConfig.dcr.mode === "stateless"` | A composition admitted by §5 may omit `RateLimitPort`. `Bridge` then uses `noopRateLimit`. |
| Hono with `BridgeConfig.dcr.mode === "stored"` | `createOAuthApp` throws `AuthConfigError` at boot unless `clientIp` is callable. |
| Hono with `BridgeConfig.dcr.mode === "stateless"` | `clientIp` is optional. `createOAuthApp` warns once about the shared `unknown` bucket when it is absent. |

A custom port that returns `true` for every call does not satisfy the bounded port contract. The boot check cannot detect that behavior.

### Checks and early returns

The Fastify, Express, and Hono adapters apply their request-body limits before calling a `Bridge` POST handler. A request rejected by an adapter does not call `RateLimitPort.check`.

| Surface | `RateLimitPort` call | Work before the call | Work after admission |
| --- | --- | --- | --- |
| `POST /oauth/register`, `Bridge.handleRegister` | `check("register:<ip>")` | In stored mode, `assertStoredRegistrationIp` rejects a missing, non-string, empty, or literal `"unknown"` IP with direct 400 `invalid_request`. | Form occurrence checks, field selection, `registerClient`, registration state, and registration audit. |
| Direct `GET /oauth/authorize`, `Bridge.resolveIdentity` | `check("authorize:<ip>")` | Each adapter rejects repeated authorize parameters before calling `Bridge.resolveIdentity`. | `IdentityPort.verify` and the identity audit. `Bridge.handleAuthorize` does not call the limiter again. |
| Pairing `GET` or `POST /oauth/authorize`, `Bridge.guardPairingAuthorize` | `check("authorize:<ip>")` | The in-process pairing-authorize gate runs first. The orchestrator then rejects repeated query members. On POST, it also checks repeated body members and Origin. | OAuth value selection, pairing session or code work, verification, consent preparation, store work, and audit. |
| `POST /oauth/authorize/approve`, `Bridge.handleApprove` | `check("approve:<ip>")` | Adapter request-body limit and normalization. | Form occurrence checks, field selection, Origin validation, consent consumption, authorization-code state, and audit. |
| `POST /oauth/token`, `Bridge.handleToken` | `check("token:<ip>")` | Adapter request-body limit and normalization. | Form occurrence checks, field selection, grant routing, token state, signing, and audit. |
| `POST /oauth/revoke`, `Bridge.handleRevoke` | `check("revoke:<ip>")` | Adapter request-body limit and normalization. | Form occurrence checks, field selection, token hashing, revocation state, and audit. An admitted unknown or already-revoked token still returns HTTP 200 under RFC 7009. |
| Upstream `GET /oauth/authorize`, `createUpstreamRedirectFlow.handleAuthorize` | `check("upstream:<ip>")` | Nothing in the handler. | Duplicate-parameter checks, client selection, CIMD resolution when applicable, flow JWT creation and size check, CIMD success audit when applicable, IdP URL construction, and the redirect response. |
| Upstream callback, `createUpstreamRedirectFlow.handleCallback` | `check("upstream:<ip>")` | Nothing in the handler. | Cookie read, clock snapshot, duplicate-parameter check, flow-cookie validation, store work, IdP exchange, identity verification, consent preparation, and audit. |
| CIMD, `CimdResolver.resolve` | `check("cimd:<ip>")` | `CimdResolver.resolve` rejects when CIMD is disabled. | Cache lookup, DNS and fetch on a miss, cache update when allowed, document validation, redirect matching, and CIMD audit. |
| Submitted pairing code, `createConsolePairingIdentity().verify` | `check("pairing:<ip>")` | Input-shape parsing. Missing or wrongly typed code or nonce returns `pairing_invalid_input` and emits an audit event before the limiter. | Active-code lookup, expiry, code and nonce comparison, attempt count, and pairing audit. |

After the `register`, `approve`, `token`, or `revoke` check admits a request, `Bridge` rejects repeated recognized URL-encoded form members before field selection. The request has consumed one limiter check, but it performs no endpoint audit or durable mutation.

The in-process pairing-authorize gate in §17.5 does not use `RateLimitPort`. It can return 429 before `Bridge.guardPairingAuthorize` runs. The `pairing:<ip>` check is a separate control for submitted codes.

### Denials and exceptions

| `RateLimitPort.check` result | Call site | Result |
| --- | --- | --- |
| `false` | `register:<ip>`, `authorize:<ip>`, `approve:<ip>`, `token:<ip>`, `revoke:<ip>`, `upstream:<ip>`, or `cimd:<ip>` | Direct 429 `temporarily_unavailable`. The work listed after admission does not run. |
| `false` | `pairing:<ip>` | `createConsolePairingIdentity().verify` emits a failure audit and returns `pairing_rate_limited`. The wrong-attempt count does not increase. `handlePairingAuthorize` then follows its failed-verification path. |
| Exception | `register:<ip>` with `BridgeConfig.dcr.mode === "stored"` | Direct 503 `temporarily_unavailable` before body selection, registration state, or registration success audit. |
| Exception | The current call sites listed above other than `register:<ip>` with `BridgeConfig.dcr.mode === "stored"` | The request continues. This includes `register:<ip>` with `BridgeConfig.dcr.mode === "stateless"`. |

The [rate-limit outage decision](../rate-limit-outage-policy.md) explains why `POST /oauth/register` with `BridgeConfig.dcr.mode === "stored"` is the current `RateLimitPort` call that returns 503 on an exception. A new call site that can create anonymous durable state must define its outage result in its contract. It does not inherit the request-continues result from the current call sites.

### Shared ports and CIMD

`Bridge` snapshots a supplied `RateLimitPort` at boot. The snapshot retains the source port's identity. If one source port is supplied to both `Bridge` and `createUpstreamRedirectFlow`, `CimdResolver` calls it once for `cimd:<ip>`. If the two source ports differ, `CimdResolver` calls both. A denial from either port denies the request. An exception from either port does not block CIMD.

### Client IP source

| Adapter | IP source |
| --- | --- |
| Fastify | Framework `req.ip`. Its value depends on the host's `trustProxy` configuration. |
| Express | Framework `req.ip`. Its value depends on the host's `trust proxy` configuration. |
| Hono | The deployer's `clientIp?: (c: Context) => string \| undefined` option. It is optional and may return `undefined` for a given request, which is why the per-request 400 rule below exists in the core and cannot be replaced by the boot check. The adapter does not read `X-Forwarded-For` or another client-supplied IP header. A deployer behind a trusted proxy supplies an extractor wired to the actual topology, such as the rightmost trusted `X-Forwarded-For` hop or the runtime's connection information. |

For Fastify and Express behind a reverse proxy, configure `trustProxy` or `trust proxy` for the actual proxy topology. If the framework does not trust the proxy hop, proxied callers share the proxy's bucket. If it trusts a client-reachable hop, a caller can select a bucket through forwarded headers. For Hono, `clientIp(c)` must derive the address from the trusted runtime or validated proxy chain. It must not pass through a client-supplied IP header.

Without a Hono `clientIp`, non-stored operations use `<prefix>:unknown` and audit events omit `ip`. Hono stored DCR rejects the missing extractor at boot. For every adapter, `Bridge.handleRegister` rejects `POST /oauth/register` in stored mode when the runtime IP is missing, non-string, empty, or the literal `"unknown"`. This rejection happens before `RateLimitPort.check`. This endpoint and mode do not use `register:unknown`.

### Protected `/mcp`

`RateLimitPort` does not protect `/mcp`. A Fastify host uses `mcp-sso/fastify/protected-resource-rate-limit`, described in §8.4 and §15. That helper installs `@fastify/rate-limit` at `onRequest` with a finite budget and `skipOnError: false`. Its counter-store failure returns 503 before bearer verification or protected handler work.
