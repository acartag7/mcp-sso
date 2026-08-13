# 7. Crypto & token contracts

All signing goes through `jose` (the only runtime dep). **Algorithm pinning is
non-negotiable**: consent tokens are HS256, access tokens are ES256 (EC P-256),
and verifiers pin the algorithm set so a `none`-alg or key-confusion token is
rejected. Consent and access keys are **separate** (the consent secret never
validates an access token and vice-versa).

## 7.1 Consent token (HS256, single-use)
Short-lived JWT binding one authorize request to a single approval. Claims:
`iss`=issuer, `aud`=`"mcp-sso/consent"`, `sub`=verified subject,
`client_id`, `redirect_uri`, `resource`, `scope` (space-joined), `code_challenge`,
`code_challenge_method`=`"S256"`, `state`?, `allowed_scopes`? (space-joined
identity ceiling — §17.4; present only when the resolved identity supplied an
`allowedScopes` ceiling, so `approve` re-intersects from the *verified token*
rather than client-resupplied input), `cimd_verified`? (§17.1.6 decision 3 —
boolean `true` only, minted ONLY on genuine CIMD validation; OMITTED when
absent/false; any present non-`true` value fails verification), `jti` (random,
single-use), `store_instance` (the opaque §12 store binding), `iat`, `exp`.
Verified with `algorithms: ["HS256"]`, pinned iss+aud, clock from
`ClockPort`. **Single-use:** the `jti` is consumed atomically on approve (§12
`consumeConsentJti`); a replay is rejected with `invalid_grant`.
Under the 0.3.0 §6.1 amendment, `verifyConsentToken` takes one
canonical snapshot before `jwtVerify`; snapshot failure remains
the existing `invalid_consent` error.

**Replica/store binding.** Before signing a consent JWT, `prepare` reads the
store's §12 opaque instance binding and includes it as `store_instance`.
`approve` requires exact equality with a fresh read from its store before denial,
JTI consumption, authorization-code generation/storage, or success audit. A
consent token minted against an independent store therefore fails with direct
`invalid_consent` even when issuer and signing secrets are shared. Replicas over
the same MySQL database read the same durable binding and remain compatible.
SQLite preserves the binding when the same file is reopened; `MemoryStore` keeps
one binding only for that object/process lifetime. Existing consent tokens lack
the claim and are invalidated on upgrade; users restart the authorization flow.

### 0.3.3 consent-JTI lifetime correction

The consent JWT's verified, signed `exp` is the sole authority for the
single-use JTI tombstone expiry. `consentTokenTtlSeconds` determines `exp` only
when a new consent JWT is signed; a later configuration value MUST NOT be used
to recompute, shorten, or extend the tombstone for an already-signed token.
`verifyConsentToken` MUST require the signed `exp`, validate it as a safe-integer
NumericDate whose millisecond conversion falls within the repository's complete
canonical UTC range (`0000-01-01T00:00:00.000Z` through
`9999-12-31T23:59:59.999Z`), and return its canonical 3-ms UTC string in the
function's additive return-only intersection. It MUST NOT add a required expiry
member to the exported `ConsentRequestClaims` signing-input interface. Missing,
non-number, non-finite, fractional, unsafe, or out-of-range `exp` maps to the
existing direct `invalid_consent` error. Negative NumericDates are accepted when
they represent canonical year-0000 timestamps; verification still rejects them
as expired at any later current time. `OAuthAuthorizationUseCase.approve` MUST
pass the returned canonical string unchanged to `consumeConsentJti`.

A JTI accepted once MUST remain rejected in a surviving conforming store through
the signed `exp`, including after a sweep whose `now` is before or exactly equal
to that expiry. A sweep after the signed expiry MAY collect the tombstone because
the JWT can no longer pass expiry verification. SQLite and MySQL preserve this
state across process replacement; `MemoryStore` remains explicitly process-local
and cannot preserve any tombstone across destruction of its owning process or
across independent replicas.

Replay rejection occurs before authorization-code generation/storage and before
an `oauth.authorize.approve` success audit. After a successful JTI consume,
`approve` MUST take a fresh canonical commit snapshot, require it to be no
earlier than the initial verification snapshot, validate the authorization-code
TTL offset at that snapshot, and recheck the signed expiry
before generating or storing a code. If `exp <= commit snapshot`, the operation
fails with the existing direct `invalid_consent`; this closes an in-flight race
where verification happened just before `exp`, an asynchronous store read or JTI
consume paused, and a concurrent post-expiry sweep removed the old tombstone.
The commit snapshot owns authorization-code expiry and every subsequent audit
timestamp. A first use that reaches commit before signed expiry still stores one
code and emits one success audit. Denial (`approved !== true`) remains unchanged
and does not consume the JTI.

| Behavior-table field | Binding rule and proof |
| --- | --- |
| Authority | The verified consent JWT's signed `exp`; never the approval-time `consentTokenTtlSeconds`, authorization-code TTL, sweep time, or adapter default. |
| Capture point | `verifyConsentToken`, after signature/algorithm/issuer/audience/time verification, parses the same verified payload and returns one canonical signed-expiry string through an additive return-only intersection. `ConsentRequestClaims` adds only the optional internal `storeInstanceId` signing input. No consumer reparses the raw JWT. |
| Consumers | Direct consent approval passes the returned expiry to `StorePort.consumeConsentJti`. The upstream-flow sibling continues to pass its independently verified flow JWT `exp`; every `consumeConsentJti` production caller is covered. |
| Side-effect order | Origin, JWT, resource, CIMD/redirect, approval, and scope gates precede JTI consumption. Successful JTI consumption is followed by a fresh commit snapshot and signed-expiry recheck; both precede code generation, `saveAuthCode`, redirect construction, and success audit. An extant-tombstone replay stops at JTI consumption. A sweep/consume race stops at the commit recheck. |
| Lifecycle: same configuration | First valid approval succeeds once; immediate or later replay before signed `exp` fails. |
| Lifecycle: shorter TTL after mint/restart | A token minted under a longer TTL retains its signed expiry. Approval under a shorter current TTL records the original signed expiry; sweeping at `approval time + shorter TTL` does not restore eligibility. |
| Lifecycle: longer TTL after mint/restart | The tombstone is not extended to the new TTL. It remains only through the token's earlier signed expiry. |
| Lifecycle: sweep boundary | Sweep before or exactly at signed expiry retains the JTI. Sweep after signed expiry may delete it. A newly started approval then fails at JWT verification; an approval verified before expiry but delayed past it fails at the post-consume commit recheck. Neither path stores a code or emits success. |
| Lifecycle: store adapters | Memory, SQLite, and MySQL have the same supplied-expiry and sweep semantics. Only persistent adapters claim process-restart durability; shared storage is required across replicas. |
| Semantic behavior | First use returns an authorization code. Any second approval while the JWT is otherwise valid returns direct `invalid_grant` and cannot mint another code. At/after JWT expiry the existing direct `invalid_consent` path wins. |
| Forbidden effects | Current TTL must not influence an already-signed token's tombstone. Replay must not generate/save a code, emit approval success, extend an existing tombstone, or redirect success. A sweep race may reinsert only the same signed expired timestamp before the commit recheck fails; it cannot make the approval successful. |
| Positive proof | An adjacent valid first-use approval remains green and records the exact verified signed expiry. Shared conformance proves all stores retain that supplied expiry through sweep. JWT boundary tests preserve consent verification at the latest mint time whose signed `exp` remains canonical; the access-token upper-bound proof stays unchanged. |
| Negative proof | (1) Mint at 600 seconds, restart/approve under 60 seconds at +100, sweep at +161, and replay before +600: replay fails with zero additional code writes and success audits. (2) In stored-DCR mode, delay a replay after pre-expiry verification, sweep after `exp`, let `consumeConsentJti` reinsert, then resume: commit recheck returns `invalid_consent` with zero code writes and success audits. |
| Semantic mutant | Restoring `approval snapshot + current consentTokenTtlSeconds` at the enforcement point makes the restart/sweep regression fail. |
| Wiring mutant | Returning the correct expiry from verification but passing a current-TTL-derived value at the actual approval call site makes the same regression fail; helper-only tests are insufficient. |

Compatibility and migration: this release adds the optional TypeScript
`getStoreInstanceId` capability and one metadata table to each SQL adapter;
authorization construction requires the capability at runtime. Existing OAuth
rows need no rewrite, but outstanding pre-upgrade consent JWTs lack the binding
and are invalidated. A tombstone already swept by vulnerable code cannot be
reconstructed because the store no longer has the original JWT. Operators that
already shortened the consent TTL under vulnerable code, ran shared-store
replicas with inconsistent consent TTLs, or cannot exclude an intervening sweep
SHOULD rotate `consentSigningSecret` while upgrading. That invalidates outstanding
consent JWTs and upstream flow cookies, requiring affected users to restart those
in-flight flows; authorization codes, access tokens, refresh families, and grants
are otherwise unchanged. Operators that have not shortened the TTL can deploy
the correction before any later reduction without rotating the secret.

## 7.2 Access token (ES256, audience-bound, fail-closed)
```ts
interface AccessTokenClaims { subject: string; clientId: string; scopes: string[]; }
```
JWT: header `{alg:"ES256", kid, typ:"JWT"}`, payload `client_id`, `scope`,
`sub`, `iss`=issuer, `aud`=**resource** (RFC 8707 audience binding), `iat`, `exp`.
Verified with `algorithms: ["ES256"]`, pinned iss + **aud=resource**
(fail-closed: a token whose `aud` ≠ resource is `invalid_token`, never accepted),
clock from `ClockPort`.
Under the 0.3.0 §6.1 amendment, `verifyAccessToken` takes one
canonical snapshot before `jwtVerify`; snapshot failure remains
the existing `invalid_token` 401.

**Fix #6 — cached verification key:** the public JWK is imported to an ES256 key
**once** (memoized on the config) rather than per request, as the source does.
`verifyAccessToken` reuses the cached `CryptoKey`.

## 7.3 Authorization code (hashed, single-use)
Format `ac_<base64url(32 random bytes)>`. Stored only as `sha256(code)`.
Single-use: `consumeAuthCode` deletes on read; missing or expired → `invalid_grant`.
A failed PKCE or client/redirect mismatch **still consumes the code** (one-shot).

The complete redemption binding is the stored code hash, `client_id`,
`redirect_uri`, PKCE verifier/challenge, and stored `resource` string. The token
use-case passes the exact current `BridgeConfig.resource` into atomic store
consumption and independently requires the returned record's `resource` to equal
that same value before redirect, client, PKCE, scope, signing, refresh-state, or
success-audit work. Resource mismatch is the same non-oracular `invalid_grant`
as an unknown, expired, client-mismatched, redirect-mismatched, or PKCE-invalid
code. Reference stores do not consume a code on resource mismatch, so a failed
B-side redemption leaves the A-bound code eligible for exactly one legitimate
A-side redemption. Once A succeeds, replay remains rejected.

**0.3.2 stored-DCR generation amendment.** An
authorization code issued under `dcr.mode:"stored"` carries
`grantGeneration = STORED_DCR_GRANT_GENERATION`. Code consumption supplies that
expected generation to the store and repeats the equality check on the returned
record in `OAuthTokenUseCase.consumeValidCode` before PKCE or token preparation.
A missing, `null`, malformed, or different generation is consumed/burned and
returns the same `invalid_grant` as an unknown code. A valid stored
`ClientStore` row does not make a legacy code eligible.

## 7.4 Refresh token (family, rotation, replay detection)
Format `rt.<familyId>.<base64url(32 random bytes)>`. `familyId` is a random
per-issuance id parseable from the token (so rotation knows which family to
rotate without a lookup). Stored only as `sha256(token)`.
- **Rotation:** `rotateRefreshToken(tokenHash, next, now)` marks the current
  token consumed, inserts the next, and returns the **consumed** record. Replay of
  an already-consumed token revokes the whole family.
- **Resource binding:** every new refresh family and every member carries the
  authorization code's exact resource string. The resource is fixed for the whole
  family. `rotateRefreshToken` receives the bridge's expected resource and checks
  the family and selected record before replay detection, consumption, successor
  persistence, or any family mutation. A different resource is the same
  `invalid_grant` as an unknown refresh token and commits no reference-store
  mutation, so the correctly bound current token remains usable. Rows from an
  older schema without a resource are legacy and fail closed; migration never
  infers one from current bridge configuration. The token use-case rechecks the
  returned record before signing or success audit work because custom stores are
  a runtime boundary.
- **0.3.2 stored-DCR generation:** a refresh family
  created from a stored-DCR-mode authorization code carries that code's
  current generation. Rotation takes the expected generation, compares it
  before consuming the predecessor or inserting a successor, and
  authoritative-copies the family's stored generation. Missing, `null`,
  malformed, or non-current generation returns `null` and therefore
  `invalid_grant`; no successor becomes live. The use-case repeats the returned
  record check before response preparation. A same-generation restart leaves
  the family valid.
- **Authorization-code preparation before write:**
  `OAuthTokenUseCase.exchangeAuthorizationCode` parses the code record's stored
  scopes and constructs the signed token response before `saveRefreshToken`.
  Rotation deliberately remains atomic and authoritative before refresh-response
  preparation so a replayed consumed predecessor always revokes its family.
- **Refresh-response compensation after rotation:** after a successful
  `rotateRefreshToken`, `OAuthTokenUseCase.refresh` treats every remaining step
  as one response-preparation unit. A client-binding or reserved-subject
  rejection, malformed stored scopes, signing failure, response-construction
  failure, or success-audit event-construction failure MUST revoke the whole
  rotated family before the error escapes. The revocation reuses the exact
  canonical timestamp already passed to `rotateRefreshToken`; compensation
  never depends on a second clock read. No successor secret is returned on a
  failed preparation, and the committed successor cannot remain active in a
  conforming available store.
- **Client binding (RFC 6749 §6):** the refresh grant MUST present a `client_id`
  matching the stored record; a mismatch revokes the family (theft signal).
- **Revocation:** `revoke` looks up the family by hash (rejecting unknown tokens
  harmlessly) and revokes the family.

The store remains an availability boundary: if the compensating
`revokeRefreshTokenFamily` call itself fails, the token endpoint fails closed
with no response, but the library cannot claim that unavailable external
storage durably recorded the revocation. Reference stores perform the
revocation before the preparation error escapes. Moving preparation before
rotation is not an alternative: it can skip the atomic consumed-token replay
detection and whole-family revocation that `rotateRefreshToken` owns.

## 7.5 PKCE S256 (timing-safe)
`verifyPkceS256(verifier, challenge)` rejects malformed inputs outright (verifier
must be 43–128 unreserved chars; challenge must be 43 base64url chars), then
compares `base64url(sha256(verifier))` to the stored challenge with
`timingSafeEqual`. A 1-char verifier can never match a stored challenge.
