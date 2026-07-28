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
single-use), `iat`, `exp`. Verified with `algorithms: ["HS256"]`, pinned iss+aud, clock from
`ClockPort`. **Single-use:** the `jti` is consumed atomically on approve (§12
`consumeConsentJti`); a replay is rejected with `invalid_grant`.
Under the 0.3.0 §6.1 amendment, `verifyConsentToken` takes one
canonical snapshot before `jwtVerify`; snapshot failure remains
the existing `invalid_consent` error.

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
