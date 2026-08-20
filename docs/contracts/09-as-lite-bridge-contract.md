# 9. AS-lite bridge contract

The AS half. Each item is a framework-free use-case or pure metadata builder; an
adapter (Phase 3) exposes them over HTTP.

## 9.1 Metadata (RFC 8414 / RFC 9728)
- **`authorizationServerMetadata(config)`** (RFC 8414), served at
  `${issuer}/.well-known/oauth-authorization-server`. Emits `issuer`,
  `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `registration_endpoint`,
  `revocation_endpoint`, `response_types_supported: ["code"]`,
  `grant_types_supported: ["authorization_code","refresh_token"]`,
  `code_challenge_methods_supported: ["S256"]`, `scopes_supported: catalog`,
  `token_endpoint_auth_methods_supported: ["none"]` (public clients + PKCE), and
  **`authorization_response_iss_parameter_supported: true`**. Every successful
  or error authorization response sent over a validated redirect carries RFC
  9207 `iss`, exactly equal to `config.issuer`. Direct HTTP errors carry no
  redirect parameters and therefore no `iss`.
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

## 9.2 DCR — `registerClient` (RFC 7591; deprecated compatibility path)
`POST /oauth/register` understands `redirect_uris` (required, each validated),
optional `application_type` (`"native"` | `"web"`, default `"web"`),
`token_endpoint_auth_method`, and `grant_types`. MCP Authorization 2026-07-28
places the `MUST` to send an appropriate `application_type` on MCP clients. The
bridge remains tolerant of omission for backwards compatibility and applies the
OIDC default of `"web"`. Other client metadata is ignored, as RFC 7591 §2
requires; it is never persisted or reflected by this AS-lite endpoint.
JSON arrays remain the representation for array-valued DCR metadata. In an
`application/x-www-form-urlencoded` registration, each recognized metadata key
(`redirect_uris`, `application_type`, `token_endpoint_auth_method`, and
`grant_types`) may occur at most once; a repeated key is a direct 400
`invalid_request` before metadata selection, client persistence, or registration
audit. A form-encoded scalar does not become an array, so clients sending
`redirect_uris` or `grant_types` use JSON rather than repeated form members.
`redirect_uris` is client-supplied untrusted input and carries the same hard
caps §10.0 states: **1..16 entries** (the same bound §17.1.5 rule 19 puts on a
CIMD document's array, same rationale — it bounds the authorize-time
exact-match scan) and **≤ 2048 UTF-8 bytes per entry, checked on the raw
string before parsing**.
When present, `grant_types` is an array of **0..32** non-empty primitive
strings, each no more than **256 UTF-8 bytes**. The bridge only inspects that
metadata to reject `client_credentials`; it does not persist or otherwise
enable the declarations. These caps bound core work and ensure the largest
request shape with metadata this bridge understands fits the Hono boundary in
§9.6.
- **Stateless mode (default):** any well-formed registration with allowlisted
  redirect URIs succeeds; loopback redirects require an explicit
  `redirectAllowlist` entry. The server mints an ephemeral `client_id`
  (`mcpdc_<random>`), returns `{ client_id, client_id_issued_at, redirect_uris,
  token_endpoint_auth_method: "none" }`, and persists nothing. At authorize, any
  non-empty `client_id` is accepted (matches the source). **Redirect policy = the
  global allowlist with no implicit loopback trust**
  (§10.1, composed per `redirectAllowlistMode` exactly as in stored mode) —
  stateless mode persists no client metadata, so per-client redirect
  policies cannot apply.
- **Stored mode (opt-in):** at **registration time** each `redirect_uri` is
  validated through the **global allowlist (§10.1), composed per
  `redirectAllowlistMode`** — built-ins + config under the default `"extend"`,
  config entries ALONE under `"replace"` — and then
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
  loopback-for-everyone. Registration is not a permanent grant of trust: every
  STORED entry is re-checked against the mode-composed global allowlist before
  the per-type policy runs, so a client registered while `"extend"` trusted the
  built-ins stops authorizing once an operator switches to `"replace"`
  (`resolveOpaqueRedirect`, `src/authorize-internals.ts`).
- **Machine-shape rejection (§17.2).** Open registration can NEVER mint a
  secret-bearing (machine) client: a request naming
  `token_endpoint_auth_method` other than `"none"`, or a `grant_types`
  containing `client_credentials`, is rejected with `invalid_client_metadata`
  (400) in BOTH modes. `application_type: "machine"` is likewise not a valid
  DCR value. Machine clients are provisioned out-of-band only.

## 9.3 Authorize + consent

**Reader map.** Keep these four questions separate while reading the exact
contract below:

1. Is the redirect destination trusted yet? If not, errors stay on the direct
   HTTP channel.
2. Which client shape is this: stored DCR, stateless DCR, or CIMD?
3. Which scopes survive the catalog, identity ceiling, and stored-grant rules?
4. Does approval commit replay state and the authorization code before success?

The following clauses are canonical; this map changes no validation order or
error shape.

**Validation order & error channels (RFC 6749 §4.1.2.1).** The authorize flow has
two error channels, split by whether the `redirect_uri` is trusted yet:

- **Direct HTTP error (NEVER redirect)** — pre-validation failures where the
  redirect destination is untrusted: an ambiguous authorize request (any of
  `response_type`, `client_id`, `redirect_uri`, `code_challenge`,
  `code_challenge_method`, `scope`, or `state` has more than one nonempty occurrence),
  identity not resolved/rejected (the resource
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
- **Redirect to `redirect_uri?error=<code>&iss=<issuer>[&state=…][&error_description=…]`** —
  every error discovered **after** `client_id` + `redirect_uri` validate:
  `unsupported_response_type`, `invalid_target`, `invalid_scope`, `invalid_request`
  (bad PKCE params), `access_denied` (the user clicked Deny), and `server_error`.
  The core provides
  `buildAuthorizationErrorRedirect(config, redirectUri, code, state?, description?)`; the
  required `BridgeConfig` supplies the exact issuer and cannot be omitted by a
  library call site; every such call site passes its validated `Bridge.config`.
  The builder replaces any pre-existing
  `error`, `iss`, `state`, or `error_description` member it owns rather than
  appending an ambiguous duplicate. It does not validate the redirect
  destination; the caller must already have established the redirect channel.
  The root export retains the pre-existing
  `buildErrorRedirect(redirectUri, code, state?, description?)` signature for
  source compatibility, but library-owned authorization responses do not use
  that issuer-less legacy helper.
  The use-case tags these errors with the validated `redirectUri` + `state` so the
  adapter answers 302. (This is what lets claude.ai render "you declined" instead
  of a dead JSON page. The source never implemented error redirects; this completes
  fix #5.) Direct errors never call the builder and never gain a `Location` or
  `iss` parameter.

**`prepare({ clientId, redirectUri, responseType, codeChallenge,
codeChallengeMethod, resource?, scope?, state?, subject, allowedScopes?, registration? })`** → `PreparedConsent`:
*(`registration?: CimdRegistration` — §17.1.6 decision 1c; supplied ONLY by the
upstream-redirect orchestrator for a carried CIMD registration, NEVER bound to
client-controlled request input; when present, `prepare` uses it and does not fetch.)*
Before building this input, `Bridge.handleAuthorize` applies the shared RFC 6749
§3.1 occurrence guard to the canonical singleton parameter set above. An
array-valued member with more than one nonempty occurrence returns direct 400
`invalid_request`, with no `Location`, before first/last-value selection,
`prepare`, consent rendering, store access, or authorize success audit. A
single-valued request follows the unchanged validation order below. The same
pure helper and key definition govern the upstream and console-pairing authorize
entry points; framework adapters reconstruct repeated query members from the raw
request URL, independent of configurable framework query parsers. The direct
header-identity routes run the same guard before
`IdentityPort.verify`; `Bridge.handleAuthorize` repeats it as defense in depth.
RFC 6749 treats valueless occurrences as omitted. RFC 8707
permits `resource` to repeat; identical nonempty resource indicators collapse to
one target, while multiple distinct targets follow the existing post-validation
`invalid_target` channel instead of the RFC 6749 duplicate channel.

1. `subject` REQUIRED (the adapter/`IdentityPort` resolves it before calling
   `prepare`). No subject ⇒ `access_denied` 401 **direct**, never a placeholder.
2. `client_id` present and `redirect_uri` **mode-appropriately validated** (§17.1.6
   decision 1a): §10 for an opaque non-scheme id; the shared CIMD document matcher for
   a validated lowercase-`https://` CIMD id (from the carried `registration` or the
   §17.1.4 success cache/fetch); any other scheme-shaped value ⇒ direct
   `invalid_client` — else **direct** (pre-validation).
3. *(redirect-eligible from here)* `response_type=code`; `resource` **defaults to
   `config.resource` when omitted and MUST equal `config.resource` when present**
   (else `invalid_target`); `scope` normalized and bounded per §11 (else
   `invalid_scope`);
   PKCE `code_challenge_method=S256` + challenge present (else `invalid_request`).
4. **Scope ceiling *(§17.4, shipped S2a).*** When the resolved identity supplied
   an `allowedScopes` ceiling, the requested scopes (and `defaultScopes`, when no
   `scope` was requested) are **narrowed by intersection** with it; an **empty
   intersection ⇒ `access_denied`** over the redirect channel. The ceiling is
   embedded in the consent-token claims (§7.1 `allowed_scopes`). Without a
   ceiling this step is a no-op (v0.1 behavior, including an empty requested set).
5. **Scope accumulation *(RC item (c)) — stored-DCR opaque clients only.*** Load
   `priorScopes = findGrantedScopes(subject, clientId, now, generation, resource)` ONLY
   for an opaque client resolved through `ClientStore` in stored-DCR mode. The lookup
   returns only active rows whose token and family both have the exact configured
   resource, so legacy and resource-A records cannot contribute to resource B. For **every scheme-shaped
   (`https://`/CIMD) client_id, and in stateless mode, `priorScopes = []`** — never
   keyed on `clientId.startsWith("https://")` and never on `cimd_verified` (§17.1.6
   decision 3; CIMD accumulation is deferred — refresh rows carry no provenance). Those
   authorizations stand alone.
6. Sign the consent token (§7.1), audit, and return
   `{ consentToken, …claims, priorScopes, requestedScopes }`. The consent page
   renders the **delta** = `requestedScopes − priorScopes` as "new" (rendering is
   an adapter concern, Phase 3; the core supplies both sets). The signer rejects
   a consent token that exceeds its 192 KiB output budget, so the server never emits
   a consent form that its 256 KiB Hono approval route will reject. Because the
   HTML carries that signed, subject-bound consent JWT, `Bridge.handleAuthorize`
   returns it with `Cache-Control: no-store`; the shared normalized response is
   relayed unchanged by Fastify, Express, and Hono.

**`approve({ consentToken, approved?, origin? })`** → `{ redirectTo, code?, state? }`:
- **Finite-clock gates (0.3.0; amended 0.3.3):** before consent-token
  processing and before `assertApproveOrigin`, `OAuthAuthorizationUseCase.approve`
  takes the §6.1 validated initial snapshot with no future offset. It reuses that
  fixed value for JWT verification, scope-accumulation time, and every
  pre-JTI-consumption audit/error path. An invalid initial snapshot takes
  precedence over an invalid Origin and returns the existing direct
  `invalid_consent` 400 with no fabricated audit timestamp. After successful
  atomic JTI consumption, approval takes a fresh commit snapshot that validates
  the authorization-code TTL offset and MUST NOT move backward relative to the
  initial snapshot. The commit snapshot rechecks the verified signed `exp` and
  owns authorization-code expiry plus every later audit timestamp. An invalid or
  backward commit snapshot returns direct `invalid_consent`; the JTI remains
  consumed, and the failure audit uses the initial operation snapshot rather
  than fabricating a commit timestamp. A valid commit snapshot at or after
  signed `exp` returns direct `invalid_consent` using that snapshot for the
  failure audit, before code generation/storage or success audit.
- **CSRF/`origin`** must be exactly one primitive string equal to the issuer
  origin or a member of `allowedOrigins` — else `invalid_origin` 403 **direct**
  (a foreign origin is never redirected anywhere). `Bridge.handleApprove`
  receives a `BridgeConfig` whose `allowedOrigins` members already passed the
  §5 exact canonical-origin grammar at boot; the opaque browser value `"null"`
  can therefore never become an allowlisted match. `Bridge.handleApprove`
  reads the normalized `NormRequest.headers` through `headerString`; an
  array-valued header or more than one case-insensitive `Origin` key becomes
  absent and fails closed rather than selecting one value. Fastify and Express
  build that normalized snapshot with `headersFromDistinct` from Node's
  `headersDistinct`, preserving every on-wire occurrence. Fetch/Hono exposes
  duplicates comma-coalesced; `readHeader` treats a comma in a non-`Cookie`
  header as ambiguous before `Bridge.handleApprove` calls the core.
- **Approve-time resource gate FIRST:** immediately after
  `verifyConsentToken` and before CIMD/redirect processing, the Deny branch,
  JTI consumption, scope lookup, code storage, audit success, or any redirect,
  the verified consent token's `resource` string MUST exactly equal
  `config.resource`. A mismatch is the existing direct, non-oracular
  `invalid_consent` response. It does not consume the JTI or use the token's
  redirect URI, so the bridge that prepared the token can still approve it once.
- **Approve-time scheme gate FIRST (§17.1.6 decision 3):** immediately after
  the resource gate and BEFORE the Deny branch below — a lowercase-`https://`
  client_id is approvable only when `cimd_verified === true` AND `cimd` enabled;
  any other scheme-shaped client_id, or `cimd_verified:true` on a non-CIMD id,
  ⇒ direct `invalid_consent` (so a legacy URL-shaped token cannot even be
  Deny-redirected to its attacker `redirect_uri`).
- **Approve-time current redirect policy gate:** immediately after the scheme
  gate and before the Deny branch, JTI consumption, scope lookup, code storage,
  success audit, or any redirect, reapply the current mode-appropriate opaque
  policy to the signed `redirect_uri`. Stateless mode reapplies the global
  allowlist directly. Stored mode reloads the current registration, reapplies
  the global allowlist/mode to every registered entry, then applies the §10.2
  per-client matcher to the presented redirect (including native loopback
  any-port semantics).
  A consent token minted while an entry was trusted is not grandfathered after
  an operator removes it; failure is direct `invalid_redirect_uri`. CIMD
  redirects remain governed by their verified client document instead.
- **Only `approved === true` approves (fail-closed):** anything else — `false`,
  absent, or malformed — ⇒ Deny: the consent token is **not** consumed; redirect
  to `redirect_uri?error=access_denied&iss=<issuer>&state=…`. The adapter's form parsing is
  equally strict (only `true`/`"true"` approves) so a POST missing the
  `approved` field can never auto-approve at either layer. *(Fix #5 — the
  source's unreachable Deny path; the UI button is Phase 3. Hardened 2026-07-07:
  the original text keyed Deny on `approved === false`, which made the ABSENT
  case an approval — a fail-open default on the consent decision.)*
  After `RateLimitPort("approve:<ip>")` and before `parseApproved` / consent-token
  work, `Bridge.handleApprove` rejects a form body in which `approved` or
  `consent_token` has more than one occurrence, including an empty occurrence,
  with direct 400
  `invalid_request` (no Deny redirect, no JTI consumption). Fastify and Hono
  reconstruct URL-encoded form occurrences as arrays so last-wins collapse
  cannot hide a second `approved=true`; Express already preserves arrays.
  When the checked form body carries **no** `consent_token`, the same handler
  falls back to the deployer-owned `mcp_idp_consent` cookie (threat-model row 4:
  the library itself sets no cookie). The cookie value is percent-decoded
  exactly once; a malformed percent-escape is the same **direct 400
  `invalid_consent`** as an unparseable form-supplied token — never a 500, and
  never silently treated as an absent cookie: the malformed value is the
  consent credential the request presented, and conflating it with "no
  credential" would misreport a malformed (possibly tampered) transport as a
  plain missing-parameter request. *(Fixed 2026-08-19: the bare
  `decodeURIComponent` escaped `handleApprove` as a raw `URIError` mapped to
  500 `internal_error`.)*
- **Validate scope state before consuming consent:** on approval, the signed
  consent `scope` claim and the loaded stored-DCR prior scopes must satisfy §11
  and the current `scopeCatalog`; a carried `allowed_scopes` ceiling must also
  satisfy §11's shape and size bound. A malformed, stale, or oversized consent
  scope or stored grant is a direct `invalid_grant`; a malformed carried ceiling
  is `access_denied`. Both failures occur before the consent JTI is consumed or
  an authorization code is written.
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
  `redirect_uri?code=…&iss=<issuer>[&state=…]` (RFC 9207 `iss`). This
  code-bearing approval response carries `Cache-Control: no-store`. The Deny
  redirect and generic sanitized error responses are not widened by this rule.

## 9.4 Token
`POST /oauth/token`, `cache-control: no-store`. Response:
`{ access_token, token_type: "Bearer", expires_in, refresh_token, scope }`.
*(This is the USER-grant shape — `UserTokenResponse`, returned by
`exchangeAuthorizationCode`/`refresh`/device. The `client_credentials` grant
(§17.2, shipped S3b) returns `MachineTokenResponse`: identical except it has NO
`refresh_token` member at all — not an optional one.)*
- **Form occurrence gate:** after `RateLimitPort("token:<ip>")` but before
  selecting `grant_type`, resolving client authentication, dispatching a grant,
  store work, token signing, or token audit, every recognized token form key may
  occur at most once: `grant_type`, `code`, `redirect_uri`, `client_id`,
  `code_verifier`, `refresh_token`, `client_secret`, `scope`, and `resource`.
  Any repeated occurrence, including an empty occurrence, is direct 400
  `invalid_request`; no first or last value selects the grant path.
- **Finite operation clock:** each of the authorization-code, refresh, and
  client-credentials issuance operations takes exactly one §6.1 snapshot before
  grant/authentication/store work and reuses it for every token, expiry,
  mutation timestamp, compensation timestamp, and audit timestamp. A bad clock
  or overflowing TTL offset is sanitized by Bridge as 500 `internal_error`
  before mutation, token signing, or audit; an honest timestamp is never
  fabricated.
- **`exchangeAuthorizationCode`**: consumes the code (§7.3), verifies PKCE S256
  and client/redirect/resource binding, then `tokenResponse` parses the stored
  scopes and
  constructs the signed access/refresh response before `saveRefreshToken`
  persists the new family. A preparation failure leaves no refresh row; the
  already-consumed authorization code stays burned. **0.3.2:** in
  stored-DCR mode, generation mismatch is the first stored-record
  validity check and is indistinguishable from any other `invalid_grant`; the
  new refresh family inherits the accepted code generation.
  Resource equality is checked atomically by each reference store before
  consumption and repeated by `OAuthTokenUseCase` on the returned record before
  every success side effect. A mismatch is `invalid_grant` with the same message
  as every other invalid authorization code; no token is signed or returned, no
  refresh state is created, and no success audit is emitted. A custom store that
  ignores the resource predicate remains unable to cause wrong-resource signing
  because the use-case check is authoritative.
- **`refresh`**: atomically rotates the refresh token (§7.4), preserving
  consumed-token replay detection and whole-family revocation; then enforces RFC
  6749 §6 client binding (mismatch ⇒ family revoked ⇒ `invalid_grant`) and mints
  a new access token carrying the rotated record's scopes. It supplies the
  current `BridgeConfig.resource` to the atomic store operation. A missing or
  different family/record resource is the uniform `invalid_grant` response, with
  no reference-store rotation, consumption, revocation, replacement persistence,
  signing, or success audit; the legitimate current token remains available to
  its bound resource. `OAuthTokenUseCase` repeats the returned-record resource
  check before every response-preparation side effect, so a custom store that
  ignores the resource argument cannot cause a wrong-audience access token or
  success audit. After a successful
  rotation, every remaining failure path attempts compensation by calling
  `revokeRefreshTokenFamily` once with the rotation timestamp before propagating
  the error, and returns no token. When that store call succeeds, a malformed
  row or signing failure leaves no active unreturned successor. When it rejects,
  durable state remains store-dependent; the boundary is recorded in §7.4.
  **0.3.2:** `OAuthTokenUseCase.refresh` requires stored-DCR-mode refresh
  rotation to check the current
  grant generation inside the atomic store operation. A valid present-day
  `ClientStore.find(clientId)` result is not grant provenance and is never used
  as a substitute.
- **`revoke`** (RFC 7009): after the adapter's request-body boundary but before
  `Bridge.handleRevoke` normalizes the body or extracts a token,
  `Bridge.handleRevoke` calls `RateLimitPort("revoke:<ip>")`. A `false` result
  returns the existing direct 429 `temporarily_unavailable` response with no token
  hashing, use-case, store, revocation, or audit work; a thrown limiter error is
  fail-open under §6.7. The limiter is not an adapter body-parser gate: malformed
  or over-cap input can return the adapter's fixed 400/413 response before this
  call. Once admitted and before selecting a token, repeated `token` or
  `token_type_hint` form members — including an empty occurrence — return direct
  400 `invalid_request`, with no token hashing, store, revocation, or audit work.
  A singleton request then reaches revocation. Known, unknown, already-revoked,
  and wrong-resource token outcomes return 200; unknown, already-revoked, and
  wrong-resource tokens are **no-ops** (never 4xx — RFC 7009 §2.2 forbids
  leaking token existence via the response). It looks up the token by hash,
  treats a record not bound to the exact configured resource as unrecognized,
  and supplies that resource to the store's atomic family-revocation predicate.
  A guessed family id or wrong-resource token revokes nothing. An unexpected
  lookup or family-revocation failure is not a token-existence outcome: it emits
  the fixed audit failure from §13 and returns the generic sanitized §9.5 500
  response.
- **Audit containment:** every `OAuthTokenUseCase` audit emission goes through
  `writeTokenAudit`. A synchronous throw or rejected promise from a nonconforming
  custom `AuditPort` is ignored, so it cannot replace an OAuth error, suppress a
  prepared token response, or turn RFC 7009 revocation into a failure.

## 9.5 Error bodies
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

## 9.6 Framework adapters *(Phase 3 — transport boundary)*
The `/fastify`, `/express`, `/hono` adapters keep OAuth domain decisions in the
core use-cases. They own framework-specific transport work: apply the raw-body
budget, normalize headers and supported bodies, preserve duplicate and ambiguous
input evidence for Bridge rejection, carry framework- or deployer-derived
client-IP data, call the use-case, and shape the response. Their built-in
semantic formats are JSON and URL-encoded forms, and one shared media gate in
the adapter HTTP module (`semanticOAuthBody`) decides what reaches the core: each
adapter normalizes a body into OAuth fields only when the request carries exactly
one `application/json` or `application/x-www-form-urlencoded` `Content-Type`
essence. The gate keys on the request's own `Content-Type`, not on which parser
filled the framework's body slot, so unsupported below-cap media remain absent
rather than becoming OAuth fields **even when the application mounted its own
parser for that media type earlier on the same OAuth path** — that parser still
owns its byte accounting and error handling (see the Express bullet), but its
output cannot be selected as OAuth input. When `Content-Type` is absent or has
one unsupported media essence, endpoint logic handles the resulting empty
fields: register and token return their existing
required-input errors; approve retains its consent-cookie/body and deny rules;
revoke keeps RFC 7009's HTTP 200 response for the resulting
fieldless/unrecognized-token request. Duplicate or otherwise ambiguous
`Content-Type` also loses its semantic body, but is not treated as fieldless:
the normalized form-provenance sentinel retains the ambiguity and the shared
Bridge form gate rejects it directly with 400 before field selection. A shipped
composition root that constructs `NormRequest` itself for
a caller-owned OAuth route uses this same gate too: both runnable examples and
the generated starter apply `semanticOAuthBody` to their console-pairing
normalizer before `handlePairingAuthorize`. The IP is trusted only when the proxy or extractor satisfies the
deployment preconditions in §6.4. Wiring rules:
- **Endpoints:** GET `/.well-known/oauth-authorization-server` →
  `authorizationServerMetadata`; GET `/.well-known/oauth-protected-resource` AND
  its path-inserted form → `protectedResourceMetadata` (§9.1); GET `/oauth/jwks` →
  `jwks`; POST `/oauth/register` → `registerClient` (behind `RateLimitPort`,
  §6.7); GET `/oauth/authorize` → resolve subject via `IdentityPort` → `prepare`,
  render the consent page; POST `/oauth/authorize/approve` →
  `RateLimitPort("approve:<ip>")` → `approve`; POST
  `/oauth/token` → `exchangeAuthorizationCode`/`refresh` (behind `RateLimitPort`);
  POST `/oauth/revoke` → adapter body boundary → `revoke` (behind
  `RateLimitPort("revoke:<ip>")` before Bridge body normalization; after
  admission and the form-occurrence gate, known, unknown, and already-revoked
  singleton token outcomes retain RFC 7009's HTTP 200 behavior; unexpected
  store failures retain the sanitized §9.5 500 behavior).
- **Direct-authorize ordering:** the header-identity GET `/oauth/authorize`
  path rejects duplicate singleton parameters before identity work, then calls
  `Bridge.resolveIdentity`, which checks
  `RateLimitPort("authorize:<ip>")` before `IdentityPort.verify`, its audit, or
  `prepare`. Limiter denial is a direct 429 with no redirect; limiter failure
  remains fail-open (§6.7). Upstream redirect and CIMD retain their independent
  budgets rather than receiving a second adapter-level check. Console pairing
  applies §17.5's mandatory shared 60-request/60-second in-process authorize
  gate first. After that gate, `handlePairingAuthorize` rejects duplicate query
  and POST body singleton parameters, applies the POST Origin gate, then charges
  `RateLimitPort("authorize:<ip>")` before pairing session, code verification, or
  consent work; it then calls `Bridge.handleAuthorize` without an additional
  `authorize:<ip>` charge. Its identity port's optional submitted-code
  `pairing:<ip>` hook remains a separate defense-in-depth budget.
- **Hono client-IP boot requirement:** `createOAuthApp` applies the §6.7 rule
  before it registers any route: with `bridge.config.dcr.mode === "stored"` and
  no `clientIp` extractor, construction throws `AuthConfigError` naming the
  option. The check reads the bridge's frozen published config once and runs
  ahead of every route registration, so the refusal leaves no partially wired
  app. Stateless mode without `clientIp` constructs normally and emits the
  §6.7 one-time shared-bucket warning; supplying `clientIp` leaves every
  adapter behavior unchanged. Fastify and Express adapters have no matching
  check — they key on the framework's validated `req.ip`.
- **OAuth POST body bound (all framework adapters):** before request-body parsing
  or any Bridge invocation, Fastify, Express, and Hono apply the same fixed
  **262,144-byte (256 KiB)** raw-body budget to `/oauth/register`,
  `/oauth/authorize/approve`, `/oauth/token`, and `/oauth/revoke`. The budget is
  defined once in the shared adapter HTTP module and applies regardless of the
  request's content type inside the adapter-owned parsing boundary. Fastify's
  per-route enforcement also constrains application-supplied parsers registered
  in the same scope; the BYTE accounting of an Express parser mounted earlier
  remains caller-owned as noted below. JSON and URL-encoded forms are the
  built-in semantic input formats. Multipart and unknown media leave the
  normalized body absent rather than yielding OAuth fields, whichever parser
  produced the framework value, because the shared media gate above admits only
  the two supported essences. The fixed budget admits a compact
  JSON serialization with all recognized DCR field values at their maxima: 16 redirect URIs ×
  2,048 UTF-8 bytes (about 192 KiB when every URI character is legally serialized
  as a JSON `\uXXXX` escape), plus 32 `grant_types` entries × 256 UTF-8 bytes
  (about 48 KiB with the same encoding). The combined regression witness is
  245,939 bytes. This is not a semantic DCR size promise: JSON permits arbitrary
  insignificant whitespace, and RFC 7591 requires unknown metadata to be ignored.
- **Hono OAuth POST body enforcement:** a request whose raw representation exceeds
  the shared finite security budget is rejected with 413 rather than passed to a
  parser. A missing `Content-Length` and a
  `Transfer-Encoding` body are stream-counted. A present `Content-Length` must
  be one canonical decimal integer (`0` or a non-zero digit followed by digits),
  must not coexist with `Transfer-Encoding`, and must not exceed the cap;
  malformed, duplicate/coalesced, conflicting, unsafe-integer, and oversized
  values fail closed. A valid declared length does not bypass streaming
  accounting: the pinned `hono/body-limit` middleware still counts the actual
  body bytes. JSON, URL-encoded, multipart, and unknown content types share the
  same pre-parse bound, but the adapter parses only the exact
  `application/json` and `application/x-www-form-urlencoded` media-type
  essences. Duplicate `Content-Type` fields arrive coalesced (`a, a`) and match
  no essence, so Hono leaves such bodies unparsed. The normalized occurrence
  snapshot marks that header ambiguous, and the same Bridge form gate used by
  Fastify and Express returns direct 400 after the route limiter and before field
  selection. A stream read/framing failure before downstream parsing
  returns a fixed direct 400 `invalid_request` response without logging the raw
  throwable or invoking downstream work. Below-cap parser failures retain the
  existing fail-closed parser-error path. A caller that uses `skipAuthorize` to
  mount a custom Hono POST authorize surface (including console pairing) MUST
  mount the adapter-exported `honoOAuthBodyLimit` before its body parser; the
  adapter's four built-in POST routes mount that same middleware automatically.
- **Fastify OAuth POST body enforcement:** every built-in OAuth POST route sets
  Fastify's per-route `bodyLimit` to the shared budget. The limit therefore
  replaces Fastify's larger server default for JSON, the adapter's URL-encoded
  parser, the adapter's buffer-valued catch-all for otherwise unsupported media
  types, and any application parser that delegates raw accounting to Fastify. The
  catch-all enforces the byte boundary without turning unsupported bytes into
  OAuth fields. The adapter registers its parsers and routes in an encapsulated
  Fastify plugin scope. That scope removes any inherited exact URL-encoded
  parser and installs the occurrence-preserving parser for the four built-in
  POST routes; the parent parser and unrelated routes remain unchanged. An
  inherited application parser for some other media type keeps running under the
  route's `bodyLimit`, but the shared media gate drops whatever it returns, so a
  `text/plain` parser that yields an object cannot supply OAuth fields. This is
  required because an inherited first/last-wins parser would erase duplicate
  evidence before `NormRequest.formBody` is built. When `skipAuthorize` leaves POST `/oauth/authorize` to the
  caller, `registerOAuthRoutes` preserves the existing automatic URL-encoded
  form behavior in the caller's scope: it installs the shared form parser when
  that scope has no exact form parser — Fastify exposes no working wildcard
  detection (`hasContentTypeParser("*")` returns false on every 5.x even after
  a wildcard is registered), so a caller-owned wildcard is deliberately not
  guarded: the exact parser is installed and, by exact-match precedence, takes
  urlencoded bodies in that scope away from that wildcard (a caller wanting
  wildcard-only semantics must register their own exact form parser, which IS
  detected and honored). It also adds a route-registration hook that clamps the
  later exact pairing POST to the lesser of its declared `bodyLimit` and the
  shared budget; a pairing POST registered before `registerOAuthRoutes` returns
  is not clamped — it still receives the form parser, but keeps its own route
  limit. JSON, form,
  and caller-parsed unknown media therefore cannot regain Fastify's larger
  default or widen the OAuth cap, while a caller's stricter route limit and
  existing exact-parser semantics remain intact. The hook does not alter other paths
  or methods. `addOAuthFormContentTypeParser` is idempotent for an inherited or
  existing exact form parser (a wildcard cannot be detected; see above) and
  remains exported with
  `OAUTH_POST_BODY_MAX_BYTES` for explicit custom composition. An over-cap
  request receives Fastify's direct 413 response before the pairing handler or
  Bridge runs.
- **Express OAuth POST body enforcement:** the returned Express router installs
  `express.json` and `express.urlencoded` with the shared limit, followed by a
  bounded raw fallback for every otherwise unmatched content type, scoped to
  the four built-in OAuth POST paths plus caller-owned POST `/oauth/authorize`
  before their handlers. The pairing path is parser-only when `skipAuthorize`
  is used: after bounded parsing it falls through to the caller's handler.
  These parsers do not
  consume unrelated routes mounted after the returned router. The fallback
  enforces the raw budget; it does not interpret an
  unsupported media type as OAuth fields. The router therefore admits the bounded
  core DCR domain and a consent form under the 192 KiB signer ceiling, while an
  over-cap body of any content type is rejected by Express before Bridge
  invocation with
  direct 413 `{error:"invalid_request",error_description:"Request body is too large"}`.
  Malformed JSON/form input is a direct sanitized 400 instead of Express's
  default development stack response/logging path. An application that mounts a
  different parser earlier on the same OAuth paths owns that parser's byte
  accounting and its own error responses — Express marks the body consumed, so
  the router's bounded parsers no longer see those bytes. What that parser
  produces is still subject to the shared media gate: an
  `express.json({ type: "text/plain" })` or
  `express.urlencoded({ type: "text/plain" })` mounted ahead of the router cannot
  turn a `text/plain` request into `redirect_uris` or a revocation `token`.
  Parsers for unrelated routes should be path-scoped. The `mcp-sso/express`
  subpath retains `EXPRESS_OAUTH_BODY_MAX_BYTES` as an exact compatibility alias
  of the shared `OAUTH_POST_BODY_MAX_BYTES` value.
- **Hono over-cap response and ordering:** a body-bound rejection is direct HTTP
  **413** with the fixed plain-text body `Payload Too Large`; it contains no raw
  request material, has no `Location`, and reveals nothing about token
  existence. Rejection precedes body parsing, Bridge and `RateLimitPort` calls,
  store writes, and success audits. The streaming implementation buffers at
  most the cap and never keeps the transport chunk that crosses it. A Fetch
  runtime may deliver that crossing chunk in a runtime-defined size (including
  when a test constructs one already-materialized oversized chunk); the adapter
  cannot retroactively bound a chunk allocated by the host, but it does not pass
  or retain that chunk for parsing. The middleware stops pulling after the
  crossing chunk; transport draining, cancellation, and upload timeouts remain
  host-server responsibilities. When Hono reconstructs the raw `Request`, the
  adapter preserves the original Request's own-property extensions. It does not
  copy prototype chains, subclass behavior, getters inherited from a prototype,
  or private runtime state. A `clientIp` implementation that needs such runtime
  context MUST read stable Hono `Context`/environment data rather than assuming
  raw Request identity survives body guarding.
- **Error → response:** an `OAuthError` with `.redirect` ⇒ **302** to the tagged
  `redirect_uri?error=…&iss=<issuer>`; otherwise direct — status `error.status`, body
  `oauthErrorBody(error)` (§9.5). On the protected `/mcp` surface, 401/403 set the
  `WWW-Authenticate` challenge from `buildUnauthorizedChallenge` (§8.2/§8.3).
  `Bridge.handleToken` performs normalized header/body extraction inside this
  error boundary, so a throwing accessor maps to the fixed `internal_error`
  response rather than escaping into framework-specific handling.
- **Header occurrence snapshot:** Fastify/Express `toNorm` calls
  `headersFromDistinct` with Node's `headersDistinct`; it never reconstructs a
  security header from the first normalized value. Fetch/Hono retains the
  platform's comma-coalesced scalar, which `readHeader` rejects for every
  header except `Cookie`. Repeated `Cookie` fields remain one logical
  semicolon-joined cookie-string. The same normalized snapshot supplies custom
  `identityHeader`, approve `Origin`, and token `Authorization` reads.
- **Authorize query occurrence snapshot:** Fastify, Express, and Hono preserve
  repeated authorize query members as arrays in `NormRequest.query` and pass
  them unchanged to their selected framework-free authorize entry point.
  `Bridge.handleAuthorize`, `handlePairingAuthorize`, and the upstream redirect
  flow use one shared pure duplicate check and one singleton-key definition;
  no adapter may select a first or last occurrence before that check.
- **OAuth form-body occurrence snapshot:** Fastify's URL-encoded parser and
  Hono's `toNorm` reconstruct `application/x-www-form-urlencoded` members with
  the same occurrence rules as `queryOccurrencesFromUrl` (single values stay
  strings; repeats become arrays; the record is null-prototype). Express
  `urlencoded({ extended: false })` already yields arrays for repeats. Each
  adapter records that exact parsed object separately on `NormRequest.formBody`
  only for the URL-encoded media type, so Bridge can distinguish repeated form
  occurrences from legitimate JSON arrays. For compatibility with custom
  adapters built against the earlier `NormRequest` shape, a framework-free
  form handler whose optional `formBody` is absent reconstructs the same
  decision from `body` plus the normalized `Content-Type`; omission therefore
  cannot bypass duplicate or ambiguous-header rejection. Supplying `formBody`
  also cannot bypass the header check: every framework-free form handler
  independently re-reads the normalized `Content-Type` occurrence before using
  either body snapshot. A duplicated, array-valued, case-duplicated, or
  comma-coalesced `Content-Type` is recorded as ambiguous and rejected as direct
  400 `invalid_request` rather than dropping provenance and trusting a
  framework-selected parser result. `handlePairingAuthorize`,
  `Bridge.handleApprove`, `Bridge.handleToken`, `Bridge.handleRevoke`, and
  `Bridge.handleRegister` reject recognized singleton-key multiplicity on the
  form snapshot; they must not see a first- or last-wins string. Pairing uses
  that checked snapshot for every subsequent field read rather than returning
  to the parser-selected `body`. The four Bridge
  POST routes charge their existing limiter first, then reject before field
  selection, grant routing, durable state, or endpoint audit. Charging the
  limiter has **two** failure outcomes and they are not the same response: a
  quota denial (`check` returns `false`) is the existing direct 429, while a
  limiter that *throws* reached no quota decision at all. Under §6.7 that throw
  is fail-open for approve, token, and revoke, and fails **closed** for
  `Bridge.handleRegister` when `dcr.mode === "stored"` — a fixed, sanitized 503
  emitted at the same point in the order, before field selection, durable state,
  or success audit, so an unavailable limiter cannot admit the anonymous durable
  write the §5 boot rule refuses to start without. Unknown form
  members remain ignored. Multipart remains outside this reconstruct (OAuth
  POSTs are URL-encoded).
- **Consent page *(fix #5)*:** GET `/oauth/authorize` success renders an HTML page
  with **Approve AND Deny** buttons; Deny POSTs `approved=false`, which the core
  redirects as `access_denied` (§9.3). CSP `default-src 'none'; style-src
  'unsafe-inline'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`,
  all values HTML-escaped. The page always displays the exact bound
  `redirect_uri`, including for opaque/stateless clients, before the decision
  buttons. This is display-only defense in depth; §10 validation remains the
  authorization control. **0.3.0 amendment:** the consent CSP omits
  `form-action`: Chromium applies that directive
  across the same-origin POST's redirect chain, so `'self'` blocks both the
  Approve and Deny 302 from reaching a validated loopback callback. The form
  action remains the literal `/oauth/authorize/approve`.
  `OAuthAuthorizationUseCase.approve` invokes `assertApproveOrigin`, verifies
  the signed consent state, and calls `assertOAuthRedirectEntry` to re-check
  the §10.0 entry grammar before producing the redirect URL. Mode-aware
  destination validation remains in `prepare` / `resolveAuthorizeClient` and
  is bound into that signed state. The pairing page is a separate surface whose
  same-origin form terminates in another bridge page; its CSP retains
  `form-action 'self'`.
  The page sends `Referrer-Policy: same-origin`, not `no-referrer`: this keeps a
  scheme/host/port `Origin` on the same-origin Approve POST for §9.3's unchanged
  strict check while suppressing the authorize query from cross-origin
  `Referer` headers. `assertApproveOrigin` remains exact: the value must equal
  the issuer origin or an `allowedOrigins` member; no automatic opaque-Origin
  exception or fallback is introduced, and §5 rejects `"null"` as configuration.
- Framework adapters are optional `peerDependencies` (`fastify`/`express`/`hono`);
  anything added to `devDependencies` for testing gets a `dependency-ledger` entry
  with the ordinary 15-day check or the verified published-advisory exception.
