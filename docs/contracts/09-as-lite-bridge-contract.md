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

## 9.2 DCR — `registerClient` (RFC 7591) *(fix #4; RC item (b))*
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

## 9.3 Authorize + consent

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
- **0.3.0 finite-clock gate:** before consent-token processing and before
  `assertApproveOrigin`, `OAuthAuthorizationUseCase.approve` takes the §6.1
  validated snapshot with the larger approval-owned TTL offset and reuses it
  for verification,
  approval-owned expiry/store timestamps, and
  `oauth.authorize.approve.occurredAt`. An invalid initial snapshot takes
  precedence over an invalid Origin and returns the existing direct
  `invalid_consent` 400 with no fabricated audit timestamp.
- **CSRF/`origin`** must be exactly one primitive string equal to the issuer
  origin or a member of `allowedOrigins` — else `invalid_origin` 403 **direct**
  (a foreign origin is never redirected anywhere). `Bridge.handleApprove`
  reads the normalized `NormRequest.headers` through `headerString`; an
  array-valued header or more than one case-insensitive `Origin` key becomes
  absent and fails closed rather than selecting one value. Fastify and Express
  build that normalized snapshot with `headersFromDistinct` from Node's
  `headersDistinct`, preserving every on-wire occurrence. Fetch/Hono exposes
  duplicates comma-coalesced; `readHeader` treats a comma in a non-`Cookie`
  header as ambiguous before `Bridge.handleApprove` calls the core.
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

## 9.4 Token
`POST /oauth/token`, `cache-control: no-store`. Response:
`{ access_token, token_type: "Bearer", expires_in, refresh_token, scope }`.
*(This is the USER-grant shape — `UserTokenResponse`, returned by
`exchangeAuthorizationCode`/`refresh`/device. The `client_credentials` grant
(§17.2, shipped S3b) returns `MachineTokenResponse`: identical except it has NO
`refresh_token` member at all — not an optional one.)*
- **`exchangeAuthorizationCode`**: consumes the code (§7.3), verifies PKCE S256
  and client/redirect binding, then `tokenResponse` parses the stored scopes and
  constructs the signed access/refresh response before `saveRefreshToken`
  persists the new family. A preparation failure leaves no refresh row; the
  already-consumed authorization code stays burned. **0.3.2:** in
  stored-DCR mode, generation mismatch is the first stored-record
  validity check and is indistinguishable from any other `invalid_grant`; the
  new refresh family inherits the accepted code generation.
- **`refresh`**: atomically rotates the refresh token (§7.4), preserving
  consumed-token replay detection and whole-family revocation; then enforces RFC
  6749 §6 client binding (mismatch ⇒ family revoked ⇒ `invalid_grant`) and mints
  a new access token carrying the rotated record's scopes. After a successful
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
- **`revoke`** (RFC 7009): **always returns 200**; an unknown or already-revoked
  token is a **no-op** (never 4xx — RFC 7009 §2.2 forbids leaking token existence
  via the response). Looks up the family by hash and revokes it; a guessed family
  id revokes nothing.
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

## 9.6 Framework adapters *(Phase 3 — thin wiring)*
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
- **Direct-authorize ordering:** the header-identity GET `/oauth/authorize`
  path calls `Bridge.resolveIdentity`, which checks
  `RateLimitPort("authorize:<ip>")` before `IdentityPort.verify`, its audit, or
  `prepare`. Limiter denial is a direct 429 with no redirect; limiter failure
  remains fail-open (§6.7). Upstream redirect, console pairing, and CIMD retain
  their independent budgets rather than receiving a second adapter-level check.
- **Error → response:** an `OAuthError` with `.redirect` ⇒ **302** to the tagged
  `redirect_uri?error=…`; otherwise direct — status `error.status`, body
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
- **Consent page *(fix #5)*:** GET `/oauth/authorize` success renders an HTML page
  with **Approve AND Deny** buttons; Deny POSTs `approved=false`, which the core
  redirects as `access_denied` (§9.3). CSP `default-src 'none'; style-src
  'unsafe-inline'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`,
  all values HTML-escaped. **0.3.0 amendment:** the consent CSP omits
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
  exception or fallback is introduced.
- Framework adapters are optional `peerDependencies` (`fastify`/`express`/`hono`);
  anything added to `devDependencies` for testing gets a `dependency-ledger` entry
  with the 15-day check.

## 9.7 Multi-resource request and metadata behavior (PENDING 0.4.0)

> **NOT ENFORCED at this commit.**

- Authorization and token requests accept exactly one primitive-string
  `resource`. Repeated/array, malformed, or unknown values are
  `invalid_target`. Omission resolves only when the normalized catalog has one
  entry; it is `invalid_target` with two or more entries. Every adapter
  preserves repeated query/form occurrences into the normalized request; no
  framework may collapse duplicate `resource` parameters to first/last wins.
- The resolved immutable `ResourceDefinition` supplies defaults and scope
  validation through consent, approval, code exchange, refresh, and
  `client_credentials`. Approval re-resolves the signed resource against the
  current catalog before saving a code.
- Consent and authorization codes retain one resource. Refresh and machine
  lineage follow §§6–7/12. A token-endpoint resource must equal stored lineage;
  mismatch writes no successor and mints no token. Code mismatch burns the
  one-time code but saves no refresh token.
- Prior grants are keyed by subject, client, resource, and generation. The same
  scope string at A is not evidence at B. `IdentityPort.allowedScopes` remains
  a generic ceiling intersected with the selected resource catalog; no
  resource policy callback is added.
- Authorization-server metadata publishes the sorted de-duplicated union of
  all resource scope catalogs. It does not publish `protected_resources`:
  that name is not standard MCP/OAuth metadata and no concrete consumer
  requires an mcp-sso-specific extension. One PRM document contains only its
  exact resource, issuer, and resource-owned scopes.
- The canonical PRM URL inserts
  `/.well-known/oauth-protected-resource` between resource origin and path. A
  challenge uses that path-inserted URL for its pinned resource.
- Each adapter mount may select a non-empty `protectedResources` subset of the
  bridge catalog. Omission selects all resources for a same-origin,
  distinct-path deployment; one resource per mount supports subdomains that
  reuse a pathname. Before the first framework side effect, the adapter
  canonicalizes and resolves the whole subset, computes each exact route
  pathname from `protectedResourceMetadataUrl(resource).pathname`, and rejects
  duplicate pathnames with `AuthConfigError` naming the pathname and both
  resources. `/path` and `/path/` remain distinct; equal paths on different
  origins still collide within one mount and require separate one-resource
  mounts. The root fallback is registered only for a one-resource mount or an
  exact origin-root resource; it never guesses among path resources. Fastify,
  Express, and Hono share this rule.

The config snapshot is immutable for one bridge instance. Restarting with a
changed catalog has explicit non-revocation semantics:

- Omitting a resource from the next instance removes its adapter routes and
  PRM, makes new requests for it `invalid_target`, and prevents a new
  authorizer from being constructed for it. Persisted resource-bound refresh
  and machine records are retained. Already-signed access tokens are stateless
  and are not revoked by the config change.
- Re-adding the same canonical URL means restoring the same security resource,
  not creating a new generation. An unexpired access token may verify again,
  and already-bound refresh or machine credentials may resume. Null pre-0.4
  state resumes only under the matching `legacySingletonResource` attestation;
  it is never inferred from a replacement URL. A clean replacement uses a
  different canonical resource URL, leaving bound credentials attached to the
  retired URL. Reusing the same URL with a clean slate additionally requires an
  operator-managed purge/revocation of its refresh and machine state plus
  keeping the endpoint absent for at least the maximum access-token lifetime;
  0.4.0 has no resource-generation reset operation.
- Moving from multi-resource config back to singleton resumes already-bound
  state only for the selected canonical resource. State bound to every other
  former resource remains mismatched and cannot be selected; null pre-0.4 state
  still requires the matching explicit attestation.
- Narrowing a resource's scope catalog is not retroactive for already-signed
  access tokens; they expire normally. Pending consent is rejected if its
  resource is absent (`invalid_target`) or any signed scope is no longer
  configured (`invalid_scope`), with no code saved. Existing codes and refresh
  families whose stored scopes are no longer a subset of the current catalog
  are `invalid_grant`. Machine issuance rejects a removed requested or implicit
  ceiling scope with `invalid_scope`; a request for a still-current subset may
  continue.

Multi-resource support does not combine tools from several resources into one
MCP endpoint, dynamically route one MCP connection between resources, or let
one connection, consent, grant, refresh family, machine credential, or access
token span resources. Backend routing and outbound MCP OAuth-client behavior
remain application responsibilities.
