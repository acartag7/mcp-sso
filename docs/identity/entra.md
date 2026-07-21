# Microsoft Entra ID identity (`createEntraRedirectIdentity`)

Sign users in through **Microsoft Entra ID** (formerly Azure AD) using the
redirect flow. mcp-sso runs the OIDC code exchange against Entra, verifies the
`id_token`, then mints its **own** audience-bound ES256 token. The upstream Entra
`id_token` is verified and discarded; any upstream access/refresh token is
discarded immediately — never stored, logged, audited, or forwarded.

```ts
import { createEntraRedirectIdentity } from "mcp-sso/identity/entra";

const identity = createEntraRedirectIdentity({
  tenantId:     process.env.ENTRA_TENANT_ID!,
  clientId:     process.env.ENTRA_CLIENT_ID!,
  clientSecret: process.env.ENTRA_CLIENT_SECRET, // omit for a public (PKCE-only) client
  redirectUri:  process.env.ENTRA_REDIRECT_URI!, // must equal issuerOrigin + callbackPath
  subjectAllowlist: [],                          // optional defense-in-depth (matches immutable oid)
}, { scopeCatalog: ["mcp:read", "mcp:write"] });
```

> **Live status:** happy path verified 2026-07-08 (Claude Code + Claude Desktop,
> real enterprise tenant). Production deny-path legs (wrong tenant, group overage,
> allowlist rejection) are covered by the unit suite but not yet driven live;
> claude.ai / ChatGPT Entra runs are not yet recorded.

There are two factories on `mcp-sso/identity/entra`:

- **`createEntraRedirectIdentity`** — the turnkey redirect port (the example wires
  it from `ENTRA_*` env). **Use this.**
- `createEntraIdentity` — lower-level primitives for hosts that drive the redirect
  dance themselves (or run header-driven mode).

## Entra setup

1. Register **one** app in the tenant (**App registrations**) for the bridge — a
   single app registration, not one per client.
2. Set the app's **redirect URI** = the bridge's Entra-callback URL =
   `originOf(OAUTH_ISSUER) + callbackPath`. Must be `https` in production — Entra
   refuses plain-`http` redirect URIs off loopback.
3. Enable **public-client PKCE** *or* create a **client secret**
   (`ENTRA_CLIENT_SECRET`). PKCE S256 is always used.
4. Consent the OIDC scopes `openid`, `profile`, `email`. The redirect port
   requests exactly `openid profile email` — **no `offline_access`** (the bridge
   discards the upstream token, so a long-lived upstream refresh token would
   violate least-grant).

For **group-based authorization** (optional, see below), additionally:

5. In the app manifest, set `groupMembershipClaims` to emit group **object IDs** —
   `ApplicationGroup` (direct membership; avoids the >200-group overage for the
   mapping use case; requires Entra P1) or `SecurityGroup` (transitive).
6. Use group **object-ID GUIDs** as mapping keys, **never display names** —
   display names are a spoof vector (anyone can create a duplicate-named group)
   and are rejected at boot.

## Configuration

| Env var | Maps to | Required | Notes |
|---|---|---|---|
| `ENTRA_TENANT_ID` | `tenantId` | **required** — presence selects the Entra branch | Builds the issuer/authorize/token/JWKS URLs. |
| `ENTRA_CLIENT_ID` | `clientId` | **required** | The `id_token` `aud` must equal this. |
| `ENTRA_CLIENT_SECRET` | `clientSecret` | optional | Omit for a public (PKCE-only) client. |
| `ENTRA_REDIRECT_URI` | `redirectUri` | **required** | Pathname becomes the mounted callback; the full URI must equal `originOf(OAUTH_ISSUER) + callbackPath`. |
| `ENTRA_ALLOWED_TENANT_IDS` | `allowedTenantIds` | optional | Comma-separated. Empty ⇒ single-tenant (only `tenantId`). |
| `ENTRA_SUBJECT_ALLOWLIST` | `subjectAllowlist` | optional | Comma-separated. Empty ⇒ delegated to Entra policy. |

Bridge signing material (`OAUTH_ISSUER`, `OAUTH_RESOURCE`,
`OAUTH_CONSENT_SIGNING_SECRET`, `OAUTH_SIGNING_PRIVATE_JWK`, optional
`OAUTH_SIGNING_KEY_ID`) is required and separate from the `ENTRA_*` identity env.

**Group authorization is programmatic-only.** `groupAuthorization` has no env
surface in the shipped example — pass it in code to the factory. When you supply
`groupAuthorization`, its `mapping` is **required** (an object keyed by group
GUID → scope); `baseScopes` is the optional nested field.

## Who is allowed

1. **Entra app assignment / Conditional Access is the primary gate** — enforced by
   Entra, outside mcp-sso.
2. **`subjectAllowlist` is optional defense-in-depth.** It matches the **immutable
   `oid`** by default (case-insensitive, trimmed). Matching the mutable
   `preferred_username` / `email` requires `allowMutableClaims: true` — Microsoft
   warns against using mutable claims for authorization. Subject is derived
   `oid ?? preferred_username ?? email`.
3. **`groupAuthorization` (optional) maps Entra groups → a scope ceiling** (§17.4).
   Mapped/base scopes must be a subset of the `scopeCatalog`, validated at boot.

## Fail-closed behavior

Verified-context rejections return `identity_rejected` (a 302 redirect with
`access_denied`) with a fixed reason:

| Condition | Reason code |
|---|---|
| `tid` not allowed (or `!= tenantId` single-tenant) | `entra_bad_tid` |
| `iss` != the tenant issuer | `entra_bad_iss` |
| `aud` != `clientId` | `entra_bad_aud` |
| `nonce` mismatch | `entra_bad_nonce` |
| No `exp` | `entra_missing_exp` |
| No `oid`/`preferred_username`/`email` to key the subject | `entra_no_subject` |
| Subject not in `subjectAllowlist` | `entra_subject_not_allowed` |
| >200 groups → overage marker present, groups omitted | `entra_groups_overage` |
| No groups claim + empty `baseScopes` | `entra_no_groups` |
| Groups present but none mapped + empty `baseScopes` | `entra_no_mapped_groups` |
| Missing raw `id_token` | `entra_id_token_missing` |
| Expired / bad claim / bad alg / unknown key / other `jose` | `entra_token_expired` / `entra_bad_claim` / `entra_unsupported_alg` / `entra_unknown_key` / `entra_token_invalid` |

**Infrastructure** failures (JWKS fetch timeout, token-exchange non-200) are
classified `exchange_failed` → a 302 `server_error`, and emit **no**
`identity.verify` audit event — no identity decision was made.

Malformed `groupAuthorization` config is a **boot** `AuthConfigError` (never a
silent "no ceiling" default): a non-object `groupAuthorization`, a non-GUID mapping
key, a duplicate case-insensitive key, an empty/non-single-token scope value, a
scope outside the catalog, or a non-array `baseScopes`.

## Gotchas

- **`>200` groups fails closed** with `entra_groups_overage` — the overage
  `_claim_sources` URL is **never** dereferenced (it is data, not an instruction).
  Remedy: `groupMembershipClaims: ApplicationGroup` (Entra P1, direct membership
  only) or reduce group sprawl.
- **Group mapping keys must be GUIDs, not display names** (spoof vector; boot-
  rejected).
- **`subjectAllowlist` matches the immutable `oid`** by default; matching mutable
  claims requires `allowMutableClaims: true`.
- **Refresh is not re-checked against the group ceiling** (there is no identity at
  refresh) — group/role revocation takes effect at the next full authorize. Shorten
  `refreshTokenTtlSeconds` or revoke the family for faster revocation.
- **`response_mode` is locked to `query`.** A `form_post` callback would arrive
  cookie-less under the flow cookie's `SameSite=Lax` and must not be used.
- **Header-driven mode is not replay-bound** — mcp-sso never minted the nonce for a
  proxy-forwarded token. Only run header mode behind a proxy that itself did the
  nonce-bound exchange (the Cloudflare Access model). A custom `IdentityPort` must
  route raw tokens through the verifying wrapper (`verify` / `verifyEntraIdToken`),
  never the pure `validateEntraIdToken` (which validates `iss`/`aud`/`tid`/`nonce`/
  `exp` but **skips signature**).
- **The Entra token endpoint is deployer-trusted** (computed from `tenantId`, not
  discovered) with a 10 s timeout — deliberately not behind the §17.1 SSRF guard.

## Verify

Run the checklist at the top of `src/identity/entra.ts` against a real tenant, and
confirm the deny legs before flipping the `live-verification.md` rows:

- A **non-allowed tenant** user → `entra_bad_tid`.
- A **wrong subject** → `entra_subject_not_allowed`.
- (groups) A **group-overage** user → `entra_groups_overage`; a **no-mapped-groups**
  user → `entra_no_mapped_groups`.
- Confirm the bridge mints its **own** audience-bound token — the Entra `id_token`
  is verified then discarded.

> **Guest / B2B users:** group-claim behavior for guests is unverified in
> Microsoft's docs — confirm a guest's membership resolves as expected before
> relying on group → scope for guests.

See [`authorization.md`](../authorization.md) for the IdP-gate vs mcp-sso-gate
model and [`contracts.md`](../contracts.md) §17.4 / §17.11 for the group-ceiling
and redirect-orchestrator contracts.
