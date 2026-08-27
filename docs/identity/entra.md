# Microsoft Entra ID identity (`createEntraRedirectIdentity`)

Sign users in through **Microsoft Entra ID** (formerly Azure AD) using the redirect flow. mcp-sso runs the OIDC code exchange against Entra, verifies the `id_token`, then mints its **own** audience-bound ES256 token. The upstream Entra `id_token` is verified and discarded. Any upstream access/refresh token is discarded immediately, never stored, logged, audited, or forwarded.

```ts
import { createEntraRedirectIdentity } from "mcp-sso/identity/entra";

const identity = createEntraRedirectIdentity({
  tenantId:     process.env.ENTRA_TENANT_ID!,
  clientId:     process.env.ENTRA_CLIENT_ID!,
  clientSecret: process.env.ENTRA_CLIENT_SECRET, // omit for a public (PKCE-only) client
  redirectUri:  process.env.ENTRA_REDIRECT_URI!, // must equal issuerOrigin + callbackPath
  subjectAllowlist: [],                          // optional; exact oid or accepted issuer|sub
  // maxJwksDocumentBytes: 65536,                // default; integer [1024, 1048576]
}, { scopeCatalog: ["mcp:read", "mcp:write"] });
```

The [client compatibility reference](../client-compatibility.md) records current live evidence for Entra ID: the claude.ai and ChatGPT connectors completed their flows at runtime commit `c9cec91` on 2026-08-27, including one against a deployment configured with `OAUTH_DCR_MODE=stateless`. The no-group, no-mapped-group, and group-overage denials were verified at `d6143b3` on 2026-08-19 and are archived in the [verification archive](../archive/verification-history.md); the rehearsal now drives those three plus wrong-tenant and subject-allowlist unattended, and the next record run records that row. Until it does, wrong-tenant, subject-allowlist, and guest/B2B outcomes remain pending here.

There are two factories on `mcp-sso/identity/entra`:

- `createEntraRedirectIdentity`. The turnkey redirect port (the example wires it from `ENTRA_*` env). **Use this.**
- `createEntraIdentity`, lower-level primitives for hosts that drive the redirect dance themselves (or run header-driven mode).

## Entra setup

1. Register **one** app in the tenant (**App registrations**) for the bridge, a single app registration, not one per client.
2. Set the app's **redirect URI** = the bridge's Entra-callback URL = `originOf(OAUTH_ISSUER) + callbackPath`. Must be `https` in production, Entra refuses plain-`http` redirect URIs off loopback.
3. Enable **public-client PKCE** *or* create a **client secret** (`ENTRA_CLIENT_SECRET`). PKCE S256 is always used.
4. Consent the OIDC scopes `openid`, `profile`, `email`. The redirect port requests exactly `openid profile email`, **no `offline_access`** (the bridge discards the upstream token, so a long-lived upstream refresh token would violate least-grant).

For **group-based authorization** (optional, see below), also:

5. In the app manifest, set `groupMembershipClaims` to emit group **object IDs**, `ApplicationGroup` (direct membership. Avoids the >200-group overage for the mapping use case. Requires Entra P1) or `SecurityGroup` (transitive).
6. Use group **object-ID GUIDs** as mapping keys, **never display names**, display names are a spoof vector (anyone can create a duplicate-named group) and are rejected at boot.

## Configuration

| Env var | Maps to | Required | Notes |
|---|---|---|---|
| `ENTRA_TENANT_ID` | `tenantId` | **required**, presence selects the Entra branch | Builds the issuer/authorize/token/JWKS URLs. |
| `ENTRA_CLIENT_ID` | `clientId` | **required** | The `id_token` `aud` must equal this. |
| `ENTRA_CLIENT_SECRET` | `clientSecret` | optional | Omit for a public (PKCE-only) client. |
| `ENTRA_REDIRECT_URI` | `redirectUri` | **required** | Pathname becomes the mounted callback. The full URI must equal `originOf(OAUTH_ISSUER) + callbackPath`. |
| `ENTRA_ALLOWED_TENANT_IDS` | `allowedTenantIds` | optional | Comma-separated. Empty ⇒ single-tenant (only `tenantId`). |
| `ENTRA_SUBJECT_ALLOWLIST` | `subjectAllowlist` | optional | Comma-separated. Empty ⇒ delegated to Entra policy. |
| `ENTRA_GROUP_AUTHORIZATION_JSON` | `groupAuthorization` | optional | Complete JSON object with `mapping` and optional `baseScopes`. See below. |

Bridge signing material (`OAUTH_ISSUER`, `OAUTH_RESOURCE`, `OAUTH_CONSENT_SIGNING_SECRET`, `OAUTH_SIGNING_PRIVATE_JWK`, optional `OAUTH_SIGNING_KEY_ID`) is required and separate from the `ENTRA_*` identity env. Direct library callers may set `maxJwksDocumentBytes`. It defaults to 65536 and must be an integer in [1024, 1048576], or identity construction fails before jose can fetch. The shipped example currently uses the default.

The shipped examples accept the same group authorization object through one JSON env variable:

```sh
ENTRA_GROUP_AUTHORIZATION_JSON='{"mapping":{"00000000-0000-0000-0000-000000000001":["mcp:read"]},"baseScopes":[]}'
```

Use Entra group object IDs from your tenant in place of the placeholder GUID. When supplied, `mapping` is required and maps each group GUID to a non-empty scope array. `baseScopes` is optional. A blank value, malformed JSON, non-GUID key, invalid scope shape, or scope outside `OAUTH_SCOPE_CATALOG` rejects both example entry points before their state directory is created. The example parser only performs JSON parsing. `assertGroupAuthorizationMapping`, called by `createEntraRedirectIdentity`, enforces the mapping and catalog contract. Library consumers may continue passing `groupAuthorization` directly in code.

## Who is allowed

1. Entra app assignment / Conditional Access is the primary gate. Enforced by Entra, outside mcp-sso.
2. **`subjectAllowlist` is optional defense-in-depth.** It keeps trimmed, case-insensitive matching for `oid`. When no usable `oid` exists, accepted issuer + `"|"` + `sub` matches byte-for-byte. Raw `sub` does not match because it drops issuer namespacing. Matching the mutable `preferred_username` / `email` requires `allowMutableClaims: true`, Microsoft warns against using mutable claims for authorization. Only those mutable candidates are compared case-insensitively. Whitespace remains significant. That opt-in affects allowlist matching only. The stored grant subject is the exact usable non-blank `oid`, or, when no usable `oid` exists, the exact accepted issuer + `"|"` + the exact usable non-blank signature-verified `sub`. Username and email never select it.
3. **`groupAuthorization` (optional) maps Entra groups → a scope ceiling** (§17.4). Mapped/base scopes must be a subset of the `scopeCatalog`, validated at boot.

## Fail-closed behavior

Verified-context rejections return `identity_rejected` with a fixed reason. Bridge completion redirects the MCP client with `access_denied`. Claims-only completion deliberately collapses the rejection with IdP denial into the fixed direct 400 described in [Website login with verified identity claims](./website-login.md#website-login-with-verified-identity-claims):

| Condition | Reason code |
|---|---|
| Multi-tenant: `tid` not in `allowedTenantIds` | `entra_bad_tid` |
| Single-tenant: token from another tenant (`iss` is checked first) | `entra_bad_iss` |
| `iss` != the tenant issuer (multi-tenant, after `tid`) | `entra_bad_iss` |
| `aud` != `clientId` | `entra_bad_aud` |
| `nonce` mismatch | `entra_bad_nonce` |
| Missing, non-numeric, or non-finite `iat` | `entra_missing_iat` (pure validator) / `entra_bad_claim` (signed wrapper) |
| No `exp` | `entra_missing_exp` |
| Neither a usable non-blank string `oid` nor `sub` | `entra_no_subject` |
| Subject not in `subjectAllowlist` | `entra_subject_not_allowed` |
| >200 groups → overage marker present, groups omitted | `entra_groups_overage` |
| No groups claim + empty `baseScopes` | `entra_no_groups` |
| Groups present but none mapped + empty `baseScopes` | `entra_no_mapped_groups` |
| Expired / bad claim / bad alg / unknown key / other `jose` | `entra_token_expired` / `entra_bad_claim` / `entra_unsupported_alg` / `entra_unknown_key` / `entra_token_invalid` |

### Infrastructure and exchange failures

A token-exchange non-200 or timeout, a token response without `id_token`, or an unreachable, over-cap, or otherwise failed JWKS fetch is classified as `exchange_failed`. The JWKS failure reason is `entra_verify_failed`. These failures emit no `identity.verify` audit event because no identity decision was made. Bridge completion redirects the MCP client with `server_error`. Claims-only completion returns a generic direct 500.

The `entra_id_token_missing` reason applies only to the lower-level header-driven primitives path, where the caller passes a raw `id_token` to `verify()`. It does not apply to the redirect flow.

Malformed `groupAuthorization` config is a **boot** `AuthConfigError` (never a silent "no ceiling" default): a non-object `groupAuthorization`, a non-GUID mapping key, a duplicate case-insensitive key, an empty/non-single-token scope value, a scope outside the catalog, or a non-array `baseScopes`.

## Gotchas

- **`>200` groups fails closed** with `entra_groups_overage`, the overage `_claim_sources` URL is **never** dereferenced (it is data, not an instruction). Remedy: `groupMembershipClaims: ApplicationGroup` (Entra P1, direct membership only) or reduce group sprawl.
- **Group mapping keys must be GUIDs, not display names.** Display names can collide, so `createEntraIdentity` rejects them at boot.
- **`subjectAllowlist` keeps trimmed, case-insensitive `oid` matching.** Accepted issuer + `"|"` + `sub` matches byte-for-byte. Matching mutable claims requires `allowMutableClaims: true`. Only case is ignored, not whitespace. Mutable allowlist candidates never become the stored grant subject.
- **Existing no-`oid` deployments do not migrate mutable-key grants.** After the next full login, the issuer-namespaced `sub` is a new subject and the user may need to approve scopes again. Existing refresh families keep their old subject. Inactivity beyond the current refresh TTL expires them, but every successful rotation renews that TTL. Revoke legacy families for deterministic cutoff (or rely on replay-family revocation). Existing access tokens, codes, and in-flight consent retain their issued subject for their normal short lifetimes.
- **Refresh is not re-checked against the group ceiling** (there is no identity at refresh), group/role revocation takes effect at the next full authorize. Shorten `refreshTokenTtlSeconds` or revoke the family for faster revocation.
- **`response_mode` is locked to `query`.** A `form_post` callback would arrive cookie-less under the flow cookie's `SameSite=Lax` and must not be used.
- Header-driven mode is not replay-bound. mcp-sso never minted the nonce for a proxy-forwarded token. Only run header mode behind a proxy that itself did the nonce-bound exchange (the Cloudflare Access model). A custom `IdentityPort` must route raw tokens through the verifying wrapper (`verify` / `verifyEntraIdToken`), never the pure `validateEntraIdToken` (which validates `iss`/`aud`/`tid`/`nonce`/ finite `iat`/`exp` but **skips signature**).
- **The Entra token endpoint is deployer-trusted** (computed from `tenantId`, not discovered) with a 10 s timeout, deliberately not behind the §17.1 SSRF guard.

## Verify

Run the checklist at the top of `src/identity/entra.ts` against your tenant before relying on its assignments and group claims. The project verified `entra_no_groups`, `entra_no_mapped_groups`, and `entra_groups_overage` at runtime commit `d6143b3` on 2026-08-19. Your deployment still needs its own check because Entra controls which claims it emits.

- A **non-allowed tenant** user → `entra_bad_tid` (multi-tenant) or `entra_bad_iss` (single-tenant, the foreign `iss` is checked first).
- A **wrong subject** → `entra_subject_not_allowed`.
- (groups) A **group-overage** user → `entra_groups_overage`. A **no-mapped-groups** user → `entra_no_mapped_groups`.
- Confirm the bridge mints its **own** audience-bound token, the Entra `id_token` is verified then discarded.

> [!IMPORTANT]
> Wrong-tenant, subject-allowlist, and guest/B2B outcomes are not current verified rows. Test them in your tenant before relying on them. The [client compatibility reference](../client-compatibility.md) separates completed evidence from pending cases.

See [`authorization.md`](../authorization.md) for the IdP-gate vs mcp-sso-gate model and [§17.4](../contracts/17-v0-2-feature-contracts.md#174-entra-group-based-authorization-gate-2-becomes-a-scope-ceiling) / [§17.11](../contracts/17-v0-2-feature-contracts.md#1711-upstream-redirect-flow) for the group-ceiling and redirect-orchestrator contracts.
