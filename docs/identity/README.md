# Identity ports

mcp-sso keeps your existing identity provider as the source of truth and mints its **own** audience-bound tokens for MCP clients. Upstream IdP tokens are verified and then discarded, they never pass through to the client. Pick the port that matches the IdP you already run. Env-var wiring for every port is in [configuration.md](../configuration.md).

## Shipped identity options

| Identity option | Import | Guide | Shape |
|---|---|---|---|
| **Cloudflare Access** | `mcp-sso/identity/cloudflare-access` | [cloudflare-access.md](./cloudflare-access.md) | Header assertion (Access fronts `/oauth/authorize`) |
| **Microsoft Entra ID** | `mcp-sso/identity/entra` | [entra.md](./entra.md) | OIDC redirect flow (+ optional group → scope) |
| **Google** | `mcp-sso/identity/google` | [google.md](./google.md) | OIDC redirect flow (Workspace `hd` gate) |
| **Website session** | root `createUpstreamRedirectFlow` export | [website-login.md](./website-login.md) | Verified claims callback without MCP consent or tokens |
| **Generic OIDC** | `mcp-sso/identity/generic-oidc` | [generic-oidc.md](./generic-oidc.md) | Any OIDC provider (Keycloak, Okta, Auth0, Dex, …) |
| **Console pairing** | `mcp-sso/identity/console-pairing` | | Zero IdP setup. Local / single-operator only |

Not yet available: [**GitHub**](./github.md) (contract-locked. GitHub OAuth is not standard OIDC).

## Who is allowed: two gates

Every port follows the same authorization model (see [`authorization.md`](../authorization.md)):

1. The IdP is the primary gate. Cloudflare Access policy, Entra app assignment and Conditional Access, or the OIDC provider policy decides who can sign in. Cloudflare Access can block a denied user at the edge before the request reaches the gateway. For bridge completion through Entra, Google, or generic OIDC, an IdP denial reaches the callback. The callback audits `oauth.upstream.callback` with reason `upstream_denied`, redirects the MCP client with `access_denied`, and mints no bridge token. For claims-only completion, the callback returns the fixed direct 400 described in [Website login with verified identity claims](./website-login.md#website-login-with-verified-identity-claims).
2. The mcp-sso allowlist is optional defense in depth, not a replacement for IdP policy. Use `emailAllowlist` with Cloudflare Access. Use `subjectAllowlist` with Entra, Google, and generic OIDC. `subjectAllowlist` matches the immutable subject instead of email unless the deployment opts in to email matching. An empty allowlist delegates the decision to the IdP.

Blank config counts as missing config. The example's env wiring rejects blank required values (`mustEnv`) and selects each provider branch by *presence*, so a blank required env var fails the **boot** instead of silently falling back to console pairing. Factories also reject their security-critical blank required fields at construction (Cloudflare's `audience`. OIDC / Google's `clientId`, `issuer`, and `redirectUri`. Entra's `tenantId` and `clientId`). Callers still reject blank environment values before selecting a provider branch, as the example's `mustEnv` does.

## Subjects prefer the immutable identifier

- Cloudflare Access → `sub` (opaque UUID), falling back to `email` if `sub` is absent
- Entra → `oid`, falling back to `${acceptedIssuer}|${sub}`. Mutable username and email claims never key grants
- Google → the provider `sub` (raw, Google's `sub` is globally unique)
- generic OIDC → `${issuer}|${sub}` (the `sub` namespaced by issuer to defend against cross-issuer collisions. The allowlist still matches the raw `sub`)

Prefer the immutable subject for grants and audits. Do not key authorization on the email, it is mutable. Cloudflare Access retains its documented email fallback. Entra does not. Email handling differs by port: **Google** surfaces the email only when the provider marks it `email_verified`. **Cloudflare Access**, **Entra**, and **generic OIDC** surface the email claim as-is (generic OIDC applies the `email_verified` check only to optional allowlist *matching*, not to whether the email is surfaced).
