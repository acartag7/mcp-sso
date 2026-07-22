# Identity ports

mcp-sso keeps your existing identity provider as the source of truth and mints its
**own** audience-bound tokens for MCP clients. Upstream IdP tokens are verified and
then discarded — they never pass through to the client. Pick the port that matches
the IdP you already run. Env-var wiring for every port is in
[configuration.md](../configuration.md).

## Shipped ports

| Provider | Import | Guide | Shape |
|---|---|---|---|
| **Cloudflare Access** | `mcp-sso/identity/cloudflare-access` | [cloudflare-access.md](./cloudflare-access.md) | Header assertion (Access fronts `/oauth/authorize`) |
| **Microsoft Entra ID** | `mcp-sso/identity/entra` | [entra.md](./entra.md) | OIDC redirect flow (+ optional group → scope) |
| **Google** | `mcp-sso/identity/google` | [google.md](./google.md) | OIDC redirect flow (Workspace `hd` gate) |
| **Generic OIDC** | `mcp-sso/identity/generic-oidc` | [generic-oidc.md](./generic-oidc.md) | Any OIDC provider (Keycloak, Okta, Auth0, Dex, …) |
| **Console pairing** | `mcp-sso/identity/console-pairing` | — | Zero IdP setup; local / single-operator only |

Not yet available: [**GitHub**](./github.md) (contract-locked; GitHub OAuth is not
standard OIDC).

## Who is allowed — two gates

Every port follows the same authorization model (see
[`authorization.md`](../authorization.md)):

1. **The IdP is the primary gate.** Cloudflare Access policy, Entra app
   assignment / Conditional Access, or the OIDC provider's own policy decides who
   can sign in. With **Cloudflare Access** a denied user is blocked at the
   Cloudflare edge and never reaches the gateway. With the **redirect flow** (Entra
   / Google / generic OIDC) an IdP denial returns to the gateway's callback, which
   audits it (`oauth.upstream.callback`, reason `upstream_denied`) and redirects the
   client with `access_denied` — the denial reaches the callback, but no bridge
   token is minted.
2. **mcp-sso's allowlist is optional defense-in-depth**, never a replacement:
   `emailAllowlist` (Cloudflare) or `subjectAllowlist` (Entra / Google / generic
   OIDC — matched against the **immutable** subject, not the email, unless you
   opt in). An **empty** allowlist delegates the decision entirely to the IdP.

Blank config counts as missing config. The example's env wiring rejects blank
required values (`mustEnv`) and selects each provider branch by *presence*, so a
blank required env var fails the **boot** instead of silently falling back to
console pairing. Most factories also reject blank required fields at construction
(Cloudflare's `audience`; the OIDC / Google `clientId`, `issuer`, `redirectUri`).
The **Entra** factory is the exception — it does not non-empty-check `tenantId` /
`clientId`, so wire it through a caller that rejects blanks (as the example's
`mustEnv` does).

## Subjects prefer the immutable identifier

- Cloudflare Access → `sub` (opaque UUID), falling back to `email` if `sub` is absent
- Entra → `oid`, falling back to `preferred_username` / `email`
- Google → the provider `sub` (raw — Google's `sub` is globally unique)
- generic OIDC → `${issuer}|${sub}` (the `sub` namespaced by issuer to defend against
  cross-issuer collisions; the allowlist still matches the raw `sub`)

Prefer the immutable subject for grants and audits; do not key authorization on the
email — it is mutable, and for Cloudflare and Entra it is also the subject
*fallback*. Email handling differs by port: **Google** surfaces the email only when
the provider marks it `email_verified`; **Cloudflare Access**, **Entra**, and
**generic OIDC** surface the email claim as-is (generic OIDC applies the
`email_verified` check only to optional allowlist *matching*, not to whether the
email is surfaced).
