# Identity ports

mcp-sso keeps your existing identity provider as the source of truth and mints its
**own** audience-bound tokens for MCP clients. Upstream IdP tokens are verified and
then discarded — they never pass through to the client. Pick the port that matches
the IdP you already run.

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
   can sign in. A denied user is stopped upstream and never reaches the gateway.
2. **mcp-sso's allowlist is optional defense-in-depth**, never a replacement:
   `emailAllowlist` (Cloudflare) or `subjectAllowlist` (Entra / Google / generic
   OIDC — matched against the **immutable** subject, not the email, unless you
   opt in). An **empty** allowlist delegates the decision entirely to the IdP.

Empty config counts as missing config: blank required identity values fail the
**boot**, never fall back to an unauthenticated or console-pairing default.

## Subjects are keyed on the immutable identifier

- Cloudflare Access → the opaque `sub` UUID
- Entra → `oid`
- Google / generic OIDC → the provider `sub`

Never key authorization on the email — it is mutable. Where a port surfaces an
email, it does so only when the provider marks it verified.
