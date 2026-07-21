# GitHub identity — not yet available

**There is no shipped GitHub identity port.** `mcp-sso/identity/github` does not
exist, and `createGitHubIdentity` is not implemented — importing either will fail.
The port is contract-locked (`contracts.md` §17.6) but not built.

## Why GitHub can't use the generic OIDC port

GitHub OAuth Apps are **not** standard OIDC:

- there is **no OIDC discovery document** (`/.well-known/openid-configuration`
  returns 404), and
- there is **no `id_token`**.

The shipped [`createGenericOidcIdentity`](./generic-oidc.md) (and the
[Google preset](./google.md)) verify an `id_token` against a discovered issuer, so
they structurally cannot serve GitHub. GitHub identity has to come from the REST
API (`GET /user`, `GET /user/emails`), which is why it needs its own dedicated
port rather than a preset — that work is planned, not done.

When it ships, the subject will key on the **numeric GitHub `id`** (stable), not
the mutable `login`.

## What to use today

Pick a shipped port instead:

- [**Cloudflare Access**](./cloudflare-access.md) — front sign-in with Cloudflare
  Zero Trust (which itself supports GitHub as an identity source).
- [**Microsoft Entra ID**](./entra.md)
- [**Google**](./google.md)
- [**Generic OIDC**](./generic-oidc.md) — any standards-compliant OIDC provider
  (Keycloak, Okta, Auth0, Dex, …).
- **Console pairing** — zero IdP setup, for local/single-operator use.

If you specifically need GitHub sign-in now, front the bridge with **Cloudflare
Access** or an **OIDC provider configured with GitHub as its upstream** (Keycloak,
Auth0, and Entra can all federate GitHub), and use the corresponding shipped port.
