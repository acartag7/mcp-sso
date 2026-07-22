# Configuration reference

mcp-sso's **library** core is configured programmatically with
`createBridgeConfig({ … })` (see [`contracts.md`](contracts.md) §5). The env vars
below are how the **runnable examples** (`examples/fastify-sqlite`,
`examples/api-key-gateway`) wire that config — copy this shape into your own
composition root, or use it as-is with the examples.

Copy [`.env.example`](../.env.example) and fill in one identity provider.

## How the identity provider is selected

The example picks a branch by the **presence** of a selector var (not its value):
`CF_ACCESS_AUDIENCE`, `ENTRA_TENANT_ID`, `GOOGLE_CLIENT_ID`, or `OIDC_ISSUER`. A
**blank** selector still selects that branch and then **fails the boot** — it
never silently falls back to console pairing. If none is set, the example uses
console pairing (local, zero IdP setup).

## Bridge (`OAUTH_*`) — required for any real identity branch

| Var | Req | Default | Purpose |
|---|---|---|---|
| `OAUTH_ISSUER` | required | — | The bridge's public HTTPS origin (e.g. `https://mcp.example.com`). |
| `OAUTH_RESOURCE` | required | — | RFC 9728 resource identifier — your protected `/mcp` URL. |
| `OAUTH_CONSENT_SIGNING_SECRET` | required 🔒 | — | HS256 secret for consent + upstream-flow tokens (≥32 chars). |
| `OAUTH_SIGNING_PRIVATE_JWK` | required 🔒 | — | ES256 access-token signing key, as a JSON JWK. |
| `OAUTH_SIGNING_KEY_ID` | optional | — | `kid` for the signing JWK. |
| `OAUTH_REDIRECT_ALLOWLIST` | optional | empty | Comma-separated client redirect URIs (DCR/consent). |
| `OAUTH_SCOPE_CATALOG` | optional | `mcp:read,mcp:write` | The scopes clients may request. |
| `OAUTH_DEFAULT_SCOPES` | optional | `mcp:read` | Scopes granted when none requested. |
| `OAUTH_ALLOWED_ORIGINS` | optional | `OAUTH_ISSUER` | Comma-separated Origin allowlist for the `/mcp` DNS-rebinding gate (add your browser clients, e.g. `https://claude.ai`). |
| `OAUTH_ALLOW_INSECURE_LOCALHOST` | optional 🔒 | `false` | `true` permits an `http://` loopback issuer — **dev only**, never in production. |
| `OAUTH_SQLITE_FILE` | optional | `<MCP_SSO_DIR>/auth.db` | sqlite store path. |

> 🔒 = secret. Deliver via a secret manager or mounted file, never `docker run -e`
> in shell history, and never commit a populated `.env`. The quickstart
> file-based secret helper is for local/console-pairing use, not production pods.

## Cloudflare Access (`CF_ACCESS_*`)

| Var | Req | Purpose |
|---|---|---|
| `CF_ACCESS_AUDIENCE` | required (selects CF) | The app's hex **AUD tag** (not the hostname). |
| `CF_ACCESS_CERTS_URL` | required | `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`. |
| `CF_ACCESS_ISSUER` | required | `https://<team>.cloudflareaccess.com` (**no trailing slash**). |
| `CF_ACCESS_EMAIL_ALLOWLIST` | optional | Comma-separated defense-in-depth email allowlist; empty ⇒ delegated to the CF Access policy. |

See [`identity/cloudflare-access.md`](identity/cloudflare-access.md).

## Microsoft Entra ID (`ENTRA_*`)

| Var | Req | Purpose |
|---|---|---|
| `ENTRA_TENANT_ID` | required (selects Entra) | Tenant id (builds the issuer/JWKS/token URLs). |
| `ENTRA_CLIENT_ID` | required | App registration client id (the id_token `aud`). |
| `ENTRA_CLIENT_SECRET` | optional 🔒 | Omit for a public (PKCE-only) client. |
| `ENTRA_REDIRECT_URI` | required | Must equal `OAUTH_ISSUER` origin + the callback path. |
| `ENTRA_ALLOWED_TENANT_IDS` | optional | Comma-separated multi-tenant allowlist; empty ⇒ single-tenant. |
| `ENTRA_SUBJECT_ALLOWLIST` | optional | Comma-separated defense-in-depth `oid` allowlist. |

See [`identity/entra.md`](identity/entra.md).

## Google (`GOOGLE_*`)

| Var | Req | Purpose |
|---|---|---|
| `GOOGLE_CLIENT_ID` | required (selects Google) | OAuth client id. |
| `GOOGLE_CLIENT_SECRET` | required 🔒 | Google's token auth is secret-based. |
| `GOOGLE_REDIRECT_URI` | required | Must equal `OAUTH_ISSUER` origin + the callback path. |
| `GOOGLE_HOSTED_DOMAIN` | optional | Workspace restriction, checked against the signed `hd` claim. |
| `GOOGLE_SUBJECT_ALLOWLIST` | optional | Comma-separated defense-in-depth `sub` allowlist. |
| `GOOGLE_ALLOW_EMAIL_ALLOWLIST` | optional | `true`/`false` — also match a verified email against the allowlist. |

See [`identity/google.md`](identity/google.md).

## Generic OIDC (`OIDC_*`)

| Var | Req | Purpose |
|---|---|---|
| `OIDC_ISSUER` | required (selects OIDC) | The OIDC issuer (exact-match anchor; discovery fetched at boot). |
| `OIDC_CLIENT_ID` | required | Client id. |
| `OIDC_CLIENT_SECRET` | optional 🔒 | Omit for a public (PKCE-only) client. |
| `OIDC_REDIRECT_URI` | required | Must equal `OAUTH_ISSUER` origin + the callback path. |
| `OIDC_SCOPES` | optional | Upstream scopes; default `openid profile email`. |
| `OIDC_SUBJECT_ALLOWLIST` | optional | Comma-separated defense-in-depth `sub` allowlist. |

See [`identity/generic-oidc.md`](identity/generic-oidc.md).

## Runtime

| Var | Req | Default | Purpose |
|---|---|---|---|
| `MCP_SSO_DIR` | optional | `./.mcp-sso` | State directory (sqlite + audit + quickstart secrets). |
| `PORT` | optional | `3000` | Listen port. |
| `HOST` | optional | by mode | Console pairing binds loopback; a real identity binds `0.0.0.0`. Override here. |

## api-key-gateway example (`BACKEND_*`)

Only for [`examples/api-key-gateway`](../examples/api-key-gateway) (SSO in front of
a token-only backend):

| Var | Req | Default | Purpose |
|---|---|---|---|
| `BACKEND_API_KEY` | required 🔒 | — | The static credential the gateway injects server-side for the backend MCP (the client never sees it). |
| `BACKEND_HOST` | optional | `127.0.0.1` | Backend MCP host. |
| `BACKEND_PORT` | optional | `8788` | Backend MCP port. |
