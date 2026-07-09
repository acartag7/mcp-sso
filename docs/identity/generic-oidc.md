# Generic OIDC identity (`createGenericOidcIdentity`)

`mcp-sso` can take the OAuth subject from **any** standards-compliant OIDC issuer
(Entra, Okta, Auth0, Keycloak, Dex, Google, your own). The bridge redirects the
user to the issuer (authorization-code + PKCE S256 + nonce), exchanges the code
for an `id_token`, validates it, and takes the subject from the stable `sub`
claim (keyed as `(issuer, sub)`). It then mints its **own** audience-bound
tokens — the upstream token is never forwarded.

> **Provider-specific presets:** for [Google](./google.md) use the dedicated
> preset (it adds the `hd` hosted-domain and `email_verified` gates). This guide
> is the generic port, parameterized for any OIDC issuer — a worked **Keycloak**
> example below, with callouts for where your provider's console differs.

## What gets validated (contracts §17.6)

The `id_token` is checked fail-closed: `iss` must **exactly** equal the
configured issuer; `aud` must contain your `clientId` and **multi-audience tokens
are rejected**; `exp` **and** `iat` must be present (jose checks their values via
the clock); algorithms are pinned to `{RS256, ES256}` ∩ the issuer's advertised
set; the **nonce is always sent and verified**; `at_hash` is validated when
present (code flow). Subject = `sub`. An optional `subjectAllowlist` matches
`sub` (and, with `allowEmailAllowlist`, a verified email).

## Config

```ts
import { createGenericOidcRedirectIdentity } from "mcp-sso/identity/generic-oidc";
import { createUpstreamRedirectFlow } from "mcp-sso";

const identity = await createGenericOidcRedirectIdentity({
  issuer: "https://kc.example.com/realms/myrealm", // https — the exact-match anchor
  clientId: "mcp-bridge",
  clientSecret: "••••",          // omit for a public client (PKCE only)
  redirectUri: "https://bridge.example.com/oauth/callback", // = issuerOrigin + callbackPath
  endpoints: "discover",         // or { authorizationEndpoint, tokenEndpoint, jwksUri } (no fetch)
  scopes: "openid profile email", // default
  subjectAllowlist: ["<stable sub>"], // optional defense-in-depth
  // allowEmailAllowlist: true,  // also match a verified email against subjectAllowlist
  // allowProviderWithoutPkce: true, // only if your issuer omits PKCE (loud)
});
const flow = createUpstreamRedirectFlow({ bridge, identity, store, clock, audit, callbackPath: "/oauth/callback" });
```

- **`endpoints: "discover"`** (recommended) — the OIDC discovery document is
  fetched once at boot from `${issuer}/.well-known/openid-configuration`. The
  document's `issuer` MUST exactly equal your configured `issuer` (else boot
  fails). Redirects are not followed. This is plain https, not the CIMD SSRF
  guard — the issuer is deployer-trusted config.
- **`endpoints: { … }`** (manual) — supply the three endpoints directly; no
  boot-time fetch. Each must still be `https://`.
- **PKCE** — always S256. If discovery does not advertise
  `code_challenge_methods_supported` containing `S256`, boot **fails** unless you
  set `allowProviderWithoutPkce: true` (it then proceeds with a loud warning;
  state + nonce + client secret still bind the flow). Prefer an issuer that
  supports PKCE.
- **`redirectUri`** must equal the bridge issuer origin + the callback path
  (e.g. `https://bridge.example.com` + `/oauth/callback`); `createUpstreamRedirectFlow`
  boot-asserts this — a mismatch is silent breakage at the IdP.

## Worked example: Keycloak

The console paths below are the Keycloak admin UI; Okta/Auth0/Dex have
equivalent screens ("Application", "Application URL", "Credentials",
"Endpoints"/"Metadata URL").

1. **Create a client.** Keycloak admin → your realm → **Clients** → **Create
   client**. Client type = **OpenID Connect**; Client ID = `mcp-bridge` (your
   `clientId`). Next.
2. **Client authentication = ON** (a confidential client with a secret) **OR**
   OFF (a public client using PKCE — then omit `clientSecret`). Save.
3. **Valid redirect URIs** = the bridge's callback URL, e.g.
   `https://bridge.example.com/oauth/callback`. (Keycloak accepts exact URIs;
   do not use a wildcard in production.) Under **Web origins** add the bridge
   origin if you front with a browser consent flow.
4. **Get the secret** (confidential client): client → **Credentials** tab →
   **Client secret** → copy (this is `clientSecret`).
5. **Confirm the endpoints.** Realm settings → **Endpoints** → **OpenID Endpoint
   Configuration** — that URL is `${issuer}/.well-known/openid-configuration`;
   the `issuer` shown there is what you put in `config.issuer` (exact match).
   With `endpoints: "discover"` you do not need the individual endpoint URLs —
   they are read from the document at boot.
6. **Scopes:** the default `openid profile email` is enough; the bridge issues
   its own audience-bound tokens and does not use an upstream refresh token.

## Live verification (the manual checklist)

Before claiming the generic port works end-to-end against a real issuer, run the
checklist at the top of [`src/identity/generic-oidc.ts`](../../src/identity/generic-oidc.ts):
register → sign in → confirm the resolved subject is the stable `sub` (not the
email) and the bridge mints its **own** token → negative tests (a multi-audience
`id_token` is rejected; a subject not in the allowlist is rejected; a bad
`iss`/`nonce`/`at_hash` is rejected). A README/live-verification conformance row
is added only after a real live pass.
