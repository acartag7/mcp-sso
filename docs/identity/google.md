# Google identity (`createGoogleIdentity`)

Google is the [generic OIDC port](./generic-oidc.md) pinned to `https://accounts.google.com` + discovery, with Google-specific claim shaping: the **`hd` (hosted domain) claim** is checked when you restrict to a Workspace (never the email's domain), and **email is surfaced only when `email_verified === true`**. Subject = the stable Google `sub` (don't key on email, it can change). `clientSecret` is **required** (Google's token auth methods are secret-based).

Part of the [identity ports](./README.md) (shared authorization model + subject rules). The `GOOGLE_*` env vars are in [configuration.md](../configuration.md).

```ts
import { createGoogleRedirectIdentity } from "mcp-sso/identity/google";
import { createUpstreamRedirectFlow } from "mcp-sso";

const identity = await createGoogleRedirectIdentity({
  clientId: "<Google OAuth Client ID>",
  clientSecret: "<Google OAuth Client Secret>", // required
  redirectUri: "https://bridge.example.com/oauth/callback", // = issuerOrigin + callbackPath
  hostedDomain: "yourcompany.com", // optional: restrict to a Google Workspace (the hd claim)
  // subjectAllowlist: ["<google sub>"], // optional defense-in-depth
});
const flow = createUpstreamRedirectFlow({ bridge, identity, store, clock, audit, callbackPath: "/oauth/callback" });
```

`iss` is accepted **only** as `https://accounts.google.com` (the schemeless legacy `accounts.google.com` variant is rejected). Discovery is fetched at boot from `https://accounts.google.com/.well-known/openid-configuration` and its `issuer` must match. Google is the preset's only cross-host discovery exception: the authorization, token, and JWKS fields must use the exact fixed hosts `accounts.google.com`, `oauth2.googleapis.com`, and `www.googleapis.com` respectively. The preset accepts no sibling/suffix match and exposes no option to widen that map. Its generic-OIDC JWKS reader inherits the fixed 65536-byte default cap and five-minute cache. An oversized key set is an `exchange_failed` infrastructure failure, not an identity rejection.

## Set up a Google OAuth client (Google Cloud Console)

1. **Open the Console.** <https://console.cloud.google.com/> → pick your project (or create one).
2. **Configure the OAuth consent screen.** APIs & Services → **OAuth consent screen** → User type **External** (or **Internal** for a Workspace-only app). Add scopes `openid`, `.../auth/userinfo.email`, `.../auth/userinfo.profile`. If restricting to your Workspace, note the domain, that is your `hostedDomain`.
3. **Create credentials.** APIs & Services → **Credentials** → **Create Credentials** → **OAuth client ID**.
4. **Application type = Web application.** Name it (e.g. `mcp-bridge`).
5. **Authorized redirect URIs** = the bridge's callback URL, e.g. `https://bridge.example.com/oauth/callback`. (Add the exact URI. No wildcards.)
6. **Copy the Client ID + Client Secret** from the result dialog, these are `config.clientId` and `config.clientSecret`.

## `hostedDomain` (Google Workspace)

If you set `hostedDomain`, the `id_token`'s **`hd` claim** must equal it exactly. Check the claim, never the email's domain (the email can be attacker-controlled while the `hd` claim is Google-signed). Outcomes: a `hd` mismatch → `google_bad_hosted_domain`. A personal Google account (no `hd`) when `hostedDomain` is set → `google_missing_hosted_domain`. `hostedDomain` unset → `hd` is ignored.

## Verify the deployment

Run the checklist at the top of [`src/identity/google.ts`](../../src/identity/google.ts) after changing `hostedDomain`, `subjectAllowlist`, or the Google OAuth client. The [client compatibility reference](../client-compatibility.md) records the current live evidence: on 2026-08-27 the claude.ai connector, Claude Code, and Codex CLI each completed a Google sign-in at runtime commit `c9cec91`, and the first two went on to call a protected `/mcp`. The hosted-domain (`hd`) and `subjectAllowlist` rejections have only archived live evidence from July 2026 ([client compatibility archive](../archive/client-compatibility-2026-07.md)) plus the automated tests; rerun the checklist above before claiming them for a new release.
