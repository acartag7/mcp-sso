# Live verification

Runnable evidence against **real** identity providers, as opposed to the
release matrix (`pnpm run test:release`), which runs on fixtures. Use these when
a release needs provider-backed proof, or when a client-facing flow changed.

Everything here reads its configuration from OpenTofu stack outputs at run time.
No hostname, tenant, client id, or secret is stored in this repository, and no
secret is printed.

## Prerequisites

1. An authenticated cloud session for the infrastructure account (`aws sso login`).
2. The infrastructure repository checked out, with its path supplied through
   `MCP_SSO_INFRA_DIR`. Supply its opaque stack handles through
   `MCP_SSO_ENTRA_STACK` and `MCP_SSO_CLOUDFLARE_STACK`; no private repository
   path or stack name is stored here.
3. The Google leg needs OAuth credentials created out of band in Google Cloud
   Console because the stacks do not provision them. Put `GOOGLE_CLIENT_ID` and
   `GOOGLE_CLIENT_SECRET` in a private mode-`0600` file at
   `~/.mcp-sso-google.env`, or point `MCP_SSO_GOOGLE_ENV` at an equivalent file.
   `run.sh` sources it only for the Google leg and never prints its contents.

The Cloudflare stack supplies the Access application, per-leg hostnames, and
tunnel ports. The Entra stack supplies the tenant, application, group mapping,
and deny-leg fixtures: an unmapped group, a group-overage user, a no-group user,
and a cross-tenant guest.

## Probes — no browser required

```sh
scripts/live/run.sh scripts/live/probe-entra.mjs       entra
scripts/live/run.sh scripts/live/probe-cloudflare.mjs  cloudflare_access
scripts/live/run.sh scripts/live/probe-e2e.mjs         entra     # needs REDIS_URL
node scripts/live/probe-google.mjs                               # standalone
```

| Probe | What it proves |
| --- | --- |
| `probe-entra` | Real discovery and JWKS; DCR; authorize redirecting to the real tenant with the provisioned client, callback, scope, PKCE S256, state and nonce; flow cookie `__Host-` + `SameSite=Lax` + HttpOnly + Secure; the group mapping accepted with real GUIDs and the deny-leg group excluded from it |
| `probe-cloudflare` | Access certs resolve; a **self-signed assertion with the correct issuer and audience is refused against the live JWKS**, and the refusal does not echo the forged subject; RFC 9728 challenge; RFC 7009 always-200; duplicate form field, unsupported media type, and unlisted redirect origin all refused; state directory `0700` |
| `probe-e2e` | Machine credential provisioned into a process-local `MachineClientStore`, exchanged through the shipped token route, and used against a protected `/mcp`, with a real Redis limiter refusing past budget and both audit sinks receiving identical event counts and no credential. The separately opened persistent SQLite store proves filesystem admission only; the shipped SQLite adapter deliberately does not implement the atomic machine-client lifecycle. |
| `probe-google` | Google discovery and JWKS; lookalike issuer, wrong audience, and multi-audience refused; discovery-host binding, non-https endpoints, and missing PKCE S256 all refused |

A leg argument is required because the example **boot-refuses more than one
identity selector** — that is a fail-closed gate, not a limitation.

## What these cannot cover

- Provider sign-in and consent (browser, by design)
- Entra group deny and ceiling reason codes, which need the deployed gateway
  because the provider redirects to the public hostname after login
- CIMD against a hosted metadata document — nothing serves one yet
