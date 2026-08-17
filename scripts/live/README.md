# Live verification

Runnable evidence against **real** identity providers, as opposed to the
release matrix (`pnpm run test:release`), which runs on fixtures. Use these when
a release needs provider-backed proof, or when a client-facing flow changed.

Provider infrastructure is read from OpenTofu stack outputs at run time. The
Google client credentials are the documented out-of-band exception and come
from an owner-held JSON file. No deployment hostname, tenant, client id, or
secret is stored in this repository, and no secret is printed.

## Prerequisites

1. An authenticated cloud session for the infrastructure account (`aws sso login`).
2. The infrastructure repository checked out, with its path supplied through
   `MCP_SSO_INFRA_DIR`. Supply its opaque stack handles through
   `MCP_SSO_ENTRA_STACK` and `MCP_SSO_CLOUDFLARE_STACK`; no private repository
   path or stack name is stored here.
3. The Google leg needs OAuth credentials created out of band in Google Cloud
   Console because the stacks do not provision them. Put `GOOGLE_CLIENT_ID` and
   `GOOGLE_CLIENT_SECRET` as the only two string fields of a JSON object in a
   private mode-`0600` file at
   `~/.mcp-sso-google.env`, or point `MCP_SSO_GOOGLE_ENV` at an equivalent file.
   `run.sh` opens it with no-follow semantics, validates and reads through that
   same descriptor, and never executes or prints its contents. It rejects a
   missing path, symlink, non-owner file, any mode other than `0600`, malformed
   JSON, extra fields, or missing/empty credentials.

The Cloudflare stack supplies the Access application, per-leg hostnames, and
tunnel ports. The Entra stack supplies the tenant, application, group mapping,
and deny-leg fixtures: an unmapped group, a group-overage user, a no-group user,
and a cross-tenant guest.

## Probes — no browser required

```sh
scripts/live/run.sh scripts/live/probe-entra.mjs       entra
scripts/live/run.sh scripts/live/probe-cloudflare.mjs  cloudflare_access
scripts/live/run.sh scripts/live/probe-google.mjs      google
```

| Probe | What it proves |
| --- | --- |
| `probe-entra` | Real discovery and JWKS; DCR; authorize redirecting to the real tenant with the provisioned client, callback, scope, PKCE S256, state and nonce; flow cookie `__Host-` + `SameSite=Lax` + HttpOnly + Secure; the required unmapped-group fixture is driven through the shipped identity port with a verified signed control and must produce `entra_no_mapped_groups` |
| `probe-cloudflare` | Access certs resolve; a **self-signed assertion with the correct issuer and audience is refused against the live JWKS**, and the refusal does not echo the forged subject; RFC 9728 challenge; RFC 7009 always-200; duplicate form field, unsupported media type, and unlisted redirect origin all refused; state directory `0700` |
| `probe-google` | Google discovery and JWKS; lookalike issuer, wrong audience, and multi-audience refused; authorization, token, and JWKS endpoints each independently checked for host binding and HTTPS; missing PKCE S256 refused |

A leg argument is required because the example **boot-refuses more than one
identity selector** — that is a fail-closed gate, not a limitation.

## What these cannot cover

- Provider sign-in and consent (browser, by design)
- A provider-issued Entra token for the deny user. The headless signed control
  proves the configured fixture reaches the exact production denial; the real
  user association still needs the deployed browser flow.
- CIMD against a hosted metadata document — nothing serves one yet
