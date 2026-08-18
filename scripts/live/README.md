# Live verification

Runnable evidence against **real** identity providers, as opposed to the
release matrix (`pnpm run test:release`), which runs on fixtures. Use these when
a release needs provider-backed proof, or when a client-facing flow changed.

Everything here reads its configuration from OpenTofu stack outputs at run time
through `run.sh`. No hostname, tenant, client id, or secret is stored in this
repository, and no probe writes a credential or provider identifier to output.

## Prerequisites

1. An authenticated cloud session for the infrastructure account
   (`aws sso login`; the Entra stack additionally needs `az login`).
2. The infrastructure repository checked out, with its path supplied through
   `MCP_SSO_INFRA_DIR` and its opaque stack handles through `MCP_SSO_ENTRA_STACK`
   and `MCP_SSO_CLOUDFLARE_STACK`. No private repository path or stack name is
   stored here.
3. `cloudflared`, `curl`, and `lsof` on `PATH` for `serve.sh`, with the tunnel
   UUID supplied through `MCP_SSO_TUNNEL` (its credentials file must exist at
   `~/.cloudflared/<uuid>.json`). `cloudflared` is also how the Cloudflare
   probe obtains its Access assertion — see below.
4. The Google leg needs OAuth credentials created out of band in Google Cloud
   Console because the stacks do not provision them. Put them in a private
   file at `~/.mcp-sso-google.env`, or point `MCP_SSO_GOOGLE_ENV` at one:

   ```
   GOOGLE_CLIENT_ID=<client id>
   GOOGLE_CLIENT_SECRET=<client secret>      # or OIDC_CLIENT_SECRET=<client secret>
   ```

   `KEY=VALUE` lines only (comments with `#`, no `export`, no quotes or
   whitespace in values, no other keys). The file must be a regular file owned by you with **no group or
   other permission bits** (`chmod 600`). `run.sh` opens it once without
   following symlinks, checks those properties on that same descriptor, and
   parses it as data — it is never sourced and never printed. A file that fails
   any of these checks stops the run before any provider I/O.
5. A Redis for `probe-e2e.mjs`, supplied through `REDIS_URL` (a local
   `docker run --rm -p 127.0.0.1:6379:6379 redis:7-alpine` is enough).

The Cloudflare stack supplies the Access application, per-leg hostnames, and
tunnel ports. The Entra stack supplies the tenant, application, group mapping,
and deny-leg fixtures: an unmapped group, a group-overage user, a no-group user,
and a cross-tenant guest.

## The runner

```sh
scripts/live/run.sh <entry> <leg>
```

`run.sh` reads the selected leg's values from the stacks, validates every one of
them through the shipped constructors (`scripts/live/run-support.mjs` runs the
example's own config parser and the leg's identity constructor over the exact
environment it assembled), generates fresh signing material for the run, and
only then executes the entry. It accepts these pairs and nothing else, so stack
credentials are only ever exported into an allowlisted script:

| Entry | Legs |
| --- | --- |
| `scripts/live/probe-entra.mjs` | `entra` |
| `scripts/live/probe-cloudflare.mjs` | `cloudflare_access` |
| `scripts/live/probe-google.mjs` | `google` |
| `scripts/live/probe-e2e.mjs` | any (needs `REDIS_URL`) |
| `examples/fastify-sqlite/index.ts` | any (what `serve.sh` starts) |

Before it reads anything it clears every inherited `ENTRA_*`, `CF_ACCESS_*`,
`GOOGLE_*`, `OIDC_*`, `OAUTH_*`, and `PROBE_*` variable, so a stale selector or
allowlist override in your shell cannot select a leg or reshape the run. Stored
DCR with the loopback origins allowlisted is the default (`MCP_SSO_ALLOW_LOOPBACK=false`
drops loopback; `MCP_SSO_DCR_MODE=stateless` switches mode).

Only the example-server entry gets a state directory, `.live-state/<leg>` in
this checkout (ignored by Git). `run-support.mjs` refuses a `.live-state` that
is a symlink or that anyone else can read, removes the previous leg state only
after the stack outputs have passed the preflight, and stops when that removal
fails — so a bad output never costs the previous run's evidence and nothing is
ever deleted through a link. The probes never touch `.live-state`; each builds
the example from a disposable temp directory the library creates and removes it
on every exit path.

## Probes — no browser required

```sh
scripts/live/run.sh scripts/live/probe-entra.mjs       entra
scripts/live/run.sh scripts/live/probe-google.mjs      google
scripts/live/run.sh scripts/live/probe-cloudflare.mjs  cloudflare_access
REDIS_URL=redis://127.0.0.1:6379 scripts/live/run.sh scripts/live/probe-e2e.mjs entra
```

| Probe | What it proves |
| --- | --- |
| `probe-entra` | Tenant discovery resolves and its `jwks_uri` is the expected Microsoft endpoint with usable RS256 keys; DCR registers a client; the authorize redirect targets exactly the discovered authorization endpoint with the provisioned client, callback, `openid profile email`, PKCE S256, state, and nonce; the flow cookie carries the issuer's security profile and a 600-second signed lifetime. Plus one **local control**, counted separately: a synthetic token carrying only the stack's unmapped group is refused as `entra_no_mapped_groups`. |
| `probe-google` | Google discovery is fetched and validated through the shipped resolver before any endpoint from it is followed; its JWKS serves usable RS256 keys; DCR registers a client; the authorize redirect targets exactly the validated authorization endpoint with the provisioned client, callback, scopes, PKCE S256, state, and nonce. |
| `probe-cloudflare` | A **current provider-signed Access assertion** (minted by `cloudflared access token` from your own Access login) reaches the consent page through the configured issuer, audience, certs URL, and identity port; the same request without an assertion is refused; an attacker signature under the provider's key ID is refused. Run `cloudflared access login <CF_HOST>/oauth/authorize` once in a browser first — `run.sh` mints the assertion from that login and never prints it. |
| `probe-e2e` | The shipped example composition, headless, on the probe's own in-process app: DCR into the shipped SQLite store; authorization code through a **probe-local identity port**; the **official MCP SDK client** completing a tool call over a real socket with the user token and again with a machine token; the tokenless RFC 9728 challenge; a machine credential provisioned into a process-local store (no shipped store implements the atomic §17.2 extension), minted through `client_credentials`, refused with a wrong secret and refused as `invalid_client` after `disableMachineClient`; refresh rotation; **`/oauth/revoke` observed** — the revoked refresh token is refused as `invalid_grant`; the **Redis limiter** admitting then refusing with 429 over a real connection; the JSONL and webhook sinks receiving the same ordered events, containing the exercised flow, and containing none of the run's credentials. It makes no identity-provider claim. |

A leg argument is required because the example **boot-refuses more than one
identity selector** — that is a fail-closed gate, not a limitation. Every probe
either exercises what a row claims or reports `FAIL`; there is no `SKIP`.

## Driving a real MCP client

```sh
scripts/live/serve.sh cloudflare_access entra google
```

Starts the shipped example once per leg on that leg's gateway port and runs the
named Cloudflare tunnel with an ingress generated for exactly those hostnames.
One tunnel carries every leg you name; start all the legs you want served in
**one** invocation, because a second connector with a different ingress would
receive part of the traffic. Before it exposes anything it proves readiness of
the process it started — the port answers, the child is alive, and `lsof`
reports the child as the only listener — and refuses a port that already has a
listener. It prints the public URL and the client command per leg, for example:

```
claude mcp add --transport http live-entra https://<host>/mcp
```

Ctrl-C stops the tunnel and the servers it started — never the process group.
Readiness waits up to `MCP_SSO_READINESS_POLLS` × 0.5 s per leg (default 120;
provider discovery at boot can take a while).
The client then performs discovery, registration, and authorize. **The consent
and identity-provider sign-in steps need a human at a browser** — that is why
`docs/live-verification.md` records those rows as owner-run, and a row flips to
verified only when the owner records the observed result and caveat. The
repeatable client × leg matrix is `scripts/live/CHECKLIST.md`.

## What these cannot cover

- Provider sign-in and consent (browser, by design — see the checklist)
- Entra group deny and ceiling reason codes on a real token, which need the
  deployed gateway because the provider redirects to the public hostname
- CIMD against a hosted metadata document — nothing serves one yet
