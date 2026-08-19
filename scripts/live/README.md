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

`run.sh` generates fresh signing material for the run, reads the selected leg's
values from the stacks, validates every one of them through the shipped code
(`scripts/live/run-support.mjs` runs every pre-state gate `buildExample` itself
runs — selector cardinality, DCR mode, proxy trust, config parse, deployment
combination — plus the Entra or Cloudflare identity constructor; Google's
constructor performs discovery, so its values are shape-checked and the probe
performs the discovery), and only then executes the entry. It accepts these
pairs and nothing else, so a stack credential is handed to an allowlisted entry
or to that preflight — never to an arbitrary path:

| Entry | Legs |
| --- | --- |
| `scripts/live/probe-entra.mjs` | `entra` |
| `scripts/live/probe-cloudflare.mjs` | `cloudflare_access` |
| `scripts/live/probe-google.mjs` | `google` |
| `scripts/live/probe-e2e.mjs` | any (needs `REDIS_URL`) |
| `examples/fastify-sqlite/index.ts` | any (what `serve.sh` starts) |

The entry's environment is an **allowlist**, not your shell's environment minus
a blocklist: it receives exactly the variables `run.sh` assembled plus `PATH`,
`HOME`, `TMPDIR`, `LANG`, and `LC_ALL` — nothing else (the example server
additionally gets `PORT` and `HOST=127.0.0.1`, so a tunnel-backed server binds
loopback only). A stale identity
selector, an `OAUTH_*` override, `HOST`, `MCP_SSO_TRUSTED_PROXIES`,
`NODE_OPTIONS`, or `NODE_TLS_REJECT_UNAUTHORIZED` in your shell cannot select
a leg or reshape the run, and every helper `node` the runner itself starts runs
under the same minimal environment. `probe-e2e.mjs` composes its own app and
receives no provider credential at all — only the issuer origin, the run's
signing material, and `REDIS_URL`. `PORT` reaches only the example-server
entry (that is how `serve.sh` places each leg). Stored DCR with the loopback
origins allowlisted is the default; `MCP_SSO_ALLOW_LOOPBACK=false` drops
loopback, and `MCP_SSO_DCR_MODE=stateless` boots only together with it (the
deployment guard refuses stateless DCR beside loopback entries, and the
preflight refuses it before any state moves).

Two Entra deny legs are driven through **operator-supplied deliberately-wrong
values**, which never come from a stack output (those are the real values):
`MCP_SSO_ENTRA_ALLOWED_TENANT_IDS` (a tenant list that excludes yours, for the
wrong-tenant denial) and `MCP_SSO_ENTRA_SUBJECT_ALLOWLIST` (a subject that is
not the one signing in, for the allowlist denial). The runner maps each onto
the example's `ENTRA_ALLOWED_TENANT_IDS` / `ENTRA_SUBJECT_ALLOWLIST` — the bare
names themselves stay un-allowlisted from the ambient shell, so a wrong value
reaches a run only through its clearly-marked `MCP_SSO_` channel. Leave both
unset and the leg runs as the positive-only configuration.

`run.sh` names the runtime commit on stderr and refuses a checkout with
uncommitted tracked changes — live evidence must name a commit; set
`MCP_SSO_ALLOW_DIRTY=true` only for a run you will not record as evidence. It
also switches off shell tracing inherited through `SHELLOPTS` before any
secret is handled.

Only the example-server entry gets a state directory, `.live-state/<leg>` in
this checkout (ignored by Git). `run-support.mjs` refuses a `.live-state` that
is a symlink or that anyone else can read, and only after the preflight has
passed does it touch prior state — and then it keeps the last generation that
holds evidence: a `.live-state/<leg>` with an `audit.jsonl` is rotated to
`.live-state/<leg>.previous` (replacing the generation before it), while a leaf
without one — a start that failed after the preflight, a server that never
took a request — is removed and `<leg>.previous` is left as it was. So a start
that fails after this point (a provider discovery at boot, a refused bind) and
the retry after it never cost the last successful run's audit trail. A rotation
or removal that fails stops the run, and nothing is ever deleted or moved
through a link. Do not start the server entry for a
leg that `serve.sh` is currently serving — that rotates the live server's state
out from under it. The probes never touch `.live-state`; each provider probe
builds the example from a disposable temp directory the library creates, and
`probe-e2e.mjs` composes the example app against one, removed on every exit
path.

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
| `probe-e2e` | The shipped example composition, headless, on the probe's own in-process app: DCR into the shipped SQLite store; authorization code through a **probe-local identity port**; the **official MCP SDK client** completing a tool call over a real socket with the user token and again with a machine token; the tokenless RFC 9728 challenge; a machine credential provisioned into a process-local store (no shipped store implements the atomic §17.2 extension), minted through `client_credentials`, refused with a wrong secret and refused as `invalid_client` after `disableMachineClient`; refresh rotation, then a **replayed predecessor refused and its live successor refused with it** — replay detection revoking the whole family, not one dead token — and **`/oauth/revoke` observed on a second family** the replay had not already revoked; the **Redis limiter** admitting then refusing with 429 over a real connection; the JSONL and webhook sinks receiving the same events and **exactly the sequence the run recorded as it happened** — each action registers the events it causes, so the receipt cannot fall behind the flow in kind or in count — and containing none of the run's credentials, likewise registered where each is created or submitted (including the deliberately rejected client secret). It makes no identity-provider claim. |

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
reports the child as the only listener, re-proved immediately before the tunnel
is exposed — and refuses a port that already has a listener. It prints the public URL and the client command per leg, for example:

```
claude mcp add --transport http live-entra https://<host>/mcp
```

The tunnel and every server run supervised: a signal delivered to `serve.sh`
itself — Ctrl-C, or a `kill` by PID — stops the tunnel and the servers it
started — with a bounded grace period before each is killed, so one child that
ignores the signal cannot stall the rest of the cleanup — never the process
group, and a server that dies **or whose port changes hands** while serving
stops the run rather than leaving the tunnel
exposing a dead or foreign backend (ownership is re-proved every second, not
only before exposure). A leg named
twice, or two legs the stack maps to the same hostname or port, is refused
before anything starts.
Readiness waits up to `MCP_SSO_READINESS_SECONDS` per leg (default 60; provider
discovery at boot can take a while) — a wall-clock budget, so a server that
accepts the connection and then stalls cannot stretch the wait.
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
