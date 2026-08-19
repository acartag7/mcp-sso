# Live client verification matrix

The automated suite (`test/e2e-*.test.ts`, `test/integration-*.test.ts`) drives the
full OAuth flow through the **official MCP SDK client**. Verifying against the
real-world MCP clients people actually use (claude.ai, ChatGPT, Claude Code, curl)
is a manual step, tracked in this file as a **provider × client matrix**. This is
the single source of truth for live verification — the README's
[Status](../README.md#status) section points here.

> **The rule for this table — never overclaim.** A row is `✅ verified` ONLY when the
> named flow was actually driven against the named provider and client, and the
> outcome recorded here with a date. `✅†` means "DCR/OAuth mechanics verified, but
> NOT the production identity leg" (see the dagger note below). `⬜ unverified` rows
> carry an exact owner-run checklist; they flip to `✅` **only when the owner runs
> them** and appends the date + observed result. A session that did not drive a flow
> MUST NOT mark it verified — leave it `⬜`. False green here is worse than an empty
> row: people choose an identity provider based on these checkmarks.

## What "verified" distinguishes

Two things get conflated; this table keeps them separate:

1. **DCR/OAuth mechanics** — the client self-registers, the user sees a real
   consent screen, the bridge mints + the client presents an audience-bound token,
   the tool round-trips. This works regardless of the *identity* backend (a local
   stub is enough).
2. **The production identity leg** — the upstream IdP (Cloudflare Access / Entra /
   etc.) actually authenticates the user and the bridge verifies THAT identity
   fail-closed. This is what an enterprise deployment depends on.

The four rows verified on 2026-07-04 cover **(1)** only. Later dated provider
rows cover **(2)**; remaining `⬜` rows still require their named owner-run
checklist.

## Pre-release campaigns

| Baseline | Evidence completed | Still pending |
| --- | --- | --- |
| Patched, uncommitted checkout based on `ee8994a` (2026-07-26/27) | Observed CIMD happy paths with Cloudflare Access, Entra ID, and Google; refresh rotation plus replay/family revocation; retained audit-log search found no backend credential. | Historical observation only: the exact dirty tree was neither committed nor archived, so this campaign does not satisfy the minimum live-row evidence contract and does not qualify as verified. |
| Clean `main` at `e71a2bb` (2026-07-28) | Three metadata/tokenless-challenge probes and DCR registrations; Cloudflare Access path gating; Entra- and Google-configured gateways resolving a public CIMD document to their authorization redirects; CIMD rejection of literal IP, DNS rebinding, DNS failure, non-200 response, wrong content type, oversized body, and timeout. See the [sanitized receipt](#clean-main-rerun-receipt-2026-07-28). | Browser completion stopped before identity and consent; the exact-runtime campaign below completed those legs. |
| Exact runtime commit `af2a61f` (2026-07-28) | Claude Code 2.1.220 completed CIMD authorization and protected `status` calls with Cloudflare Access, Entra ID, and Google. A corrected refresh harness proved A→B→C rotation, HTTP 400 `invalid_grant` on replayed A, then HTTP 400 `invalid_grant` on current C. Audit and retained client-result scans found zero backend-credential matches. See the [sanitized receipt](#exact-runtime-live-receipt-2026-07-28). | Entra deny/ceiling cases and the older claude.ai/ChatGPT CIMD observations remain pending as reproducible rows. |

No secrets, tenant/team identifiers, provider subjects, or deployment URLs from
these campaigns are retained in this public record.

### Clean-main rerun receipt (2026-07-28)

The partial rerun used a clean worktree at exact commit
`e71a2bbaf6902f98502a788a8d1e4bfc604b9bbc`. Provider configuration was loaded
from uncommitted private environment files; the retained public receipt contains
no provider value or deployment URL.

| Probe | Observed result |
| --- | --- |
| Discovery and tokenless protected-resource request | All three configured gateways returned their metadata, then rejected a tokenless `/mcp` request with 401 and a `resource_metadata` challenge constructed by `buildUnauthorizedChallenge`. |
| Dynamic registration | All three gateways returned 201 for a valid DCR registration. |
| CIMD redirect entry | The Entra- and Google-configured gateways resolved the public CIMD document and redirected to their configured identity provider. This stopped before browser login and is not a provider happy-path claim. |
| Cloudflare Access path gate | The public metadata, registration, token, and protected-resource paths remained reachable while the browser authorization path required the Access assertion. |
| Guarded CIMD rejection | Authorization rejected literal-IP admission, DNS rebinding, DNS failure, non-200 response, wrong content type, body over 5 KiB, and timeout cases. These requests exercised `createGuardedFetcher` through the gateway authorization path. |

### Exact-runtime live receipt (2026-07-28)

The three gateways ran from exact commit
`af2a61f1aa772a7f3963acfa9dab15c47f676607`; its runtime code is identical to
`e71a2bb` because the intervening changes are documentation and source comments
only. Provider secrets and identifiers remained in private environment files.

| Probe | Observed result |
| --- | --- |
| Cloudflare Access CIMD | Claude Code 2.1.220 completed CIMD fetch, Access identity verification, consent approval, authorization-code exchange, and a protected `status` call. The audit `clientId` for the protected call was an HTTPS CIMD identifier. |
| Entra ID CIMD | Claude Code 2.1.220 completed CIMD fetch, Entra identity verification, upstream callback, consent approval, authorization-code exchange, and a protected `status` call. The audit `clientId` for the protected call was an HTTPS CIMD identifier. |
| Google CIMD | Claude Code 2.1.220 completed CIMD fetch, Google identity verification, upstream callback, consent approval, authorization-code exchange, and a protected `status` call. The audit `clientId` for the protected call was an HTTPS CIMD identifier. |
| Refresh replay | A corrected harness required the full response shape: refresh A→B and B→C returned 200; replayed A returned HTTP 400 `invalid_grant`; current C then returned HTTP 400 `invalid_grant`, proving family revocation rather than a generic outage. |
| Credential containment | All three retained `status` tool results contained only the expected `ok`, `backend`, and `via` fields and contained no backend key. Each provider's audit log also had zero backend-key matches. |

## Matrix

| Provider | Client | Flow driven | Status | Date | Caveat / environment |
| --- | --- | --- | --- | --- | --- |
| local stub identity | curl | full OAuth dance + tokenless 401 challenge | ✅ | 2026-07-04 | `examples/fastify-sqlite` locally; DCR/PKCE/consent/token mechanics. Identity was the example's stub; **not** a real-IdP identity leg. |
| local stub identity | Official MCP SDK client | register→authorize→token→`/mcp`→refresh→replay-revoke→revoke | ✅ | 2026-07-04 | `test/e2e-mcp-sdk.test.ts` (automated; the current equivalent suite stays green). Stub identity; **not** a real-IdP identity leg. |
| local stub identity | Claude Code | consent (correct scopes) + `ping` round-trip | ✅† | 2026-07-04 | `claude mcp add --transport http` against local `http://localhost`. Originally ran against `DEV_STUB_SUBJECT` (since removed — replaced by console pairing). Mechanics only. |
| local stub identity | claude.ai (custom connector) | consent (correct scopes) + `ping` round-trip | ✅† | 2026-07-04 | Via a **named Cloudflare tunnel** (transport) on a real domain — see [`troubleshooting.md`](troubleshooting.md) for why ad-hoc `--url` tunnels are unreliable. Originally ran against `DEV_STUB_SUBJECT`. Mechanics only. |
| Cloudflare Access (production identity leg) | Claude Code (CLI), Codex CLI, claude.ai, ChatGPT, Official MCP SDK client | full flow against CF-Access-injected identity; fail-closed on policy, allowlist, and bypass | ✅ | 2026-07-07 | Five clients completed register→authorize→consent→token→`/mcp`. A denied account was stopped at the Access edge; a gateway allowlist rejection and missing-assertion rejection were audit-confirmed. The Access application was path-scoped to the browser authorize leg. Wrong-`aud` rejection was suite-covered but not separately live-driven. Codex CLI success is historical; see the current-version caveat below. |
| Cloudflare Access (production identity leg) | Claude Code 2.1.220 | CIMD `client_id`→authorize→Access identity→consent→token→`/mcp` `status` | ✅ | 2026-07-28 | Passed at exact runtime commit `af2a61f1aa772a7f3963acfa9dab15c47f676607`; audit-confirmed CIMD client ID and successful identity, approval, token exchange, and protected call. |
| Google sign-in (production identity leg) | Claude Code (CLI), Official MCP SDK client | register→authorize→Google login→callback→consent→token→`/mcp` `ping`; tokenless 401; hosted-domain rejection | ✅ | 2026-07-10 | Both clients completed the flow. The stable provider subject was consistent per account and distinct across accounts; no subject values are published. An outside hosted-domain account was rejected before token minting. Google remains the only generic-OIDC-family provider live-driven; a second generic issuer is pending. |
| Google sign-in (production identity leg) | Claude Code 2.1.220 | CIMD `client_id`→authorize→Google identity→consent→token→`/mcp` `status` | ✅ | 2026-07-28 | Passed at exact runtime commit `af2a61f1aa772a7f3963acfa9dab15c47f676607`; audit-confirmed CIMD client ID and successful identity, callback, approval, token exchange, and protected call. |
| Google sign-in (production identity leg) | Owner browser + refresh harness | DCR→authorize→Google login→callback→consent→token; refresh A→B→C→replay A→reject current C | ✅ | 2026-07-28 | Passed at exact runtime commit `af2a61f1aa772a7f3963acfa9dab15c47f676607`; replayed A returned HTTP 400 `invalid_grant`, then current C returned HTTP 400 `invalid_grant`, proving family revocation. |
| Entra ID (redirect flow, §17.11) | Claude Code | register→authorize→Entra login→consent→token→`/mcp` tools | ✅ | 2026-07-08 | The reproducible enterprise happy path used `mcp-sso@0.2.0`. See [`docs/field-report-api-key-gateway.md`](field-report-api-key-gateway.md). |
| Entra ID (redirect flow, §17.11) | Claude Desktop | register→authorize→Entra login→consent→token→`/mcp` tools | ✅ | 2026-07-08 | The enterprise happy path completed with `mcp-sso@0.2.0`. |
| Entra ID (redirect flow, §17.11) | Claude Code 2.1.220 | CIMD `client_id`→authorize→Entra identity→consent→token→`/mcp` `status` | ✅ | 2026-07-28 | Passed at exact runtime commit `af2a61f1aa772a7f3963acfa9dab15c47f676607`; audit-confirmed CIMD client ID and successful identity, callback, approval, token exchange, and protected call. |
| Entra ID (redirect flow, §17.11) | Owner browser + provider harness | wrong-tenant, group-overage, no-group, no-mapped-group, allowlist, and guest/B2B outcomes | ⬜ | 2026-07-26/27 | Observed on the patched, uncommitted `ee8994a`-based checkout, whose exact tree was not archived. The deny/ceiling sweep must be repeated on clean main to qualify. |
| Entra ID (redirect flow, §17.11) | claude.ai (custom connector) | CIMD `client_id`→authorize→Entra identity→consent→token→`/mcp` | ⬜ | 2026-07-26/27 | Observed on the patched, uncommitted `ee8994a`-based checkout, whose exact tree was not archived. This does not qualify as a verified row; clean-main browser completion is required. |
| Entra ID (redirect flow, §17.11) | ChatGPT (custom connector) | CIMD `client_id`→authorize→Entra identity→consent→token→`/mcp` | ⬜ | 2026-07-26/27 | Observed on the patched, uncommitted `ee8994a`-based checkout, whose exact tree was not archived. This does not qualify as a verified row; clean-main browser completion is required. |
| Cloudflare Access | ChatGPT custom connector | consent + tool round-trip | ✅ | 2026-07-07 | ChatGPT completed register→authorize→consent→token→`/mcp` `ping` against the same sanitized Cloudflare Access deployment. |
| Cloudflare Access / Entra / Google | Claude Code 2.1.220 + **api-key-gateway example** | full CIMD proxied round trip: client → gateway → token-only backend | ✅ | 2026-07-28 | All three `status` calls returned the expected allowlisted response shape at exact runtime commit `af2a61f1aa772a7f3963acfa9dab15c47f676607`; retained client results and all three audit logs had zero backend-key matches. |

**Current Codex CLI caveat (2026-07-28):** the installed 0.144.1 client showed
an RFC 9207 `iss` callback regression. This does not invalidate the dated
historical success row, but compatibility with that current client version is
pending upstream resolution and retest.

### † Dagger note (the four 2026-07-04 rows)

These four rows verify the **DCR/OAuth mechanics, not the production identity leg.**
At verification time the example used `DEV_STUB_SUBJECT`, a dev bypass that let the
OAuth dance complete with no real identity provider (MCP clients don't send
`Cf-Access-Jwt-Assertion` on their own). `DEV_STUB_SUBJECT` is now **removed** —
replaced by console pairing
([§17.5](contracts/17-v0-2-feature-contracts.md#175-console-pairing-identity-zero-idp-setup))
— and the same DCR/OAuth
mechanics are covered by the automated e2e (`test/e2e-pairing.test.ts`). The real
Cloudflare Access identity check — header-injected, fail-closed — is now live-verified
across Claude Code (CLI), Codex CLI, claude.ai, ChatGPT, and the official MCP SDK
client (matrix row above, 2026-07-07). Console pairing is for
single-operator/private-console deployments only; **never expose it on a public URL**
(it erases per-user attribution — see [`gateway-deployment.md`](gateway-deployment.md)).

---

## Executable probe harness

`scripts/live/` is the runnable harness: `run.sh` pulls one leg's values from
the OpenTofu stacks and executes an allowlisted entry, `probe-*.mjs` drive one
subject each against the shipped `examples/fastify-sqlite` app, `serve.sh`
exposes one or more legs behind the named tunnel for real MCP clients, and
`CHECKLIST.md` is the client × leg matrix a human runs against it. Its own
record is [`scripts/live/README.md`](../scripts/live/README.md); the harness
changes and its record change in the same pull request. **A harness is not
evidence.** A matrix row above flips only when the owner runs the probe or the
checklist against real provider infrastructure and records the observed result
— running the test suite proves the harness is wired, never that a provider
accepted anything.

| Harness | Drives | Evidence it can establish | Live-run status |
| --- | --- | --- | --- |
| `probe-cloudflare.mjs` | Cloudflare Access | a provider-signed assertion reaches consent; a missing assertion and an attacker signature under the provider key ID are both refused | not run in this change: `run.sh` at `a1dcba2` stopped, as designed, at minting the assertion — it needs the operator's own Access login (`cloudflared access login`) first |
| `probe-entra.mjs` | Entra ID | tenant discovery resolves to the expected JWKS with usable RS256 keys; the authorize redirect targets exactly the discovered endpoint and carries the expected upstream cookie profile; one local group-denial control | 13 live checks and the local control passed on 2026-08-19 through `run.sh` at runtime commit `a1dcba2` (the record commit after it is documentation only) |
| `probe-google.mjs` | Google sign-in | discovery is validated through the shipped resolver before its JWKS is followed; the authorize redirect targets exactly the validated endpoint | 11 live checks passed on 2026-08-19 through `run.sh` at runtime commit `a1dcba2` |
| `probe-e2e.mjs` | the shipped example composition, headless, with a probe-local identity port | DCR into the shipped SQLite store; authorization code; refresh rotation, then the replayed predecessor AND its live successor both refused as `invalid_grant` (replay-detection family revocation, not one dead token), with `/oauth/revoke` observed as `invalid_grant` on a second family the replay had not already revoked; the official MCP SDK client completing a tool call over a real socket with a user token and with a machine token; the tokenless RFC 9728 challenge; the §17.2 machine grant minting, refusing a wrong secret, and refusing a disabled client as `invalid_client`; the §17.10 Redis limiter admitting exactly the remaining window budget then refusing, over a real connection; the JSONL and webhook sinks receiving the same ordered events with none of the run's credentials (consent token, code, verifier, tokens, secrets, the signing private key). Machine rows live in a process-local store (no shipped store implements the atomic extension); no identity-provider claim | 43 checks passed on 2026-08-19 through `run.sh` at runtime commit `a1dcba2`, against a local Redis; `test/live-e2e-probe.test.mjs` spawns it in CI against the Redis service |

Each provider probe requires its credentials out of band, and none writes a
credential or provider identifier to output. Each provider probe builds the
example against a disposable state directory the library itself creates
(`ensureStateDir` refuses a pre-existing directory without its managed
`.gitignore`, so the temp container is never the state directory), and
`probe-e2e.mjs` composes the example app against a disposable temp directory;
every probe disposes of the app, the store, and that directory on every exit
path, so a run never mutates the deployment it is verifying. Each validates its
DCR callback against the effective redirect allowlist before any provider I/O.
Every probe either exercises what a row claims or reports `FAIL`; none reports
`SKIP`.

`run.sh` names the runtime commit and refuses a checkout with uncommitted
tracked changes (a run declared non-evidence with `MCP_SSO_ALLOW_DIRTY=true`
says so on stderr), switches off inherited shell tracing before any secret is
handled, and hands the entry an allowlisted environment — exactly the
variables it assembled plus `PATH`, `HOME`, `TMPDIR`, `LANG`, `LC_ALL` (the
server also `PORT` and `HOST=127.0.0.1`, loopback only) — so nothing
inherited (a stale selector, an OAuth override, `HOST`,
`MCP_SSO_TRUSTED_PROXIES`, `NODE_OPTIONS`) can choose a leg or reshape the run,
and its own helper processes run under the same minimal environment; validates
that exact environment through every pre-state gate the example itself runs
plus the leg's shipped identity constructor before it touches state; reads the
Google credential file through one descriptor as owner-only data rather than
sourcing it; hands `probe-e2e.mjs` no provider credential at all; and refuses a
symlinked or shared `.live-state` parent before rotating a previous leg's state
to `<leg>.previous` — only a leaf holding an `audit.jsonl` is rotated, so a
failed start and its retry never cost the last successful run's evidence —
stopping when that rotation fails. `serve.sh` bounds each leg's readiness wait by wall clock (`MCP_SSO_READINESS_SECONDS`, default 60) rather than by poll count, accepts readiness only from the process it
started (`lsof` must report that child as the only listener) and re-proves that
ownership immediately before exposing the tunnel, aborts when a server fails or
times out during startup, refuses a leg named twice or two
legs sharing a hostname or port, supervises the tunnel and every server so a
signal to the script itself still runs cleanup and a server dying while
serving stops the run, and signals only its own children on exit. These properties are exercised by `test/live-run-script.test.mjs` and
`test/live-serve-script.test.mjs`, which spawn the shipped scripts against
fixture infrastructure, and `test/live-e2e-probe.test.mjs`, which spawns the
end-to-end probe.

### Provisioning — the environment is infrastructure-as-code, not hand-built

The identity providers, hostnames, tunnel ports, and test users the harness
needs are **provisioned by OpenTofu stacks in a separate private repository**,
one stack per provider leg. Nothing is assembled by hand, and no provider
secret is stored in this repository or read from a developer's shell profile.

| What the harness needs | Where it comes from |
| --- | --- |
| `CF_ACCESS_ISSUER`, `CF_ACCESS_AUDIENCE`, `CF_ACCESS_CERTS_URL` | Cloudflare stack outputs |
| Public issuer origin + tunnel ingress port, per leg | Cloudflare stack outputs, keyed by leg so legs run side by side |
| Entra tenant, client id, client secret, redirect URI | Entra stack outputs, read by `run.sh` at run time; the secret is read as a sensitive output and exported only into the allowlisted entry |
| `ENTRA_GROUP_AUTHORIZATION_JSON` | the Entra stack's group-authorization mapping output, wrapped as `{"mapping": …}` with no `baseScopes` |
| Deny-leg fixtures — an unmapped group, a group-overage user, a no-group user, a cross-tenant guest | Entra stack outputs; the negative legs are provisioned, not improvised |
| Google client id and secret | a private owner-only `KEY=VALUE` file that `run.sh` reads as data (`scripts/live/README.md`) |

Two rules make this reproducible rather than a one-off: the mapping is fed in
through configuration, never by patching source (a run that edits library or
example code to make a leg pass has verified the patch, not the release); and
provider credentials reach the process from the stack outputs for the duration
of the run through `run.sh`, and every probe's output guards keep them out of
the evidence it prints. The stack handles, repository path, and tunnel id are supplied
through `MCP_SSO_*` environment variables and recorded in the maintainer's
project memory, because they name private infrastructure. Everything a run
*observes* — reason codes, statuses, flows — is public and belongs in the
matrix above.

---

## Owner-run checklists

These repeatable procedures produced the dated matrix evidence above and remain
the gate for any pending clean-main rerun. A new `⬜` row flips only after the
owner records the observed result and caveat in the matrix.

### A — Cloudflare Access (production identity leg) × a live client

The goal: prove a real MCP client completes the flow when Cloudflare Access — not a
local stub — is the identity source, and that a user NOT in the Access policy is
rejected.

**Create the Access application path-scoped to `/oauth/authorize*` — not the whole
hostname.** CF Access is the assertion-injecting proxy for the *browser authorize leg
only*: it must inject `Cf-Access-Jwt-Assertion` on `/oauth/authorize` (the consent
`/oauth/authorize/approve` is authenticated by the signed `consent_token`, not the CF
JWT — gating it under `/oauth/authorize*` is optional session-coherence defense-in-depth,
not required for the flow). The API paths the MCP client calls server-side —
`/.well-known/*`, `/oauth/register`, `/oauth/token`, `/oauth/revoke`, and `/mcp` (which
is protected by the bridge's own audience-bound token) — must stay **public**. A
whole-hostname Access app gates `/mcp` and `/oauth/token` too, so the client's
no-cookie requests get a login redirect instead of reaching the verifier and the flow
cannot complete. (Verified the hard way on 2026-07-07: a whole-hostname app returned
`302 → login` on every path; rescoping to `/oauth/authorize` + `/oauth/authorize/approve`
left only the authorize leg gated and the flow completed.) Two capture landmines when
filling the env below: `CF_ACCESS_ISSUER` is `https://<team>.cloudflareaccess.com` with
**no trailing slash** (jose matches `iss` exactly); `CF_ACCESS_AUDIENCE` is the app's
hex **AUD tag**, not the hostname.

```bash
# 1. Real signing material + the Cloudflare Access production path on a public https origin:
OAUTH_ISSUER=https://<your-host> \
OAUTH_RESOURCE=https://<your-host>/mcp \
OAUTH_CONSENT_SIGNING_SECRET=$(openssl rand -hex 32) \
OAUTH_SIGNING_PRIVATE_JWK='{"kty":"EC","crv":"P-256",...}' \
CF_ACCESS_AUDIENCE=<your-app-aud> \
CF_ACCESS_CERTS_URL=https://<team>.cloudflareaccess.com/cdn-cgi/access/certs \
CF_ACCESS_ISSUER=https://<team>.cloudflareaccess.com \
CF_ACCESS_EMAIL_ALLOWLIST=you@example.com \
node examples/fastify-sqlite/index.ts &

# 2. Expose it via a NAMED Cloudflare tunnel (ad-hoc --url tunnels are unreliable —
#    see docs/troubleshooting.md):
cloudflared tunnel route dns <tunnel-id> <your-host>
cloudflared tunnel --config tunnel-config.yml run

# 3. In the client (Claude Code: `claude mcp add --transport http`; claude.ai: add a
#    custom connector), point at https://<your-host>/mcp. You should hit the Cloudflare
#    Access sign-in first; after Access approves you, the mcp-sso consent screen appears;
#    approve; the tool is callable.
```

**Flips to ✅ when:** a user in the Access policy completes the flow and a tool
round-trips; AND a user NOT in the policy (or with a wrong-audience/`aud` Access JWT)
is rejected (fail-closed, direct 401 — never a bypass). Record the date + the Access
policy shape.

### B — Entra ID (redirect flow) × a live client

The goal: prove the §17.11 upstream redirect-leg orchestrator (`createEntraRedirectIdentity`)
works against a real Entra tenant, end-to-end through a browser, with a live MCP client.

- Register an Entra app; note `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`,
  and set `ENTRA_REDIRECT_URI=https://<your-host>/callback` (the orchestrator boot-asserts
  `identity.redirectUri === originOf(OAUTH_ISSUER) + callbackPath`; `/callback` here is the
  path you choose — the examples derive `callbackPath` from the URI's pathname).
- Use the api-key-gateway example (or fastify-sqlite) with `ENTRA_TENANT_ID` set, on a
  public https origin behind a named tunnel.
- In Claude Code / claude.ai, point at `https://<your-host>/mcp`. The mcp-sso authorize
  route redirects to Entra; after Entra sign-in + consent, the mcp-sso consent screen
  appears; approve; the tool is callable.

**Flips to ✅ when:** a real Entra user completes the redirect flow through a browser
and a tool round-trips; AND a user outside `ENTRA_SUBJECT_ALLOWLIST` / the wrong tenant
is rejected. The redirect-mechanics checklist is at the top of
`src/identity/entra-redirect.ts`; the deny, group-overage, and guest/B2B checklist
is at the top of `src/identity/entra.ts`. Record both before claiming the combined
provider flow and deny sweep live-complete.

### C — ChatGPT (custom connector) × a live client

The goal: repeat the historically completed ChatGPT custom-connector flow against
the release candidate. Pick **Cloudflare Access or Entra** as the identity backend
(do not use console pairing on a public URL).

- Stand up the example on a public https origin behind a named tunnel, with a real IdP
  (checklist A or B).
- In ChatGPT, add the connector at `https://<your-host>/mcp`; complete the OAuth flow;
  call a tool.

**Completion evidence:** ChatGPT identifies through an HTTPS CIMD `client_id` or
completes DCR registration, matching the mode named in the matrix row, then
completes authorization, consent, and a tool round-trip. Record which IdP was
used.

### D — api-key-gateway example × a live client

The goal: prove the worked gateway example (`examples/api-key-gateway/`) runs standalone
and that the backend credential is genuinely injected server-side and never reaches the
client — observed through a real MCP client, not just the automated test.

```bash
# 1. Set the backend credential (the static key the gateway injects for the backend):
BACKEND_API_KEY=$(openssl rand -hex 32) \
node examples/api-key-gateway/index.ts
#    → prints the gateway URL + the backend it proxies to; identity is console pairing
#      (paste the one-time code) by default. For a multi-user run, use the CF Access or
#      Entra or Google env-switch instead (docs/gateway-deployment.md).

# 2. In Claude Code: claude mcp add --transport http gw http://localhost:3000/mcp
#    → consent; call the `status` tool; the response comes from the BACKEND through the
#      gateway (the backend's marker proves the proxy round trip).

# 3. Verify the backend credential never leaked: it is NOT in the client, NOT in any
#      response the client saw, NOT in ./.mcp-sso/audit.jsonl (the default state dir
#      when MCP_SSO_DIR is unset and the server is started from the repo root).
#      (The automated test test/integration-gateway.test.ts asserts this probe already;
#      the live run confirms it against a real client.)
```

**Completion evidence:** a real client completes the flow through the gateway, a
proxied backend tool round-trips, and a manual check confirms the backend
credential appears in no client-visible output. Record the identity backend used
(console pairing / Cloudflare Access / Entra / Google) in the matrix row.

---

## Tunnel note

Anonymous quick tunnels (`cloudflared tunnel --url`) are unreliable for OAuth callback
flows; use a **named tunnel** with an explicit `ingress:` config. Full write-up:
[`troubleshooting.md`](troubleshooting.md).
